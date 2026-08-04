from __future__ import annotations

import asyncio
import inspect
import json
import sqlite3
import tempfile
import threading
import unittest
from collections.abc import Iterator
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request as StarletteRequest

from router_dump_analyzer.annotation_store import (
    CORRELATION_REPORT_SCHEMA_VERSION,
    ReviewValidationError,
)
from router_dump_analyzer.control_plane import (
    ControlPlane,
    ControlPlaneError,
    ControlPlaneLimits,
)
from router_dump_analyzer.ingestion import IngestionCoordinator
from router_dump_analyzer.ingestion_pipeline import (
    ImportScope,
    ImportState,
    IngestionPipelineError,
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
    RetentionPolicy,
)
from router_dump_analyzer.operational_logging import (
    MAX_OPERATIONAL_COUNTER,
    OPERATIONAL_EVENT_CONTRACT,
    OperationalEventClassHealthSnapshot,
    OperationalEventDiagnosticsSnapshot,
    OperationalEventHealthSnapshot,
)
from router_dump_analyzer.plugin_api import DomainEvent
from router_dump_analyzer.private_analysis import (
    WORKSPACE_DISCLOSURE_POLICY_VERSION,
)
from router_dump_analyzer.session_store import CatalogRetentionPolicy
from router_dump_analyzer.value_core import MAX_JSON_SAFE_INTEGER
from router_dump_analyzer.web.control_plane_api import (
    _API_ERROR_DOMAIN_ROOTS,
    _API_ERROR_POLICY_BY_CLASS,
    CONTROL_PLANE_ADMIN_ROLE,
    CONTROL_PLANE_INSTANCE_OPERATOR_ROLE,
    CONTROL_PLANE_READ_ROLE,
    CONTROL_PLANE_WRITE_ROLE,
    MAX_CONTROL_PLANE_JSON_BODY_BYTES,
    ControlPlaneAccessDenialReporter,
    ControlPlaneAccessPhase,
    ControlPlaneAccessReason,
    ControlPlaneIdentity,
    TrustedHeaderIdentityResolver,
    _api_error_policy,
    _ControlPlaneAccessDenied,
    _parse_if_match,
    _raise_api_error,
    _request_canonical_integer,
    _resolved_tenant_correlation,
    _retention_integer,
    _retention_policies,
    control_plane_router,
    preview_workspace_retention,
)
from tests.test_control_plane import _EventPlugin

PRIVATE_API_FAILURE_MARKER = "PRIVATE-API-FAILURE-0c84af"


class _SecretApiCoordinator(IngestionCoordinator):
    def ingest(self, plugin, input_path, *, node_hint=None, metadata=None):
        del plugin, input_path, node_hint, metadata
        raise RuntimeError(PRIVATE_API_FAILURE_MARKER)


class _PluginNsEventPlugin(_EventPlugin):
    """Exercise opaque plug-in fields that resemble core time names."""

    def parse_text_trace(self, reader, spec):
        for output in super().parse_text_trace(reader, spec):
            if isinstance(output, DomainEvent):
                output = replace(
                    output,
                    attributes={
                        **output.attributes,
                        "hold_down_ns": "fast",
                        "opaque_counter_ns": 7,
                    },
                )
            yield output


def _fixture_bytes(*, ifindex: int, final_state: str = "up") -> bytes:
    return (
        "\n".join(
            (
                json.dumps(
                    {
                        "captured_at_ns": 100,
                        "ifindex": ifindex,
                        "name": f"xe-0/0/{ifindex}",
                        "oper_status": "down",
                    }
                ),
                json.dumps(
                    {
                        "captured_at_ns": 200,
                        "ifindex": ifindex,
                        "name": f"xe-0/0/{ifindex}",
                        "oper_status": final_state,
                    }
                ),
            )
        )
        + "\n"
    ).encode()


class ControlPlaneApiTests(unittest.TestCase):
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"
    project_id = "project-shared"
    workspace_id = "workspace-shared"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.control_plane = ControlPlane(
            Path(self.temporary.name),
            registry=PluginRegistry((_PluginNsEventPlugin(),)),
            pipeline_limits=PipelineLimits(
                max_upload_bytes=1024 * 1024,
                max_workers=1,
                lease_seconds=30,
                poll_interval_seconds=0.01,
                plugin_execution_mode=PluginExecutionMode.INLINE,
            ),
            limits=ControlPlaneLimits(
                max_dataset_bytes=1024 * 1024,
                dataset_cache_entries=2,
            ),
        )
        self.control_plane.start()
        application = FastAPI()
        application.include_router(control_plane_router)
        application.state.control_plane = self.control_plane
        application.state.control_plane_identity_resolver = (
            TrustedHeaderIdentityResolver(
                allowed_hosts=("testserver",),
                allowed_origins=("http://testserver",),
            )
        )
        self.client_context = TestClient(application)
        self.client = self.client_context.__enter__()

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)
        self.control_plane.close(timeout=5)
        self.temporary.cleanup()

    @staticmethod
    def _read_headers(tenant_id: str) -> dict[str, str]:
        return {"X-Tenant-ID": tenant_id}

    @classmethod
    def _write_headers(
        cls,
        tenant_id: str,
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, str]:
        result = {
            **cls._read_headers(tenant_id),
            "X-Principal-ID": "reviewer@example.test",
        }
        if idempotency_key is not None:
            result["Idempotency-Key"] = idempotency_key
        return result

    @staticmethod
    def _capturing_access_reporter(
        events: list[tuple[str, dict[str, object]]],
        *,
        minimum_interval_seconds: float = 0.0,
        maximum_interval_seconds: float = 0.0,
        monotonic=lambda: 0.0,
    ) -> ControlPlaneAccessDenialReporter:
        def capture(event: str, **fields: object) -> bool:
            events.append((event, dict(fields)))
            return True

        return ControlPlaneAccessDenialReporter(
            emitter=capture,
            monotonic=monotonic,
            minimum_interval_seconds=minimum_interval_seconds,
            maximum_interval_seconds=maximum_interval_seconds,
        )

    @property
    def workspace_path(self) -> str:
        return (
            f"/v1/control-plane/projects/{self.project_id}"
            f"/workspaces/{self.workspace_id}"
        )

    def test_health_is_available_without_identity_or_analysis_session(self) -> None:
        response = self.client.get("/v1/control-plane/health")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        payload = response.json()
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["configured"])
        self.assertTrue(payload["healthy"])
        self.assertTrue(payload["ingestion_workers"]["started"])
        self.assertEqual(payload["ingestion_workers"]["configured_workers"], 1)
        self.assertEqual(payload["ingestion_workers"]["live_workers"], 1)

    def test_manual_router_mount_lazily_installs_an_app_scoped_reporter(self) -> None:
        self.assertFalse(
            hasattr(
                self.client.app.state,
                "control_plane_access_denial_reporter",
            )
        )
        denied = self.client.get("/v1/control-plane/projects")
        self.assertEqual(denied.status_code, 401, denied.text)
        reporter = self.client.app.state.control_plane_access_denial_reporter
        self.assertIsInstance(reporter, ControlPlaneAccessDenialReporter)
        self.assertEqual(reporter.snapshot().observed_denials, 1)

    def test_retention_preview_is_async_and_uses_a_dedicated_offload(self) -> None:
        # A synchronous FastAPI handler consumes AnyIO's shared sync-route
        # worker capacity while waiting.  The preview is an async handler that
        # explicitly offloads its bounded blocking inventory through asyncio's
        # executor instead, leaving health and other sync routes independent.
        self.assertTrue(inspect.iscoroutinefunction(preview_workspace_retention))

    def test_health_degrades_for_an_aged_pending_import(self) -> None:
        ingestion = self.control_plane.ingestion
        ingestion.close(timeout=5)
        scope = ImportScope(
            self.tenant_a,
            self.project_id,
            self.workspace_id,
        )
        admitted = ingestion.submit_bytes(
            scope,
            _fixture_bytes(ifindex=41),
            original_name="stalled-health.jsonl",
        )
        with ingestion._connect() as connection:
            connection.execute(
                "UPDATE ingestion_imports SET updated_at_ns = 0 WHERE import_id = ?",
                (admitted.import_id,),
            )

        response = self.client.get("/v1/control-plane/health")
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["status"], "degraded")
        self.assertFalse(payload["healthy"])
        self.assertEqual(payload["ingestion_workers"]["pending_imports"], 1)
        self.assertEqual(payload["ingestion_workers"]["stalled_imports"], 1)

    def _provision_scope(self, tenant_id: str) -> None:
        project = self.client.post(
            "/v1/control-plane/projects",
            headers=self._write_headers(
                tenant_id,
                idempotency_key=f"{tenant_id}-project",
            ),
            json={
                "project_id": self.project_id,
                "label": f"Project for {tenant_id}",
            },
        )
        self.assertEqual(project.status_code, 201, project.text)
        workspace = self.client.post(
            f"/v1/control-plane/projects/{self.project_id}/workspaces",
            headers=self._write_headers(
                tenant_id,
                idempotency_key=f"{tenant_id}-workspace",
            ),
            json={
                "workspace_id": self.workspace_id,
                "label": f"Workspace for {tenant_id}",
            },
        )
        self.assertEqual(workspace.status_code, 201, workspace.text)

    def test_workspace_private_analysis_policy_is_versioned_and_default_denied(
        self,
    ) -> None:
        self._provision_scope(self.tenant_a)
        path = f"{self.workspace_path}/private-analysis-policy"
        default = self.client.get(
            path,
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(default.status_code, 200, default.text)
        self.assertEqual(default.headers["etag"], '"0"')
        self.assertFalse(default.json()["explicit"])
        self.assertEqual(default.json()["policy"]["mode"], "disabled")

        headers = {
            **self._write_headers(
                self.tenant_a,
                idempotency_key="enable-private-analysis",
            ),
            "If-Match": '"0"',
        }
        body = {
            "policy_version": WORKSPACE_DISCLOSURE_POLICY_VERSION,
            "mode": "full_fidelity",
            "transports": ["in_process"],
        }
        enabled = self.client.put(path, headers=headers, json=body)
        self.assertEqual(enabled.status_code, 200, enabled.text)
        self.assertEqual(enabled.headers["etag"], '"1"')
        self.assertEqual(enabled.json()["policy"], body)
        self.assertIsInstance(enabled.json()["created_at_ns"], str)

        replay = self.client.put(path, headers=headers, json=body)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json(), enabled.json())
        stale_headers = {
            **self._write_headers(self.tenant_a),
            "If-Match": '"0"',
        }
        stale = self.client.put(
            path,
            headers=stale_headers,
            json={
                "policy_version": WORKSPACE_DISCLOSURE_POLICY_VERSION,
                "mode": "disabled",
                "transports": [],
            },
        )
        self.assertEqual(stale.status_code, 409, stale.text)
        current = self.client.get(
            path,
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(current.headers["etag"], '"1"')
        self.assertEqual(current.json(), enabled.json())

    def test_workspace_private_analysis_policy_is_admin_and_scope_bound(self) -> None:
        self._provision_scope(self.tenant_a)
        path = f"{self.workspace_path}/private-analysis-policy"
        body = {
            "policy_version": WORKSPACE_DISCLOSURE_POLICY_VERSION,
            "mode": "client_safe",
            "transports": ["local_subprocess"],
        }
        original_resolver = self.client.app.state.control_plane_identity_resolver
        self.client.app.state.control_plane_identity_resolver = lambda _request: (
            ControlPlaneIdentity(
                tenant_id=self.tenant_a,
                principal_id="reader-only",
                roles=frozenset({CONTROL_PLANE_READ_ROLE, CONTROL_PLANE_WRITE_ROLE}),
            )
        )
        denied = self.client.put(
            path,
            headers={
                "X-Tenant-ID": self.tenant_a,
                "X-Principal-ID": "reader-only",
                "If-Match": '"0"',
            },
            json=body,
        )
        self.assertEqual(denied.status_code, 403, denied.text)

        self.client.app.state.control_plane_identity_resolver = lambda _request: (
            ControlPlaneIdentity(
                tenant_id=self.tenant_a,
                principal_id="admin-only",
                roles=frozenset({CONTROL_PLANE_ADMIN_ROLE}),
                project_ids=frozenset({self.project_id}),
                workspace_ids=frozenset({self.workspace_id}),
            )
        )
        accepted = self.client.put(
            path,
            headers={
                "X-Tenant-ID": self.tenant_a,
                "X-Principal-ID": "admin-only",
                "If-Match": '"0"',
            },
            json=body,
        )
        self.assertEqual(accepted.status_code, 200, accepted.text)

        self.client.app.state.control_plane_identity_resolver = lambda _request: (
            ControlPlaneIdentity(
                tenant_id=self.tenant_a,
                principal_id="scoped-reader",
                roles=frozenset({CONTROL_PLANE_READ_ROLE}),
                project_ids=frozenset({"another-project"}),
                workspace_ids=frozenset({"another-workspace"}),
            )
        )
        hidden = self.client.get(
            path,
            headers={"X-Tenant-ID": self.tenant_a},
        )
        self.assertEqual(hidden.status_code, 404, hidden.text)
        self.client.app.state.control_plane_identity_resolver = original_resolver
        wrong_project = self.client.get(
            (
                "/v1/control-plane/projects/another-project/workspaces/"
                f"{self.workspace_id}/private-analysis-policy"
            ),
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(wrong_project.status_code, 404, wrong_project.text)

    def test_workspace_private_analysis_policy_rejects_noncanonical_body(self) -> None:
        self._provision_scope(self.tenant_a)
        path = f"{self.workspace_path}/private-analysis-policy"
        headers = {
            **self._write_headers(self.tenant_a),
            "If-Match": '"0"',
        }
        cases = (
            {},
            {
                "policy_version": WORKSPACE_DISCLOSURE_POLICY_VERSION,
                "mode": "full_fidelity",
                "transports": ["in_process"],
                "future": True,
            },
            {
                "policy_version": WORKSPACE_DISCLOSURE_POLICY_VERSION,
                "mode": "full_fidelity",
                "transports": ["public_api"],
            },
            {
                "policy_version": WORKSPACE_DISCLOSURE_POLICY_VERSION,
                "mode": "full_fidelity",
                "transports": ["local_subprocess", "in_process"],
            },
        )
        for body in cases:
            with self.subTest(body=body):
                response = self.client.put(path, headers=headers, json=body)
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(
                    response.json(),
                    {"detail": "workspace disclosure policy is invalid"},
                )
        missing_precondition = self.client.put(
            path,
            headers=self._write_headers(self.tenant_a),
            json={
                "policy_version": WORKSPACE_DISCLOSURE_POLICY_VERSION,
                "mode": "disabled",
                "transports": [],
            },
        )
        self.assertEqual(missing_precondition.status_code, 428)

    def _upload(
        self,
        content: bytes,
        *,
        original_name: str,
        idempotency_key: str,
        node_hint: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        midpoint = max(1, len(content) // 2)

        def stream() -> Iterator[bytes]:
            yield content[:midpoint]
            yield content[midpoint:]

        headers = {
            **self._write_headers(
                self.tenant_a,
                idempotency_key=idempotency_key,
            ),
            "Content-Type": "application/x-ndjson",
        }
        if node_hint is not None:
            headers["X-Node-Hint"] = node_hint
        if metadata is not None:
            headers["X-Import-Metadata"] = json.dumps(metadata)
        admitted = self.client.post(
            f"{self.workspace_path}/imports",
            params={"original_name": original_name},
            headers=headers,
            content=stream(),
        )
        self.assertEqual(admitted.status_code, 202, admitted.text)
        body = admitted.json()
        self.assertEqual(body["state"], "admitting")
        self.assertFalse(body["terminal"])
        completed = self.control_plane.ingestion.wait(
            ImportScope(
                self.tenant_a,
                self.project_id,
                self.workspace_id,
            ),
            body["import_id"],
            timeout=10,
        )
        self.assertEqual(
            completed.state,
            ImportState.COMPLETED,
            completed.error_message,
        )
        fetched = self.client.get(
            f"{self.workspace_path}/imports/{body['import_id']}",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(fetched.status_code, 200, fetched.text)
        self.assertEqual(fetched.json()["state"], "completed")
        events = self.client.get(
            f"{self.workspace_path}/imports/{body['import_id']}/events",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(events.status_code, 200, events.text)
        self.assertEqual(
            [event["event_type"] for event in events.json()["items"]],
            [
                "upload_staged",
                "admission_started",
                "upload_admitted",
                "probe_started",
                "plugin_auto_selected",
                "ingestion_started",
                "revision_staged",
                "publication_started",
                "revision_published",
            ],
        )
        return fetched.json()

    def _catalog_revisions(self) -> list[dict[str, Any]]:
        response = self.client.get(
            f"{self.workspace_path}/revisions",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["items"]

    def test_time_range_subject_accepts_precise_decimal_nanoseconds(self) -> None:
        self._provision_scope(self.tenant_a)
        start = 9_007_199_254_740_993
        end = start + 10
        fixture = (
            json.dumps(
                {
                    "captured_at_ns": start,
                    "ifindex": 7,
                    "name": "xe-0/0/7",
                    "oper_status": "down",
                }
            )
            + "\n"
            + json.dumps(
                {
                    "captured_at_ns": end,
                    "ifindex": 7,
                    "name": "xe-0/0/7",
                    "oper_status": "up",
                }
            )
            + "\n"
        ).encode()
        self._upload(
            fixture,
            original_name="status.jsonl",
            idempotency_key="precise-time-upload",
        )
        revision_id = self._catalog_revisions()[0]["revision_id"]
        response = self.client.post(
            f"{self.workspace_path}/annotations",
            headers=self._write_headers(self.tenant_a),
            json={
                "kind": "marker",
                "subjects": [
                    {
                        "revision_id": revision_id,
                        "kind": "time_range",
                        "start_ns": str(start),
                        "end_ns": str(end),
                    }
                ],
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        subject = response.json()["subjects"][0]
        self.assertEqual(subject["start_ns"], str(start))
        self.assertEqual(subject["end_ns"], str(end))

    def test_cursor_integer_language_is_canonical_and_round_trips(self) -> None:
        self._provision_scope(self.tenant_a)
        completed = self._upload(
            _fixture_bytes(ifindex=17),
            original_name="status.jsonl",
            idempotency_key="cursor-upload",
        )
        for invalid in ("01", "+1", "-0", "1.0", "-1"):
            with self.subTest(before_created_at_ns=invalid):
                response = self.client.get(
                    f"{self.workspace_path}/imports",
                    params={
                        "before_created_at_ns": invalid,
                        "before_import_id": completed["import_id"],
                    },
                    headers=self._read_headers(self.tenant_a),
                )
                self.assertEqual(response.status_code, 422, response.text)
            with self.subTest(after_sequence=invalid):
                response = self.client.get(
                    f"{self.workspace_path}/imports/{completed['import_id']}/events",
                    params={"after_sequence": invalid},
                    headers=self._read_headers(self.tenant_a),
                )
                self.assertEqual(response.status_code, 422, response.text)
            with self.subTest(review_after_sequence=invalid):
                response = self.client.get(
                    f"{self.workspace_path}/review-audit",
                    params={"after_sequence": invalid},
                    headers=self._read_headers(self.tenant_a),
                )
                self.assertEqual(response.status_code, 422, response.text)

        review_range_failures = {
            "01": "after_sequence must be a canonical decimal integer",
            "+1": "after_sequence must be a canonical decimal integer",
            "-1": "after_sequence must be at least 0",
            str(MAX_JSON_SAFE_INTEGER + 1): (
                f"after_sequence must be no greater than {MAX_JSON_SAFE_INTEGER}"
            ),
        }
        for value, expected_detail in review_range_failures.items():
            with self.subTest(review_after_sequence=value):
                response = self.client.get(
                    f"{self.workspace_path}/review-audit",
                    params={"after_sequence": value},
                    headers=self._read_headers(self.tenant_a),
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(response.json()["detail"], expected_detail)

        first_page = self.client.get(
            f"{self.workspace_path}/imports",
            params={"limit": "1"},
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(first_page.status_code, 200, first_page.text)
        cursor = first_page.json()["next_cursor"]
        self.assertIsNotNone(cursor)
        second_page = self.client.get(
            f"{self.workspace_path}/imports",
            params=cursor,
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(second_page.status_code, 200, second_page.text)
        self.assertEqual(second_page.json()["items"], [])

    def test_retention_audit_cursors_use_canonical_json_safe_integers(self) -> None:
        self._provision_scope(self.tenant_a)
        headers = self._read_headers(self.tenant_a)
        failures = {
            "01": "must be a canonical decimal integer",
            "+1": "must be a canonical decimal integer",
            "-1": "must be at least 0",
            str(MAX_JSON_SAFE_INTEGER + 1): (
                f"must be no greater than {MAX_JSON_SAFE_INTEGER}"
            ),
        }
        for field in ("catalog_after_sequence", "review_after_sequence"):
            for value, suffix in failures.items():
                with self.subTest(field=field, value=value):
                    response = self.client.get(
                        f"{self.workspace_path}/retention/audit",
                        params={field: value},
                        headers=headers,
                    )
                    self.assertEqual(response.status_code, 422, response.text)
                    self.assertEqual(response.json()["detail"], f"{field} {suffix}")

        boundary = self.client.get(
            f"{self.workspace_path}/retention/audit",
            params={
                "catalog_after_sequence": str(MAX_JSON_SAFE_INTEGER),
                "review_after_sequence": str(MAX_JSON_SAFE_INTEGER),
            },
            headers=headers,
        )
        self.assertEqual(boundary.status_code, 200, boundary.text)

        self.control_plane.sessions._connection.execute(
            "INSERT INTO sqlite_sequence(name, seq) VALUES (?, ?)",
            ("catalog_retention_audit", MAX_JSON_SAFE_INTEGER - 1),
        )
        self.control_plane.sessions.purge_retention(
            self.tenant_a,
            self.workspace_id,
            CatalogRetentionPolicy(enabled=True),
            operation_id="api-sequence-boundary",
        )
        projected = self.client.get(
            f"{self.workspace_path}/retention/audit",
            params={"catalog_after_sequence": str(MAX_JSON_SAFE_INTEGER - 1)},
            headers=headers,
        )
        self.assertEqual(projected.status_code, 200, projected.text)
        self.assertEqual(
            projected.json()["catalog"][0]["sequence"],
            MAX_JSON_SAFE_INTEGER,
        )

        unsafe_sequence = MAX_JSON_SAFE_INTEGER + 1
        self.control_plane.sessions._connection.execute(
            "UPDATE catalog_retention_audit SET sequence = ? WHERE operation_id = ?",
            (unsafe_sequence, "api-sequence-boundary"),
        )
        corrupt = self.client.get(
            f"{self.workspace_path}/retention/audit",
            headers=headers,
        )
        self.assertEqual(corrupt.status_code, 500, corrupt.text)
        self.assertNotIn(str(unsafe_sequence), corrupt.text)

    def test_absent_control_plane_and_trusted_tenant_boundary(self) -> None:
        application = FastAPI()
        application.include_router(control_plane_router)
        with TestClient(application) as client:
            unavailable = client.get(
                "/v1/control-plane/projects",
                headers=self._read_headers(self.tenant_a),
            )
        self.assertEqual(unavailable.status_code, 503)

        missing_tenant = self.client.get("/v1/control-plane/projects")
        self.assertEqual(missing_tenant.status_code, 401)
        missing_principal = self.client.post(
            "/v1/control-plane/projects",
            headers=self._read_headers(self.tenant_a),
            json={"project_id": "project-a", "label": "Project A"},
        )
        self.assertEqual(missing_principal.status_code, 401)

        self._provision_scope(self.tenant_a)
        self._provision_scope(self.tenant_b)
        created = self.client.post(
            f"{self.workspace_path}/sessions",
            headers=self._write_headers(self.tenant_a),
            json={"session_id": "session-private", "label": "A-only"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        other_tenant = self.client.get(
            f"{self.workspace_path}/sessions",
            headers=self._read_headers(self.tenant_b),
        )
        self.assertEqual(other_tenant.status_code, 200, other_tenant.text)
        self.assertEqual(other_tenant.json()["items"], [])

        replay_key = self._write_headers(
            self.tenant_a,
            idempotency_key="project-conflict",
        )
        first = self.client.post(
            "/v1/control-plane/projects",
            headers=replay_key,
            json={"project_id": "project-idempotent", "label": "First"},
        )
        self.assertEqual(first.status_code, 201, first.text)
        conflict = self.client.post(
            "/v1/control-plane/projects",
            headers=replay_key,
            json={"project_id": "project-idempotent", "label": "Different"},
        )
        self.assertEqual(conflict.status_code, 409, conflict.text)

        verified_application = FastAPI()
        verified_application.include_router(control_plane_router)
        verified_application.state.control_plane = self.control_plane
        verified_application.state.control_plane_identity_resolver = lambda _request: (
            ControlPlaneIdentity(
                tenant_id=self.tenant_a,
                principal_id="verified-reviewer",
                roles=frozenset(
                    {
                        CONTROL_PLANE_READ_ROLE,
                        CONTROL_PLANE_WRITE_ROLE,
                    }
                ),
                project_ids=frozenset({self.project_id}),
                workspace_ids=frozenset({self.workspace_id}),
            )
        )
        with TestClient(verified_application) as verified:
            spoofed_tenant = verified.get(
                "/v1/control-plane/projects",
                headers=self._read_headers(self.tenant_b),
            )
            spoofed_principal = verified.post(
                f"{self.workspace_path}/sessions",
                headers=self._write_headers(self.tenant_a),
                json={"session_id": "spoofed", "label": "Spoofed"},
            )
            denied_workspace = verified.get(
                f"/v1/control-plane/projects/{self.project_id}"
                "/workspaces/workspace-other/sessions",
                headers={
                    "X-Tenant-ID": self.tenant_a,
                    "X-Principal-ID": "verified-reviewer",
                },
            )
        self.assertEqual(spoofed_tenant.status_code, 403)
        self.assertEqual(spoofed_principal.status_code, 403)
        self.assertEqual(denied_workspace.status_code, 404)

    def test_access_denial_logging_is_exactly_once_and_does_not_log_successes(
        self,
    ) -> None:
        events: list[tuple[str, dict[str, object]]] = []
        self.client.app.state.control_plane_access_denial_reporter = (
            self._capturing_access_reporter(events)
        )

        health = self.client.get("/v1/control-plane/health")
        allowed = self.client.get(
            "/v1/control-plane/projects",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(health.status_code, 200)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(events, [])

        missing_tenant = self.client.get("/v1/control-plane/projects")
        self.assertEqual(missing_tenant.status_code, 401)
        self.assertEqual(
            missing_tenant.json()["detail"],
            "control-plane identity could not be verified",
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][1]["reason"], "tenant_required")
        events.clear()

        secret = "PRIVATE-CREDENTIAL-C:\\tenant\\token"

        def failing_resolver(_request: Any) -> ControlPlaneIdentity:
            raise RuntimeError(secret)

        self.client.app.state.control_plane_identity_resolver = failing_resolver
        denied = self.client.get(
            "/v1/control-plane/projects",
            headers={
                "X-Tenant-ID": "attacker-tenant-secret",
                "Authorization": "Bearer attacker-token-secret",
            },
        )
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(
            denied.json()["detail"],
            "control-plane identity could not be verified",
        )
        self.assertEqual(len(events), 1)
        event, fields = events[0]
        self.assertEqual(event, "control_plane.access.denied")
        self.assertEqual(fields["phase"], "identity_verification")
        self.assertEqual(fields["reason"], "identity_verification_failed")
        self.assertEqual(fields["response_status"], 401)
        self.assertEqual(fields["request_method"], "GET")
        self.assertEqual(fields["route_name"], "list_projects")
        serialized = json.dumps(fields, sort_keys=True)
        for private in (
            secret,
            "attacker-tenant-secret",
            "attacker-token-secret",
            "/v1/control-plane/projects",
        ):
            self.assertNotIn(private, serialized)

        for error_type in (HTTPException, StarletteHTTPException):
            with self.subTest(resolver_error_type=error_type.__module__):
                events.clear()

                def resolver_denial(
                    _request: Any,
                    error_type: type[StarletteHTTPException] = error_type,
                ) -> ControlPlaneIdentity:
                    raise error_type(
                        status_code=403,
                        detail="deployment credential was rejected",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

                self.client.app.state.control_plane_identity_resolver = resolver_denial
                resolver_response = self.client.get(
                    "/v1/control-plane/projects",
                    headers=self._read_headers(self.tenant_a),
                )
                self.assertEqual(resolver_response.status_code, 403)
                self.assertEqual(
                    resolver_response.json()["detail"],
                    "deployment credential was rejected",
                )
                self.assertEqual(
                    resolver_response.headers["www-authenticate"],
                    "Bearer",
                )
                self.assertEqual(len(events), 1)
                self.assertEqual(
                    events[0][1]["reason"],
                    "identity_verification_failed",
                )
                self.assertNotIn("deployment credential", json.dumps(events))

        events.clear()

        def resolver_non_auth_failure(_request: Any) -> ControlPlaneIdentity:
            raise HTTPException(
                status_code=418,
                detail='private "C:/srv/tenant/identity.sqlite3"\u202e',
            )

        self.client.app.state.control_plane_identity_resolver = (
            resolver_non_auth_failure
        )
        resolver_failure = self.client.get(
            "/v1/control-plane/projects",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(resolver_failure.status_code, 500)
        self.assertEqual(
            resolver_failure.json(),
            {"detail": "internal control-plane operation failed"},
        )
        self.assertNotIn("identity.sqlite3", resolver_failure.text)
        self.assertEqual(events, [])

    def test_access_denial_logging_covers_binding_role_scope_and_source(
        self,
    ) -> None:
        events: list[tuple[str, dict[str, object]]] = []
        self.client.app.state.control_plane_access_denial_reporter = (
            self._capturing_access_reporter(events)
        )

        source_cases = (
            (
                {
                    **self._write_headers(self.tenant_a),
                    "Host": "private-host.attacker.example",
                },
                400,
                "host_rejected",
            ),
            (
                {
                    **self._write_headers(self.tenant_a),
                    "Origin": "https://private-origin.attacker.example",
                },
                403,
                "origin_rejected",
            ),
        )
        for index, (headers, status, reason) in enumerate(source_cases):
            with self.subTest(source=reason):
                response = self.client.post(
                    "/v1/control-plane/projects",
                    headers=headers,
                    json={
                        "project_id": f"source-denied-{index}",
                        "label": "Denied",
                    },
                )
                self.assertEqual(response.status_code, status)
                self.assertEqual(events[-1][1]["reason"], reason)
                self.assertEqual(events[-1][1]["phase"], "request_source")

        missing_principal = self.client.post(
            "/v1/control-plane/projects",
            headers=self._read_headers(self.tenant_a),
            json={"project_id": "missing-principal", "label": "Denied"},
        )
        self.assertEqual(missing_principal.status_code, 401)
        self.assertEqual(events[-1][1]["reason"], "principal_required")

        verified_identity = ControlPlaneIdentity(
            tenant_id=self.tenant_a,
            principal_id="verified-reviewer",
            roles=frozenset({CONTROL_PLANE_READ_ROLE}),
            project_ids=frozenset({self.project_id}),
            workspace_ids=frozenset({self.workspace_id}),
        )
        self.client.app.state.control_plane_identity_resolver = lambda _request: (
            verified_identity
        )
        spoofed_tenant = self.client.get(
            "/v1/control-plane/projects",
            headers={
                "X-Tenant-ID": "private-spoofed-tenant",
                "X-Principal-ID": "verified-reviewer",
            },
        )
        spoofed_principal = self.client.get(
            "/v1/control-plane/projects",
            headers={
                "X-Tenant-ID": self.tenant_a,
                "X-Principal-ID": "private-spoofed-principal",
            },
        )
        denied_role = self.client.post(
            "/v1/control-plane/projects",
            headers={
                "X-Tenant-ID": self.tenant_a,
                "X-Principal-ID": "verified-reviewer",
            },
            json={"project_id": self.project_id, "label": "Denied"},
        )
        hidden_project = self.client.get(
            "/v1/control-plane/projects/private-hidden-project/workspaces",
            headers={
                "X-Tenant-ID": self.tenant_a,
                "X-Principal-ID": "verified-reviewer",
            },
        )
        hidden_workspace = self.client.get(
            f"/v1/control-plane/projects/{self.project_id}"
            "/workspaces/private-hidden-workspace/sessions",
            headers={
                "X-Tenant-ID": self.tenant_a,
                "X-Principal-ID": "verified-reviewer",
            },
        )
        self.assertEqual(spoofed_tenant.status_code, 403)
        self.assertEqual(spoofed_principal.status_code, 403)
        self.assertEqual(denied_role.status_code, 403)
        self.assertEqual(hidden_project.status_code, 404)
        self.assertEqual(hidden_workspace.status_code, 404)
        self.assertEqual(
            [item[1]["reason"] for item in events[-5:]],
            [
                "tenant_binding_mismatch",
                "principal_binding_mismatch",
                "required_role_missing",
                "project_scope_denied",
                "workspace_scope_denied",
            ],
        )
        self.assertFalse(events[-2][1].get("concealed") is False)
        self.assertTrue(events[-2][1]["concealed"])
        self.assertTrue(events[-1][1]["concealed"])
        correlations = {
            str(fields["tenant_correlation"])
            for _, fields in events[-5:]
            if "tenant_correlation" in fields
        }
        self.assertEqual(len(correlations), 1)
        correlation = correlations.pop()
        self.assertRegex(correlation, r"\A[0-9a-f]{32}\Z")
        self.assertNotEqual(correlation, self.tenant_a)
        serialized = json.dumps(events, sort_keys=True)
        for private in (
            "private-spoofed-tenant",
            "private-spoofed-principal",
            "private-hidden-project",
            "private-hidden-workspace",
        ):
            self.assertNotIn(private, serialized)

        scoped_writer = ControlPlaneIdentity(
            tenant_id=self.tenant_a,
            principal_id="verified-reviewer",
            roles=frozenset({CONTROL_PLANE_READ_ROLE, CONTROL_PLANE_WRITE_ROLE}),
            project_ids=frozenset({self.project_id}),
            workspace_ids=frozenset({self.workspace_id}),
        )
        self.client.app.state.control_plane_identity_resolver = lambda _request: (
            scoped_writer
        )
        denied_project_creation = self.client.post(
            "/v1/control-plane/projects",
            headers={
                "X-Tenant-ID": self.tenant_a,
                "X-Principal-ID": "verified-reviewer",
            },
            json={"project_id": "private-project-create", "label": "Denied"},
        )
        denied_workspace_creation = self.client.post(
            f"/v1/control-plane/projects/{self.project_id}/workspaces",
            headers={
                "X-Tenant-ID": self.tenant_a,
                "X-Principal-ID": "verified-reviewer",
            },
            json={
                "workspace_id": "private-workspace-create",
                "label": "Denied",
            },
        )
        self.assertEqual(denied_project_creation.status_code, 403)
        self.assertEqual(denied_workspace_creation.status_code, 403)
        self.assertEqual(
            [item[1]["reason"] for item in events[-2:]],
            [
                "project_creation_scope_denied",
                "workspace_creation_scope_denied",
            ],
        )

    def test_real_not_found_and_health_do_not_emit_access_denial(self) -> None:
        events: list[tuple[str, dict[str, object]]] = []
        self.client.app.state.control_plane_access_denial_reporter = (
            self._capturing_access_reporter(events)
        )
        self.client.app.state.control_plane_identity_resolver = (
            TrustedHeaderIdentityResolver(
                allowed_hosts=("testserver",),
                allowed_origins=("http://testserver",),
            )
        )
        self._provision_scope(self.tenant_a)
        missing = self.client.get(
            f"{self.workspace_path}/sessions/actual-missing-session",
            headers=self._read_headers(self.tenant_a),
        )
        health = self.client.get("/v1/control-plane/health")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(health.status_code, 200)
        self.assertEqual(events, [])

    def test_access_denial_sampler_separates_suppression_from_enqueue_loss(
        self,
    ) -> None:
        clock = [0.0]
        captured: list[dict[str, object]] = []

        def capture(_event: str, **fields: object) -> bool:
            captured.append(dict(fields))
            return True

        reporter = ControlPlaneAccessDenialReporter(
            emitter=capture,
            monotonic=lambda: clock[0],
            minimum_interval_seconds=5.0,
            maximum_interval_seconds=60.0,
            max_keys=2,
        )
        denial = _ControlPlaneAccessDenied(
            status_code=403,
            public_detail="request identity lacks the required role",
            phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
            required_role=CONTROL_PLANE_WRITE_ROLE,
            tenant_correlation=_resolved_tenant_correlation(self.tenant_a),
        )
        for _ in range(1_000):
            reporter.report(
                denial=denial,
                request_method="POST",
                route_name="create_project",
                mutating=True,
            )
        first = reporter.snapshot()
        self.assertEqual(first.observed_denials, 1_000)
        self.assertEqual(first.emitted_events, 1)
        self.assertEqual(first.intentionally_suppressed, 999)
        self.assertEqual(first.enqueue_failures, 0)
        self.assertEqual(len(captured), 1)

        # A different trusted tenant digest is not a sampling key. It cannot
        # create attacker-controlled cardinality or bypass the flood bound.
        same_decision_other_tenant = _ControlPlaneAccessDenied(
            status_code=403,
            public_detail="request identity lacks the required role",
            phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
            required_role=CONTROL_PLANE_WRITE_ROLE,
            tenant_correlation=_resolved_tenant_correlation(self.tenant_b),
        )
        reporter.report(
            denial=same_decision_other_tenant,
            request_method="POST",
            route_name="create_project",
            mutating=True,
        )
        self.assertEqual(reporter.snapshot().admitted_keys, 1)
        self.assertEqual(len(captured), 1)

        clock[0] = 60.0
        reporter.report(
            denial=denial,
            request_method="POST",
            route_name="create_project",
            mutating=True,
        )
        after_window = reporter.snapshot()
        self.assertEqual(after_window.emitted_events, 2)
        self.assertEqual(captured[-1]["occurrences"], 1_002)
        self.assertEqual(captured[-1]["suppressed_since_last"], 1_000)
        self.assertEqual(
            captured[-1]["tenant_correlation"],
            denial.tenant_correlation,
        )

        # A new single-tenant sample window can carry its own trusted token
        # again after the mixed aggregate was emitted successfully.
        clock[0] = 120.0
        reporter.report(
            denial=denial,
            request_method="POST",
            route_name="create_project",
            mutating=True,
        )
        self.assertEqual(
            captured[-1]["tenant_correlation"],
            denial.tenant_correlation,
        )

        # The key table is independently bounded even if future code adds
        # enough declared route/reason combinations to exceed its capacity.
        for route_name in ("route_two", "route_three"):
            reporter.report(
                denial=denial,
                request_method="POST",
                route_name=route_name,
                mutating=True,
            )
        bounded = reporter.snapshot()
        self.assertEqual(bounded.admitted_keys, 2)
        self.assertEqual(bounded.overflow_observations, 1)
        self.assertEqual(bounded.overflow_emitted_events, 1)
        self.assertEqual(captured[-1]["sampling_scope"], "overflow")

        attempts: list[dict[str, object]] = []
        outcomes = iter((False, True))

        def fail_once(_event: str, **fields: object) -> bool:
            attempts.append(dict(fields))
            return next(outcomes)

        loss_reporter = ControlPlaneAccessDenialReporter(
            emitter=fail_once,
            monotonic=lambda: clock[0],
            minimum_interval_seconds=5.0,
            maximum_interval_seconds=60.0,
        )
        clock[0] = 0.0
        self.assertFalse(
            loss_reporter.report(
                denial=denial,
                request_method="POST",
                route_name="create_project",
                mutating=True,
            )
        )
        self.assertFalse(
            loss_reporter.report(
                denial=denial,
                request_method="POST",
                route_name="create_project",
                mutating=True,
            )
        )
        clock[0] = 60.0
        self.assertTrue(
            loss_reporter.report(
                denial=denial,
                request_method="POST",
                route_name="create_project",
                mutating=True,
            )
        )
        loss = loss_reporter.snapshot()
        self.assertEqual(loss.observed_denials, 3)
        self.assertEqual(loss.emitted_events, 1)
        self.assertEqual(loss.intentionally_suppressed, 1)
        self.assertEqual(loss.enqueue_failures, 1)
        self.assertEqual(attempts[-1]["suppressed_since_last"], 1)
        self.assertEqual(attempts[-1]["enqueue_failures_since_last"], 1)

    def test_access_denial_vocabulary_is_exact_at_both_typed_boundaries(
        self,
    ) -> None:
        with self.assertRaisesRegex(TypeError, "closed enum"):
            _ControlPlaneAccessDenied(
                status_code=403,
                public_detail="denied",
                phase="role_authorization",  # type: ignore[arg-type]
                reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
            )
        with self.assertRaisesRegex(TypeError, "closed enum"):
            _ControlPlaneAccessDenied(
                status_code=403,
                public_detail="denied",
                phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
                reason="required_role_missing",  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "does not belong"):
            _ControlPlaneAccessDenied(
                status_code=403,
                public_detail="denied",
                phase=ControlPlaneAccessPhase.REQUEST_SOURCE,
                reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
            )

        captured: list[dict[str, object]] = []
        reporter = ControlPlaneAccessDenialReporter(
            emitter=lambda _event, **fields: captured.append(dict(fields)) or True,
            monotonic=lambda: 0.0,
        )
        denial = _ControlPlaneAccessDenied(
            status_code=403,
            public_detail="denied",
            phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
        )

        class _HostileVocabulary:
            value = "PRIVATE-C:\\tenant\\credential"

        denial.phase = _HostileVocabulary()  # type: ignore[assignment]
        self.assertFalse(
            reporter.report(
                denial=denial,
                request_method="GET",
                route_name="list_projects",
                mutating=False,
            )
        )
        snapshot = reporter.snapshot()
        self.assertEqual(snapshot.observed_denials, 1)
        self.assertEqual(snapshot.invalid_denials, 1)
        self.assertEqual(captured, [])

        denial.phase = ControlPlaneAccessPhase.REQUEST_SOURCE
        self.assertFalse(
            reporter.report(
                denial=denial,
                request_method="GET",
                route_name="list_projects",
                mutating=False,
            )
        )
        snapshot = reporter.snapshot()
        self.assertEqual(snapshot.observed_denials, 2)
        self.assertEqual(snapshot.invalid_denials, 2)
        self.assertEqual(captured, [])

    def test_access_denial_reporter_isolates_custom_base_exception_only(
        self,
    ) -> None:
        class _TelemetryAbort(BaseException):
            pass

        denial = _ControlPlaneAccessDenied(
            status_code=403,
            public_detail="denied",
            phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
        )

        def aborting_emitter(_event: str, **_fields: object) -> bool:
            raise _TelemetryAbort("private telemetry failure")

        reporter = ControlPlaneAccessDenialReporter(
            emitter=aborting_emitter,
            monotonic=lambda: 0.0,
        )
        self.assertFalse(
            reporter.report(
                denial=denial,
                request_method="GET",
                route_name="list_projects",
                mutating=False,
            )
        )
        self.assertEqual(reporter.snapshot().enqueue_failures, 1)

        for interruption in (
            KeyboardInterrupt(),
            SystemExit(7),
            GeneratorExit(),
        ):

            def interrupting_emitter(
                _event: str,
                _interruption: BaseException = interruption,
                **_fields: object,
            ) -> bool:
                raise _interruption

            interrupted = ControlPlaneAccessDenialReporter(
                emitter=interrupting_emitter,
                monotonic=lambda: 0.0,
            )
            with (
                self.subTest(interruption=type(interruption).__name__),
                self.assertRaises(type(interruption)),
            ):
                interrupted.report(
                    denial=denial,
                    request_method="GET",
                    route_name="list_projects",
                    mutating=False,
                )

        class _ExplodingReporter(ControlPlaneAccessDenialReporter):
            def report(self, **_kwargs: object) -> bool:
                raise _TelemetryAbort("private reporter failure")

        self.client.app.state.control_plane_access_denial_reporter = (
            _ExplodingReporter()
        )
        response = self.client.get("/v1/control-plane/projects")
        self.assertEqual(response.status_code, 401, response.text)
        self.assertEqual(
            response.json(),
            {"detail": "control-plane identity could not be verified"},
        )

    def test_access_denial_emission_is_reentrant_without_holding_sampler_lock(
        self,
    ) -> None:
        denial = _ControlPlaneAccessDenied(
            status_code=403,
            public_detail="denied",
            phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
        )
        reporter_box: dict[str, ControlPlaneAccessDenialReporter] = {}
        snapshots: list[object] = []

        def reentrant_emitter(_event: str, **_fields: object) -> bool:
            reporter = reporter_box["reporter"]
            snapshots.append(reporter.snapshot())
            self.assertFalse(
                reporter.report(
                    denial=denial,
                    request_method="GET",
                    route_name="list_projects",
                    mutating=False,
                )
            )
            return True

        reporter = ControlPlaneAccessDenialReporter(
            emitter=reentrant_emitter,
            monotonic=lambda: 0.0,
            minimum_interval_seconds=0.0,
            maximum_interval_seconds=0.0,
        )
        reporter_box["reporter"] = reporter
        result: list[bool] = []
        worker = threading.Thread(
            target=lambda: result.append(
                reporter.report(
                    denial=denial,
                    request_method="GET",
                    route_name="list_projects",
                    mutating=False,
                )
            )
        )
        worker.start()
        worker.join(timeout=2.0)
        self.assertFalse(worker.is_alive(), "reentrant telemetry deadlocked")
        self.assertEqual(result, [True])
        self.assertEqual(len(snapshots), 1)
        snapshot = reporter.snapshot()
        self.assertEqual(snapshot.observed_denials, 2)
        self.assertEqual(snapshot.emitted_events, 1)
        self.assertEqual(snapshot.intentionally_suppressed, 1)

    def test_access_denial_rejects_invalid_dimensions_before_admission(
        self,
    ) -> None:
        mutations = (
            ("status", lambda denial: setattr(denial, "status_code", 418), "GET", "route", False),
            ("role", lambda denial: setattr(denial, "required_role", "private-role"), "GET", "route", False),
            ("concealed", lambda denial: setattr(denial, "concealed", 1), "GET", "route", False),
            ("tenant", lambda denial: setattr(denial, "tenant_correlation", "bad"), "GET", "route", False),
            ("pair", lambda denial: setattr(denial, "reason", ControlPlaneAccessReason.ORIGIN_REJECTED), "GET", "route", False),
            ("method", lambda denial: None, "TRACE", "route", False),
            ("route", lambda denial: None, "GET", "PRIVATE C:\\tenant", False),
            ("mutating", lambda denial: None, "GET", "route", 1),
        )
        for label, mutate, method, route, mutating in mutations:
            with self.subTest(label=label):
                captured: list[dict[str, object]] = []
                reporter = ControlPlaneAccessDenialReporter(
                    emitter=(
                        lambda _event, _captured=captured, **fields: _captured.append(
                            dict(fields)
                        )
                        or True
                    ),
                    monotonic=lambda: 0.0,
                    max_keys=1,
                )
                denial = _ControlPlaneAccessDenied(
                    status_code=403,
                    public_detail="denied",
                    phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
                    reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
                )
                mutate(denial)
                self.assertFalse(
                    reporter.report(
                        denial=denial,
                        request_method=method,
                        route_name=route,
                        mutating=mutating,  # type: ignore[arg-type]
                    )
                )
                snapshot = reporter.snapshot()
                self.assertEqual(snapshot.observed_denials, 1)
                self.assertEqual(snapshot.invalid_denials, 1)
                self.assertEqual(snapshot.admitted_keys, 0)
                self.assertEqual(snapshot.enqueue_failures, 0)
                self.assertEqual(captured, [])

    def test_access_denial_clock_failures_are_observed_invalid_decisions(
        self,
    ) -> None:
        denial = _ControlPlaneAccessDenied(
            status_code=403,
            public_detail="denied",
            phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
        )
        clocks = (
            lambda: float("nan"),
            lambda: (_ for _ in ()).throw(RuntimeError("private clock")),
        )
        for clock in clocks:
            with self.subTest(clock=clock):
                reporter = ControlPlaneAccessDenialReporter(
                    emitter=lambda _event, **_fields: True,
                    monotonic=clock,
                )
                self.assertFalse(
                    reporter.report(
                        denial=denial,
                        request_method="GET",
                        route_name="list_projects",
                        mutating=False,
                    )
                )
                snapshot = reporter.snapshot()
                self.assertEqual(snapshot.observed_denials, 1)
                self.assertEqual(snapshot.invalid_denials, 1)

    def test_access_denial_rotation_uses_stable_overflow_and_global_ceiling(
        self,
    ) -> None:
        clock = [0.0]
        captured: list[dict[str, object]] = []
        reporter = ControlPlaneAccessDenialReporter(
            emitter=lambda _event, **fields: captured.append(dict(fields)) or True,
            monotonic=lambda: clock[0],
            minimum_interval_seconds=0.0,
            maximum_interval_seconds=0.0,
            max_keys=2,
            global_burst=3,
            global_refill_per_second=1.0,
        )
        denial = _ControlPlaneAccessDenied(
            status_code=403,
            public_detail="denied",
            phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
        )
        for index in range(2_000):
            reporter.report(
                denial=denial,
                request_method="GET",
                route_name=f"route_{index}",
                mutating=False,
            )
        saturated = reporter.snapshot()
        self.assertEqual(saturated.observed_denials, 2_000)
        self.assertEqual(saturated.admitted_keys, 2)
        self.assertEqual(saturated.key_capacity, 2)
        self.assertEqual(saturated.overflow_observations, 1_998)
        self.assertEqual(saturated.overflow_emitted_events, 1)
        self.assertEqual(saturated.emitted_events, 3)
        self.assertEqual(saturated.global_suppressed, 1_997)
        self.assertEqual(len(captured), 3)
        self.assertEqual(captured[-1]["sampling_scope"], "overflow")

        # A refill lets an original admitted state emit with its preserved
        # occurrence history; rotation did not evict and recreate it.
        clock[0] = 1.0
        reporter.report(
            denial=denial,
            request_method="GET",
            route_name="route_0",
            mutating=False,
        )
        self.assertEqual(len(captured), 4)
        self.assertEqual(captured[-1]["sampling_scope"], "exact")
        self.assertEqual(captured[-1]["occurrences"], 2)

    def test_access_denial_capacity_is_bounded_under_concurrent_rotation(
        self,
    ) -> None:
        errors: list[BaseException] = []
        reporter = ControlPlaneAccessDenialReporter(
            emitter=lambda _event, **_fields: True,
            monotonic=lambda: 0.0,
            minimum_interval_seconds=0.0,
            maximum_interval_seconds=0.0,
            max_keys=8,
            global_burst=5,
            global_refill_per_second=0.0,
        )
        denial = _ControlPlaneAccessDenied(
            status_code=403,
            public_detail="denied",
            phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
            reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
        )

        def rotate(worker: int) -> None:
            try:
                for index in range(125):
                    reporter.report(
                        denial=denial,
                        request_method="GET",
                        route_name=f"route_{worker}_{index}",
                        mutating=False,
                    )
            except Exception as error:  # noqa: BLE001 - propagate worker failures
                errors.append(error)

        threads = [
            threading.Thread(target=rotate, args=(index,)) for index in range(16)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        snapshot = reporter.snapshot()
        self.assertEqual(snapshot.observed_denials, 2_000)
        self.assertEqual(snapshot.admitted_keys, 8)
        self.assertEqual(snapshot.overflow_observations, 1_992)
        self.assertEqual(snapshot.emitted_events, 5)
        self.assertLessEqual(snapshot.admitted_keys, snapshot.key_capacity)

    def test_access_denial_tenant_attribution_is_bounded_and_conservative(
        self,
    ) -> None:
        tenant_a = _resolved_tenant_correlation(self.tenant_a)
        tenant_b = _resolved_tenant_correlation(self.tenant_b)

        def exercise(values: list[str | None]) -> dict[str, object]:
            clock = [0.0]
            attempts: list[dict[str, object]] = []

            def fail_once(_event: str, **fields: object) -> bool:
                attempts.append(dict(fields))
                return len(attempts) > 1

            reporter = ControlPlaneAccessDenialReporter(
                emitter=fail_once,
                monotonic=lambda: clock[0],
                minimum_interval_seconds=5.0,
                maximum_interval_seconds=60.0,
            )
            for correlation in values:
                reporter.report(
                    denial=_ControlPlaneAccessDenied(
                        status_code=403,
                        public_detail="denied",
                        phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
                        reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
                        tenant_correlation=correlation,
                    ),
                    request_method="GET",
                    route_name="list_projects",
                    mutating=False,
                )
            clock[0] = 60.0
            reporter.report(
                denial=_ControlPlaneAccessDenied(
                    status_code=403,
                    public_detail="denied",
                    phase=ControlPlaneAccessPhase.ROLE_AUTHORIZATION,
                    reason=ControlPlaneAccessReason.REQUIRED_ROLE_MISSING,
                    tenant_correlation=values[-1],
                ),
                request_method="GET",
                route_name="list_projects",
                mutating=False,
            )
            self.assertEqual(reporter.snapshot().admitted_keys, 1)
            self.assertEqual(attempts[-1]["enqueue_failures_since_last"], 1)
            return attempts[-1]

        for values in (
            [tenant_a] * 502 + [tenant_b],
            [tenant_b] + [tenant_a] * 502,
        ):
            with self.subTest(order=values[0]):
                self.assertEqual(
                    exercise(values)["tenant_correlation"],
                    tenant_a,
                )

        balanced = exercise([tenant_a] * 250 + [tenant_b] * 250 + [None])
        self.assertNotIn("tenant_correlation", balanced)

    def test_authenticated_operational_diagnostics_are_payload_free_and_total(
        self,
    ) -> None:
        application = FastAPI()
        application.include_router(control_plane_router)
        application.state.control_plane = None
        events: list[tuple[str, dict[str, object]]] = []
        reporter = self._capturing_access_reporter(events)
        application.state.control_plane_access_denial_reporter = reporter

        def tenant_admin(_request: Any) -> ControlPlaneIdentity:
            return ControlPlaneIdentity(
                tenant_id=self.tenant_a,
                principal_id="operator",
                roles=frozenset({CONTROL_PLANE_ADMIN_ROLE}),
            )

        application.state.control_plane_identity_resolver = tenant_admin
        with TestClient(application) as client:
            public_health = client.get("/v1/control-plane/health")
            self.assertEqual(public_health.status_code, 200)
            public_text = json.dumps(public_health.json(), sort_keys=True)
            self.assertNotIn("event_classes", public_text)
            self.assertNotIn("access_denial_sampling", public_text)

            denied = client.get(
                "/v1/control-plane/diagnostics/operational-events",
                headers={"X-Tenant-ID": self.tenant_a},
            )
            self.assertEqual(denied.status_code, 403, denied.text)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0][1]["reason"], "required_role_missing")
            self.assertEqual(
                events[0][1]["required_role"],
                CONTROL_PLANE_INSTANCE_OPERATOR_ROLE,
            )

            def instance_operator(_request: Any) -> ControlPlaneIdentity:
                return ControlPlaneIdentity(
                    tenant_id=self.tenant_a,
                    principal_id="operator",
                    roles=frozenset({CONTROL_PLANE_INSTANCE_OPERATOR_ROLE}),
                )

            application.state.control_plane_identity_resolver = instance_operator
            operator_cannot_admin = client.get(
                "/v1/control-plane/projects/project/workspaces/workspace/retention/audit",
                headers={"X-Tenant-ID": self.tenant_a},
            )
            self.assertEqual(operator_cannot_admin.status_code, 403)
            with reporter._lock:
                reporter._observed_denials = MAX_OPERATIONAL_COUNTER
            zero = OperationalEventClassHealthSnapshot(0, 0, 0, 0)
            classes = {event: zero for event in OPERATIONAL_EVENT_CONTRACT}
            classes["control_plane.access.denied"] = (
                OperationalEventClassHealthSnapshot(
                    MAX_OPERATIONAL_COUNTER,
                    0,
                    0,
                    MAX_OPERATIONAL_COUNTER,
                )
            )
            operational = OperationalEventDiagnosticsSnapshot(
                channel=OperationalEventHealthSnapshot(
                    MAX_OPERATIONAL_COUNTER,
                    0,
                    MAX_OPERATIONAL_COUNTER,
                    0,
                    1_024,
                    True,
                ),
                event_classes=MappingProxyType(classes),
            )
            with patch(
                "router_dump_analyzer.web.control_plane_api."
                "operational_event_diagnostics_snapshot",
                return_value=operational,
            ):
                accepted = client.get(
                    "/v1/control-plane/diagnostics/operational-events",
                    headers={"X-Tenant-ID": self.tenant_a},
                )
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(accepted.headers["cache-control"], "no-store")
        payload = accepted.json()
        self.assertEqual(payload["schema"], "rda.operational-diagnostics.v1")
        self.assertEqual(payload["status"], "degraded")
        self.assertEqual(
            payload["access_denial_sampling"]["observed_denials"],
            str(MAX_OPERATIONAL_COUNTER),
        )
        self.assertEqual(
            payload["operational_events"]["delivery_failures"],
            str(MAX_OPERATIONAL_COUNTER),
        )
        classes_payload = payload["operational_events"]["event_classes"]
        self.assertEqual(
            [item["event"] for item in classes_payload],
            sorted(OPERATIONAL_EVENT_CONTRACT),
        )
        access_class = next(
            item
            for item in classes_payload
            if item["event"] == "control_plane.access.denied"
        )
        self.assertEqual(
            access_class["delivery_failures"],
            str(MAX_OPERATIONAL_COUNTER),
        )
        serialized = json.dumps(payload, sort_keys=True)
        for private in (
            self.tenant_a,
            self.tenant_b,
            "tenant_correlation",
            "route_name",
            "PRIVATE-CREDENTIAL",
        ):
            self.assertNotIn(private, serialized)

    def test_trusted_local_resolver_role_grants_are_exact_and_operator_is_opt_in(
        self,
    ) -> None:
        def resolve(*, grant_instance_operator: bool) -> ControlPlaneIdentity:
            resolver = TrustedHeaderIdentityResolver(
                allowed_hosts=("testserver",),
                allowed_origins=("http://testserver",),
                grant_instance_operator=grant_instance_operator,
            )
            request = StarletteRequest(
                {
                    "type": "http",
                    "asgi": {"version": "3.0"},
                    "http_version": "1.1",
                    "method": "GET",
                    "scheme": "http",
                    "path": "/v1/control-plane/projects",
                    "raw_path": b"/v1/control-plane/projects",
                    "root_path": "",
                    "query_string": b"",
                    "headers": (
                        (b"host", b"testserver"),
                        (b"x-tenant-id", b"tenant-a"),
                    ),
                    "client": ("127.0.0.1", 40000),
                    "server": ("testserver", 80),
                }
            )
            return resolver(request)

        self.assertEqual(
            resolve(grant_instance_operator=False).roles,
            frozenset(
                {
                    CONTROL_PLANE_ADMIN_ROLE,
                    CONTROL_PLANE_READ_ROLE,
                    CONTROL_PLANE_WRITE_ROLE,
                }
            ),
        )
        self.assertEqual(
            resolve(grant_instance_operator=True).roles,
            frozenset(
                {
                    CONTROL_PLANE_ADMIN_ROLE,
                    CONTROL_PLANE_INSTANCE_OPERATOR_ROLE,
                    CONTROL_PLANE_READ_ROLE,
                    CONTROL_PLANE_WRITE_ROLE,
                }
            ),
        )

        denied = self.client.get(
            "/v1/control-plane/diagnostics/operational-events",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(denied.status_code, 403, denied.text)

        self.client.app.state.control_plane_identity_resolver = (
            TrustedHeaderIdentityResolver(
                allowed_hosts=("testserver",),
                allowed_origins=("http://testserver",),
                grant_instance_operator=True,
            )
        )
        accepted = self.client.get(
            "/v1/control-plane/diagnostics/operational-events",
            headers=self._read_headers(self.tenant_a),
        )

        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(accepted.headers["cache-control"], "no-store")

    def test_integer_adapters_preserve_grammar_and_range_failures(self) -> None:
        cases = (
            (
                lambda: _request_canonical_integer(
                    "01",
                    "offset",
                    minimum=0,
                    maximum=10,
                ),
                "offset must be a canonical decimal integer",
            ),
            (
                lambda: _request_canonical_integer(
                    -1,
                    "offset",
                    minimum=0,
                    maximum=10,
                ),
                "offset must be at least 0",
            ),
            (
                lambda: _request_canonical_integer(
                    11,
                    "offset",
                    minimum=0,
                    maximum=10,
                ),
                "offset must be no greater than 10",
            ),
            (
                lambda: _retention_integer(
                    {"maximum_candidates": -1},
                    "maximum_candidates",
                    minimum=0,
                    maximum=10,
                ),
                "maximum_candidates must be at least 0",
            ),
            (
                lambda: _retention_integer(
                    {"maximum_candidates": 11},
                    "maximum_candidates",
                    minimum=0,
                    maximum=10,
                ),
                "maximum_candidates must be no greater than 10",
            ),
            (
                lambda: _parse_if_match('"-1"'),
                "If-Match version must be at least 0",
            ),
            (
                lambda: _parse_if_match(f'"{1 << 63}"'),
                f"If-Match version must be no greater than {(1 << 63) - 1}",
            ),
            (
                lambda: _parse_if_match('"01"'),
                "If-Match must contain one strong canonical numeric ETag",
            ),
        )
        for operation, expected_detail in cases:
            with self.subTest(detail=expected_detail):
                with self.assertRaises(HTTPException) as raised:
                    operation()
                self.assertEqual(raised.exception.status_code, 422)
                self.assertEqual(raised.exception.detail, expected_detail)

        for adapter in (_request_canonical_integer, _retention_integer):
            with self.subTest(adapter=adapter.__name__):
                parameters = inspect.signature(adapter).parameters
                for bound in ("minimum", "maximum"):
                    self.assertEqual(
                        parameters[bound].kind,
                        inspect.Parameter.KEYWORD_ONLY,
                    )
                    self.assertIs(
                        parameters[bound].default,
                        inspect.Parameter.empty,
                    )

    def test_browser_paging_coordinates_are_json_safe_across_control_plane(
        self,
    ) -> None:
        headers = self._read_headers(self.tenant_a)
        accepted = self.client.get(
            "/v1/control-plane/context",
            params={"offset": str(MAX_JSON_SAFE_INTEGER)},
            headers=headers,
        )
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(accepted.json()["offset"], MAX_JSON_SAFE_INTEGER)

        unsafe = str(MAX_JSON_SAFE_INTEGER + 1)
        bounded_query_paths = (
            "/v1/control-plane/context",
            "/v1/control-plane/projects",
            "/v1/control-plane/projects/project-a/workspaces",
            f"{self.workspace_path}/retention/audit",
            f"{self.workspace_path}/fixtures",
            f"{self.workspace_path}/revisions",
            f"{self.workspace_path}/sessions",
            f"{self.workspace_path}/snapshots",
            f"{self.workspace_path}/annotations",
            f"{self.workspace_path}/correlations",
            f"{self.workspace_path}/review-audit",
        )
        for path in bounded_query_paths:
            with self.subTest(path=path):
                parameter = (
                    "catalog_after_sequence"
                    if path.endswith("/retention/audit")
                    else "after_sequence"
                    if path.endswith("/review-audit")
                    else "offset"
                )
                response = self.client.get(
                    path,
                    params={parameter: unsafe},
                    headers=headers,
                )
                self.assertEqual(response.status_code, 422, response.text)

        for suffix in ("events", "events/stream"):
            with self.subTest(path=suffix):
                response = self.client.get(
                    f"{self.workspace_path}/imports/import-missing/{suffix}",
                    params={"after_sequence": unsafe},
                    headers=headers,
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(
                    response.json()["detail"],
                    (f"after_sequence must be no greater than {MAX_JSON_SAFE_INTEGER}"),
                )

    def test_review_sequence_fields_share_one_json_safe_domain(self) -> None:
        self._provision_scope(self.tenant_a)
        headers = self._write_headers(self.tenant_a)
        connection = self.control_plane.annotations._connection
        connection.execute(
            """
            INSERT INTO review_overlay_audit (
                sequence, tenant_id, project_id, workspace_id, entity_kind,
                entity_id, operation, version, actor, occurred_at_ns,
                snapshot_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                MAX_JSON_SAFE_INTEGER,
                self.tenant_a,
                self.project_id,
                self.workspace_id,
                "annotation",
                "boundary-annotation",
                "create",
                1,
                "boundary-tester",
                1,
                "{}",
            ),
        )

        annotation_page = self.client.get(
            f"{self.workspace_path}/annotations",
            params={"expected_audit_watermark": str(MAX_JSON_SAFE_INTEGER)},
            headers=headers,
        )
        self.assertEqual(annotation_page.status_code, 200, annotation_page.text)
        self.assertEqual(
            annotation_page.json()["audit_watermark"],
            str(MAX_JSON_SAFE_INTEGER),
        )
        audit_page = self.client.get(
            f"{self.workspace_path}/review-audit",
            params={"after_sequence": str(MAX_JSON_SAFE_INTEGER - 1)},
            headers=headers,
        )
        self.assertEqual(audit_page.status_code, 200, audit_page.text)
        self.assertEqual(
            audit_page.json()["items"][0]["sequence"],
            MAX_JSON_SAFE_INTEGER,
        )

        preview = self.client.post(
            f"{self.workspace_path}/retention/preview",
            headers=headers,
            json={
                "review": {
                    "enabled": True,
                    "tombstone_before_ns": str((1 << 63) - 1),
                    "audit_mode": "prune_explicit",
                    "audit_before_sequence": str(MAX_JSON_SAFE_INTEGER),
                }
            },
        )
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual(
            preview.json()["review"]["policy"]["audit_before_sequence"],
            MAX_JSON_SAFE_INTEGER,
        )
        self.assertEqual(
            preview.json()["review"]["policy"]["tombstone_before_ns"],
            str((1 << 63) - 1),
        )

        unsafe = str(MAX_JSON_SAFE_INTEGER + 1)
        unsafe_requests = (
            self.client.get(
                f"{self.workspace_path}/annotations",
                params={"expected_audit_watermark": unsafe},
                headers=headers,
            ),
            self.client.get(
                f"{self.workspace_path}/review-audit",
                params={"after_sequence": unsafe},
                headers=headers,
            ),
            self.client.post(
                f"{self.workspace_path}/retention/preview",
                headers=headers,
                json={
                    "review": {
                        "audit_mode": "prune_explicit",
                        "audit_before_sequence": unsafe,
                    }
                },
            ),
        )
        for response in unsafe_requests:
            with self.subTest(detail=response.text):
                self.assertEqual(response.status_code, 422, response.text)
                self.assertIn(
                    f"must be no greater than {MAX_JSON_SAFE_INTEGER}",
                    response.json()["detail"],
                )

        for invalid in ("01", "+1"):
            with self.subTest(audit_before_sequence=invalid):
                response = self.client.post(
                    f"{self.workspace_path}/retention/preview",
                    headers=headers,
                    json={
                        "review": {
                            "audit_mode": "prune_explicit",
                            "audit_before_sequence": invalid,
                        }
                    },
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(
                    response.json()["detail"],
                    "audit_before_sequence must be a canonical decimal integer",
                )

        unsafe_sequence = MAX_JSON_SAFE_INTEGER + 1
        connection.execute(
            """
            INSERT INTO review_overlay_audit (
                sequence, tenant_id, project_id, workspace_id, entity_kind,
                entity_id, operation, version, actor, occurred_at_ns,
                snapshot_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                unsafe_sequence,
                self.tenant_a,
                self.project_id,
                self.workspace_id,
                "annotation",
                "unsafe-annotation",
                "create",
                1,
                "boundary-tester",
                1,
                "{}",
            ),
        )
        for path in ("annotations", "review-audit"):
            with self.subTest(preseeded_path=path):
                response = self.client.get(
                    f"{self.workspace_path}/{path}",
                    headers=headers,
                )
                self.assertEqual(response.status_code, 500, response.text)
                self.assertNotIn(str(unsafe_sequence), response.text)

    def test_core_time_projection_preserves_opaque_metadata_suffixes(self) -> None:
        self._provision_scope(self.tenant_a)
        metadata = {
            "hold_down_ns": 7,
            "nested": {"delay_ns": "fast", "counter_ns": 9},
        }
        created = self.client.post(
            f"{self.workspace_path}/sessions",
            headers=self._write_headers(self.tenant_a),
            json={
                "session_id": "opaque-time-metadata",
                "label": "Opaque metadata",
                "metadata": metadata,
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.json()["metadata"], metadata)
        self.assertIsInstance(created.json()["created_at_ns"], str)

        fetched = self.client.get(
            f"{self.workspace_path}/sessions/opaque-time-metadata",
            headers=self._read_headers(self.tenant_a),
        )
        listed = self.client.get(
            f"{self.workspace_path}/sessions",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(fetched.status_code, 200, fetched.text)
        self.assertEqual(fetched.json()["metadata"], metadata)
        listed_item = next(
            item
            for item in listed.json()["items"]
            if item["session_id"] == "opaque-time-metadata"
        )
        self.assertEqual(listed_item["metadata"], metadata)

    def test_structured_request_bounds_and_recursive_metadata_fail_closed(
        self,
    ) -> None:
        oversized = self.client.post(
            "/v1/control-plane/projects",
            headers={
                **self._write_headers(self.tenant_a),
                "Content-Type": "application/json",
            },
            content=b"{" + b" " * MAX_CONTROL_PLANE_JSON_BODY_BYTES + b"}",
        )
        self.assertEqual(oversized.status_code, 413, oversized.text)

        nested_document = (
            '{"project_id":"nested","label":"Nested","metadata":'
            + "[" * 1_500
            + "0"
            + "]" * 1_500
            + "}"
        )
        recursive_body = self.client.post(
            "/v1/control-plane/projects",
            headers={
                **self._write_headers(self.tenant_a),
                "Content-Type": "application/json",
            },
            content=nested_document.encode("ascii"),
        )
        self.assertEqual(recursive_body.status_code, 422, recursive_body.text)

        self._provision_scope(self.tenant_a)
        nested_header = '{"nested":' + "[" * 1_500 + "0" + "]" * 1_500 + "}"
        recursive_header = self.client.post(
            f"{self.workspace_path}/imports",
            params={"original_name": "recursive.jsonl"},
            headers={
                **self._write_headers(self.tenant_a),
                "X-Import-Metadata": nested_header,
                "Content-Type": "application/octet-stream",
            },
            content=b"one line",
        )
        self.assertEqual(recursive_header.status_code, 422, recursive_header.text)
        imports = self.client.get(
            f"{self.workspace_path}/imports",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(imports.status_code, 200, imports.text)
        self.assertEqual(imports.json()["items"], [])

    def test_trusted_header_profile_rejects_host_and_origin_confusion(
        self,
    ) -> None:
        cases = (
            (
                "foreign host",
                {
                    **self._write_headers(self.tenant_a),
                    "Host": "attacker.example",
                },
                400,
            ),
            (
                "lookalike host",
                {
                    **self._write_headers(self.tenant_a),
                    "Host": "testserver.attacker.example",
                },
                400,
            ),
            (
                "foreign browser origin",
                {
                    **self._write_headers(self.tenant_a),
                    "Origin": "https://attacker.example",
                },
                403,
            ),
            (
                "opaque browser origin",
                {
                    **self._write_headers(self.tenant_a),
                    "Origin": "null",
                },
                403,
            ),
        )
        for index, (label, headers, status_code) in enumerate(cases):
            with self.subTest(label=label):
                response = self.client.post(
                    "/v1/control-plane/projects",
                    headers=headers,
                    json={
                        "project_id": f"blocked-project-{index}",
                        "label": "Must not be created",
                    },
                )
                self.assertEqual(response.status_code, status_code, response.text)

        cli_style = self.client.post(
            "/v1/control-plane/projects",
            headers=self._write_headers(self.tenant_a),
            json={"project_id": "cli-project", "label": "CLI project"},
        )
        same_origin_browser = self.client.post(
            "/v1/control-plane/projects",
            headers={
                **self._write_headers(self.tenant_a),
                "Origin": "http://testserver",
            },
            json={
                "project_id": "browser-project",
                "label": "Browser project",
            },
        )
        self.assertEqual(cli_style.status_code, 201, cli_style.text)
        self.assertEqual(
            same_origin_browser.status_code,
            201,
            same_origin_browser.text,
        )

        rebound_read = self.client.get(
            "/v1/control-plane/projects",
            headers={
                **self._read_headers(self.tenant_a),
                "Host": "attacker.example",
            },
        )
        self.assertEqual(rebound_read.status_code, 400, rebound_read.text)

    def test_review_validation_errors_remain_client_errors(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            _raise_api_error(ReviewValidationError("invalid review input"))
        self.assertEqual(raised.exception.status_code, 422)
        self.assertEqual(raised.exception.detail, "invalid review input")

    def test_api_error_policy_is_exhaustive_and_order_independent(self) -> None:
        expected_status_by_class_name = {
            "CatalogExecutionProcessError": 502,
            "CatalogRetentionDisabledError": 500,
            "CatalogExecutionTimeoutError": 504,
            "ControlPlaneError": 422,
            "ControlPlaneScopeError": 422,
            "DatasetIntegrityError": 500,
            "HiddenSubjectResolutionError": 404,
            "IdempotencyConflict": 409,
            "ImportConflictError": 409,
            "ImportNotFoundError": 404,
            "ImportQuotaExceededError": 409,
            "IngestionPipelineError": 422,
            "IngestionStateRootPathError": 500,
            "KeyError": 404,
            "OSError": 500,
            "PluginExecutionProcessError": 422,
            "PluginExecutionTimeoutError": 422,
            "ReviewConflictError": 409,
            "ReviewIdempotencyConflictError": 409,
            "ReviewOverlayError": 500,
            "ReviewRetentionDisabledError": 500,
            "ReviewValidationError": 422,
            "SessionConflictError": 409,
            "SessionStoreError": 500,
            "SessionStoreDeadlineExceeded": 504,
            "StaleSessionVersion": 409,
            "StaleWorkspaceDisclosurePolicyVersion": 409,
            "SubjectResolutionError": 422,
            "TimeoutError": 504,
            "TypeError": 500,
            "ValueError": 500,
        }
        actual_status_by_class_name = {
            exception_type.__name__: policy.status_code
            for exception_type, policy in _API_ERROR_POLICY_BY_CLASS.items()
        }
        self.assertEqual(
            actual_status_by_class_name,
            expected_status_by_class_name,
        )
        self.assertEqual(
            {
                exception_type.__name__
                for exception_type, policy in _API_ERROR_POLICY_BY_CLASS.items()
                if policy.expose_message
            },
            {
                "IdempotencyConflict",
                "ImportConflictError",
                "ImportQuotaExceededError",
                "ReviewConflictError",
                "ReviewIdempotencyConflictError",
                "ReviewValidationError",
                "SessionConflictError",
                "StaleSessionVersion",
            },
            "only exact declared public-domain errors may expose bounded text",
        )

        production_domain_errors: set[type[Exception]] = set()
        pending = list(_API_ERROR_DOMAIN_ROOTS)
        while pending:
            exception_type = pending.pop()
            if exception_type in production_domain_errors:
                continue
            production_domain_errors.add(exception_type)
            pending.extend(
                subclass
                for subclass in exception_type.__subclasses__()
                if subclass.__module__.startswith("router_dump_analyzer.")
            )
        self.assertLessEqual(
            production_domain_errors,
            set(_API_ERROR_POLICY_BY_CLASS),
            "every production domain exception needs an explicit HTTP policy",
        )

        for exception_type, declared_policy in _API_ERROR_POLICY_BY_CLASS.items():
            with self.subTest(exception_type=exception_type.__name__):
                error = exception_type(PRIVATE_API_FAILURE_MARKER)
                resolved_policy = _api_error_policy(error)
                self.assertEqual(resolved_policy, declared_policy)
                with self.assertRaises(HTTPException) as raised:
                    _raise_api_error(error)
                self.assertEqual(
                    raised.exception.status_code,
                    declared_policy.status_code,
                )
                if declared_policy.expose_message:
                    self.assertEqual(
                        raised.exception.detail,
                        PRIVATE_API_FAILURE_MARKER,
                    )
                else:
                    self.assertNotIn(
                        PRIVATE_API_FAILURE_MARKER,
                        str(raised.exception.detail),
                    )

        integrity_type = next(
            exception_type
            for exception_type in _API_ERROR_POLICY_BY_CLASS
            if exception_type.__name__ == "DatasetIntegrityError"
        )
        self.assertEqual(
            _api_error_policy(integrity_type("corrupt")).status_code,
            500,
        )

        service_http_error = HTTPException(
            status_code=418,
            detail="private C:/srv/tenant/reviews.sqlite3\u202e",
        )
        with self.assertRaises(HTTPException) as raised:
            _raise_api_error(service_http_error)
        self.assertEqual(raised.exception.status_code, 500)
        self.assertEqual(
            raised.exception.detail,
            "internal control-plane operation failed",
        )

        unknown = RuntimeError("not declared at the HTTP boundary")
        with self.assertRaises(RuntimeError) as raised_unknown:
            _raise_api_error(unknown)
        self.assertIs(raised_unknown.exception, unknown)

    def test_internal_error_text_is_not_projected_through_http(self) -> None:
        for error, expected_status, expected_detail in (
            (
                IngestionPipelineError(PRIVATE_API_FAILURE_MARKER),
                422,
                "ingestion request was rejected",
            ),
            (
                ControlPlaneError(PRIVATE_API_FAILURE_MARKER),
                422,
                "control-plane request was rejected",
            ),
            (
                TimeoutError(PRIVATE_API_FAILURE_MARKER),
                504,
                "operation timed out",
            ),
            (
                ValueError(PRIVATE_API_FAILURE_MARKER),
                500,
                "internal control-plane operation failed",
            ),
            (
                TypeError(PRIVATE_API_FAILURE_MARKER),
                500,
                "internal control-plane operation failed",
            ),
            (
                OSError(PRIVATE_API_FAILURE_MARKER),
                500,
                "durable control-plane storage failed",
            ),
        ):
            with self.subTest(error_type=type(error).__name__):
                with self.assertRaises(HTTPException) as raised:
                    _raise_api_error(error)
                self.assertEqual(raised.exception.status_code, expected_status)
                self.assertEqual(raised.exception.detail, expected_detail)
                self.assertNotIn(
                    PRIVATE_API_FAILURE_MARKER,
                    str(raised.exception.detail),
                )

    def test_upload_filesystem_error_does_not_expose_the_host_path(self) -> None:
        self._provision_scope(self.tenant_a)
        private_host_path = (
            "C:/Users/private/AppData/Local/router-state/locks/content/"
            + PRIVATE_API_FAILURE_MARKER
        )
        failure = FileNotFoundError(
            2,
            "The system cannot find the path specified",
            private_host_path,
        )

        with patch.object(
            self.control_plane.ingestion,
            "submit_chunks",
            side_effect=failure,
        ):
            response = self.client.post(
                f"{self.workspace_path}/imports",
                params={"original_name": "state.jsonl"},
                headers={
                    **self._write_headers(self.tenant_a),
                    "Content-Type": "application/octet-stream",
                },
                content=b"state",
            )

        self.assertEqual(response.status_code, 500, response.text)
        self.assertEqual(
            response.json()["detail"],
            "durable control-plane storage failed",
        )
        self.assertNotIn(private_host_path, response.text)
        self.assertNotIn(PRIVATE_API_FAILURE_MARKER, response.text)

    def test_public_domain_error_details_are_exact_class_and_bounded(self) -> None:
        class UndeclaredReviewValidationError(ReviewValidationError):
            pass

        for error in (
            ReviewValidationError("unsafe\nreview detail"),
            ReviewValidationError("unsafe\u0085review detail"),
            ReviewValidationError("unsafe\u2028review detail"),
            ReviewValidationError("unsafe\u202ereview detail"),
            ReviewValidationError("unsafe\U000e0061review detail"),
            ReviewValidationError("unsafe\U000e0000review detail"),
            ReviewValidationError(
                'invalid state at "C:/srv/private/tenant/reviews.sqlite3"'
            ),
            ReviewValidationError("x" * 1_025),
            UndeclaredReviewValidationError("undeclared public detail"),
        ):
            with self.subTest(error_type=type(error).__name__):
                with self.assertRaises(HTTPException) as raised:
                    _raise_api_error(error)
                self.assertEqual(raised.exception.status_code, 422)
                self.assertEqual(
                    raised.exception.detail,
                    "review request was rejected",
                )

    def test_public_domain_error_details_make_display_ambiguity_explicit(self) -> None:
        detail = (
            "emoji \u26a0\ufe0f \u2764\ufe0f \u2139\ufe0f "
            "\U0001f3f3\ufe0f\u200d\U0001f308; Mongolian \u1820\u180b; "
            "CGJ \u034f; PUA \ue000; object \ufffc"
        )
        with self.assertRaises(HTTPException) as raised:
            _raise_api_error(ReviewValidationError(detail))
        self.assertEqual(
            raised.exception.detail,
            "emoji \u26a0\ufe0f \u2764\ufe0f \u2139\ufe0f "
            "\U0001f3f3\ufe0f\u200d\U0001f308; Mongolian \u1820\\u180b; "
            "CGJ \\u034f; PUA \\ue000; object \\ufffc",
        )
        for sequence in (
            "\u26a0\ufe0f",
            "\u2764\ufe0f",
            "\u2139\ufe0f",
            "\U0001f3f3\ufe0f\u200d\U0001f308",
        ):
            self.assertIn(sequence, raised.exception.detail)
        for character in ("\u180b", "\u034f", "\ue000", "\ufffc"):
            self.assertNotIn(character, raised.exception.detail)

        with self.assertRaises(HTTPException) as raw:
            _raise_api_error(ReviewValidationError("state\u034fchanged"))
        with self.assertRaises(HTTPException) as literal:
            _raise_api_error(ReviewValidationError("state\\u034fchanged"))
        self.assertNotEqual(raw.exception.detail, literal.exception.detail)

    def test_unsupported_field_names_use_the_shared_public_detail_policy(self) -> None:
        unsafe_key = "private\u202e/srv/tenant/catalog.sqlite3"
        for payload in (
            {unsafe_key: {}},
            {"catalog": {unsafe_key: True}},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(HTTPException) as raised:
                    _retention_policies(payload)
                self.assertEqual(raised.exception.status_code, 422)
                self.assertEqual(
                    raised.exception.detail,
                    "control-plane request was rejected",
                )
                self.assertNotIn("/srv/tenant", str(raised.exception.detail))
                self.assertNotIn("\u202e", str(raised.exception.detail))

    def test_service_http_exception_cannot_bypass_public_error_policy(self) -> None:
        failure = HTTPException(
            status_code=418,
            detail='private "C:/srv/tenant/catalog.sqlite3"\u202e',
        )
        with patch.object(
            self.control_plane.sessions,
            "list_projects",
            side_effect=failure,
        ):
            response = self.client.get(
                "/v1/control-plane/projects",
                headers=self._read_headers(self.tenant_a),
            )

        self.assertEqual(response.status_code, 500, response.text)
        self.assertEqual(
            response.json(),
            {"detail": "internal control-plane operation failed"},
        )
        self.assertNotIn("/srv/tenant", response.text)
        self.assertNotIn("\u202e", response.text)

    def test_framework_validation_is_bounded_without_flattening_adapter_4xx(
        self,
    ) -> None:
        validation = self.client.get(
            "/v1/control-plane/projects",
            headers=self._read_headers(self.tenant_a),
            params={"limit": "not-an-integer\u202e/srv/private"},
        )
        self.assertEqual(validation.status_code, 422, validation.text)
        self.assertEqual(
            validation.json(),
            {"detail": "control-plane request validation failed"},
        )
        self.assertNotIn("not-an-integer", validation.text)
        self.assertNotIn("/srv/private", validation.text)
        self.assertNotIn("\u202e", validation.text)

        adapter_validation = self.client.post(
            "/v1/control-plane/projects",
            headers=self._write_headers(self.tenant_a),
            json={"project_id": " invalid ", "label": "Invalid"},
        )
        self.assertEqual(adapter_validation.status_code, 422, adapter_validation.text)
        self.assertEqual(adapter_validation.json()["detail"], "project_id is invalid")

    def test_route_fence_covers_pre_operation_service_acquisition(self) -> None:
        for error_type in (HTTPException, StarletteHTTPException):
            with self.subTest(error_type=error_type.__module__):
                failure = error_type(
                    status_code=418,
                    detail='private "C:/srv/tenant/catalog.sqlite3"\u202e',
                )
                with patch(
                    "router_dump_analyzer.web.control_plane_api._control_plane",
                    side_effect=failure,
                ):
                    response = self.client.post(
                        "/v1/control-plane/projects",
                        headers=self._write_headers(self.tenant_a),
                        json={
                            "project_id": "must-not-be-created",
                            "label": "Must not be created",
                        },
                    )

                self.assertEqual(response.status_code, 500, response.text)
                self.assertEqual(
                    response.json(),
                    {"detail": "internal control-plane operation failed"},
                )
                self.assertNotIn("/srv/tenant", response.text)
                self.assertNotIn("\u202e", response.text)

    def test_catalog_public_text_uses_the_shared_invisible_character_rule(
        self,
    ) -> None:
        for index, character in enumerate(
            (
                "\u0085",
                "\u2003",
                "\u115f",
                "\u1160",
                "\u17b4",
                "\u17b5",
                "\u2028",
                "\u202e",
                "\u2800",
                "\u3164",
                "\uffa0",
                "\U00013441",
                "\U00013442",
                "\U000e0061",
                "\U000e0000",
            )
        ):
            cases = (
                {
                    "project_id": f"project{character}hidden",
                    "label": "Visible label",
                },
                {
                    "project_id": f"project-label-{index}",
                    "label": f"Visible{character}hidden",
                },
                {
                    "project_id": f"project-metadata-{index}",
                    "label": "Visible label",
                    "metadata": {f"key{character}": f"value{character}"},
                },
            )
            for case_index, payload in enumerate(cases):
                with self.subTest(
                    codepoint=f"U+{ord(character):04X}",
                    case=case_index,
                ):
                    response = self.client.post(
                        "/v1/control-plane/projects",
                        headers=self._write_headers(
                            self.tenant_a,
                            idempotency_key=(f"unsafe-catalog-{index}-{case_index}"),
                        ),
                        json=payload,
                    )
                    self.assertEqual(response.status_code, 422, response.text)
                    self.assertNotIn(character, response.text)

        for index, character in enumerate(
            (
                "\u034f",
                "\ufe0e",
                "\ufe0f",
                "\U000e0100",
                "\ufffc",
                "\ue000",
            )
        ):
            with self.subTest(identifier_codepoint=f"U+{ord(character):04X}"):
                response = self.client.post(
                    "/v1/control-plane/projects",
                    headers=self._write_headers(
                        self.tenant_a,
                        idempotency_key=f"spoofing-unicode-{index}",
                    ),
                    json={
                        "project_id": f"spoofed-{index}-{character}",
                        "label": "Visible label",
                    },
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertNotIn(character, response.text)

        for index, character in enumerate(("\u200c", "\u200d")):
            with self.subTest(allowed_codepoint=f"U+{ord(character):04X}"):
                response = self.client.post(
                    "/v1/control-plane/projects",
                    headers=self._write_headers(
                        self.tenant_a,
                        idempotency_key=f"allowed-unicode-{index}",
                    ),
                    json={
                        "project_id": f"allowed-{index}-{character}",
                        "label": f"Visible{character}text",
                    },
                )
                self.assertEqual(response.status_code, 201, response.text)

    def test_correlation_report_hides_internal_value_error_path_over_http(
        self,
    ) -> None:
        self._provision_scope(self.tenant_a)
        self._upload(
            _fixture_bytes(ifindex=7),
            original_name="status.jsonl",
            idempotency_key="private-path-upload",
        )
        revision_id = self._catalog_revisions()[0]["revision_id"]
        private_path = r"C:\private\tenant-a\workspace-shared\datasets\revision.json"
        with patch.object(
            self.control_plane,
            "_dataset_path",
            side_effect=ValueError(f"invalid dataset path: {private_path}"),
        ):
            response = self.client.post(
                f"{self.workspace_path}/correlation-report",
                headers=self._read_headers(self.tenant_a),
                json={"revision_ids": [revision_id]},
            )

        self.assertEqual(response.status_code, 500, response.text)
        self.assertEqual(
            response.json(),
            {"detail": "internal control-plane operation failed"},
        )
        self.assertNotIn(private_path, response.text)

    def test_malformed_request_contracts_fail_before_service_io(self) -> None:
        """Every caller-owned request family has an exact live 422 boundary."""

        read = self._read_headers(self.tenant_a)
        write = self._write_headers(self.tenant_a)
        match_write = {**write, "If-Match": '"0"'}
        base = self.workspace_path
        long_catalog_id = "i" * 257
        long_review_id = "r" * 1_025
        oversized_metadata = {"value": "m" * 65_537}
        valid_retention = {
            "catalog": {"enabled": False},
            "review": {"enabled": False},
        }
        cases: tuple[tuple[str, str, str, dict[str, Any]], ...] = (
            (
                "tenant scope identifier",
                "GET",
                "/v1/control-plane/projects",
                {"headers": self._read_headers("t" * 257)},
            ),
            (
                "project path identifier",
                "GET",
                f"/v1/control-plane/projects/{long_catalog_id}/workspaces",
                {"headers": read},
            ),
            (
                "workspace path identifier",
                "GET",
                f"/v1/control-plane/projects/p/workspaces/{long_catalog_id}/fixtures",
                {"headers": read},
            ),
            (
                "session path identifier",
                "GET",
                f"{base}/sessions/{long_catalog_id}",
                {"headers": read},
            ),
            (
                "member path identifier",
                "DELETE",
                f"{base}/sessions/s/members/{long_catalog_id}",
                {"headers": match_write},
            ),
            (
                "snapshot path identifier",
                "GET",
                f"{base}/snapshots/{long_catalog_id}",
                {"headers": read},
            ),
            (
                "import path identifier",
                "GET",
                f"{base}/imports/{'i' * 129}",
                {"headers": read},
            ),
            (
                "annotation path identifier",
                "GET",
                f"{base}/annotations/{long_review_id}",
                {"headers": read},
            ),
            (
                "correlation path identifier",
                "GET",
                f"{base}/correlations/{long_review_id}",
                {"headers": read},
            ),
            (
                "project label",
                "POST",
                "/v1/control-plane/projects",
                {"headers": write, "json": {"label": "l" * 257}},
            ),
            (
                "project identifier",
                "POST",
                "/v1/control-plane/projects",
                {
                    "headers": write,
                    "json": {"project_id": long_catalog_id, "label": "valid"},
                },
            ),
            (
                "project metadata",
                "POST",
                "/v1/control-plane/projects",
                {
                    "headers": write,
                    "json": {"label": "valid", "metadata": oversized_metadata},
                },
            ),
            (
                "project idempotency",
                "POST",
                "/v1/control-plane/projects",
                {
                    "headers": {**write, "Idempotency-Key": "k" * 257},
                    "json": {"label": "valid"},
                },
            ),
            (
                "workspace label",
                "POST",
                "/v1/control-plane/projects/p/workspaces",
                {"headers": write, "json": {"label": "l" * 257}},
            ),
            (
                "workspace identifier",
                "POST",
                "/v1/control-plane/projects/p/workspaces",
                {
                    "headers": write,
                    "json": {"workspace_id": long_catalog_id, "label": "valid"},
                },
            ),
            (
                "workspace metadata",
                "POST",
                "/v1/control-plane/projects/p/workspaces",
                {
                    "headers": write,
                    "json": {"label": "valid", "metadata": oversized_metadata},
                },
            ),
            (
                "workspace idempotency",
                "POST",
                "/v1/control-plane/projects/p/workspaces",
                {
                    "headers": {**write, "Idempotency-Key": "k" * 257},
                    "json": {"label": "valid"},
                },
            ),
            (
                "session label",
                "POST",
                f"{base}/sessions",
                {"headers": write, "json": {"label": "l" * 257}},
            ),
            (
                "session identifier",
                "POST",
                f"{base}/sessions",
                {
                    "headers": write,
                    "json": {"session_id": long_catalog_id, "label": "valid"},
                },
            ),
            (
                "session metadata",
                "POST",
                f"{base}/sessions",
                {
                    "headers": write,
                    "json": {"label": "valid", "metadata": oversized_metadata},
                },
            ),
            (
                "session create idempotency",
                "POST",
                f"{base}/sessions",
                {
                    "headers": {**write, "Idempotency-Key": "k" * 257},
                    "json": {"label": "valid"},
                },
            ),
            (
                "session update label",
                "PATCH",
                f"{base}/sessions/session",
                {"headers": match_write, "json": {"label": "l" * 257}},
            ),
            (
                "session update metadata",
                "PATCH",
                f"{base}/sessions/session",
                {"headers": match_write, "json": {"metadata": oversized_metadata}},
            ),
            (
                "session update idempotency",
                "PATCH",
                f"{base}/sessions/session",
                {
                    "headers": {
                        **match_write,
                        "Idempotency-Key": "k" * 257,
                    },
                    "json": {"label": "valid"},
                },
            ),
            (
                "retention protected identifier",
                "POST",
                f"{base}/retention/preview",
                {
                    "headers": write,
                    "json": {
                        "catalog": {"protected_fixture_ids": [long_catalog_id]},
                        "review": {},
                    },
                },
            ),
            (
                "retention duplicate protected identifiers",
                "POST",
                f"{base}/retention/preview",
                {
                    "headers": write,
                    "json": {
                        "catalog": {"protected_fixture_ids": ["same", "same"]},
                        "review": {},
                    },
                },
            ),
            (
                "retention protected identifier limit",
                "POST",
                f"{base}/retention/preview",
                {
                    "headers": write,
                    "json": {
                        "catalog": {
                            "protected_fixture_ids": [
                                f"fixture-{index}" for index in range(5_001)
                            ]
                        },
                        "review": {},
                    },
                },
            ),
            (
                "retention operation identifier",
                "POST",
                f"{base}/retention/execute",
                {
                    "headers": {**write, "Idempotency-Key": "o" * 249},
                    "json": valid_retention,
                },
            ),
            (
                "retention actor",
                "POST",
                f"{base}/retention/execute",
                {
                    "headers": {
                        **self._write_headers(self.tenant_a),
                        "X-Principal-ID": "a" * 257,
                        "Idempotency-Key": "retention-operation",
                    },
                    "json": valid_retention,
                },
            ),
            (
                "revision node filter",
                "GET",
                f"{base}/revisions",
                {"headers": read, "params": {"node_id": long_catalog_id}},
            ),
            (
                "list offset bound",
                "GET",
                "/v1/control-plane/projects",
                {
                    "headers": read,
                    "params": {"offset": str(1 << 63)},
                },
            ),
            (
                "revision fixture filter",
                "GET",
                f"{base}/revisions",
                {"headers": read, "params": {"fixture_id": long_catalog_id}},
            ),
            (
                "snapshot session filter",
                "GET",
                f"{base}/snapshots",
                {"headers": read, "params": {"session_id": long_catalog_id}},
            ),
            (
                "import cursor pairing",
                "GET",
                f"{base}/imports",
                {"headers": read, "params": {"before_created_at_ns": "1"}},
            ),
            (
                "import cursor identifier",
                "GET",
                f"{base}/imports",
                {
                    "headers": read,
                    "params": {
                        "before_created_at_ns": "1",
                        "before_import_id": "i" * 129,
                    },
                },
            ),
            (
                "member fixture identifier",
                "PUT",
                f"{base}/sessions/session/members/member",
                {
                    "headers": match_write,
                    "json": {"fixture_id": long_catalog_id, "revision_id": "r"},
                },
            ),
            (
                "member revision identifier",
                "PUT",
                f"{base}/sessions/session/members/member",
                {
                    "headers": match_write,
                    "json": {"fixture_id": "f", "revision_id": long_catalog_id},
                },
            ),
            (
                "member role",
                "PUT",
                f"{base}/sessions/session/members/member",
                {
                    "headers": match_write,
                    "json": {
                        "fixture_id": "f",
                        "revision_id": "r",
                        "role": "r" * 129,
                    },
                },
            ),
            (
                "member make_default",
                "PUT",
                f"{base}/sessions/session/members/member",
                {
                    "headers": match_write,
                    "json": {
                        "fixture_id": "f",
                        "revision_id": "r",
                        "make_default": 1,
                    },
                },
            ),
            (
                "upload original name",
                "POST",
                f"{base}/imports",
                {
                    "headers": write,
                    "params": {"original_name": "bad\x00name"},
                    "content": b"x",
                },
            ),
            (
                "upload preferred plugin",
                "POST",
                f"{base}/imports",
                {
                    "headers": write,
                    "params": {
                        "original_name": "fixture.bin",
                        "preferred_plugin_id": "bad plugin",
                    },
                    "content": b"x",
                },
            ),
            (
                "upload node hint",
                "POST",
                f"{base}/imports",
                {
                    "headers": {**write, "X-Node-Hint": ""},
                    "params": {"original_name": "fixture.bin"},
                    "content": b"x",
                },
            ),
            (
                "upload idempotency",
                "POST",
                f"{base}/imports",
                {
                    "headers": {**write, "Idempotency-Key": ""},
                    "params": {"original_name": "fixture.bin"},
                    "content": b"x",
                },
            ),
            (
                "upload metadata",
                "POST",
                f"{base}/imports",
                {
                    "headers": {**write, "X-Import-Metadata": "not-json"},
                    "params": {"original_name": "fixture.bin"},
                    "content": b"x",
                },
            ),
            *tuple(
                (
                    f"selection {field}",
                    "POST",
                    f"{base}/imports/import/selection",
                    {
                        "headers": {
                            **write,
                            "Idempotency-Key": "selection-operation",
                        },
                        "json": {
                            "probe_set_hash": "probe",
                            "plugin_id": "plugin",
                            "plugin_version": "version",
                            "package_hash": "package",
                            field: "",
                        },
                    },
                )
                for field in (
                    "probe_set_hash",
                    "plugin_id",
                    "plugin_version",
                    "package_hash",
                )
            ),
            (
                "selection idempotency",
                "POST",
                f"{base}/imports/import/selection",
                {
                    "headers": {**write, "Idempotency-Key": ""},
                    "json": {
                        "probe_set_hash": "probe",
                        "plugin_id": "plugin",
                        "plugin_version": "version",
                        "package_hash": "package",
                    },
                },
            ),
            (
                "report revision identifier",
                "POST",
                f"{base}/correlation-report",
                {"headers": read, "json": {"revision_ids": [long_catalog_id]}},
            ),
            (
                "report duplicate revisions",
                "POST",
                f"{base}/correlation-report",
                {"headers": read, "json": {"revision_ids": ["r", "r"]}},
            ),
            (
                "report revision limit",
                "POST",
                f"{base}/correlation-report",
                {
                    "headers": read,
                    "json": {
                        "revision_ids": [f"revision-{index}" for index in range(5_001)]
                    },
                },
            ),
            (
                "report session selector",
                "POST",
                f"{base}/correlation-report",
                {"headers": read, "json": {"session_id": ""}},
            ),
            (
                "report snapshot selector",
                "POST",
                f"{base}/correlation-report",
                {"headers": read, "json": {"snapshot_id": long_catalog_id}},
            ),
            (
                "report selector exclusivity",
                "POST",
                f"{base}/correlation-report",
                {
                    "headers": read,
                    "json": {"revision_ids": ["r"], "session_id": "s"},
                },
            ),
        )

        for label, method, path, request_arguments in cases:
            with self.subTest(label=label):
                response = self.client.request(
                    method,
                    path,
                    **request_arguments,
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertNotIn(PRIVATE_API_FAILURE_MARKER, response.text)

    def test_live_internal_value_error_remains_a_redacted_500(self) -> None:
        private_path = r"C:\private\catalog\database.sqlite3"
        with patch.object(
            self.control_plane.sessions,
            "create_project",
            side_effect=ValueError(f"invalid internal path: {private_path}"),
        ):
            response = self.client.post(
                "/v1/control-plane/projects",
                headers=self._write_headers(self.tenant_a),
                json={"project_id": "valid-project", "label": "Valid project"},
            )

        self.assertEqual(response.status_code, 500, response.text)
        self.assertEqual(
            response.json(),
            {"detail": "internal control-plane operation failed"},
        )
        self.assertNotIn(private_path, response.text)

    def test_failure_diagnostics_stay_out_of_http_events_and_sse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = PluginRegistry()
            registry.register(
                _EventPlugin(),
                coordinator=_SecretApiCoordinator(),
            )
            control_plane = ControlPlane(
                Path(directory),
                registry=registry,
                pipeline_limits=PipelineLimits(
                    max_upload_bytes=1024 * 1024,
                    max_workers=1,
                    lease_seconds=30,
                    poll_interval_seconds=0.01,
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                ),
            )
            control_plane.start()
            application = FastAPI()
            application.include_router(control_plane_router)
            application.state.control_plane = control_plane
            application.state.control_plane_identity_resolver = (
                TrustedHeaderIdentityResolver(
                    allowed_hosts=("testserver",),
                    allowed_origins=("http://testserver",),
                )
            )
            try:
                with TestClient(application) as client:
                    write_headers = self._write_headers("tenant-private")
                    project = client.post(
                        "/v1/control-plane/projects",
                        headers=write_headers,
                        json={
                            "project_id": "project-private",
                            "label": "Private diagnostics",
                        },
                    )
                    self.assertEqual(project.status_code, 201, project.text)
                    workspace = client.post(
                        "/v1/control-plane/projects/project-private/workspaces",
                        headers=write_headers,
                        json={
                            "workspace_id": "workspace-private",
                            "label": "Private diagnostics",
                        },
                    )
                    self.assertEqual(workspace.status_code, 201, workspace.text)
                    base = (
                        "/v1/control-plane/projects/project-private"
                        "/workspaces/workspace-private"
                    )
                    admitted = client.post(
                        f"{base}/imports",
                        params={"original_name": "status.jsonl"},
                        headers={
                            **write_headers,
                            "Content-Type": "application/x-ndjson",
                        },
                        content=_fixture_bytes(ifindex=21),
                    )
                    self.assertEqual(admitted.status_code, 202, admitted.text)
                    import_id = admitted.json()["import_id"]
                    scope = ImportScope(
                        "tenant-private",
                        "project-private",
                        "workspace-private",
                    )
                    failed = control_plane.ingestion.wait(
                        scope,
                        import_id,
                        timeout=10,
                    )
                    self.assertEqual(failed.state, ImportState.FAILED)

                    descriptor = client.get(
                        f"{base}/imports/{import_id}",
                        headers=self._read_headers("tenant-private"),
                    )
                    events = client.get(
                        f"{base}/imports/{import_id}/events",
                        headers=self._read_headers("tenant-private"),
                    )
                    with client.stream(
                        "GET",
                        f"{base}/imports/{import_id}/events/stream",
                        headers=self._read_headers("tenant-private"),
                    ) as response:
                        sse = "".join(response.iter_text())
                    absent_endpoint = client.get(
                        f"{base}/imports/{import_id}/failure-diagnostics",
                        headers=self._read_headers("tenant-private"),
                    )

                self.assertEqual(descriptor.status_code, 200, descriptor.text)
                self.assertEqual(events.status_code, 200, events.text)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(absent_endpoint.status_code, 404)
                public_surface = descriptor.text + events.text + sse
                self.assertNotIn(PRIVATE_API_FAILURE_MARKER, public_surface)
                self.assertIn("worker_failure", public_surface)

                with closing(
                    sqlite3.connect(control_plane.ingestion.database_path)
                ) as connection:
                    diagnostic = connection.execute(
                        """
                        SELECT exception_message
                        FROM ingestion_failure_diagnostics
                        WHERE import_id = ?
                        """,
                        (import_id,),
                    ).fetchone()
                self.assertIsNotNone(diagnostic)
                assert diagnostic is not None
                self.assertIn(PRIVATE_API_FAILURE_MARKER, diagnostic[0])
            finally:
                control_plane.close(timeout=5)

    def test_revision_catalog_preserves_legacy_plan_absence(self) -> None:
        self._provision_scope(self.tenant_a)
        self.control_plane.sessions.attach_fixture(
            self.tenant_a,
            self.workspace_id,
            "legacy-fixture",
            label="Legacy fixture",
            content_digest="a" * 64,
        )
        self.control_plane.sessions.publish_revision(
            self.tenant_a,
            self.workspace_id,
            "legacy-fixture",
            "legacy-revision",
            node_id="legacy-node",
            identity_digest="b" * 64,
            plugin_ids=("legacy.plugin",),
        )

        revisions = self._catalog_revisions()

        self.assertEqual(len(revisions), 1)
        self.assertIsNone(revisions[0]["execution_plan"])
        self.assertEqual(revisions[0]["plugin_ids"], ["legacy.plugin"])

    def test_streamed_upload_and_multi_revision_session_membership(self) -> None:
        self._provision_scope(self.tenant_a)
        first_import = self._upload(
            _fixture_bytes(ifindex=7),
            original_name="status.jsonl",
            idempotency_key="upload-revision-1",
            node_hint="router-hinted",
            metadata={"site": "lab-a"},
        )
        self.assertEqual(first_import["node_hint"], "router-hinted")
        self.assertEqual(first_import["metadata"], {"site": "lab-a"})
        self.assertEqual(first_import["node_id"], "router-hinted")
        self._upload(
            _fixture_bytes(ifindex=8),
            original_name="status.jsonl",
            idempotency_key="upload-revision-2",
        )
        revisions = self._catalog_revisions()
        self.assertEqual(len(revisions), 2)
        self.assertEqual(
            len({revision["fixture_id"] for revision in revisions}),
            2,
        )
        for revision in revisions:
            execution_plan = revision["execution_plan"]
            self.assertEqual(
                execution_plan["plan_digest"],
                revision["metadata"]["plugin_execution_plan_digest"],
            )
            self.assertEqual(execution_plan["node_id"], revision["node_id"])
            self.assertEqual(len(execution_plan["plugins"]), 1)
            pin = execution_plan["plugins"][0]
            self.assertEqual(pin["plugin_id"], "tests.control-plane-events")
            self.assertIn("configuration_digest", pin)
            self.assertNotIn("configuration", pin)
            self.assertIn(
                pin["artifact"]["package_hash"].split(":", 1)[0],
                {"module-sha256", "package-sha256"},
            )

        created = self.client.post(
            f"{self.workspace_path}/sessions",
            headers=self._write_headers(self.tenant_a),
            json={"session_id": "review-set", "label": "Two revisions"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.headers["etag"], '"0"')
        session_path = f"{self.workspace_path}/sessions/review-set"
        empty_session_report = self.client.post(
            f"{self.workspace_path}/correlation-report",
            headers=self._read_headers(self.tenant_a),
            json={"session_id": "review-set"},
        )
        self.assertEqual(empty_session_report.status_code, 422)
        first_body = {
            "fixture_id": revisions[0]["fixture_id"],
            "revision_id": revisions[0]["revision_id"],
            "make_default": True,
        }
        precondition_required = self.client.put(
            f"{session_path}/members/router-a-first",
            headers=self._write_headers(self.tenant_a),
            json=first_body,
        )
        self.assertEqual(precondition_required.status_code, 428)

        first_member = self.client.put(
            f"{session_path}/members/router-a-first",
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"0"',
            },
            json=first_body,
        )
        self.assertEqual(first_member.status_code, 200, first_member.text)
        self.assertEqual(first_member.headers["etag"], '"1"')

        other_workspace = self.client.post(
            f"/v1/control-plane/projects/{self.project_id}/workspaces",
            headers=self._write_headers(self.tenant_a),
            json={
                "workspace_id": "workspace-other",
                "label": "Other workspace",
            },
        )
        self.assertEqual(
            other_workspace.status_code,
            201,
            other_workspace.text,
        )
        other_session_path = (
            f"/v1/control-plane/projects/{self.project_id}"
            "/workspaces/workspace-other/sessions/review-set"
        )
        rejected_cross_workspace_put = self.client.put(
            f"{other_session_path}/members/rogue",
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"1"',
            },
            json=first_body,
        )
        rejected_cross_workspace_delete = self.client.delete(
            f"{other_session_path}/members/router-a-first",
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"1"',
            },
        )
        rejected_cross_workspace_snapshot = self.client.post(
            f"{other_session_path}/snapshots",
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"1"',
            },
        )
        self.assertEqual(rejected_cross_workspace_put.status_code, 404)
        self.assertEqual(rejected_cross_workspace_delete.status_code, 404)
        self.assertEqual(rejected_cross_workspace_snapshot.status_code, 404)
        unchanged = self.client.get(
            session_path,
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(unchanged.status_code, 200, unchanged.text)
        self.assertEqual(unchanged.json()["version"], 1)
        self.assertEqual(
            [member["member_id"] for member in unchanged.json()["members"]],
            ["router-a-first"],
        )

        second_body = {
            "fixture_id": revisions[1]["fixture_id"],
            "revision_id": revisions[1]["revision_id"],
        }
        stale = self.client.put(
            f"{session_path}/members/router-a-second",
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"0"',
            },
            json=second_body,
        )
        self.assertEqual(stale.status_code, 409, stale.text)
        for invalid_if_match in ('W/"1"', "1", '"01"', '"+1"', "*"):
            with self.subTest(if_match=invalid_if_match):
                rejected_if_match = self.client.put(
                    f"{session_path}/members/router-a-second",
                    headers={
                        **self._write_headers(self.tenant_a),
                        "If-Match": invalid_if_match,
                    },
                    json=second_body,
                )
                self.assertEqual(
                    rejected_if_match.status_code,
                    422,
                    rejected_if_match.text,
                )
        second_member = self.client.put(
            f"{session_path}/members/router-a-second",
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"1"',
            },
            json=second_body,
        )
        self.assertEqual(second_member.status_code, 200, second_member.text)
        session = second_member.json()
        self.assertEqual(session["version"], 2)
        self.assertEqual(len(session["members"]), 2)
        self.assertEqual(
            {member["revision_id"] for member in session["members"]},
            {revision["revision_id"] for revision in revisions},
        )
        updated_session = self.client.patch(
            session_path,
            headers={
                **self._write_headers(
                    self.tenant_a,
                    idempotency_key="rename-review-set",
                ),
                "If-Match": '"2"',
            },
            json={"label": "Two immutable revisions"},
        )
        self.assertEqual(
            updated_session.status_code,
            200,
            updated_session.text,
        )
        self.assertEqual(updated_session.json()["version"], 3)

        snapshot = self.client.post(
            f"{session_path}/snapshots",
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"3"',
            },
        )
        self.assertEqual(snapshot.status_code, 201, snapshot.text)
        self.assertEqual(len(snapshot.json()["members"]), 2)
        snapshot_id = snapshot.json()["snapshot_id"]
        fetched_snapshot = self.client.get(
            f"{self.workspace_path}/snapshots/{snapshot_id}",
            headers=self._read_headers(self.tenant_a),
        )
        hidden_snapshot = self.client.get(
            f"/v1/control-plane/projects/{self.project_id}"
            f"/workspaces/workspace-other/snapshots/{snapshot_id}",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(fetched_snapshot.status_code, 200)
        self.assertEqual(hidden_snapshot.status_code, 404)
        listed_snapshots = self.client.get(
            f"{self.workspace_path}/snapshots",
            params={"session_id": "review-set"},
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(listed_snapshots.status_code, 200)
        self.assertEqual(
            [item["snapshot_id"] for item in listed_snapshots.json()["items"]],
            [snapshot_id],
        )
        snapshot_report = self.client.post(
            f"{self.workspace_path}/correlation-report",
            headers=self._read_headers(self.tenant_a),
            json={"snapshot_id": snapshot_id},
        )
        self.assertEqual(snapshot_report.status_code, 200, snapshot_report.text)
        protected_delete = self.client.delete(
            session_path,
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"3"',
            },
        )
        self.assertEqual(protected_delete.status_code, 409)

    def test_restricted_identity_filters_project_and_workspace_collections(
        self,
    ) -> None:
        tenant = "tenant-restricted"
        sessions = self.control_plane.sessions
        for project_id in ("project-allowed", "project-hidden"):
            sessions.create_project(
                tenant,
                project_id,
                project_id=project_id,
            )
        sessions.create_workspace(
            tenant,
            "project-allowed",
            "Allowed workspace",
            workspace_id="workspace-allowed",
        )
        sessions.create_workspace(
            tenant,
            "project-allowed",
            "Hidden workspace",
            workspace_id="workspace-hidden",
        )

        def restricted_identity(_request: Any) -> ControlPlaneIdentity:
            return ControlPlaneIdentity(
                tenant_id=tenant,
                principal_id="reader@example.test",
                roles=frozenset({CONTROL_PLANE_READ_ROLE}),
                project_ids=frozenset({"project-allowed"}),
                workspace_ids=frozenset({"workspace-allowed"}),
            )

        self.client.app.state.control_plane_identity_resolver = restricted_identity
        headers = {
            "X-Tenant-ID": tenant,
            "X-Principal-ID": "reader@example.test",
        }
        context = self.client.get(
            "/v1/control-plane/context",
            headers=headers,
        )
        projects = self.client.get(
            "/v1/control-plane/projects",
            headers=headers,
        )
        workspaces = self.client.get(
            "/v1/control-plane/projects/project-allowed/workspaces",
            headers=headers,
        )

        self.assertEqual(context.status_code, 200, context.text)
        self.assertFalse(context.json()["can_write"])
        self.assertEqual(
            [item["project_id"] for item in context.json()["projects"]],
            ["project-allowed"],
        )
        self.assertEqual(
            [item["project_id"] for item in projects.json()["items"]],
            ["project-allowed"],
        )
        self.assertEqual(
            [item["workspace_id"] for item in workspaces.json()["items"]],
            ["workspace-allowed"],
        )
        hidden = self.client.get(
            "/v1/control-plane/projects/project-hidden/workspaces",
            headers=headers,
        )
        denied_create = self.client.post(
            "/v1/control-plane/projects",
            headers=headers,
            json={
                "project_id": "project-hidden",
                "label": "Not authorized",
            },
        )
        self.assertEqual(hidden.status_code, 404)
        self.assertEqual(denied_create.status_code, 403)

    def test_retention_admin_preview_execute_and_bounded_audit(self) -> None:
        self._provision_scope(self.tenant_a)
        context = self.client.get(
            "/v1/control-plane/context",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(context.status_code, 200, context.text)
        self.assertTrue(context.json()["can_admin"])

        policy = {
            "catalog": {
                "enabled": True,
                "snapshot_before_ns": "100",
                "maximum_candidates": 5,
            },
            "review": {
                "enabled": True,
                "tombstone_before_ns": "100",
                "maximum_candidates": 5,
            },
        }
        actual_to_thread = asyncio.to_thread
        with patch(
            "router_dump_analyzer.web.control_plane_api.asyncio.to_thread",
            wraps=actual_to_thread,
        ) as offload:
            preview = self.client.post(
                f"{self.workspace_path}/retention/preview",
                headers=self._write_headers(self.tenant_a),
                json=policy,
            )
        offload.assert_awaited_once()
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertFalse(preview.json()["executed"])
        self.assertEqual(
            preview.json()["observation_mode"],
            "best_effort_preview",
        )
        self.assertEqual(
            preview.json()["catalog"]["policy"]["snapshot_before_ns"],
            "100",
        )

        missing_key = self.client.post(
            f"{self.workspace_path}/retention/execute",
            headers=self._write_headers(self.tenant_a),
            json=policy,
        )
        self.assertEqual(missing_key.status_code, 428, missing_key.text)

        executed = self.client.post(
            f"{self.workspace_path}/retention/execute",
            headers=self._write_headers(
                self.tenant_a,
                idempotency_key="retention-run-1",
            ),
            json=policy,
        )
        self.assertEqual(executed.status_code, 200, executed.text)
        self.assertTrue(executed.json()["executed"])
        self.assertEqual(
            executed.json()["observation_mode"],
            "coordinated_execution",
        )
        audit = self.client.get(
            f"{self.workspace_path}/retention/audit",
            params={"limit": 1},
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(audit.status_code, 200, audit.text)
        self.assertEqual(
            audit.json()["catalog"][0]["operation_id"],
            "retention-run-1:catalog",
        )
        self.assertEqual(
            audit.json()["review"][0]["operation_id"],
            "retention-run-1:review",
        )
        self.assertEqual(
            audit.json()["review"][0]["actor"],
            "reviewer@example.test",
        )
        replay = self.client.post(
            f"{self.workspace_path}/retention/execute",
            headers=self._write_headers(
                self.tenant_a,
                idempotency_key="retention-run-1",
            ),
            json=policy,
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json(), executed.json())
        replay_audit = self.client.get(
            f"{self.workspace_path}/retention/audit",
            params={"limit": 1},
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(replay_audit.status_code, 200, replay_audit.text)
        self.assertEqual(replay_audit.json(), audit.json())

    def test_retention_release_survives_restart_and_converges_through_api(
        self,
    ) -> None:
        self._provision_scope(self.tenant_a)
        completed = self._upload(
            _fixture_bytes(ifindex=43),
            original_name="status.jsonl",
            idempotency_key="restart-retention-upload",
        )
        ingestion_policy = RetentionPolicy(
            enabled=True,
            terminal_import_grace_seconds=0,
            idempotency_replay_seconds=0,
            orphan_artifact_grace_seconds=0,
            stale_partial_seconds=0,
        )
        self.control_plane.ingestion.retention_policy = ingestion_policy
        with self.control_plane.sessions._transaction() as cursor:
            cursor.execute(
                "UPDATE fixtures SET created_at_ns = 10 "
                "WHERE tenant_id = ? AND workspace_id = ?",
                (self.tenant_a, self.workspace_id),
            )
            cursor.execute(
                "UPDATE analysis_revisions SET published_at_ns = 10 "
                "WHERE tenant_id = ? AND workspace_id = ?",
                (self.tenant_a, self.workspace_id),
            )
            cursor.execute(
                "UPDATE idempotency_keys SET created_at_ns = 10 WHERE tenant_id = ?",
                (self.tenant_a,),
            )
        with self.control_plane.ingestion._connect() as connection:
            connection.execute(
                "UPDATE ingestion_imports SET updated_at_ns = 0 WHERE import_id = ?",
                (completed["import_id"],),
            )
            row = connection.execute(
                "SELECT blob_ref, staged_dataset_ref "
                "FROM ingestion_imports WHERE import_id = ?",
                (completed["import_id"],),
            ).fetchone()
        assert row is not None
        blob_path = self.control_plane.ingestion.blob_root / Path(str(row["blob_ref"]))
        dataset_path = self.control_plane.ingestion.dataset_root / Path(
            str(row["staged_dataset_ref"])
        )
        policy = {
            "catalog": {
                "enabled": True,
                "idempotency_before_ns": "20",
                "revision_before_ns": "20",
                "fixture_before_ns": "20",
            },
            "review": {"enabled": False},
        }

        first = self.client.post(
            f"{self.workspace_path}/retention/execute",
            headers=self._write_headers(
                self.tenant_a,
                idempotency_key="restart-retention-first",
            ),
            json=policy,
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["ingestion"]["deleted_imports"], 0)
        with self.control_plane.ingestion._connect() as connection:
            self.assertEqual(
                int(
                    connection.execute(
                        "SELECT COUNT(*) FROM ingestion_artifact_pins"
                    ).fetchone()[0]
                ),
                1,
            )

        old_control_plane = self.control_plane
        old_control_plane.close(timeout=5)
        self.control_plane = ControlPlane(
            Path(self.temporary.name),
            registry=PluginRegistry((_PluginNsEventPlugin(),)),
            pipeline_limits=PipelineLimits(
                max_upload_bytes=1024 * 1024,
                max_workers=1,
                lease_seconds=30,
                poll_interval_seconds=0.01,
            ),
            retention_policy=ingestion_policy,
            limits=ControlPlaneLimits(
                max_dataset_bytes=1024 * 1024,
                dataset_cache_entries=2,
            ),
        )
        self.control_plane.start()
        self.client.app.state.control_plane = self.control_plane
        with self.control_plane.ingestion._connect() as connection:
            self.assertEqual(
                int(
                    connection.execute(
                        "SELECT COUNT(*) FROM ingestion_artifact_pins"
                    ).fetchone()[0]
                ),
                1,
            )

        second = self.client.post(
            f"{self.workspace_path}/retention/execute",
            headers=self._write_headers(
                self.tenant_a,
                idempotency_key="restart-retention-second",
            ),
            json=policy,
        )
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(second.json()["ingestion"]["deleted_imports"], 1)
        self.assertEqual(second.json()["ingestion"]["content_blobs"], 1)
        self.assertEqual(second.json()["ingestion"]["revision_datasets"], 1)
        self.assertFalse(blob_path.exists())
        self.assertFalse(dataset_path.exists())
        with self.control_plane.ingestion._connect() as connection:
            self.assertEqual(
                int(
                    connection.execute(
                        "SELECT COUNT(*) FROM ingestion_artifact_pins"
                    ).fetchone()[0]
                ),
                0,
            )

    def test_retention_admin_role_and_policy_vocabulary_fail_closed(self) -> None:
        self._provision_scope(self.tenant_a)

        def non_admin_identity(_request: Any) -> ControlPlaneIdentity:
            return ControlPlaneIdentity(
                tenant_id=self.tenant_a,
                principal_id="reviewer@example.test",
                roles=frozenset(
                    {
                        CONTROL_PLANE_READ_ROLE,
                        CONTROL_PLANE_WRITE_ROLE,
                    }
                ),
            )

        self.client.app.state.control_plane_identity_resolver = non_admin_identity
        denied = self.client.post(
            f"{self.workspace_path}/retention/preview",
            headers=self._write_headers(self.tenant_a),
            json={},
        )
        self.assertEqual(denied.status_code, 403, denied.text)

        def admin_identity(_request: Any) -> ControlPlaneIdentity:
            return ControlPlaneIdentity(
                tenant_id=self.tenant_a,
                principal_id="reviewer@example.test",
                roles=frozenset({CONTROL_PLANE_ADMIN_ROLE}),
            )

        self.client.app.state.control_plane_identity_resolver = admin_identity
        for payload in (
            {"catalog": {"external_references_checked": True}},
            {"catalog": {"enabled": 1}},
            {"review": {"audit_mode": "delete_everything"}},
            {"unexpected": {}},
        ):
            invalid = self.client.post(
                f"{self.workspace_path}/retention/preview",
                headers=self._write_headers(self.tenant_a),
                json=payload,
            )
            self.assertEqual(invalid.status_code, 422, invalid.text)

    def test_exact_annotations_correlation_and_deterministic_report(self) -> None:
        self._provision_scope(self.tenant_a)
        self._provision_scope(self.tenant_b)
        self._upload(
            _fixture_bytes(ifindex=7),
            original_name="status.jsonl",
            idempotency_key="review-upload-1",
        )
        self._upload(
            _fixture_bytes(ifindex=7, final_state="degraded"),
            original_name="status.jsonl",
            idempotency_key="review-upload-2",
        )
        revisions = self._catalog_revisions()
        self.assertEqual(len(revisions), 2)
        scope = self.control_plane.scope(
            self.tenant_a,
            self.project_id,
            self.workspace_id,
        )
        event_subjects: list[dict[str, str]] = []
        for revision in revisions:
            dataset = self.control_plane.load_revision_dataset(
                scope,
                revision["revision_id"],
            )
            event_subjects.append(
                {
                    "revision_id": revision["revision_id"],
                    "kind": "event",
                    "subject_id": dataset["events"][0]["event_uid"],
                    "node_id": revision["node_id"],
                }
            )

        invalid = self.client.post(
            f"{self.workspace_path}/annotations",
            headers=self._write_headers(self.tenant_a),
            json={
                "kind": "marker",
                "subjects": [
                    {
                        **event_subjects[0],
                        "subject_id": "event-does-not-exist",
                    }
                ],
            },
        )
        self.assertEqual(invalid.status_code, 422, invalid.text)
        other_workspace = self.client.post(
            f"/v1/control-plane/projects/{self.project_id}/workspaces",
            headers=self._write_headers(self.tenant_a),
            json={
                "workspace_id": "review-other",
                "label": "Other review workspace",
            },
        )
        self.assertEqual(other_workspace.status_code, 201)
        other_review_path = (
            f"/v1/control-plane/projects/{self.project_id}/workspaces/review-other"
        )
        hidden_subject = self.client.post(
            f"{other_review_path}/annotations",
            headers=self._write_headers(self.tenant_a),
            json={
                "kind": "marker",
                "subjects": [event_subjects[0]],
            },
        )
        hidden_report = self.client.post(
            f"{other_review_path}/correlation-report",
            headers=self._read_headers(self.tenant_a),
            json={"revision_ids": [revisions[0]["revision_id"]]},
        )
        self.assertEqual(hidden_subject.status_code, 404)
        self.assertEqual(hidden_report.status_code, 404)

        created = self.client.post(
            f"{self.workspace_path}/annotations",
            headers=self._write_headers(
                self.tenant_a,
                idempotency_key="annotation-create",
            ),
            json={
                "annotation_id": "annotation-1",
                "kind": "marker",
                "subjects": [event_subjects[0]],
                "title": "Investigate transition",
                "body": "The first observation is the review anchor.",
                "tags": ["needs-review"],
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.headers["etag"], '"1"')
        annotation_path = f"{self.workspace_path}/annotations/annotation-1"
        first_annotation_page = self.client.get(
            f"{self.workspace_path}/annotations",
            headers=self._read_headers(self.tenant_a),
            params={"limit": 1, "offset": 0},
        )
        self.assertEqual(first_annotation_page.status_code, 200)
        first_annotation_watermark = first_annotation_page.json()["audit_watermark"]
        self.assertIsInstance(first_annotation_watermark, str)
        self.assertRegex(first_annotation_watermark, r"^(0|[1-9][0-9]*)$")
        missing_continuation_watermark = self.client.get(
            f"{self.workspace_path}/annotations",
            headers=self._read_headers(self.tenant_a),
            params={"limit": 1, "offset": 1},
        )
        self.assertEqual(missing_continuation_watermark.status_code, 428)
        valid_annotation_continuation = self.client.get(
            f"{self.workspace_path}/annotations",
            headers=self._read_headers(self.tenant_a),
            params={
                "limit": 1,
                "offset": 1,
                "expected_audit_watermark": first_annotation_watermark,
            },
        )
        self.assertEqual(valid_annotation_continuation.status_code, 200)
        self.assertEqual(valid_annotation_continuation.json()["items"], [])
        self.assertEqual(
            valid_annotation_continuation.json()["audit_watermark"],
            first_annotation_watermark,
        )
        invalid_annotation_watermark = self.client.get(
            f"{self.workspace_path}/annotations",
            headers=self._read_headers(self.tenant_a),
            params={"expected_audit_watermark": "01"},
        )
        self.assertEqual(invalid_annotation_watermark.status_code, 422)

        stale = self.client.patch(
            annotation_path,
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"99"',
            },
            json={"title": "Stale update"},
        )
        self.assertEqual(stale.status_code, 409, stale.text)
        updated = self.client.patch(
            annotation_path,
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"1"',
            },
            json={"title": "Confirmed transition", "tags": ["confirmed"]},
        )
        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertEqual(updated.headers["etag"], '"2"')
        self.assertEqual(updated.json()["title"], "Confirmed transition")
        stale_annotation_page = self.client.get(
            f"{self.workspace_path}/annotations",
            headers=self._read_headers(self.tenant_a),
            params={
                "offset": 1,
                "expected_audit_watermark": first_annotation_watermark,
            },
        )
        self.assertEqual(stale_annotation_page.status_code, 409)
        refreshed_annotation_page = self.client.get(
            f"{self.workspace_path}/annotations",
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(refreshed_annotation_page.status_code, 200)
        self.assertGreater(
            int(refreshed_annotation_page.json()["audit_watermark"]),
            int(first_annotation_watermark),
        )

        invalid_patch_subject = self.client.patch(
            annotation_path,
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"2"',
            },
            json={
                "subjects": [
                    {
                        **event_subjects[0],
                        "subject_id": "event-does-not-exist",
                    }
                ]
            },
        )
        invalid_patch_kind = self.client.patch(
            annotation_path,
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"2"',
            },
            json={"kind": "plugin-private-kind"},
        )
        self.assertEqual(
            invalid_patch_subject.status_code,
            422,
            invalid_patch_subject.text,
        )
        self.assertEqual(
            invalid_patch_kind.status_code,
            422,
            invalid_patch_kind.text,
        )
        unchanged_annotation = self.client.get(
            annotation_path,
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(
            unchanged_annotation.status_code,
            200,
            unchanged_annotation.text,
        )
        self.assertEqual(unchanged_annotation.json()["version"], 2)

        correlation = self.client.post(
            f"{self.workspace_path}/correlations",
            headers=self._write_headers(
                self.tenant_a,
                idempotency_key="correlation-create",
            ),
            json={
                "correlation_id": "correlation-1",
                "subjects": event_subjects,
                "edges": [
                    {
                        "source_ordinal": 0,
                        "target_ordinal": 1,
                        "link_type": "user.same-transition",
                        "directed": True,
                    }
                ],
                "rationale": "These revision-qualified events describe one change.",
                "tags": ["cross-revision"],
                "confidence": 0.9,
            },
        )
        self.assertEqual(correlation.status_code, 201, correlation.text)
        self.assertEqual(correlation.headers["etag"], '"1"')
        invalid_correlation_patch = self.client.patch(
            f"{self.workspace_path}/correlations/correlation-1",
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"1"',
            },
            json={
                "subjects": [
                    event_subjects[0],
                    {
                        **event_subjects[1],
                        "subject_id": "event-does-not-exist",
                    },
                ]
            },
        )
        self.assertEqual(
            invalid_correlation_patch.status_code,
            422,
            invalid_correlation_patch.text,
        )

        report_body = {
            "revision_ids": [revision["revision_id"] for revision in revisions]
        }
        first_json = self.client.post(
            f"{self.workspace_path}/correlation-report",
            headers=self._read_headers(self.tenant_a),
            json=report_body,
        )
        second_json = self.client.post(
            f"{self.workspace_path}/correlation-report",
            headers=self._read_headers(self.tenant_a),
            json=report_body,
        )
        markdown = self.client.post(
            f"{self.workspace_path}/correlation-report",
            params={"format": "markdown"},
            headers=self._read_headers(self.tenant_a),
            json=report_body,
        )
        self.assertEqual(first_json.status_code, 200, first_json.text)
        self.assertEqual(second_json.status_code, 200, second_json.text)
        self.assertEqual(markdown.status_code, 200, markdown.text)
        self.assertEqual(first_json.content, second_json.content)
        self.assertEqual(first_json.headers["etag"], second_json.headers["etag"])
        self.assertEqual(markdown.headers["etag"], first_json.headers["etag"])
        document = first_json.json()
        self.assertEqual(
            document["schema_version"],
            CORRELATION_REPORT_SCHEMA_VERSION,
        )
        self.assertEqual(document["summary"]["annotation_count"], 1)
        self.assertEqual(document["summary"]["manual_correlation_count"], 1)
        self.assertEqual(document["summary"]["event_count"], 2)
        self.assertTrue(
            all(
                event["attributes"]["hold_down_ns"] == "fast"
                and event["attributes"]["opaque_counter_ns"] == 7
                for event in document["observations"]["events"]
            )
        )
        self.assertIn("Confirmed transition", markdown.text)
        self.assertIn("user.same-transition", markdown.text)

        tenant_isolated = self.client.get(
            annotation_path,
            headers=self._read_headers(self.tenant_b),
        )
        self.assertEqual(tenant_isolated.status_code, 404)
        deleted = self.client.delete(
            annotation_path,
            headers={
                **self._write_headers(self.tenant_a),
                "If-Match": '"2"',
            },
        )
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertEqual(deleted.headers["etag"], '"3"')
        hidden_tombstone = self.client.get(
            annotation_path,
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(hidden_tombstone.status_code, 404)
        visible_tombstone = self.client.get(
            annotation_path,
            params={"include_deleted": "true"},
            headers=self._read_headers(self.tenant_a),
        )
        self.assertEqual(visible_tombstone.status_code, 200)
        self.assertIsNotNone(visible_tombstone.json()["deleted_at_ns"])


if __name__ == "__main__":
    unittest.main()
