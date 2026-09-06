from __future__ import annotations

import hashlib
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from router_dump_analyzer.annotation_store import ReviewScope
from router_dump_analyzer.control_plane import ControlPlane, ControlPlaneLimits
from router_dump_analyzer.ingestion_pipeline import (
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
)
from router_dump_analyzer.management_analysis import (
    ManagementAnalysisRequestError,
    parse_management_analysis_query,
    query_management_analysis,
)
from router_dump_analyzer.web.control_plane_api import (
    CONTROL_PLANE_READ_ROLE,
    ControlPlaneIdentity,
    control_plane_router,
)
from tests.test_ingestion import ParseOnlyPlugin


def _dataset(label="visible-port"):
    return {
        "_ingestion": {
            "revision_id": "source-revision",
            "timeline_start_ns": "100",
            "timeline_end_ns": "200",
            "host_path": "C:/PRIVATE/store",
        },
        "kind_descriptors": [
            {
                "kind": "INTERFACE",
                "key_fields": ["ifindex"],
                "condition_field": "oper_status",
                "properties": [
                    {"name": "name", "client_visible": True},
                    {"name": "oper_status", "client_visible": True},
                    {"name": "secret", "sensitive": True},
                    {"name": "hidden", "client_visible": False},
                ],
            }
        ],
        "resources": [
            {
                "resource_id": "r1",
                "kind": "INTERFACE",
                "layer": "interface",
                "label": label,
                "key": {"ifindex": 7, "undeclared": "PRIVATE-KEY"},
                "state": {
                    "name": label,
                    "secret": "PRIVATE-SECRET",
                    "hidden": "PRIVATE-HIDDEN",
                    "undeclared": "PRIVATE-UNDECLARED",
                },
            }
        ],
        "lifecycle_intervals": [
            {"resource": "r1", "valid_from_ns": "100", "valid_to_ns": None}
        ],
        "state_intervals": [
            {
                "resource": "r1",
                "valid_from_ns": "100",
                "valid_to_ns": "200",
                "properties": {
                    "name": label,
                    "oper_status": "down",
                    "secret": "PRIVATE-SECRET",
                    "undeclared": "PRIVATE-UNDECLARED",
                },
                "status": "down",
                "status_class": "degraded",
                "quality": "exact",
            },
            {
                "resource": "r1",
                "valid_from_ns": "200",
                "valid_to_ns": None,
                "properties": {"name": label, "oper_status": "up"},
                "status": "up",
                "status_class": "healthy",
                "quality": "exact",
            },
        ],
        "events": [
            {
                "event_uid": "event-1",
                "event_type": "interface_down",
                "timestamp_ns": "100",
                "action": "modify",
                "outcome": "success",
                "attributes": {
                    "secret": "PRIVATE-SECRET",
                    "host_path": "C:/PRIVATE/event",
                },
                "evidence": {"locator": "C:/PRIVATE/dump"},
            },
            {
                "event_uid": "event-2",
                "event_type": "interface_up",
                "timestamp_ns": "200",
                "action": "modify",
                "outcome": "success",
            },
        ],
        "relationships": [],
        "relationship_intervals": [],
        "findings": [],
        "metadata": {"secret": "PRIVATE-METADATA"},
    }


class ManagementAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.control = ControlPlane(
            Path(self.temporary.name),
            registry=PluginRegistry((ParseOnlyPlugin(),)),
            pipeline_limits=PipelineLimits(
                max_upload_bytes=1024 * 1024,
                max_workers=1,
                plugin_execution_mode=PluginExecutionMode.INLINE,
            ),
            limits=ControlPlaneLimits(max_dataset_bytes=1024 * 1024),
        )
        self.addCleanup(self.control.close)
        self.datasets = {}
        for tenant in ("tenant-a", "tenant-b"):
            self.control.sessions.create_project(tenant, "Project", project_id="p")
            for workspace in ("w", "other"):
                self.control.sessions.create_workspace(
                    tenant, "p", workspace, workspace_id=workspace
                )
        self._publish("tenant-a", "w", "revision-a", "port-a")
        self._publish("tenant-a", "w", "revision-b", "port-b")
        self._publish("tenant-a", "other", "revision-other", "foreign-workspace")
        self._publish("tenant-b", "w", "revision-a", "tenant-b-port")
        self.application = FastAPI()
        self.application.include_router(control_plane_router)
        self.application.state.control_plane = self.control
        self.application.state.control_plane_identity_resolver = lambda request: (
            ControlPlaneIdentity(
                tenant_id=request.headers.get("X-Tenant-ID", "tenant-a"),
                principal_id="reader",
                roles=frozenset({CONTROL_PLANE_READ_ROLE}),
            )
        )
        self.runtime_sentinel = object()
        self.application.state.runtime_session = self.runtime_sentinel
        self.client = TestClient(self.application)
        self.addCleanup(self.client.close)
        self.path = "/v1/control-plane/projects/p/workspaces/w/analysis/query"

    def _publish(self, tenant, workspace, revision, label):
        fixture = "fixture-" + revision
        self.control.sessions.attach_fixture(
            tenant,
            workspace,
            fixture,
            label=label,
            content_digest=hashlib.sha256(fixture.encode()).hexdigest(),
        )
        self.control.sessions.publish_revision(
            tenant,
            workspace,
            fixture,
            revision,
            node_id="same-node",
            identity_digest=hashlib.sha256((tenant + revision).encode()).hexdigest(),
            metadata={"dataset_ref": "C:/PRIVATE/catalog"},
        )
        self.datasets[(tenant, revision)] = _dataset(label)

    def _load(self, scope, revision):
        return deepcopy(self.datasets[(scope.tenant_id, revision)])

    def _post(self, body=None, *, tenant="tenant-a", path=None):
        with patch.object(
            self.control, "load_revision_dataset", side_effect=self._load
        ):
            return self.client.post(
                path or self.path,
                headers={"X-Tenant-ID": tenant},
                json=body or {"selector": {"revision_ids": ["revision-a"]}},
            )

    def _session(self):
        session = self.control.sessions.create_session(
            "tenant-a", "w", "Comparison", session_id="s"
        )
        for index, revision in enumerate(("revision-a", "revision-b")):
            session = self.control.sessions.put_member(
                "tenant-a",
                "s",
                f"member-{index}",
                fixture_id="fixture-" + revision,
                revision_id=revision,
                expected_version=session.version,
                make_default=index == 1,
            )
        return session

    def test_read_only_identity_can_query_without_principal_and_never_switches_runtime(
        self,
    ):
        response = self._post()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        body = response.json()
        self.assertEqual(body["selected_member"]["revision_id"], "revision-a")
        self.assertFalse(body["capabilities"]["route"]["available"])
        self.assertFalse(body["capabilities"]["topology"]["available"])
        self.assertIs(self.application.state.runtime_session, self.runtime_sentinel)
        self.assertNotIn("PRIVATE", response.text)

    def test_missing_tenant_and_mismatched_principal_fail_closed(self):
        body = {"selector": {"revision_ids": ["revision-a"]}}
        self.assertIn(self.client.post(self.path, json=body).status_code, (401, 403))
        self.assertEqual(
            self.client.post(
                self.path,
                json=body,
                headers={"X-Tenant-ID": "tenant-a", "X-Principal-ID": "impostor"},
            ).status_code,
            403,
        )

    def test_tenant_and_workspace_isolation_precede_dataset_load(self):
        with patch.object(self.control, "load_revision_dataset") as loader:
            for selector in (
                {"revision_ids": ["revision-b"]},
                {"revision_ids": ["revision-other"]},
            ):
                response = self.client.post(
                    self.path,
                    headers={"X-Tenant-ID": "tenant-b"},
                    json={"selector": selector},
                )
                self.assertEqual(response.status_code, 404, response.text)
            loader.assert_not_called()
        foreign = self._post({"selector": {"revision_ids": ["revision-other"]}})
        self.assertEqual(foreign.status_code, 404, foreign.text)

    def test_same_node_session_members_and_snapshot_are_explicit(self):
        session = self._session()
        snapshot = self.control.sessions.snapshot_session(
            "tenant-a", "s", expected_version=session.version
        )
        body = {"selector": {"session_id": "s"}, "section": "resources"}
        response = self._post(body)
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(
            [member["node_id"] for member in payload["revision_vector"]],
            ["same-node", "same-node"],
        )
        self.assertEqual(payload["selected_member"]["member_id"], "member-1")
        self.assertEqual(payload["items"][0]["label"], "port-b")
        body["selected_member_id"] = "member-0"
        self.assertEqual(self._post(body).json()["items"][0]["label"], "port-a")
        snapshot_response = self._post(
            {"selector": {"snapshot_id": snapshot.snapshot_id}}
        )
        self.assertEqual(
            snapshot_response.json()["revision_vector"], payload["revision_vector"]
        )
        with patch.object(self.control, "load_revision_dataset") as loader:
            foreign = self.client.post(
                self.path, headers={"X-Tenant-ID": "tenant-b"}, json=body
            )
            self.assertEqual(foreign.status_code, 404)
            loader.assert_not_called()

    def test_continuation_detects_session_membership_change(self):
        session = self._session()
        initial = self._post({"selector": {"session_id": "s"}}).json()
        self.control.sessions.delete_member(
            "tenant-a", "s", "member-1", expected_version=session.version
        )
        response = self._post(
            {
                "selector": {"session_id": "s"},
                "expected_revision_vector_digest": initial["selection"][
                    "revision_vector_digest"
                ],
            }
        )
        self.assertEqual(response.status_code, 409, response.text)

    def test_continuation_detects_default_member_change(self):
        session = self._session()
        initial = self._post({"selector": {"session_id": "s"}}).json()
        self.control.sessions.put_member(
            "tenant-a",
            "s",
            "member-0",
            fixture_id="fixture-revision-a",
            revision_id="revision-a",
            expected_version=session.version,
            make_default=True,
        )
        response = self._post(
            {
                "selector": {"session_id": "s"},
                "expected_revision_vector_digest": initial["selection"][
                    "revision_vector_digest"
                ],
            }
        )
        self.assertEqual(response.status_code, 409, response.text)

    def test_resource_observation_time_and_schema_redaction(self):
        body = {
            "selector": {"revision_ids": ["revision-a"]},
            "section": "resources",
            "time_ns": "150",
        }
        response = self._post(body)
        self.assertEqual(response.status_code, 200, response.text)
        row = response.json()["items"][0]
        self.assertEqual(row["state"]["oper_status"], "down")
        self.assertNotIn("PRIVATE", response.text)
        body["time_ns"] = "200"
        self.assertEqual(
            self._post(body).json()["items"][0]["state"]["oper_status"], "up"
        )
        body["time_ns"] = "0"
        self.assertFalse(self._post(body).json()["items"][0]["exists"])

    def test_events_page_range_search_and_hidden_fields(self):
        body = {
            "selector": {"revision_ids": ["revision-a"]},
            "section": "events",
            "limit": 1,
        }
        first = self._post(body)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["total_count"], 2)
        self.assertEqual(first.json()["next_offset"], 1)
        self.assertNotIn("PRIVATE", first.text)
        body["offset"] = 1
        self.assertEqual(self._post(body).json()["items"][0]["event_uid"], "event-2")
        body.update(offset=0, start_ns="150", end_ns="250")
        self.assertEqual(self._post(body).json()["total_count"], 1)
        body["search"] = "PRIVATE"
        self.assertEqual(self._post(body).json()["total_count"], 0)
        body["search"] = "interface_up"
        self.assertEqual(self._post(body).json()["total_count"], 1)

    def test_core_nanoseconds_remain_exact_strings(self):
        timestamp = 2**53 + 7
        data = self.datasets[("tenant-a", "revision-a")]
        data["state_intervals"][-1]["valid_from_ns"] = timestamp
        data["_ingestion"]["timeline_end_ns"] = str(timestamp)
        response = self._post(
            {"selector": {"revision_ids": ["revision-a"]}, "section": "resources"}
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["items"][0]["valid_from_ns"], str(timestamp))
        self.assertEqual(response.json()["time_ns"], str(timestamp))

    def test_relationships_reuse_exact_lifecycle_and_interval_rules(self):
        data = self.datasets[("tenant-a", "revision-a")]
        data["resources"].append(
            {
                "resource_id": "r2",
                "kind": "INTERFACE",
                "layer": "interface",
                "label": "peer",
            }
        )
        data["lifecycle_intervals"].append(
            {"resource": "r2", "valid_from_ns": "100", "valid_to_ns": None}
        )
        data["relationship_intervals"] = [
            {
                "source": "r1",
                "target": "r2",
                "relation_type": "peer",
                "valid_from_ns": "150",
                "valid_to_ns": "200",
                "attributes": {"secret": "PRIVATE-RELATIONSHIP"},
                "evidence": {"locator": "C:/PRIVATE/relationship"},
            }
        ]
        body = {
            "selector": {"revision_ids": ["revision-a"]},
            "section": "relationships",
            "time_ns": "175",
        }
        response = self._post(body)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["items"][0]["type"], "peer")
        self.assertNotIn("PRIVATE", response.text)
        body["time_ns"] = "200"
        self.assertEqual(self._post(body).json()["total_count"], 0)

    def test_relationship_presence_is_preserved_and_absent_edges_are_excluded(self):
        data = self.datasets[("tenant-a", "revision-a")]
        second = deepcopy(data["resources"][0])
        second["resource_id"] = "r2"
        data["resources"].append(second)
        data["lifecycle_intervals"].append(
            {"resource": "r2", "valid_from_ns": "100", "valid_to_ns": None}
        )
        for relation_type, present in (
            ("unknown-peer", None),
            ("confirmed-peer", True),
            ("absent-peer", False),
            ("legacy-peer", True),
        ):
            interval = {
                "source": "r1",
                "target": "r2",
                "relation_type": relation_type,
                "present": present,
                "valid_from_ns": "100",
                "valid_to_ns": None,
                "quality": "exact",
                "evidence": {"locator": "C:/PRIVATE/relationship"},
            }
            if relation_type == "legacy-peer":
                del interval["present"]
            data["relationship_intervals"].append(interval)
        response = self._post(
            {"selector": {"revision_ids": ["revision-a"]}, "section": "relationships"}
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["total_count"], 3)
        self.assertEqual(
            {row["type"]: row["present"] for row in response.json()["items"]},
            {"unknown-peer": None, "confirmed-peer": True, "legacy-peer": True},
        )
        self.assertNotIn("PRIVATE", response.text)

    def test_findings_use_existing_allowlisted_projection(self):
        self.datasets[("tenant-a", "revision-a")]["findings"] = [
            {
                "rule_id": "test-rule",
                "summary": "Visible finding",
                "severity": "warning",
                "details": {"secret": "PRIVATE-SECRET", "public": "visible"},
                "evidence": [
                    {"artifact_id": "artifact", "locator": "C:/PRIVATE/finding"}
                ],
                "arbitrary": {"path": "C:/PRIVATE/unknown"},
            }
        ]
        response = self._post(
            {"selector": {"revision_ids": ["revision-a"]}, "section": "findings"}
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["items"][0]["summary"], "Visible finding")
        self.assertNotIn("PRIVATE", response.text)

    def test_invalid_query_bounds_are_rejected_before_loading(self):
        invalid = (
            {},
            {"selector": {}},
            {"selector": {"revision_ids": []}},
            {"selector": {"revision_ids": ["revision-a", "revision-a"]}},
            {"selector": {"revision_ids": ["revision-a"], "session_id": "s"}},
        )
        for body in invalid:
            with (
                self.subTest(body=body),
                self.assertRaises(ManagementAnalysisRequestError),
            ):
                parse_management_analysis_query(body)
        base = {"selector": {"revision_ids": ["revision-a"]}}
        for changes in (
            {"limit": 501},
            {"offset": -1},
            {"offset": 2**53},
            {"time_ns": "01"},
            {"search": "x" * 257},
            {"section": "route"},
            {"start_ns": "1"},
            {"arbitrary": True},
            {"selected_member_id": "missing"},
        ):
            response = self._post({**base, **changes})
            self.assertEqual(response.status_code, 422, (changes, response.text))

    def test_million_event_page_only_projects_returned_rows(self):
        data = self.datasets[("tenant-a", "revision-a")]
        # Shared immutable row input keeps this scale regression lightweight;
        # ingestion integrity separately verifies actual unique event identities.
        data["events"] = [data["events"][0]] * 1_250_000
        import router_dump_analyzer.management_analysis as implementation

        with patch.object(
            implementation,
            "redact_event_for_client",
            wraps=implementation.redact_event_for_client,
        ) as project:
            response = self._post(
                {
                    "selector": {"revision_ids": ["revision-a"]},
                    "section": "events",
                    "offset": 1_249_998,
                    "limit": 2,
                }
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["total_count"], 1_250_000)
        self.assertEqual(response.json()["count"], 2)
        self.assertIsNone(response.json()["next_offset"])
        self.assertEqual(project.call_count, 2)

    def test_concurrent_scopes_do_not_share_selection(self):
        query = parse_management_analysis_query(
            {"selector": {"revision_ids": ["revision-a"]}, "section": "resources"}
        )
        with (
            patch.object(self.control, "load_revision_dataset", side_effect=self._load),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            futures = [
                executor.submit(
                    query_management_analysis,
                    self.control,
                    ReviewScope(tenant, "p", "w"),
                    query,
                )
                for tenant in ("tenant-a", "tenant-b")
            ]
            results = [future.result(timeout=10) for future in futures]
        self.assertEqual(
            [result["items"][0]["label"] for result in results],
            ["port-a", "tenant-b-port"],
        )

    def test_integrity_errors_do_not_expose_catalog_dataset_path(self):
        response = self.client.post(
            self.path,
            headers={"X-Tenant-ID": "tenant-a"},
            json={"selector": {"revision_ids": ["revision-a"]}},
        )
        self.assertEqual(response.status_code, 500, response.text)
        self.assertNotIn("PRIVATE", response.text)

    def test_large_returned_row_fails_with_bounded_public_error(self):
        data = self.datasets[("tenant-a", "revision-a")]
        data["state_intervals"][-1]["properties"]["name"] = "x" * (1024 * 1024 + 1)
        response = self._post(
            {"selector": {"revision_ids": ["revision-a"]}, "section": "resources"}
        )
        self.assertEqual(response.status_code, 422, response.text[:500])
        self.assertLess(len(response.content), 1024)

    def test_real_ingested_dataset_uses_verified_observation_state(self):
        self.control.start()
        scope = self.control.import_scope("tenant-a", "p", "w")
        content = (
            b'{"captured_at_ns":100,"ifindex":7,"name":"eth0","oper_status":"down"}\n'
        )
        admitted = self.control.ingestion.submit_bytes(
            scope, content, original_name="status.jsonl"
        )
        completed = self.control.ingestion.wait(scope, admitted.import_id, timeout=15)
        self.assertEqual(completed.state.value, "completed", completed.error_message)
        response = self.client.post(
            self.path,
            headers={"X-Tenant-ID": "tenant-a"},
            json={
                "selector": {"revision_ids": [completed.revision_id]},
                "section": "resources",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["items"][0]["state"]["oper_status"], "down")


if __name__ == "__main__":
    unittest.main()
