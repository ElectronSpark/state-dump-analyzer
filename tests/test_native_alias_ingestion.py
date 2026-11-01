from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from router_dump_analyzer.control_plane import ControlPlane
from router_dump_analyzer.ingestion import IngestionCoordinator, IngestionLimits
from router_dump_analyzer.ingestion_pipeline import (
    ImportState,
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
)
from router_dump_analyzer.plugin_execution_plan import PluginExecutionPlanAuthority
from tests.fixtures.native_alias_plugin import NativeAliasPlugin


class NativeAliasIngestionTests(unittest.TestCase):
    @staticmethod
    def _registry(maximum):
        registry = PluginRegistry()
        registry.register(
            NativeAliasPlugin(),
            coordinator=IngestionCoordinator(
                limits=IngestionLimits(max_output_value_units=maximum),
            ),
        )
        return registry

    @staticmethod
    def _limits():
        return PipelineLimits(
            max_upload_bytes=1024 * 1024,
            max_workers=1,
            max_attempts=1,
            lease_seconds=120,
            poll_interval_seconds=0.01,
            plugin_execution_mode=PluginExecutionMode.PROCESS,
            publisher_execution_mode=PluginExecutionMode.PROCESS,
            plugin_execution_timeout_seconds=60,
        )

    @staticmethod
    def _payload():
        return json.dumps(
            {
                "captured_at_ns": 100,
                "samples": [
                    {"time": i, "received": i * 2, "sent": i * 3} for i in range(1_023)
                ],
            },
            separators=(",", ":"),
        ).encode("utf-8")

    def _submit(self, control, raw):
        control.sessions.create_project(
            "alias-tenant", "Alias project", project_id="alias-project"
        )
        control.sessions.create_workspace(
            "alias-tenant",
            "alias-project",
            "Alias workspace",
            workspace_id="alias-workspace",
        )
        scope = control.import_scope("alias-tenant", "alias-project", "alias-workspace")
        control.start()
        admitted = control.ingestion.submit_bytes(
            scope,
            raw,
            original_name="counters.json",
            node_hint="sample-node",
        )
        completed = control.ingestion.wait(scope, admitted.import_id, timeout=120)
        with control.ingestion._connect() as connection:
            failures = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM ingestion_failure_diagnostics WHERE import_id = ? ORDER BY attempt_number",
                    (completed.import_id,),
                )
            ]
        return completed, failures

    def test_json_aliases_and_configured_output_budget_publish_through_processes(self):
        raw = self._payload()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with ControlPlane(
                root, registry=self._registry(16_384), pipeline_limits=self._limits()
            ) as control:
                completed, failures = self._submit(control, raw)
                self.assertEqual(completed.state, ImportState.COMPLETED, failures)
                self.assertEqual(failures, [])
                self.assertIsNone(completed.error_code)
                revisions = control.sessions.list_revisions(
                    "alias-tenant", "alias-workspace"
                )
                self.assertEqual(len(revisions), 1)
                revision = revisions[0]
                self.assertEqual(revision.revision_id, completed.revision_id)
                self.assertEqual(
                    revision.execution_plan.execution_plan_authority,
                    PluginExecutionPlanAuthority.PROCESS,
                )
                review_scope = control.scope(
                    "alias-tenant", "alias-project", "alias-workspace"
                )
                dataset = control.load_revision_dataset(
                    review_scope, revision.revision_id
                )
                self.assertEqual(
                    dataset["resources"][0]["state"]["samples"],
                    json.loads(raw)["samples"],
                )
                source = dataset["source_records"][0]
                self.assertEqual(json.loads(source["copy_text"]), json.loads(raw))
                self.assertEqual(source["attributes"]["sample_count"], 1_023)
                self.assertNotEqual(source["attributes"]["parser_pid"], os.getpid())
                self.assertEqual(
                    source["evidence"][0]["excerpt_sha256"],
                    hashlib.sha256(raw).hexdigest(),
                )
                self.assertEqual(dataset["diagnostics"][0]["code"], "JSON_ROUNDTRIP")
                self.assertEqual(
                    dataset["diagnostics"][0]["details"]["sample_count"], 1_023
                )
                dataset_path = (
                    control.ingestion.dataset_root / revision.metadata["dataset_ref"]
                )
                self.assertTrue(dataset_path.is_file())
                self.assertEqual(tuple(control.ingestion.spool_root.iterdir()), ())
            # Read the actual catalog and retained bytes in a new control-plane instance.
            with ControlPlane(
                root, registry=self._registry(16_384), pipeline_limits=self._limits()
            ) as reopened:
                scope = reopened.scope(
                    "alias-tenant", "alias-project", "alias-workspace"
                )
                self.assertEqual(
                    reopened.load_revision_dataset(scope, revision.revision_id), dataset
                )

    def test_default_budget_rejects_large_json_output_without_publication(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            ControlPlane(
                Path(directory),
                registry=self._registry(4_096),
                pipeline_limits=self._limits(),
            ) as control,
        ):
            completed, failures = self._submit(control, self._payload())
            self.assertEqual(completed.state, ImportState.FAILED, failures)
            self.assertIsNone(completed.revision_id)
            self.assertEqual(
                control.sessions.list_revisions("alias-tenant", "alias-workspace"),
                (),
            )
            self.assertIn("maximum value unit count", json.dumps(failures))
            self.assertEqual(tuple(control.ingestion.dataset_root.rglob("*.json")), ())
            self.assertEqual(tuple(control.ingestion.spool_root.iterdir()), ())


if __name__ == "__main__":
    unittest.main()
