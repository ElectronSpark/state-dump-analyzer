from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rsl_demo_generator.workbench import workflow_inputs, write_workflow_inputs
from rsl_demo_plugin.deployment import build_plugin_deployment
from rsl_demo_plugin.offline_analysis import build_offline_analysis_deployment

from router_dump_analyzer.control_plane import ControlPlane, ControlPlaneLimits
from router_dump_analyzer.ingestion_pipeline import (
    ImportState,
    PipelineLimits,
    PluginExecutionMode,
)
from router_dump_analyzer.plugin_composition_deployment import (
    PluginCompositionDeploymentContext,
)
from router_dump_analyzer.private_analysis import (
    EvidenceScope,
    PrivateAnalysisClockMode,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisLimits,
    PrivateAnalysisTaskKind,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
)
from router_dump_analyzer.private_analysis_deployment import (
    PrivateAnalysisDeploymentContext,
)
from router_dump_analyzer.private_analysis_run_store import PrivateAnalysisRunState
from router_dump_analyzer.private_analysis_service import PrivateAnalysisRequestSpec


class DemoWorkbenchTests(unittest.TestCase):
    def test_generator_is_deterministic_and_refuses_conflicts_before_writing(self):
        self.assertEqual(workflow_inputs(), workflow_inputs())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = write_workflow_inputs(root)
            self.assertEqual(first, write_workflow_inputs(root))
            (root / "after/minimal-status.jsonl").write_bytes(b"user-edited")
            (root / "before/minimal-status.jsonl").unlink()
            with self.assertRaises(ValueError):
                write_workflow_inputs(root)
            self.assertFalse((root / "before/minimal-status.jsonl").exists())
            self.assertEqual(
                (root / "after/minimal-status.jsonl").read_bytes(), b"user-edited"
            )

    def test_generator_rejects_intermediate_file_before_creating_any_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "after").write_text("unrelated file", encoding="utf-8")
            with self.assertRaises(ValueError):
                write_workflow_inputs(root)
            self.assertEqual({item.name for item in root.iterdir()}, {"after"})

    def test_generated_revisions_project_findings_and_offline_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plugins = build_plugin_deployment(PluginCompositionDeploymentContext(root))
            private = build_offline_analysis_deployment(
                PrivateAnalysisDeploymentContext(root)
            )
            self.assertFalse(
                private.registrations[
                    0
                ].core_revision_evidence_policy.full_fidelity_workspace_data
            )
            control = ControlPlane(
                root,
                registry=plugins.primary_registry,
                capability_providers=plugins.capability_providers,
                plugin_composition_policy=plugins.policy,
                private_analysis_runners=private.registrations,
                pipeline_limits=PipelineLimits(
                    max_workers=1,
                    poll_interval_seconds=0.01,
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                ),
                limits=ControlPlaneLimits(
                    max_dataset_bytes=1024 * 1024, dataset_cache_entries=3
                ),
            )
            try:
                control.sessions.create_project(
                    "workbench", "Workbench", project_id="coverage"
                )
                control.sessions.create_workspace(
                    "workbench", "coverage", "Workflow", workspace_id="workflow"
                )
                scope = control.import_scope("workbench", "coverage", "workflow")
                control.start()
                revisions = []
                for name, expected in (
                    ("before", "fail"),
                    ("after", "pass"),
                    ("peer", "fail"),
                ):
                    imported = control.ingestion.submit_bytes(
                        scope,
                        workflow_inputs()[f"{name}/minimal-status.jsonl"],
                        original_name="minimal-status.jsonl",
                        idempotency_key=name,
                        node_hint="workbench-peer"
                        if name == "peer"
                        else "workbench-router",
                    )
                    completed = control.ingestion.wait(
                        scope, imported.import_id, timeout=30
                    )
                    self.assertIs(completed.state, ImportState.COMPLETED, completed)
                    revisions.append(completed.revision_id)
                    dataset = control.load_revision_dataset(
                        control.scope("workbench", "coverage", "workflow"),
                        completed.revision_id,
                    )
                    self.assertEqual(len(dataset["resources"]), 3)
                    declarations = dataset["relationship_declarations"]
                    self.assertEqual(len(declarations), 1)
                    self.assertEqual(declarations[0]["relation_type"], "corresponds_to")
                    self.assertEqual(dataset["findings"][0]["result"], expected)

                control.sessions.set_workspace_disclosure_policy(
                    "workbench",
                    "workflow",
                    WorkspaceDisclosurePolicy(
                        PrivateAnalysisDisclosureMode.CLIENT_SAFE,
                        (PrivateAnalysisTransport.IN_PROCESS,),
                    ),
                    actor_id="local-user",
                    expected_version=0,
                )
                evidence_scope = EvidenceScope("workbench", "coverage", "workflow")
                created = control.private_analysis.create(
                    PrivateAnalysisRequestSpec(
                        scope=evidence_scope,
                        revision_ids=tuple(sorted(revisions)),
                        runner_id="demo.scripted-evidence-walk",
                        runner_version="1.0.0",
                        task_kind=PrivateAnalysisTaskKind.GENERAL_EVIDENCE_REVIEW,
                        query="Demonstrate a retained evidence source and provider citation.",
                        clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
                        selected_time_ns=None,
                        limits=PrivateAnalysisLimits(
                            max_tool_calls=8, deadline_ms=30000
                        ),
                    ),
                    actor_id="local-user",
                    idempotency_key="walk",
                )
                executed = control.private_analysis.execute(
                    evidence_scope,
                    created.run_id,
                    expected_version=created.version,
                    actor_id="local-user",
                )
                self.assertIs(
                    executed.state, PrivateAnalysisRunState.COMPLETED, executed
                )
                report = control.private_analysis.get_report(
                    evidence_scope, created.run_id
                )
                self.assertIn("not a model", report.outcome.result.summary.text)
                self.assertEqual(len(report.outcome.result.summary.citations), 2)
                self.assertFalse(report.outcome.result.proposals)
                self.assertTrue(
                    any(
                        ref.producer.plugin_instance_id
                        == "demo.example-router.evidence-analysis"
                        for ref in report.evidence_references
                    )
                )
            finally:
                control.close(timeout=5)


if __name__ == "__main__":
    unittest.main()
