"""The documented parser demo can resolve browser subjects durably."""
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from rsl_demo_plugin import parser_plugin

from router_dump_analyzer.annotation_store import (
    ReviewAnnotationKind,
    ReviewSubject,
    ReviewSubjectKind,
)
from router_dump_analyzer.control_plane import ControlPlane
from router_dump_analyzer.ingestion_pipeline import (
    ImportState,
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
)
from router_dump_analyzer.runtime import (
    RuntimeApplicationRequest,
    create_runtime_application,
    require_plugin_runtime,
)

FIXTURE = Path(__file__).resolve().parents[1] / "demo/fixtures/minimal-status.jsonl"


class DemoDurableReviewTests(unittest.TestCase):
    def test_parser_browser_revision_resolves_to_durable_annotation_subject(self):
        with tempfile.TemporaryDirectory(prefix="rda-review-") as directory:
            control = ControlPlane(
                Path(directory), registry=PluginRegistry((parser_plugin,)),
                pipeline_limits=PipelineLimits(
                    max_workers=1, poll_interval_seconds=0.01,
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                ),
            )
            try:
                control.sessions.create_project("review", "Review", project_id="demo")
                control.sessions.create_workspace("review", "demo", "Example", workspace_id="example")
                control.start()
                scope = control.import_scope("review", "demo", "example")
                imported = control.ingestion.submit_bytes(
                    scope, FIXTURE.read_bytes(), original_name=FIXTURE.name,
                    idempotency_key="parser-example",
                )
                completed = control.ingestion.wait(scope, imported.import_id, timeout=30)
                self.assertIs(completed.state, ImportState.COMPLETED, completed)
                application = create_runtime_application(RuntimeApplicationRequest(
                    runtime=require_plugin_runtime(parser_plugin), input_path=FIXTURE,
                    serve_frontend=False,
                ))
                with TestClient(application) as client:
                    response = client.get("/v1/workspace")
                    self.assertEqual(response.status_code, 200, response.text)
                    workspace = response.json()
                runtime_revision = workspace["workspace"]["revision_id"]
                matches = control.sessions.list_revisions(
                    "review", "example", source_revision_id=runtime_revision,
                )
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0].revision_id, completed.revision_id)
                resource = workspace["resources"][0]
                resource_id = resource.get("id", resource.get("resource_id"))
                source_uid = workspace["source_records"][0]["source_record_uid"]
                for kind, identifier in (
                    (ReviewSubjectKind.RESOURCE, resource_id),
                    (ReviewSubjectKind.SOURCE_RECORD, source_uid),
                ):
                    annotation = control.create_annotation(
                        control.scope("review", "demo", "example"),
                        kind=ReviewAnnotationKind.NOTE,
                        subjects=(ReviewSubject(
                            completed.revision_id, kind, subject_id=identifier,
                        ),),
                        author="reviewer", body="A browser subject resolved to its durable revision.",
                    )
                    self.assertEqual(annotation.subjects[0].subject_id, identifier)
            finally:
                control.close(timeout=10)


if __name__ == "__main__":
    unittest.main()
