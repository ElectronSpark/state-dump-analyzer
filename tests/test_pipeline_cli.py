from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer.control_plane import ControlPlane
from router_dump_analyzer.ingestion_pipeline import (
    ImportState,
    IngestionStateRootPathError,
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
)
from router_dump_analyzer.pipeline_cli import (
    HeadlessIngestionConfiguration,
    _effective_content_type,
    _encode_document,
    _idempotency_key,
    _public_cli_error,
    main,
    parse_args,
    run,
)
from tests.test_ingestion import ParseOnlyPlugin

PRIVATE_CLI_FAILURE_MARKER = "PRIVATE-CLI-FAILURE-b59f21"


class _SecretParsePlugin(ParseOnlyPlugin):
    def parse_status(self, reader, spec):
        del reader, spec
        raise RuntimeError(PRIVATE_CLI_FAILURE_MARKER)


def _fixture(index: int) -> bytes:
    return (
        json.dumps(
            {
                "captured_at_ns": 100 + index,
                "ifindex": index + 1,
                "name": f"xe-0/0/{index}",
                "oper_status": "up",
            }
        )
        + "\n"
    ).encode()


class PipelineCliTests(unittest.TestCase):
    @staticmethod
    def _limits() -> PipelineLimits:
        return PipelineLimits(
            max_upload_bytes=1024 * 1024,
            max_workers=1,
            lease_seconds=30,
            poll_interval_seconds=0.01,
            plugin_execution_mode=PluginExecutionMode.INLINE,
        )

    def test_parser_accepts_repeatable_multi_fixture_input(self) -> None:
        parsed = parse_args(
            [
                "--plugin-module",
                "demo.plugin",
                "--state-dir",
                "state",
                "--tenant",
                "tenant-a",
                "--project",
                "project-a",
                "--workspace",
                "workspace-a",
                "--input",
                "one.jsonl",
                "--input",
                "two.jsonl",
                "--timeout",
                "10",
                "--node-hint",
                "router-a",
                "--metadata-json",
                '{"site":"lab-a"}',
                "--pretty",
                "--retention-policy",
                "retention.json",
            ]
        )
        self.assertEqual(
            parsed.input_paths,
            (Path("one.jsonl"), Path("two.jsonl")),
        )
        self.assertEqual(parsed.plugin_modules, ("demo.plugin",))
        self.assertEqual(parsed.node_hint, "router-a")
        self.assertEqual(parsed.metadata, {"site": "lab-a"})
        self.assertTrue(parsed.pretty)
        self.assertEqual(parsed.retention_policy_path, Path("retention.json"))

    def test_pre_import_failure_does_not_print_raw_exception_text(self) -> None:
        stderr = io.StringIO()
        with (
            patch(
                "router_dump_analyzer.pipeline_cli.parse_args",
                return_value=object(),
            ),
            patch(
                "router_dump_analyzer.pipeline_cli.run",
                side_effect=RuntimeError(PRIVATE_CLI_FAILURE_MARKER),
            ),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as raised,
        ):
            main([])

        self.assertEqual(raised.exception.code, 1)
        self.assertNotIn(PRIVATE_CLI_FAILURE_MARKER, stderr.getvalue())
        self.assertIn("the ingestion command failed", stderr.getvalue())

    def test_state_root_preflight_detail_is_safe_and_actionable(self) -> None:
        detail = (
            "durable state directory is too long for ingestion on Windows: "
            "resolved length 132 UTF-16 code units exceeds the supported "
            "maximum of 131; core-owned staging paths reserve 128 units "
            "within the 259-unit path budget; choose a shorter --state-dir"
        )
        self.assertEqual(
            _public_cli_error(IngestionStateRootPathError(detail)),
            detail,
        )

    def test_result_encoding_is_safe_for_legacy_windows_stdout(self) -> None:
        encoded = _encode_document(
            {"input_path": r"C:\Users\reviewer\文档\dump.tgz"},
            pretty=True,
        )
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
        stream.write(encoded)
        stream.flush()
        self.assertEqual(
            json.loads(raw.getvalue().decode("cp1252"))["input_path"],
            r"C:\Users\reviewer\文档\dump.tgz",
        )

    def test_headless_idempotency_uses_effective_mime_and_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            path.write_bytes(_fixture(0))
            configuration = HeadlessIngestionConfiguration(
                state_dir=Path(directory) / "state",
                tenant_id="tenant-a",
                project_id="project-a",
                workspace_id="workspace-a",
                project_label="Project A",
                workspace_label="Workspace A",
                plugin_names=(),
                plugin_modules=("test.plugin",),
                input_paths=(path,),
                timeout_seconds=10,
                auto_select=True,
                preferred_plugin_id=None,
                content_type=None,
                node_hint="router-a",
                metadata={"site": "lab-a"},
                output_path=None,
                pretty=False,
            )
            effective_content_type = _effective_content_type(
                configuration,
                path,
            )
            first = _idempotency_key(
                configuration,
                path,
                "a" * 64,
                effective_content_type=effective_content_type,
                registry_fingerprint="sha256:" + ("1" * 64),
            )
            changed_mime = _idempotency_key(
                configuration,
                path,
                "a" * 64,
                effective_content_type="application/octet-stream",
                registry_fingerprint="sha256:" + ("1" * 64),
            )
            changed_registry = _idempotency_key(
                configuration,
                path,
                "a" * 64,
                effective_content_type=effective_content_type,
                registry_fingerprint="sha256:" + ("2" * 64),
            )

            self.assertEqual(effective_content_type, "application/json")
            self.assertNotEqual(first, changed_mime)
            self.assertNotEqual(first, changed_registry)

    def test_headless_run_ingests_all_inputs_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_paths = (
                root / "one" / "status.jsonl",
                root / "two" / "status.jsonl",
            )
            for index, path in enumerate(input_paths):
                path.parent.mkdir()
                path.write_bytes(_fixture(index))
            output = root / "result" / "imports.json"
            configuration = HeadlessIngestionConfiguration(
                state_dir=root / "state",
                tenant_id="tenant-a",
                project_id="project-a",
                workspace_id="workspace-a",
                project_label="Project A",
                workspace_label="Workspace A",
                plugin_names=(),
                plugin_modules=("test.plugin",),
                input_paths=input_paths,
                timeout_seconds=10,
                auto_select=True,
                preferred_plugin_id=None,
                content_type=None,
                node_hint="router-a",
                metadata={"site": "lab-a"},
                output_path=output,
                pretty=False,
            )
            first_output = io.StringIO()
            first_code = run(
                configuration,
                module_loader=lambda target: (
                    ParseOnlyPlugin()
                    if target == "test.plugin"
                    else self.fail(target)
                ),
                entry_point_loader=lambda name: self.fail(name),
                stdout=first_output,
                pipeline_limits=self._limits(),
            )
            first = json.loads(first_output.getvalue())
            self.assertEqual(first_code, 0)
            self.assertEqual(first["summary"]["completed_count"], 2)
            self.assertEqual(len(first["imports"]), 2)
            self.assertTrue(
                all(
                    item["revision_id"].startswith("revision-")
                    for item in first["imports"]
                )
            )
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                first,
            )

            second_output = io.StringIO()
            second_code = run(
                configuration,
                module_loader=lambda target: ParseOnlyPlugin(),
                entry_point_loader=lambda name: self.fail(name),
                stdout=second_output,
                pipeline_limits=self._limits(),
            )
            second = json.loads(second_output.getvalue())
            self.assertEqual(second_code, 0)
            self.assertEqual(
                [item["import_id"] for item in second["imports"]],
                [item["import_id"] for item in first["imports"]],
            )

            with ControlPlane(
                root / "state",
                registry=PluginRegistry((ParseOnlyPlugin(),)),
                pipeline_limits=self._limits(),
            ) as control_plane:
                scope = control_plane.import_scope(
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                )
                imports = control_plane.ingestion.list_imports(scope)
                self.assertEqual(len(imports), 2)
                revisions = control_plane.sessions.list_revisions(
                    "tenant-a",
                    "workspace-a",
                )
                self.assertEqual(len(revisions), 2)

    def test_headless_run_reports_selection_required_with_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "status.jsonl"
            input_path.write_bytes(_fixture(0))
            configuration = HeadlessIngestionConfiguration(
                state_dir=root / "state",
                tenant_id="tenant-a",
                project_id="project-a",
                workspace_id="workspace-a",
                project_label="Project A",
                workspace_label="Workspace A",
                plugin_names=(),
                plugin_modules=("test.plugin",),
                input_paths=(input_path,),
                timeout_seconds=10,
                auto_select=False,
                preferred_plugin_id=None,
                content_type=None,
                node_hint=None,
                metadata={},
                output_path=None,
                pretty=False,
            )
            stdout = io.StringIO()
            exit_code = run(
                configuration,
                module_loader=lambda target: ParseOnlyPlugin(),
                entry_point_loader=lambda name: self.fail(name),
                stdout=stdout,
                pipeline_limits=self._limits(),
            )
            document = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 2)
            self.assertEqual(
                document["imports"][0]["state"],
                ImportState.AWAITING_SELECTION.value,
            )
            self.assertEqual(
                len(document["imports"][0]["plugin_candidates"]),
                1,
            )

    def test_headless_failure_output_never_contains_private_diagnostics(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "status.jsonl"
            input_path.write_bytes(_fixture(0))
            configuration = HeadlessIngestionConfiguration(
                state_dir=root / "state",
                tenant_id="tenant-a",
                project_id="project-a",
                workspace_id="workspace-a",
                project_label="Project A",
                workspace_label="Workspace A",
                plugin_names=(),
                plugin_modules=("secret.plugin",),
                input_paths=(input_path,),
                timeout_seconds=10,
                auto_select=True,
                preferred_plugin_id=None,
                content_type=None,
                node_hint="router-a",
                metadata={},
                output_path=None,
                pretty=False,
            )
            stdout = io.StringIO()
            exit_code = run(
                configuration,
                module_loader=lambda _target: _SecretParsePlugin(),
                entry_point_loader=lambda name: self.fail(name),
                stdout=stdout,
                pipeline_limits=self._limits(),
            )
            output = stdout.getvalue()
            document = json.loads(output)
            self.assertEqual(exit_code, 1)
            self.assertEqual(document["summary"]["failed_count"], 1)
            self.assertNotIn(PRIVATE_CLI_FAILURE_MARKER, output)
            self.assertEqual(
                document["imports"][0]["error"]["code"],
                "plugin_execution_failed",
            )

            database_path = configuration.state_dir / "control-plane.sqlite3"
            with closing(sqlite3.connect(database_path)) as connection:
                diagnostic = connection.execute(
                    """
                    SELECT exception_message
                    FROM ingestion_failure_diagnostics
                    ORDER BY diagnostic_id DESC LIMIT 1
                    """
                ).fetchone()
            self.assertIsNotNone(diagnostic)
            assert diagnostic is not None
            self.assertIn(PRIVATE_CLI_FAILURE_MARKER, diagnostic[0])

    def test_headless_run_rejects_manifest_only_plugin_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "status.jsonl"
            input_path.write_bytes(_fixture(0))
            configuration = HeadlessIngestionConfiguration(
                state_dir=root / "state",
                tenant_id="tenant-a",
                project_id="project-a",
                workspace_id="workspace-a",
                project_label="Project A",
                workspace_label="Workspace A",
                plugin_names=(),
                plugin_modules=("test.plugin",),
                input_paths=(input_path,),
                timeout_seconds=10,
                auto_select=True,
                preferred_plugin_id=None,
                content_type=None,
                node_hint=None,
                metadata={},
                output_path=None,
                pretty=False,
            )
            uninspectable_type = type(
                "_UninspectablePlugin",
                (ParseOnlyPlugin,),
                {"__module__": "missing_pipeline_plugin_identity_test"},
            )

            with self.assertRaisesRegex(
                ValueError,
                "no bounded executable package identity",
            ):
                run(
                    configuration,
                    module_loader=lambda target: uninspectable_type(),
                    entry_point_loader=lambda name: self.fail(name),
                    stdout=io.StringIO(),
                    pipeline_limits=self._limits(),
                )
            self.assertFalse(configuration.state_dir.exists())

    def test_durable_control_plane_rejects_local_manifest_fallback(self) -> None:
        uninspectable_type = type(
            "_UninspectablePlugin",
            (ParseOnlyPlugin,),
            {"__module__": "missing_control_plane_plugin_identity_test"},
        )
        registry = PluginRegistry(
            (uninspectable_type(),),
            allow_manifest_identity=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory) / "state"
            with self.assertRaisesRegex(
                ValueError,
                "durable ingestion requires executable plug-in identities",
            ):
                ControlPlane(state_dir, registry=registry)
            self.assertFalse(state_dir.exists())

    def test_control_plane_defaults_to_process_isolated_plugins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            control_plane = ControlPlane(
                Path(directory) / "state",
                registry=PluginRegistry((ParseOnlyPlugin(),)),
            )
            try:
                self.assertIs(
                    control_plane.ingestion.limits.plugin_execution_mode,
                    PluginExecutionMode.PROCESS,
                )
                self.assertGreater(
                    control_plane.ingestion.limits
                    .plugin_execution_timeout_seconds,
                    0,
                )
            finally:
                control_plane.close()


if __name__ == "__main__":
    unittest.main()
