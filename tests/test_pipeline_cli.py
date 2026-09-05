from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from typing import Self
from unittest.mock import patch

from router_dump_analyzer.capability_router import CapabilityProviderRegistry
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
from router_dump_analyzer.plugin_composition import (
    PluginCompositionPolicy,
    PluginCompositionRule,
    PluginParticipationSelection,
)
from router_dump_analyzer.plugin_identity import PluginExecutableIdentityError
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

    def test_parser_accepts_exact_plugin_composition_deployment(self) -> None:
        parsed = parse_args(
            [
                "--plugin-deployment-module",
                "deployment.plugins:build",
                "--state-dir",
                "state",
                "--tenant",
                "tenant-a",
                "--project",
                "project-a",
                "--workspace",
                "workspace-a",
                "--input",
                "fixture.tgz",
            ]
        )
        self.assertEqual(parsed.plugin_names, ())
        self.assertEqual(parsed.plugin_modules, ())
        self.assertEqual(
            parsed.plugin_deployment_module,
            "deployment.plugins:build",
        )

    def test_plugin_composition_deployment_reaches_headless_control_plane(
        self,
    ) -> None:
        registry = object()
        providers = object()
        policy = object()
        deployment = SimpleNamespace(
            primary_registry=registry,
            capability_providers=providers,
            policy=policy,
            deployment_digest="sha256:" + "a" * 64,
            allow_inline_only=True,
            requires_inline_execution=True,
        )
        captured: dict[str, object] = {}

        class EmptyControlPlane:
            def __init__(self, root: Path, **values: object) -> None:
                captured["root"] = root
                captured.update(values)

            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_values: object) -> None:
                return None

            def import_scope(self, *_values: str) -> object:
                return object()

        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            configuration = HeadlessIngestionConfiguration(
                state_dir=state,
                tenant_id="tenant-a",
                project_id="project-a",
                workspace_id="workspace-a",
                project_label="Project A",
                workspace_label="Workspace A",
                plugin_names=(),
                plugin_modules=(),
                input_paths=(),
                timeout_seconds=10,
                auto_select=True,
                preferred_plugin_id=None,
                content_type=None,
                node_hint=None,
                metadata={},
                output_path=None,
                pretty=False,
                plugin_deployment_module="deployment.plugins:build",
            )
            with patch("router_dump_analyzer.pipeline_cli._ensure_scope"):
                result = run(
                    configuration,
                    entry_point_loader=lambda _name: self.fail(),
                    module_loader=lambda _target: self.fail(),
                    plugin_deployment_loader=lambda _target, **_values: deployment,
                    stdout=io.StringIO(),
                    pipeline_limits=self._limits(),
                    control_plane_factory=EmptyControlPlane,
                )

        self.assertEqual(result, 0)
        self.assertEqual(captured["root"], state.resolve())
        self.assertIs(captured["registry"], registry)
        self.assertIs(captured["capability_providers"], providers)
        self.assertIs(captured["plugin_composition_policy"], policy)
        self.assertIs(captured["allow_inline_only"], True)
        effective_limits = captured["pipeline_limits"]
        self.assertIsInstance(effective_limits, PipelineLimits)
        assert isinstance(effective_limits, PipelineLimits)
        self.assertIs(
            effective_limits.plugin_execution_mode,
            PluginExecutionMode.INLINE,
        )
        self.assertIs(
            effective_limits.effective_publisher_execution_mode,
            PluginExecutionMode.PROCESS,
        )

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
                execution_environment_fingerprint="sha256:" + ("1" * 64),
            )
            changed_mime = _idempotency_key(
                configuration,
                path,
                "a" * 64,
                effective_content_type="application/octet-stream",
                execution_environment_fingerprint="sha256:" + ("1" * 64),
            )
            changed_registry = _idempotency_key(
                configuration,
                path,
                "a" * 64,
                effective_content_type=effective_content_type,
                execution_environment_fingerprint="sha256:" + ("2" * 64),
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
                for revision in revisions:
                    assert revision.execution_plan is not None
                    artifact = revision.execution_plan.plugins[0].artifact
                    self.assertEqual(
                        artifact.distribution_name,
                        "direct-module",
                    )
                    self.assertEqual(artifact.distribution_version, "0")
                    self.assertEqual(artifact.entry_point_name, "direct-module")
                    self.assertEqual(
                        artifact.module_target,
                        "test.plugin:plugin",
                    )

    def test_headless_run_honors_explicit_preference_without_auto_selection(self) -> None:
        cases = (
            (None, 2, ImportState.AWAITING_SELECTION),
            (ParseOnlyPlugin.manifest.plugin_id, 0, ImportState.COMPLETED),
            ("tests.not-registered", 1, ImportState.FAILED),
        )
        for preferred, expected_exit, expected_state in cases:
            with (
                self.subTest(preferred=preferred),
                tempfile.TemporaryDirectory() as directory,
            ):
                self._assert_headless_selection_result(
                    Path(directory), preferred, expected_exit, expected_state
                )

    def _assert_headless_selection_result(
        self,
        root: Path,
        preferred: str | None,
        expected_exit: int,
        expected_state: ImportState,
    ) -> None:
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
            preferred_plugin_id=preferred,
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
        self.assertEqual(exit_code, expected_exit)
        self.assertEqual(document["imports"][0]["state"], expected_state.value)
        if expected_state is ImportState.AWAITING_SELECTION:
            self.assertEqual(
                len(document["imports"][0]["plugin_candidates"]),
                1,
            )
        elif expected_state is ImportState.COMPLETED:
            self.assertTrue(document["imports"][0]["revision_id"].startswith("revision-"))

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

    def test_durable_control_plane_rejects_inline_only_auxiliary_atomically(
        self,
    ) -> None:
        primary_registry = PluginRegistry()
        primary = primary_registry.register(
            ParseOnlyPlugin(),
            instance_id="primary",
        )
        package_identity = "package-sha256:" + "7" * 64
        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
                return_value=package_identity,
            ),
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_module_target_fingerprint",
                side_effect=PluginExecutableIdentityError(
                    "target attestation unavailable"
                ),
            ),
        ):
            auxiliary = PluginRegistry(allow_manifest_identity=True).register(
                ParseOnlyPlugin(),
                instance_id="inline-only-auxiliary",
            )
        with patch(
            "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
            side_effect=lambda plugin: (
                package_identity
                if plugin is auxiliary.plugin
                else primary.package_hash
            ),
        ):
            providers = CapabilityProviderRegistry((primary, auxiliary))
        policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(
                        PluginParticipationSelection(
                            instance_id=auxiliary.instance_id,
                            registered_execution_identity=(
                                auxiliary.registered_execution_identity
                            ),
                            roles=("private_analysis_evidence",),
                        ),
                    ),
                ),
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory) / "state"
            with self.assertRaisesRegex(ValueError, "INLINE-only"):
                ControlPlane(
                    state_dir,
                    registry=primary_registry,
                    capability_providers=providers,
                    plugin_composition_policy=policy,
                )
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
