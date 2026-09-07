from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path, PurePosixPath
from typing import Self
from unittest.mock import patch
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    ArtifactInfo,
    DiagnosticSeverity,
    DiagnosticStage,
    DumpInventory,
    InputParserKind,
    InputSpec,
    PluginCapability,
    PluginDiagnostic,
    PluginManifest,
    PluginSchema,
    ProbeMatchKind,
    ProbeReport,
    ProbeResult,
    ReconstructionSupport,
)
from router_dump_analyzer.plugin_validation import main, validate_plugin


class Boom(BaseException):
    """Adversarial non-process-control throwable supplied by a plug-in."""


class _ExplodingHashText(str):
    failure: BaseException
    armed: bool

    def __new__(
        cls,
        value: str,
        failure: BaseException,
    ) -> Self:
        result = super().__new__(cls, value)
        result.failure = failure
        result.armed = False
        return result

    def __hash__(self) -> int:
        if self.armed:
            raise self.failure
        return str.__hash__(self)


def manifest(*capabilities: PluginCapability) -> PluginManifest:
    return PluginManifest(
        plugin_id="example.minimal",
        plugin_version="1.0.0",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("example-router",),
        supported_software_versions=">=1,<2",
        capabilities=frozenset(capabilities),
        reconstruction_default=ReconstructionSupport.EXACT,
    )


class MinimalPlugin(AnalyzerPluginBase):
    manifest = manifest(PluginCapability.STATUS_PARSE)

    def describe(self) -> PluginSchema:
        return PluginSchema(resource_kinds=(), relationship_types=())

    def probe(self, inventory: DumpInventory) -> ProbeReport:
        return ProbeReport(result=None)

    def locate_inputs(self, inventory: DumpInventory):
        return ()

    def parse_status(self, reader, spec):
        return ()


class MissingOverridePlugin(MinimalPlugin):
    manifest = manifest(PluginCapability.CTF_PARSE)


class MissingRelationshipProjectionOverridePlugin(MinimalPlugin):
    manifest = manifest(PluginCapability.RELATIONSHIP_PROJECTION)


class LegacyDispatchPlugin(MinimalPlugin):
    def probe(self, inventory: DumpInventory) -> ProbeReport:
        if not inventory.artifacts:
            return ProbeReport(result=None)
        return ProbeReport(
            result=ProbeResult(
                confidence=1.0,
                reasons=("author fixture is present",),
                match_kind=ProbeMatchKind.EXACT,
            )
        )

    def locate_inputs(self, inventory: DumpInventory):
        if not inventory.artifacts:
            return ()
        return (
            InputSpec(
                artifact_ids=(inventory.artifacts[0].artifact_id,),
                role="status",
                node="node-a",
                layer="control",
                parser_id="example.status.v1",
            ),
        )


class ForgedProbePlugin(MinimalPlugin):
    def probe(self, inventory: DumpInventory) -> ProbeReport:
        result = ProbeResult(
            confidence=1.0,
            reasons=("initially valid",),
            detected_platform="example-router",
        )
        object.__setattr__(result, "detected_platform", "x" * 257)
        return ProbeReport(result=result)


class ForgedProbeDiagnosticPlugin(MinimalPlugin):
    def probe(self, inventory: DumpInventory) -> ProbeReport:
        del inventory
        diagnostic = PluginDiagnostic(
            stage=DiagnosticStage.PROBE,
            severity=DiagnosticSeverity.WARNING,
            code="example.forged",
            message="initially valid",
            recoverable=True,
        )
        object.__setattr__(diagnostic, "message", "x" * 8_193)
        return ProbeReport(result=None, diagnostics=(diagnostic,))


class ExplodingProbePlugin(MinimalPlugin):
    def __init__(self, message: str) -> None:
        self.message = message

    def probe(self, inventory: DumpInventory) -> ProbeReport:
        del inventory
        raise RuntimeError(self.message)


class ExplodingDescribePlugin(MinimalPlugin):
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def describe(self) -> PluginSchema:
        raise self.error


class ExplodingGetattrPlugin:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def __getattr__(self, name: str):
        del name
        raise self.error


class DescriptorBackedPlugin:
    def __init__(self) -> None:
        self.accesses = {
            "manifest": 0,
            "describe": 0,
            "probe": 0,
            "locate_inputs": 0,
            "parse_status": 0,
        }
        self._manifest = manifest(PluginCapability.STATUS_PARSE)

    @property
    def manifest(self):
        self.accesses["manifest"] += 1
        return self._manifest

    @property
    def describe(self):
        self.accesses["describe"] += 1

        def resolved_describe():
            return PluginSchema(resource_kinds=(), relationship_types=())

        return resolved_describe

    @property
    def probe(self):
        self.accesses["probe"] += 1

        def resolved_probe(inventory):
            del inventory
            return ProbeReport(result=None)

        return resolved_probe

    @property
    def locate_inputs(self):
        self.accesses["locate_inputs"] += 1

        def resolved_locate_inputs(inventory):
            del inventory
            return ()

        return resolved_locate_inputs

    @property
    def parse_status(self):
        self.accesses["parse_status"] += 1

        def resolved_parse_status(reader, spec):
            del reader, spec
            return ()

        return resolved_parse_status


class ExplodingManifestDescriptorPlugin:
    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.accesses = 0

    @property
    def manifest(self):
        self.accesses += 1
        raise self.error


class ExplodingProbeDescriptorPlugin(MinimalPlugin):
    def __init__(self, error: BaseException) -> None:
        self.error = error
        self.accesses = 0

    @property
    def probe(self):
        self.accesses += 1
        raise self.error


class InstanceOnlyHookDescriptor:
    def __init__(self) -> None:
        self.class_accesses = 0
        self.instance_accesses = 0

    def __get__(self, instance, owner):
        del owner
        if instance is None:
            self.class_accesses += 1
            raise RuntimeError(r"class lookup reached C:\private\plugin.py")
        self.instance_accesses += 1

        def resolved_parse_status(reader, spec):
            del reader, spec
            return ()

        return resolved_parse_status


instance_only_parse_status = InstanceOnlyHookDescriptor()


class StaticDescriptorOverridePlugin(MinimalPlugin):
    manifest = manifest(PluginCapability.STATUS_PARSE)
    parse_status = instance_only_parse_status


class MismatchedDispatchPlugin(MinimalPlugin):
    manifest = manifest(PluginCapability.TEXT_TRACE_PARSE)

    def locate_inputs(self, inventory: DumpInventory):
        return (
            InputSpec(
                artifact_ids=(UUID(int=1),),
                role="status",
                node="node-a",
                layer="control",
                parser_id="example.status.v1",
                parser_kind=InputParserKind.STATUS,
            ),
        )

    def parse_text_trace(self, reader, spec):
        return ()


class FixtureOnlyLegacyPlugin(MinimalPlugin):
    def locate_inputs(self, inventory: DumpInventory):
        if not inventory.artifacts:
            return ()
        return (
            InputSpec(
                artifact_ids=(inventory.artifacts[0].artifact_id,),
                role="status",
                node="node-a",
                layer="control",
                parser_id="example.status.v1",
            ),
        )


def author_inventory() -> DumpInventory:
    return DumpInventory(
        node_hint="node-a",
        artifacts=(
            ArtifactInfo(
                artifact_id=UUID(int=2),
                logical_path=PurePosixPath("status.jsonl"),
                parent_artifact_id=None,
                media_type="application/x-ndjson",
                compressed_size=10,
                uncompressed_size=10,
                sha256=None,
            ),
        ),
    )


class PluginValidationTests(unittest.TestCase):
    @staticmethod
    def _plugin_with_exploding_manifest_value(
        failure: BaseException,
    ) -> MinimalPlugin:
        capability = _ExplodingHashText("vendor.custom", failure)
        plugin = MinimalPlugin()
        plugin.manifest = PluginManifest(
            plugin_id="example.hostile-value",
            plugin_version="1.0.0",
            core_api_version=CORE_PLUGIN_API_VERSION,
            supported_platforms=("example-router",),
            supported_software_versions="*",
            capabilities=frozenset({capability}),
            reconstruction_default=ReconstructionSupport.EXACT,
        )
        capability.armed = True
        return plugin

    def test_nested_manifest_values_are_bounded_and_preserve_process_controls(
        self,
    ) -> None:
        supplied = r"manifest value failed at C:\private\tenant\plugin.py"
        result = validate_plugin(
            self._plugin_with_exploding_manifest_value(Boom(supplied))
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.plugin_id, "<unknown>")
        self.assertEqual(len(result.errors), 1)
        self.assertIn("could not inspect plug-in-owned values", result.errors[0])
        self.assertNotIn(supplied, result.errors[0])
        self.assertLessEqual(len(result.errors[0]), 1_100)

        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(
                exception_type=exception_type.__name__
            ), self.assertRaises(exception_type):
                validate_plugin(
                    self._plugin_with_exploding_manifest_value(
                        exception_type("process control")
                    )
                )

    def test_minimal_plugin_passes(self) -> None:
        result = validate_plugin(MinimalPlugin())
        self.assertTrue(result.ok, result.errors)

    def test_plugin_owned_descriptors_are_resolved_once(self) -> None:
        plugin = DescriptorBackedPlugin()

        result = validate_plugin(plugin)

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(
            plugin.accesses,
            {
                "manifest": 1,
                "describe": 1,
                "probe": 1,
                "locate_inputs": 1,
                "parse_status": 1,
            },
        )

    def test_manifest_descriptor_errors_are_bounded_public_results(self) -> None:
        cases = (
            RuntimeError(r"manifest failed at C:\private\tenant\plugin.py"),
            RuntimeError("manifest\x00failed"),
            RuntimeError("manifest\u202efailed"),
            RuntimeError("x" * 2_000),
        )
        for raised in cases:
            with self.subTest(raised=repr(raised)):
                plugin = ExplodingManifestDescriptorPlugin(raised)

                result = validate_plugin(plugin)

                rendered = "\n".join(result.errors)
                self.assertFalse(result.ok)
                self.assertEqual(plugin.accesses, 1)
                self.assertIn("plug-in exception details unavailable", rendered)
                self.assertNotIn(str(raised), rendered)
                self.assertNotIn("\x00", rendered)
                self.assertNotIn("\u202e", rendered)
                self.assertLessEqual(len(rendered), 1_200)

    def test_hook_descriptor_error_is_contained_without_a_second_lookup(self) -> None:
        supplied = r"probe failed at C:\private\tenant\probe.py"
        plugin = ExplodingProbeDescriptorPlugin(RuntimeError(supplied))

        result = validate_plugin(plugin)

        rendered = "\n".join(result.errors)
        self.assertFalse(result.ok)
        self.assertEqual(plugin.accesses, 1)
        self.assertIn("required hook probe() could not be resolved", rendered)
        self.assertIn("plug-in exception details unavailable", rendered)
        self.assertNotIn(supplied, rendered)

    def test_nonstandard_base_exceptions_are_contained_at_author_boundaries(
        self,
    ) -> None:
        supplied = r"plug-in failed at C:\private\tenant\hostile.py"
        plugins = (
            ExplodingManifestDescriptorPlugin(Boom(supplied)),
            ExplodingGetattrPlugin(Boom(supplied)),
            ExplodingProbeDescriptorPlugin(Boom(supplied)),
            ExplodingDescribePlugin(Boom(supplied)),
        )
        for plugin in plugins:
            with self.subTest(plugin=type(plugin).__name__):
                result = validate_plugin(plugin)
                rendered = "\n".join(result.errors)
                self.assertFalse(result.ok)
                self.assertIn("plug-in exception details unavailable", rendered)
                self.assertNotIn(supplied, rendered)
                self.assertLessEqual(len(rendered), 1_200)

    def test_override_check_uses_static_descriptor_inspection(self) -> None:
        instance_only_parse_status.class_accesses = 0
        instance_only_parse_status.instance_accesses = 0

        result = validate_plugin(StaticDescriptorOverridePlugin())

        self.assertTrue(result.ok, result.errors)
        self.assertEqual(instance_only_parse_status.instance_accesses, 1)
        self.assertEqual(instance_only_parse_status.class_accesses, 0)

    def test_probe_validation_rechecks_the_canonical_contract(self) -> None:
        result = validate_plugin(ForgedProbePlugin())
        self.assertFalse(result.ok)
        self.assertTrue(
            any("detected_platform" in error for error in result.errors),
            result.errors,
        )

    def test_probe_diagnostics_use_the_same_bounded_contract(self) -> None:
        result = validate_plugin(ForgedProbeDiagnosticPlugin())
        self.assertFalse(result.ok)
        self.assertTrue(
            any("probe.diagnostics[0].message" in error for error in result.errors),
            result.errors,
        )

    def test_untrusted_hook_diagnostics_use_the_public_display_policy(self) -> None:
        safe = validate_plugin(ExplodingProbePlugin("decoder rejected frame 4"))
        self.assertTrue(
            any(
                "RuntimeError: decoder rejected frame 4" in error
                for error in safe.errors
            ),
            safe.errors,
        )

        cases = (
            ("x" * 2_000, "plug-in exception details unavailable"),
            (
                r"decoder failed at C:\private\tenant\decoder.py",
                "plug-in exception details unavailable",
            ),
            ("decoder\x00failed", "plug-in exception details unavailable"),
            ("state\u034fchanged", r"state\u034fchanged"),
        )
        for supplied, expected in cases:
            with self.subTest(supplied=repr(supplied[:40])):
                result = validate_plugin(ExplodingProbePlugin(supplied))
                diagnostic = next(
                    error for error in result.errors if error.startswith("probe()")
                )
                self.assertIn(expected, diagnostic)
                self.assertNotIn(supplied, diagnostic)
                self.assertLessEqual(len(diagnostic), 1_200)

    def test_declared_capability_requires_override(self) -> None:
        result = validate_plugin(MissingOverridePlugin())
        self.assertFalse(result.ok)
        self.assertTrue(
            any("requires an override of parse_ctf" in error for error in result.errors)
        )

        projection = validate_plugin(
            MissingRelationshipProjectionOverridePlugin()
        )
        self.assertFalse(projection.ok)
        self.assertTrue(
            any(
                "requires an override of project_relationships" in error
                for error in projection.errors
            )
        )

    def test_new_plugins_must_select_parser_kind(self) -> None:
        inventory = author_inventory()
        strict = validate_plugin(LegacyDispatchPlugin(), inventory=inventory)
        compatible = validate_plugin(
            LegacyDispatchPlugin(),
            inventory=inventory,
            allow_legacy_input_dispatch=True,
        )
        self.assertFalse(strict.ok)
        self.assertTrue(compatible.ok)
        self.assertTrue(compatible.warnings)

    def test_author_fixture_exercises_nonempty_dispatch_path(self) -> None:
        plugin = FixtureOnlyLegacyPlugin()
        empty_only = validate_plugin(plugin)
        representative = validate_plugin(plugin, inventory=author_inventory())
        self.assertTrue(empty_only.ok)
        self.assertFalse(representative.ok)
        self.assertTrue(
            any("has no parser_kind" in error for error in representative.errors)
        )

    def test_input_dispatch_requires_matching_capability(self) -> None:
        result = validate_plugin(MismatchedDispatchPlugin())
        self.assertFalse(result.ok)
        self.assertTrue(
            any("does not declare 'status_parse'" in error for error in result.errors)
        )

    def test_invalid_manifest_scalars_are_reported_without_crashing(self) -> None:
        plugin = MinimalPlugin()
        plugin.manifest = PluginManifest(
            plugin_id=7,  # type: ignore[arg-type]
            plugin_version=None,  # type: ignore[arg-type]
            core_api_version="0",
            supported_platforms=(None,),  # type: ignore[arg-type]
            supported_software_versions=1,  # type: ignore[arg-type]
            capabilities=frozenset(),
            reconstruction_default="invented",  # type: ignore[arg-type]
        )
        result = validate_plugin(plugin)
        self.assertFalse(result.ok)
        self.assertGreaterEqual(len(result.errors), 6)

    def test_cli_reports_missing_entry_point_without_traceback(self) -> None:
        output = io.StringIO()
        with patch(
            "router_dump_analyzer.plugin_validation.installed_plugin_entry_points",
            return_value=(),
        ), redirect_stdout(output):
            return_code = main(["missing"])
        self.assertEqual(return_code, 2)
        self.assertIn("no 'router_dump_analyzer.plugins' entry point", output.getvalue())

    def test_cli_reports_broken_entry_point_without_traceback(self) -> None:
        class BrokenEntryPoint:
            name = "broken"

            def load(self):
                raise ImportError("missing vendor decoder")

        output = io.StringIO()
        with patch(
            "router_dump_analyzer.plugin_validation.installed_plugin_entry_points",
            return_value=(BrokenEntryPoint(),),
        ), redirect_stdout(output):
            return_code = main(["broken"])
        self.assertEqual(return_code, 2)
        self.assertIn(
            "failed to load entry point 'broken': ImportError: missing vendor decoder",
            output.getvalue(),
        )

    def test_cli_stdout_projects_untrusted_loader_diagnostics(self) -> None:
        cases = (
            ("x" * 2_000, "plug-in validation request failed"),
            (
                r"decoder failed at C:\private\tenant\decoder.py",
                "plug-in validation request failed",
            ),
            ("decoder\x00failed", "plug-in validation request failed"),
            ("state\u034fchanged", r"state\u034fchanged"),
        )
        for supplied, expected in cases:
            class BrokenEntryPoint:
                name = "broken"

                def __init__(self, message: str) -> None:
                    self.message = message

                def load(self):
                    raise ImportError(self.message)

            output = io.StringIO()
            with (
                self.subTest(supplied=repr(supplied[:40])),
                patch(
                    "router_dump_analyzer.plugin_validation.installed_plugin_entry_points",
                    return_value=(BrokenEntryPoint(supplied),),
                ),
                redirect_stdout(output),
            ):
                return_code = main(["broken"])
            rendered = output.getvalue()
            self.assertEqual(return_code, 2)
            self.assertIn(expected, rendered)
            self.assertNotIn(supplied, rendered)
            self.assertLessEqual(len(rendered), 1_100)

    def test_cli_preserves_safe_loader_detail_within_the_total_budget(self) -> None:
        supplied = "x" * 980

        class BrokenEntryPoint:
            name = "broken"

            def load(self):
                raise RuntimeError(supplied)

        output = io.StringIO()
        with patch(
            "router_dump_analyzer.plugin_validation.installed_plugin_entry_points",
            return_value=(BrokenEntryPoint(),),
        ), redirect_stdout(output):
            return_code = main(["broken"])

        rendered = output.getvalue()
        self.assertEqual(return_code, 2)
        self.assertIn(f"RuntimeError: {supplied}", rendered)
        self.assertLessEqual(len(rendered), 1_100)

    def test_cli_contains_unexpected_ordinary_validation_exceptions(self) -> None:
        supplied = r"validator failed at C:\private\tenant\validator.py"
        output = io.StringIO()
        with (
            patch(
                "router_dump_analyzer.plugin_validation.load_entry_point",
                return_value=MinimalPlugin(),
            ),
            patch(
                "router_dump_analyzer.plugin_validation.validate_plugin",
                side_effect=RuntimeError(supplied),
            ),
            redirect_stdout(output),
        ):
            return_code = main(["hostile"])

        rendered = output.getvalue()
        self.assertEqual(return_code, 2)
        self.assertIn("ERROR: plug-in validation failed", rendered)
        self.assertIn("plug-in exception details unavailable", rendered)
        self.assertNotIn(supplied, rendered)
        self.assertLessEqual(len(rendered), 1_100)

    def test_cli_contains_nonstandard_base_exceptions_without_traceback(self) -> None:
        supplied = r"validator failed at C:\private\tenant\boom.py"
        for failure_stage in ("load", "validate"):
            with self.subTest(failure_stage=failure_stage):
                output = io.StringIO()
                if failure_stage == "load":
                    with patch(
                        "router_dump_analyzer.plugin_validation.load_entry_point",
                        side_effect=Boom(supplied),
                    ), redirect_stdout(output):
                        return_code = main(["hostile"])
                else:
                    with patch(
                        "router_dump_analyzer.plugin_validation.load_entry_point",
                        return_value=MinimalPlugin(),
                    ), patch(
                        "router_dump_analyzer.plugin_validation.validate_plugin",
                        side_effect=Boom(supplied),
                    ), redirect_stdout(output):
                        return_code = main(["hostile"])

                rendered = output.getvalue()
                self.assertEqual(return_code, 2)
                self.assertNotIn(supplied, rendered)
                self.assertNotIn("Traceback", rendered)
                self.assertLessEqual(len(rendered), 1_100)

    def test_module_cli_contains_installed_boom_entry_points(self) -> None:
        supplied = r"C:\Users\alice\secret\plugin.py"
        cases = {
            "manifest": f"""
class Boom(BaseException):
    pass
class P:
    @property
    def manifest(self):
        raise Boom(r"failed at {supplied}")
plugin = P()
""",
            "getattr": f"""
class Boom(BaseException):
    pass
class P:
    def __getattr__(self, name):
        raise Boom(r"failed at {supplied}")
plugin = P()
""",
            "describe": f"""
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION, PluginManifest, ProbeReport, ReconstructionSupport
)
class Boom(BaseException):
    pass
class P:
    manifest = PluginManifest(
        plugin_id="hostile.test",
        plugin_version="1",
        core_api_version=CORE_PLUGIN_API_VERSION,
        supported_platforms=("test",),
        supported_software_versions="*",
        capabilities=frozenset(),
        reconstruction_default=ReconstructionSupport.EXACT,
    )
    def describe(self):
        raise Boom(r"failed at {supplied}")
    def probe(self, inventory):
        return ProbeReport(result=None)
    def locate_inputs(self, inventory):
        return ()
plugin = P()
""",
        }
        for case, module_source in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "hostile_plugin.py").write_text(
                    module_source,
                    encoding="utf-8",
                )
                distribution = root / "hostile_plugin-1.0.dist-info"
                distribution.mkdir()
                (distribution / "METADATA").write_text(
                    "Metadata-Version: 2.1\nName: hostile-plugin\nVersion: 1.0\n",
                    encoding="utf-8",
                )
                (distribution / "entry_points.txt").write_text(
                    "[router_dump_analyzer.plugins]\n"
                    "hostile = hostile_plugin:plugin\n",
                    encoding="utf-8",
                )
                environment = os.environ.copy()
                environment["PYTHONUTF8"] = "1"
                environment["PYTHONIOENCODING"] = "utf-8"
                environment["PYTHONPATH"] = os.pathsep.join(
                    filter(
                        None,
                        (
                            str(root),
                            str(ROOT / "src"),
                            environment.get("PYTHONPATH"),
                        ),
                    )
                )
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "router_dump_analyzer.plugin_validation",
                        "hostile",
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                rendered = completed.stdout + completed.stderr
                self.assertNotEqual(completed.returncode, 0)
                self.assertNotIn(supplied, rendered)
                self.assertNotIn("Traceback", rendered)
                self.assertLessEqual(len(rendered), 2_200)

    def test_hook_and_loader_process_controls_are_not_swallowed(self) -> None:
        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(exception_type=exception_type.__name__):
                with self.assertRaises(exception_type):
                    validate_plugin(
                        ExplodingDescribePlugin(exception_type("process control"))
                    )

                with (
                    patch(
                        "router_dump_analyzer.plugin_validation.load_entry_point",
                        side_effect=exception_type("process control"),
                    ),
                    self.assertRaises(exception_type),
                ):
                    main(["hostile"])

    def test_descriptor_process_controls_are_not_swallowed(self) -> None:
        for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
            with self.subTest(exception_type=exception_type.__name__):
                with self.assertRaises(exception_type):
                    validate_plugin(
                        ExplodingManifestDescriptorPlugin(
                            exception_type("process control")
                        )
                    )

                output = io.StringIO()
                with (
                    patch(
                        "router_dump_analyzer.plugin_validation.load_entry_point",
                        return_value=ExplodingManifestDescriptorPlugin(
                            exception_type("process control")
                        ),
                    ),
                    redirect_stdout(output),
                    self.assertRaises(exception_type),
                ):
                    main(["hostile"])
                self.assertEqual(output.getvalue(), "")

    def test_cli_builds_and_checks_representative_inventory(self) -> None:
        class InstalledEntryPoint:
            name = "legacy"

            def load(self):
                return LegacyDispatchPlugin()

        output = io.StringIO()
        with patch(
            "router_dump_analyzer.plugin_validation.installed_plugin_entry_points",
            return_value=(InstalledEntryPoint(),),
        ), redirect_stdout(output):
            return_code = main(
                [
                    "legacy",
                    "--artifact",
                    __file__,
                    "--node-hint",
                    "node-a",
                    "--allow-legacy-input-dispatch",
                ]
            )
        self.assertEqual(return_code, 0)
        self.assertIn("WARNING: InputSpec output 0 has no parser_kind", output.getvalue())
        self.assertIn("OK: example.minimal", output.getvalue())


if __name__ == "__main__":
    unittest.main()
