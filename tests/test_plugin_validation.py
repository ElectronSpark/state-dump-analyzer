from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path, PurePosixPath
from unittest.mock import patch
from uuid import UUID


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    ArtifactInfo,
    DumpInventory,
    InputParserKind,
    InputSpec,
    PluginCapability,
    PluginManifest,
    PluginSchema,
    ProbeMatchKind,
    ProbeReport,
    ProbeResult,
    ReconstructionSupport,
)
from router_dump_analyzer.plugin_validation import main, validate_plugin


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
    def test_minimal_plugin_passes(self) -> None:
        result = validate_plugin(MinimalPlugin())
        self.assertTrue(result.ok, result.errors)

    def test_declared_capability_requires_override(self) -> None:
        result = validate_plugin(MissingOverridePlugin())
        self.assertFalse(result.ok)
        self.assertTrue(
            any("requires an override of parse_ctf" in error for error in result.errors)
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
            "router_dump_analyzer.plugin_validation._entry_points",
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
            "router_dump_analyzer.plugin_validation._entry_points",
            return_value=(BrokenEntryPoint(),),
        ), redirect_stdout(output):
            return_code = main(["broken"])
        self.assertEqual(return_code, 2)
        self.assertIn(
            "failed to load entry point 'broken': ImportError: missing vendor decoder",
            output.getvalue(),
        )

    def test_cli_builds_and_checks_representative_inventory(self) -> None:
        class InstalledEntryPoint:
            name = "legacy"

            def load(self):
                return LegacyDispatchPlugin()

        output = io.StringIO()
        with patch(
            "router_dump_analyzer.plugin_validation._entry_points",
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
