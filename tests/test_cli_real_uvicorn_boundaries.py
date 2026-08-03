from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SECRET = "ROUND17-PLUGIN-SECRET-MARKER"

_PLUGIN_SOURCE = textwrap.dedent(
    '''\
    from router_dump_analyzer.plugin_api import (
        CORE_PLUGIN_API_VERSION,
        DiagnosticSeverity,
        DiagnosticStage,
        PluginManifest,
        PluginDiagnostic,
        PluginSchema,
        ProbeMatchKind,
        ProbeReport,
        ProbeResult,
        ReconstructionSupport,
    )

    class Boom(BaseException):
        pass

    class ManifestFailurePlugin:
        @property
        def manifest(self):
            raise Boom(__SECRET__)

    class RuntimeFailureRuntime:
        capability_id = "router_dump_analyzer.runtime.v1"

        def open(self, _input_path):
            raise Boom(__SECRET__)

    class RuntimeFailurePlugin:
        runtime = RuntimeFailureRuntime()

    class ParserPlugin:
        manifest = PluginManifest(
            plugin_id="round17.hostile",
            plugin_version="1",
            core_api_version=CORE_PLUGIN_API_VERSION,
            supported_platforms=("round17",),
            supported_software_versions="*",
            capabilities=frozenset(),
            reconstruction_default=ReconstructionSupport.EXACT,
        )

        def describe(self):
            return PluginSchema(resource_kinds=(), relationship_types=())

        def probe(self, _inventory):
            return ProbeReport(
                result=ProbeResult(
                    confidence=1.0,
                    reasons=("round17 fixture",),
                    match_kind=ProbeMatchKind.EXACT,
                )
            )

        def locate_inputs(self, _inventory):
            return ()

    class HookFailurePlugin(ParserPlugin):
        def describe(self):
            raise Boom(__SECRET__)

    class GeneratorFailurePlugin(ParserPlugin):
        def locate_inputs(self, _inventory):
            for index in range(2):
                yield PluginDiagnostic(
                    stage=DiagnosticStage.LOCATE,
                    severity=DiagnosticSeverity.INFO,
                    code=f"round17-{index}",
                    message="accepted prefix output",
                    recoverable=True,
                )
            raise Boom(__SECRET__)

    manifest_plugin = ManifestFailurePlugin()
    runtime_plugin = RuntimeFailurePlugin()
    hook_plugin = HookFailurePlugin()
    generator_plugin = GeneratorFailurePlugin()
    '''
).replace("__SECRET__", repr(_SECRET))


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class RealUvicornCliBoundaryTests(unittest.TestCase):
    def test_lifespan_plugin_failures_have_one_bounded_process_projection(
        self,
    ) -> None:
        cases = {
            "manifest": "does not implement the standard core-ingestion parser contract",
            "runtime": "plug-in runtime session open failed",
            "hook": "plug-in runtime session enter failed",
            "generator": "plug-in runtime session enter failed",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "input"
            input_path.mkdir()
            site_packages = root / "site-packages"
            site_packages.mkdir()
            (site_packages / "round17_hostile_plugins.py").write_text(
                _PLUGIN_SOURCE,
                encoding="utf-8",
            )
            distribution = site_packages / "round17_hostile_plugins-1.0.dist-info"
            distribution.mkdir()
            (distribution / "METADATA").write_text(
                "Metadata-Version: 2.1\n"
                "Name: round17-hostile-plugins\n"
                "Version: 1.0\n",
                encoding="utf-8",
            )
            (distribution / "entry_points.txt").write_text(
                "[router_dump_analyzer.plugins]\n"
                + "".join(
                    f"hostile-{case} = "
                    f"round17_hostile_plugins:{case}_plugin\n"
                    for case in cases
                ),
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
                        str(site_packages),
                        str(ROOT / "src"),
                        environment.get("PYTHONPATH"),
                    ),
                )
            )
            forbidden_paths = (
                ROOT,
                root,
                Path(sys.executable).resolve().parent,
                Path(sys.prefix),
            )
            forbidden_text = (
                "c:/python",
                "site-packages",
                _SECRET.casefold(),
                "traceback",
            )

            for case, expected_detail in cases.items():
                with self.subTest(case=case):
                    completed = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "router_dump_analyzer",
                            "--plugin",
                            f"hostile-{case}",
                            "--input",
                            str(input_path),
                            "--no-browser",
                            "--api-only",
                            "--port",
                            str(_available_port()),
                        ],
                        cwd=ROOT,
                        env=environment,
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                    rendered = completed.stdout + completed.stderr
                    lines = completed.stderr.splitlines()
                    self.assertNotEqual(completed.returncode, 0, case)
                    self.assertEqual(completed.stdout, "", rendered)
                    self.assertEqual(
                        len(lines),
                        1,
                        f"{case} emitted {len(lines)} lines:\n{rendered}",
                    )
                    self.assertTrue(
                        lines[0].startswith("router-dump-analyzer: error: "),
                        rendered,
                    )
                    self.assertIn(expected_detail, lines[0], rendered)
                    self.assertLessEqual(len(lines[0]), 512, rendered)
                    lowered = rendered.casefold().replace("\\", "/")
                    for path in forbidden_paths:
                        needle = str(path.resolve()).casefold().replace("\\", "/")
                        self.assertNotIn(needle, lowered, rendered)
                    for needle in forbidden_text:
                        self.assertNotIn(needle, lowered, rendered)


if __name__ == "__main__":
    unittest.main()
