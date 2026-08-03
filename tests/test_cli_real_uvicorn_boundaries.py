from __future__ import annotations

import os
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
        PluginManifest,
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

    class RuntimeFailurePlugin:
        @property
        def runtime(self):
            raise Boom(__SECRET__)

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
            if False:
                yield None
            raise Boom(__SECRET__)

    manifest_plugin = ManifestFailurePlugin()
    runtime_plugin = RuntimeFailurePlugin()
    hook_plugin = HookFailurePlugin()
    generator_plugin = GeneratorFailurePlugin()
    '''
).replace("__SECRET__", repr(_SECRET))


class RealUvicornCliBoundaryTests(unittest.TestCase):
    def test_lifespan_plugin_failures_have_one_bounded_process_projection(
        self,
    ) -> None:
        cases = {
            "manifest": "does not implement the standard core-ingestion parser contract",
            "runtime": "plug-in runtime descriptor could not be resolved",
            "hook": "plug-in runtime session enter failed",
            "generator": "plug-in runtime session enter failed",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "input"
            input_path.mkdir()
            (root / "round17_hostile_plugins.py").write_text(
                _PLUGIN_SOURCE,
                encoding="utf-8",
            )
            distribution = root / "round17_hostile_plugins-1.0.dist-info"
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
                        str(ROOT / "src"),
                        environment.get("PYTHONPATH"),
                    ),
                )
            )
            forbidden = (
                str(ROOT).casefold(),
                r"c:\python",
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
                            "65530",
                        ],
                        cwd=ROOT,
                        env=environment,
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                    rendered = completed.stdout + completed.stderr
                    lines = tuple(
                        line for line in rendered.splitlines() if line.strip()
                    )
                    self.assertNotEqual(completed.returncode, 0, case)
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
                    lowered = rendered.casefold()
                    for needle in forbidden:
                        self.assertNotIn(needle, lowered, rendered)


if __name__ == "__main__":
    unittest.main()
