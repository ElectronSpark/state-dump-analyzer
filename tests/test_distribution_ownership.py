from __future__ import annotations

import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DistributionOwnershipTests(unittest.TestCase):
    def test_core_is_the_only_application_distribution(self) -> None:
        core = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        demo = tomllib.loads(
            (ROOT / "demo" / "pyproject.toml").read_text(encoding="utf-8")
        )

        self.assertEqual(
            core["project"]["scripts"],
            {
                "router-dump-analyzer": "router_dump_analyzer.cli:main",
                "router-dump-ingest": "router_dump_analyzer.pipeline_cli:main",
                "router-dump-maintain": (
                    "router_dump_analyzer.maintenance_cli:main"
                ),
                "router-dump-health": "router_dump_analyzer.health_cli:main",
                "router-dump-server": "router_dump_analyzer.server_cli:main",
                "router-dump-plugin-validate": (
                    "router_dump_analyzer.plugin_validation:main"
                ),
            },
        )
        self.assertNotIn("scripts", demo["project"])
        self.assertNotIn("gui-scripts", demo["project"])
        self.assertEqual(
            demo["project"]["entry-points"],
            {
                "router_dump_analyzer.plugins": {
                    "demo_router": "rsl_demo_plugin:plugin"
                }
            },
        )

    def test_demo_distribution_contains_no_web_application_module(self) -> None:
        source_root = ROOT / "demo"
        packages = (
            source_root / "rsl_demo_plugin",
            source_root / "rsl_demo_generator",
        )
        self.assertFalse((source_root / "src").exists())
        self.assertTrue(all(package.is_dir() for package in packages))

        forbidden = ("fastapi", "starlette", "uvicorn")
        for package in packages:
            for source in package.rglob("*.py"):
                text = source.read_text(encoding="utf-8")
                for module in forbidden:
                    with self.subTest(source=source.name, module=module):
                        self.assertNotIn(f"import {module}", text)
                        self.assertNotIn(f"from {module}", text)

    def test_demo_packages_the_minimal_conformance_fixture(self) -> None:
        demo = tomllib.loads(
            (ROOT / "demo" / "pyproject.toml").read_text(encoding="utf-8")
        )
        force_include = demo["tool"]["hatch"]["build"]["targets"]["wheel"][
            "force-include"
        ]
        self.assertEqual(
            force_include["fixtures/minimal-status.jsonl"],
            "rsl_demo_plugin/fixtures/minimal-status.jsonl",
        )
        self.assertTrue(
            (ROOT / "demo" / "fixtures" / "minimal-status.jsonl").is_file()
        )

    def test_setup_removes_the_retired_demo_application_distribution(self) -> None:
        for relative_path in ("scripts/setup_demo.ps1", "scripts/setup_demo.sh"):
            script = (ROOT / relative_path).read_text(encoding="utf-8")
            with self.subTest(script=relative_path):
                self.assertIn(
                    "pip",
                    script,
                )
                self.assertIn(
                    "uninstall",
                    script,
                )
                self.assertIn(
                    "router-dump-analyzer-design",
                    script,
                )
                self.assertIn(
                    ".[test,web]",
                    script,
                )
                self.assertIn(
                    "./demo" if relative_path.endswith(".sh") else ".\\demo",
                    script,
                )


if __name__ == "__main__":
    unittest.main()
