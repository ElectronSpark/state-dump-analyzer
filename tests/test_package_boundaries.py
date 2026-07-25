from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path
from typing import Iterator


ROOT = Path(__file__).resolve().parents[1]
CORE_SOURCE = ROOT / "src" / "router_dump_analyzer"
DEMO_ROOT = ROOT / "demo"
DEMO_SOURCE = DEMO_ROOT / "src"
DEMO_APPLICATION = DEMO_SOURCE / "router_dump_analyzer_demo"
DEMO_PLUGINS = DEMO_SOURCE / "router_dump_analyzer_demo_plugins"
DEMO_FRONTEND = DEMO_ROOT / "frontend"

DEMO_IMPORT_ROOTS = frozenset(
    {"router_dump_analyzer_demo", "router_dump_analyzer_demo_plugins"}
)
DEMO_ONLY_IMPORT_ROOTS = frozenset({"fastapi", "starlette", "uvicorn"})
MOVED_CORE_FILENAMES = frozenset(
    {
        "demo_app.py",
        "demo_data.py",
        "demo_fixture_plugin.py",
        "demo_multi_node_route.py",
        "demo_multi_node_topology.py",
        "demo_scale_plugin.py",
        "demo_source_plugin.py",
        "demo_temporal_topology.py",
        "frontend_host.py",
        "scale_data.py",
    }
)


def _python_files(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(path for path in root.rglob("*.py") if path.is_file()))


def _literal_imports(path: Path) -> Iterator[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom):
            prefix = "." * node.level
            yield node.lineno, f"{prefix}{node.module or ''}"
        elif isinstance(node, ast.Call) and node.args:
            function = node.func
            is_dynamic_import = (
                isinstance(function, ast.Name)
                and function.id == "__import__"
            ) or (
                isinstance(function, ast.Attribute)
                and function.attr == "import_module"
            )
            first_argument = node.args[0]
            if (
                is_dynamic_import
                and isinstance(first_argument, ast.Constant)
                and isinstance(first_argument.value, str)
            ):
                yield node.lineno, first_argument.value


def _absolute_import_root(import_name: str) -> str | None:
    if not import_name or import_name.startswith("."):
        return None
    return import_name.split(".", 1)[0]


def _relative_import_root(import_name: str) -> str | None:
    if not import_name.startswith("."):
        return None
    relative_name = import_name.lstrip(".")
    return relative_name.split(".", 1)[0] if relative_name else None


def _dependency_name(requirement: str) -> str:
    name = re.split(r"[\s\[<>=!~;@]", requirement.strip(), maxsplit=1)[0]
    return name.lower().replace("_", "-").replace(".", "-")


class PackageBoundaryTests(unittest.TestCase):
    def test_core_source_contains_only_core_modules(self) -> None:
        self.assertTrue(CORE_SOURCE.is_dir())
        core_files = _python_files(CORE_SOURCE)
        self.assertTrue(core_files)

        moved = sorted(path.name for path in core_files if path.name in MOVED_CORE_FILENAMES)
        prefixed = sorted(
            path.relative_to(CORE_SOURCE).as_posix()
            for path in core_files
            if path.stem == "demo" or path.stem.startswith("demo_")
        )
        browser_assets = sorted(
            path.relative_to(CORE_SOURCE).as_posix()
            for path in CORE_SOURCE.rglob("*")
            if path.is_file() and path.suffix.lower() in {".css", ".html", ".js"}
        )
        self.assertEqual(moved, [], f"demo-owned files remain in core: {moved}")
        self.assertEqual(prefixed, [], f"demo-named files remain in core: {prefixed}")
        self.assertEqual(
            browser_assets,
            [],
            f"demo browser assets remain in core: {browser_assets}",
        )

    def test_core_import_graph_cannot_reach_demo_or_web_application_modules(
        self,
    ) -> None:
        violations: list[str] = []
        for path in _python_files(CORE_SOURCE):
            for line, import_name in _literal_imports(path):
                absolute_root = _absolute_import_root(import_name)
                relative_root = _relative_import_root(import_name)
                if absolute_root in DEMO_IMPORT_ROOTS | DEMO_ONLY_IMPORT_ROOTS:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{line}: {import_name}"
                    )
                if relative_root and (
                    relative_root == "demo"
                    or relative_root.startswith("demo_")
                    or f"{relative_root}.py" in MOVED_CORE_FILENAMES
                ):
                    violations.append(
                        f"{path.relative_to(ROOT)}:{line}: {import_name}"
                    )
        self.assertEqual(
            violations,
            [],
            "core imports demo-owned code:\n" + "\n".join(violations),
        )

    def test_core_project_metadata_excludes_demo_runtime_and_assets(self) -> None:
        project_file = ROOT / "pyproject.toml"
        project = tomllib.loads(project_file.read_text(encoding="utf-8"))

        self.assertEqual(project["project"]["name"], "router-dump-analyzer-core")
        self.assertEqual(
            project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"],
            ["src/router_dump_analyzer"],
        )
        scripts = project["project"].get("scripts", {})
        self.assertEqual(
            scripts.get("router-dump-plugin-validate"),
            "router_dump_analyzer.plugin_validation:main",
        )
        self.assertNotIn("router-dump-demo", scripts)

        dependencies = {
            _dependency_name(requirement)
            for requirement in project["project"].get("dependencies", ())
        }
        self.assertTrue(
            dependencies.isdisjoint(
                {
                    "router-dump-analyzer-demo",
                    "fastapi",
                    "starlette",
                    "uvicorn",
                    "pydantic-core",
                }
            ),
            f"core retains demo runtime dependencies: {sorted(dependencies)}",
        )

        wheel = project["tool"]["hatch"]["build"]["targets"]["wheel"]
        self.assertNotIn("force-include", wheel)
        source_distribution = project["tool"]["hatch"]["build"]["targets"].get(
            "sdist", {}
        )
        included_paths = tuple(source_distribution.get("include", ()))
        self.assertFalse(
            any(
                "frontend" in path.replace("\\", "/").split("/")
                or "demo" in path.replace("\\", "/").split("/")
                for path in included_paths
            ),
            f"core source distribution includes demo assets: {included_paths}",
        )

    def test_demo_project_owns_application_plugins_frontend_and_cli(self) -> None:
        project_file = DEMO_ROOT / "pyproject.toml"
        self.assertTrue(project_file.is_file())
        project = tomllib.loads(project_file.read_text(encoding="utf-8"))

        self.assertEqual(project["project"]["name"], "router-dump-analyzer-demo")
        self.assertEqual(
            set(project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]),
            {
                "src/router_dump_analyzer_demo",
                "src/router_dump_analyzer_demo_plugins",
            },
        )
        self.assertEqual(
            project["project"]["scripts"].get("router-dump-demo"),
            "router_dump_analyzer_demo.app:main",
        )
        dependencies = {
            _dependency_name(requirement)
            for requirement in project["project"].get("dependencies", ())
        }
        self.assertIn("router-dump-analyzer-core", dependencies)

        force_include = project["tool"]["hatch"]["build"]["targets"]["wheel"].get(
            "force-include", {}
        )
        normalized_force_include = {
            key.replace("\\", "/").rstrip("/"): value.replace("\\", "/").rstrip("/")
            for key, value in force_include.items()
        }
        self.assertEqual(
            normalized_force_include.get("frontend"),
            "router_dump_analyzer_demo/frontend",
        )
        self.assertTrue(
            (DEMO_FRONTEND / "frontend-manifest.json").is_file(),
            "demo frontend manifest is missing",
        )
        self.assertTrue((DEMO_APPLICATION / "__init__.py").is_file())
        self.assertTrue((DEMO_PLUGINS / "__init__.py").is_file())

    def test_demo_plugins_never_import_the_demo_application(self) -> None:
        self.assertTrue(DEMO_PLUGINS.is_dir())
        violations: list[str] = []
        for path in _python_files(DEMO_PLUGINS):
            for line, import_name in _literal_imports(path):
                if _absolute_import_root(import_name) == "router_dump_analyzer_demo":
                    violations.append(
                        f"{path.relative_to(ROOT)}:{line}: {import_name}"
                    )
        self.assertEqual(
            violations,
            [],
            "demo plug-ins depend on the demo application:\n"
            + "\n".join(violations),
        )

    def test_core_imports_in_an_isolated_subprocess_without_demo_or_site_packages(
        self,
    ) -> None:
        core_source = json.dumps(str(ROOT / "src"))
        program = textwrap.dedent(
            f"""
            import importlib
            import pkgutil
            import sys

            sys.path[:] = [
                {core_source},
                *[
                    entry
                    for entry in sys.path
                    if "site-packages" not in entry.replace("\\\\", "/")
                    and "dist-packages" not in entry.replace("\\\\", "/")
                ],
            ]

            import router_dump_analyzer

            loaded = []
            for module in pkgutil.walk_packages(
                router_dump_analyzer.__path__,
                prefix="router_dump_analyzer.",
            ):
                loaded.append(module.name)
                importlib.import_module(module.name)

            forbidden = [
                name
                for name in sys.modules
                if name.split(".", 1)[0]
                in {sorted(DEMO_IMPORT_ROOTS | DEMO_ONLY_IMPORT_ROOTS)!r}
            ]
            if forbidden:
                raise SystemExit("core imported forbidden modules: " + repr(forbidden))
            if not loaded:
                raise SystemExit("no core submodules were discovered")
            """
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            completed = subprocess.run(
                [sys.executable, "-I", "-c", program],
                cwd=temporary_directory,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
        self.assertEqual(
            completed.returncode,
            0,
            "isolated core import failed:\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
