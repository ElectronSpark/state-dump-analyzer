from __future__ import annotations

import ast
import hashlib
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
CORE_WEB = CORE_SOURCE / "web"
CORE_FRONTEND = ROOT / "frontend"
DEMO_ROOT = ROOT / "demo"
DEMO_PLUGIN = DEMO_ROOT / "rsl_demo_plugin"
DEMO_GENERATOR = DEMO_ROOT / "rsl_demo_generator"
DEMO_PACKAGES = (DEMO_PLUGIN, DEMO_GENERATOR)
SCENARIO_GENERATOR_ROOT = ROOT / "state-dump-generator"
SCENARIO_GENERATOR_SOURCE = (
    SCENARIO_GENERATOR_ROOT / "src" / "state_dump_generator"
)

DEMO_IMPORT_ROOTS = frozenset(
    {
        "plugin",
        "generator",
        "rsl_demo_plugin",
        "rsl_demo_generator",
        "router_dump_analyzer_demo",
        "router_dump_analyzer_demo_plugins",
        "router_dump_analyzer_demo_plugin",
        "router_dump_analyzer_demo_generator",
    }
)
DEMO_PLUGIN_POLICY_MODULES = frozenset(
    {
        "__init__.py",
        "archive.py",
        "advanced_trace.py",
        "assembly_store.py",
        "data.py",
        "route_policy.py",
        "scenario_registry.py",
        "scale.py",
        "scale_data.py",
        "session.py",
        "source_records.py",
        "temporal_contract.py",
        "topology_contract.py",
    }
)
WEB_RUNTIME_IMPORT_ROOTS = frozenset({"fastapi", "starlette", "uvicorn"})
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
    def test_normalized_query_foundation_has_one_core_owner(self) -> None:
        core = (
            ROOT
            / "src"
            / "router_dump_analyzer"
            / "normalized_data.py"
        ).read_text(encoding="utf-8")
        demo = (
            DEMO_PLUGIN
            / "data.py"
        ).read_text(encoding="utf-8")
        runtime = (
            DEMO_PLUGIN
            / "session.py"
        ).read_text(encoding="utf-8")

        self.assertIn("class NormalizedDataService:", core)
        self.assertIn("class NormalizedDatasetSource(Protocol):", core)
        self.assertIn("class NormalizedDataPolicy(Protocol):", core)
        for operation in (
            "resource_state_at",
            "relationships_at",
            "resources_at",
            "events_in_range",
            "dashboard_query",
            "range_summary",
            "redact_event_for_client",
        ):
            self.assertIn(f"def {operation}(", core)
            self.assertNotIn(f"def {operation}(", demo)
            self.assertNotIn(f"def {operation}(", runtime)
        self.assertIn("class DemoDatasetSource:", runtime)
        self.assertIn("class DemoDataPolicy:", runtime)
        self.assertNotIn("class DemoDataProvider:", runtime)

    def test_root_and_demo_distributions_share_no_source_file_payloads(
        self,
    ) -> None:
        """Keep the demo dependent on core without copying core source."""

        source_suffixes = {
            ".cmd",
            ".css",
            ".html",
            ".js",
            ".json",
            ".jsonl",
            ".md",
            ".mjs",
            ".ps1",
            ".py",
            ".sh",
            ".toml",
            ".yaml",
            ".yml",
        }

        def source_files(*roots: Path) -> tuple[Path, ...]:
            return tuple(
                sorted(
                    path
                    for root in roots
                    for path in (
                        root.rglob("*")
                        if root.is_dir()
                        else (root,)
                    )
                    if path.is_file()
                    and path.suffix.lower() in source_suffixes
                    and "__pycache__" not in path.parts
                )
            )

        core_files = source_files(
            CORE_SOURCE,
            CORE_FRONTEND,
            ROOT / "scripts",
            ROOT / "pyproject.toml",
        )
        demo_files = source_files(
            *DEMO_PACKAGES,
            DEMO_ROOT / "fixtures",
            DEMO_ROOT / "README.md",
            DEMO_ROOT / "pyproject.toml",
        )
        core_by_digest: dict[str, list[Path]] = {}
        for path in core_files:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            core_by_digest.setdefault(digest, []).append(path)

        duplicates = [
            (
                core_path.relative_to(ROOT).as_posix(),
                demo_path.relative_to(ROOT).as_posix(),
            )
            for demo_path in demo_files
            for core_path in core_by_digest.get(
                hashlib.sha256(demo_path.read_bytes()).hexdigest(),
                (),
            )
        ]
        self.assertEqual(
            duplicates,
            [],
            "demo source duplicates root-owned source payloads: "
            + repr(duplicates),
        )

    def test_repository_has_one_core_one_demo_and_one_independent_generator(
        self,
    ) -> None:
        self.assertTrue((ROOT / "pyproject.toml").is_file())
        self.assertEqual(
            tuple(
                path.relative_to(ROOT).as_posix()
                for path in sorted(ROOT.glob("*/pyproject.toml"))
            ),
            (
                "demo/pyproject.toml",
                "state-dump-generator/pyproject.toml",
            ),
        )
        self.assertTrue(SCENARIO_GENERATOR_SOURCE.is_dir())

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
            f"browser source must stay in the separate core frontend tree: {browser_assets}",
        )

    def test_core_import_graph_cannot_reach_demo_or_web_modules_outside_web_adapter(
        self,
    ) -> None:
        violations: list[str] = []
        for path in _python_files(CORE_SOURCE):
            is_web_adapter = (
                CORE_WEB in path.parents
                or path.name in {
                    "cli.py",
                    "control_plane_server.py",
                    "runtime.py",
                }
            )
            for line, import_name in _literal_imports(path):
                absolute_root = _absolute_import_root(import_name)
                relative_root = _relative_import_root(import_name)
                if absolute_root in DEMO_IMPORT_ROOTS or (
                    absolute_root in WEB_RUNTIME_IMPORT_ROOTS
                    and not is_web_adapter
                ):
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

    def test_core_project_metadata_owns_frontend_but_excludes_demo_runtime(
        self,
    ) -> None:
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
        self.assertEqual(
            scripts.get("router-dump-analyzer"),
            "router_dump_analyzer.cli:main",
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
            f"core base install retains optional web/demo dependencies: {sorted(dependencies)}",
        )
        optional_dependencies = project["project"].get(
            "optional-dependencies",
            {},
        )
        web_dependencies = {
            _dependency_name(requirement)
            for requirement in optional_dependencies.get("web", ())
        }
        self.assertIn("fastapi", web_dependencies)

        wheel = project["tool"]["hatch"]["build"]["targets"]["wheel"]
        force_include = wheel.get("force-include", {})
        normalized_force_include = {
            key.replace("\\", "/").rstrip("/"): value.replace("\\", "/").rstrip("/")
            for key, value in force_include.items()
        }
        self.assertEqual(
            normalized_force_include.get("frontend"),
            "router_dump_analyzer/frontend",
        )
        source_distribution = project["tool"]["hatch"]["build"]["targets"].get(
            "sdist", {}
        )
        included_paths = tuple(source_distribution.get("include", ()))
        self.assertIn(
            "/frontend",
            included_paths,
            f"core source distribution omits frontend assets: {included_paths}",
        )
        self.assertFalse(
            any("demo" in path.replace("\\", "/").split("/") for path in included_paths),
            f"core source distribution includes demo code: {included_paths}",
        )
        self.assertTrue((CORE_FRONTEND / "frontend-manifest.json").is_file())

    def test_demo_project_owns_only_plugin_and_fixture_tooling(self) -> None:
        project_file = DEMO_ROOT / "pyproject.toml"
        self.assertTrue(project_file.is_file())
        project = tomllib.loads(project_file.read_text(encoding="utf-8"))

        self.assertEqual(project["project"]["name"], "router-dump-analyzer-demo")
        self.assertEqual(
            set(project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]),
            {
                "rsl_demo_plugin",
                "rsl_demo_generator",
            },
        )
        self.assertEqual(
            project["project"].get("scripts", {}),
            {},
            "the demo must not install an application or executable",
        )
        self.assertEqual(
            project["project"]["entry-points"][
                "router_dump_analyzer.plugins"
            ],
            {
                "demo_router": "rsl_demo_plugin:plugin"
            },
            "the one demo distribution must install exactly one example plug-in",
        )
        dependencies = {
            _dependency_name(requirement)
            for requirement in project["project"].get("dependencies", ())
        }
        self.assertIn("router-dump-analyzer-core", dependencies)

        force_include = project["tool"]["hatch"]["build"]["targets"]["wheel"].get(
            "force-include", {}
        )
        self.assertEqual(
            force_include,
            {
                "fixtures/minimal-status.jsonl": (
                    "rsl_demo_plugin/fixtures/minimal-status.jsonl"
                ),
                "router-state-lab-default.scenario.json": (
                    "rsl_demo_generator/router-state-lab-default.scenario.json"
                ),
            },
            "the demo wheel may package its conformance fixture and canonical "
            "authoring save, but no application/frontend payload: "
            f"{force_include}",
        )
        included_paths = tuple(
            project["tool"]["hatch"]["build"]["targets"]
            .get("sdist", {})
            .get("include", ())
        )
        self.assertFalse(
            any("frontend" in path.replace("\\", "/").split("/") for path in included_paths),
            f"demo source distribution still embeds frontend assets: {included_paths}",
        )
        self.assertTrue((DEMO_PLUGIN / "__init__.py").is_file())
        self.assertTrue((DEMO_GENERATOR / "__init__.py").is_file())
        self.assertFalse(
            (DEMO_ROOT / "src").exists(),
            "demo packages must live directly under demo/, without a src wrapper",
        )
        for retired_package in (
            "plugin",
            "generator",
            "router_dump_analyzer_demo",
            "router_dump_analyzer_demo_plugins",
            "router_dump_analyzer_demo_plugin",
            "router_dump_analyzer_demo_generator",
        ):
            self.assertFalse(
                (DEMO_ROOT / retired_package).exists(),
                f"retired compatibility namespace remains: {retired_package}",
            )

    def test_demo_source_contains_no_web_application_framework(self) -> None:
        violations: list[str] = []
        for package in DEMO_PACKAGES:
            for path in _python_files(package):
                for line, import_name in _literal_imports(path):
                    if _absolute_import_root(import_name) in WEB_RUNTIME_IMPORT_ROOTS:
                        violations.append(
                            f"{path.relative_to(ROOT)}:{line}: {import_name}"
                        )
        self.assertEqual(
            violations,
            [],
            "the demo plug-in/fixture package imports web application "
            "frameworks:\n" + "\n".join(violations),
        )

    def test_demo_plugin_policy_modules_do_not_import_application_composition(
        self,
    ) -> None:
        violations: list[str] = []
        policy_modules = _python_files(DEMO_PLUGIN)
        self.assertEqual(
            {path.name for path in policy_modules},
            set(DEMO_PLUGIN_POLICY_MODULES),
        )
        for path in policy_modules:
            for line, import_name in _literal_imports(path):
                absolute_root = _absolute_import_root(import_name)
                if absolute_root in {
                    "generator",
                    "rsl_demo_generator",
                    "router_dump_analyzer_demo",
                    "router_dump_analyzer_demo_plugins",
                    "router_dump_analyzer_demo_generator",
                }:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{line}: {import_name}"
                    )
        self.assertEqual(
            violations,
            [],
            "demo plug-in policy depends on demo application composition:\n"
            + "\n".join(violations),
        )

    def test_demo_has_no_packaged_static_presentation_fallback(self) -> None:
        self.assertFalse(
            (DEMO_PLUGIN / "presentation.py").exists(),
            "generated plug-in descriptors must not be shadowed by a static "
            "presentation fallback",
        )

    def test_demo_generator_is_distribution_self_contained(self) -> None:
        generator_root = DEMO_GENERATOR
        obsolete_generators = (
            "generate_demo_fixture.py",
            "generate_packed_scale_bundle.py",
            "generate_sample_bundle.py",
            "generate_scale_fixtures.py",
            "validate_scale_archive.py",
        )
        self.assertEqual(
            [
                name
                for name in obsolete_generators
                if (ROOT / "scripts" / name).exists()
            ],
            [],
            "obsolete repository-level generator entry points remain",
        )

        violations: list[str] = []
        for path in _python_files(generator_root):
            for line, import_name in _literal_imports(path):
                if _absolute_import_root(import_name) == "scripts":
                    violations.append(
                        f"{path.relative_to(ROOT)}:{line}: {import_name}"
                    )
        self.assertEqual(
            violations,
            [],
            "packaged generator imports repository scripts:\n"
            + "\n".join(violations),
        )

        core_source = json.dumps(str(ROOT / "src"))
        demo_root = json.dumps(str(DEMO_ROOT))
        program = textwrap.dedent(
            f"""
            import sys

            sys.path[:] = [
                {core_source},
                {demo_root},
                *[
                    entry
                    for entry in sys.path
                    if "site-packages" not in entry.replace("\\\\", "/")
                    and "dist-packages" not in entry.replace("\\\\", "/")
                ],
            ]

            import importlib.util

            import rsl_demo_generator
            import rsl_demo_generator.__main__

            for retired_name in (
                "plugin",
                "generator",
                "router_dump_analyzer_demo",
                "router_dump_analyzer_demo_plugins",
                "router_dump_analyzer_demo_plugin",
                "router_dump_analyzer_demo_generator",
            ):
                if importlib.util.find_spec(retired_name) is not None:
                    raise SystemExit(
                        "retired demo namespace remains importable: " + retired_name
                    )

            repository_scripts = [
                name for name in sys.modules
                if name == "scripts" or name.startswith("scripts.")
            ]
            if repository_scripts:
                raise SystemExit(
                    "generator imported repository scripts: "
                    + repr(repository_scripts)
                )
            application_modules = (
                "router_dump_analyzer_demo",
                "router_dump_analyzer_demo_plugins",
                "router_dump_analyzer_demo_plugin",
                "router_dump_analyzer_demo_generator",
            )
            loaded_application_modules = [
                name
                for name in sys.modules
                if any(
                    name == module_name or name.startswith(module_name + ".")
                    for module_name in application_modules
                )
            ]
            if loaded_application_modules:
                raise SystemExit(
                    "generator imported demo application composition: "
                    + repr(loaded_application_modules)
                )
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
            "isolated demo generator import failed:\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}",
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
                if module.name == "router_dump_analyzer.web" or module.name.startswith(
                    "router_dump_analyzer.web."
                ):
                    continue
                loaded.append(module.name)
                importlib.import_module(module.name)

            forbidden = [
                name
                for name in sys.modules
                if name.split(".", 1)[0]
                in {sorted(DEMO_IMPORT_ROOTS | WEB_RUNTIME_IMPORT_ROOTS)!r}
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
