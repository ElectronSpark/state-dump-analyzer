from __future__ import annotations

import ast
import json
import re
import sys
import tempfile
import tomllib
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from router_dump_analyzer.annotation_store import (
    CorrelationReportProvenanceClass,
)
from router_dump_analyzer.private_analysis import (
    ASSISTANT_DIRECT_GROUND_TRUTH_MUTATION_ALLOWED,
    ASSISTANT_DIRECT_PLUGIN_AUTHORITY_ALLOWED,
    PRIVATE_ANALYSIS_POLICY_VERSION,
    PUBLIC_MODEL_API_INTEGRATION_ALLOWED,
    PrivateAnalysisContributionKind,
    PrivateAnalysisPolicy,
    PrivateAnalysisTransport,
)

ROOT = Path(__file__).resolve().parents[1]
CORE_SOURCE = ROOT / "src" / "router_dump_analyzer"
PRIVATE_ANALYSIS_SOURCE = CORE_SOURCE / "private_analysis"
PRIVATE_ANALYSIS_TOOL_SERVICE_SOURCE = CORE_SOURCE / "private_analysis_tool_service.py"
PRIVATE_ANALYSIS_EXECUTION_SOURCE = CORE_SOURCE / "private_analysis_execution.py"
PRIVATE_ANALYSIS_SERVICE_SOURCE = CORE_SOURCE / "private_analysis_service.py"
PRIVATE_ANALYSIS_IN_PROCESS_RUNNER_SOURCE = (
    CORE_SOURCE / "private_analysis_in_process_runner.py"
)
PRIVATE_ANALYSIS_RUNNER_SUPPORT_SOURCE = (
    CORE_SOURCE / "private_analysis_runner_support.py"
)
PRIVATE_ANALYSIS_SUBPROCESS_RUNNER_SOURCE = (
    CORE_SOURCE / "private_analysis_subprocess_runner.py"
)
DECISION_DOCUMENT = ROOT / "docs" / "private-ai-analysis.md"

APPROVED_PROJECT_REQUIREMENTS = {
    "base": frozenset(),
    "web": frozenset({"fastapi>=0.115,<1", "uvicorn>=0.30,<1"}),
    "test": frozenset(
        {
            "fastapi>=0.115,<1",
            "httpx>=0.27,<1",
            "mypy>=1.15,<2",
            "pytest>=8.3,<9",
            "pytest-subtests>=0.14,<1",
            "ruff>=0.12,<1",
            "uvicorn>=0.30,<1",
        }
    ),
}
APPROVED_BUILD_SYSTEM_REQUIREMENTS = frozenset({"hatchling>=1.27"})
APPROVED_BUILD_BACKEND = "hatchling.build"
APPROVED_PACKAGING_MANIFESTS = {
    "pyproject.toml": {
        "requirements": APPROVED_PROJECT_REQUIREMENTS,
        "scripts": {
            "router-dump-analyzer": "router_dump_analyzer.cli:main",
            "router-dump-health": "router_dump_analyzer.health_cli:main",
            "router-dump-ingest": "router_dump_analyzer.pipeline_cli:main",
            "router-dump-maintain": "router_dump_analyzer.maintenance_cli:main",
            "router-dump-plugin-validate": (
                "router_dump_analyzer.plugin_validation:main"
            ),
            "router-dump-private-analysis": (
                "router_dump_analyzer.private_analysis_cli:main"
            ),
            "router-dump-server": "router_dump_analyzer.server_cli:main",
        },
        "entry-points": {},
        "tool": {
            "hatch": {
                "build": {
                    "targets": {
                        "wheel": {
                            "packages": ["src/router_dump_analyzer"],
                            "force-include": {
                                "frontend": "router_dump_analyzer/frontend"
                            },
                        },
                        "sdist": {
                            "include": [
                                "/src",
                                "/frontend",
                                "/README.md",
                                "/pyproject.toml",
                            ]
                        },
                    }
                }
            },
            "pytest": {"ini_options": {"testpaths": ["tests"]}},
        },
    },
    "demo/pyproject.toml": {
        "requirements": {
            "base": frozenset(
                {
                    "pydantic-core>=2.20,<3",
                    "router-dump-analyzer-core>=0.1.0,<1",
                }
            )
        },
        "scripts": {},
        "entry-points": {
            "router_dump_analyzer.plugins": {"demo_router": "rsl_demo_plugin:plugin"}
        },
        "tool": {
            "hatch": {
                "build": {
                    "targets": {
                        "wheel": {
                            "packages": [
                                "rsl_demo_plugin",
                                "rsl_demo_generator",
                            ],
                            "force-include": {
                                "fixtures/minimal-status.jsonl": (
                                    "rsl_demo_plugin/fixtures/minimal-status.jsonl"
                                ),
                                "router-state-lab-default.scenario.json": (
                                    "rsl_demo_generator/"
                                    "router-state-lab-default.scenario.json"
                                ),
                            },
                        },
                        "sdist": {
                            "include": [
                                "/rsl_demo_plugin",
                                "/rsl_demo_generator",
                                "/fixtures/minimal-status.jsonl",
                                "/router-state-lab-default.scenario.json",
                                "/README.md",
                                "/pyproject.toml",
                            ]
                        },
                    }
                }
            }
        },
    },
    "state-dump-generator/pyproject.toml": {
        "requirements": {"base": frozenset()},
        "scripts": {"state-dump-generator": "state_dump_generator.__main__:main"},
        "entry-points": {},
        "tool": {
            "hatch": {
                "build": {
                    "targets": {
                        "wheel": {
                            "packages": ["src/state_dump_generator"],
                            "force-include": {
                                "src/state_dump_generator/web": (
                                    "state_dump_generator/web"
                                )
                            },
                        },
                        "sdist": {
                            "include": [
                                "/src",
                                "/tests",
                                "/README.md",
                                "/environment.yml",
                                "/launch.cmd",
                                "/launch.ps1",
                                "/launch.sh",
                                "/pyproject.toml",
                            ]
                        },
                    }
                }
            },
            "pytest": {
                "ini_options": {
                    "testpaths": ["tests"],
                    "pythonpath": ["src"],
                }
            },
        },
    },
}
APPROVED_ENVIRONMENT_MANIFESTS = {
    "environment.yml": (
        "name: router-dump-analyzer-demo",
        "channels:",
        "  - conda-forge",
        "dependencies:",
        "  - python=3.12",
        "  - pip>=24",
        "  - pip:",
        "      - -e .[test,web]",
        "      - -e ./demo",
    ),
    "state-dump-generator/environment.yml": (
        "name: state-dump-generator",
        "channels:",
        "  - conda-forge",
        "dependencies:",
        "  - python=3.12",
        "  - pip",
        "  - pip:",
        "      - -e .",
    ),
}
APPROVED_NODE_MANIFESTS = {
    "frontend/package.json": {
        "name": "router-dump-analyzer-core-frontend",
        "private": True,
        "version": "0.1.0",
        "type": "module",
        "engines": {"node": ">=18"},
        "scripts": {
            "check": "node scripts/check.mjs && node --test",
            "test": "node --test",
            "serve": "node scripts/dev-server.mjs",
        },
    }
}
DEPENDENCY_MANIFEST_NAMES = frozenset(
    {
        "Pipfile",
        "Pipfile.lock",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "conda-lock.yml",
        "conda-lock.yaml",
        "environment.yml",
        "environment.yaml",
        "pdm.lock",
        "poetry.lock",
        "pyproject.toml",
        "requirements.in",
        "requirements.txt",
        "setup.cfg",
        "setup.py",
        "uv.lock",
        "yarn.lock",
    }
)
APPROVED_EXTERNAL_IMPORT_ROOTS = frozenset({"fastapi", "starlette", "uvicorn"})
PRIVATE_ANALYSIS_ALLOWED_IMPORT_PREFIXES = (
    "__future__",
    ".policy",
    "collections.abc",
    "dataclasses",
    "enum",
    "json",
    "typing",
)
PRIVATE_ANALYSIS_ALLOWED_PARENT_IMPORTS = frozenset(
    {
        "..canonical",
        "..contract_validation",
        "..public_text",
        "..value_core",
    }
)
NETWORK_CAPABLE_IMPORT_PREFIXES = (
    "aiohttp",
    "anyio",
    "asyncio",
    "ftplib",
    "grpc",
    "http.client",
    "httpcore",
    "httpx",
    "imaplib",
    "nntplib",
    "poplib",
    "requests",
    "smtplib",
    "socket",
    "ssl",
    "telnetlib",
    "trio",
    "urllib.request",
    "urllib3",
    "websockets",
    "xmlrpc.client",
)
CORE_NETWORK_IMPORT_ALLOWLIST = {
    "cli.py": ("asyncio",),
    "control_plane_server.py": ("asyncio",),
    "multi_node_topology.py": ("urllib.parse",),
    "runtime.py": ("asyncio",),
    "web/control_plane_api.py": ("asyncio", "urllib.parse"),
}
CORE_ASYNCIO_ATTRIBUTE_ALLOWLIST = {
    "cli.py": frozenset({"Runner", "run"}),
    "control_plane_server.py": frozenset({"to_thread"}),
    "runtime.py": frozenset({"to_thread"}),
    "web/control_plane_api.py": frozenset({"sleep", "to_thread"}),
}
PUBLIC_MODEL_ENDPOINT_MARKERS = (
    "api.anthropic.com",
    "api.cohere.ai",
    "api.mistral.ai",
    "api.openai.com",
    "bedrock-runtime.",
    "generativelanguage.googleapis.com",
    ".openai.azure.com",
)
PUBLIC_MODEL_CONFIGURATION_MARKERS = (
    "anthropic_api_key",
    "ai_model_api_key",
    "ai_model_endpoint",
    "cohere_api_key",
    "google_api_key",
    "llm_api_key",
    "llm_base_url",
    "llm_endpoint",
    "llm_fallback",
    "mistral_api_key",
    "model_api_key",
    "model_base_url",
    "model_endpoint",
    "model_fallback",
    "openai_api_key",
)
PUBLIC_MODEL_PROVIDER_PACKAGE_MARKERS = frozenset(
    {
        "anthropic",
        "cohere",
        "google-generativeai",
        "litellm",
        "mistralai",
        "openai",
    }
)
MODEL_CONFIGURATION_SUBJECTS = (
    "ai",
    "anthropic",
    "azureopenai",
    "bedrock",
    "cloudmodel",
    "cohere",
    "gemini",
    "llm",
    "mistral",
    "model",
    "openai",
    "privatemodel",
    "publicprovider",
    "publicmodel",
    "remoteprovider",
    "remotemodel",
    "vertexai",
)
MODEL_LOCATION_TERMS = (
    "api",
    "apibase",
    "apiendpoint",
    "apigateway",
    "apihost",
    "apihostname",
    "apiuri",
    "apiurl",
    "base",
    "baseurl",
    "endpoint",
    "gateway",
    "host",
    "hostname",
    "uri",
    "url",
)
MODEL_SECRET_TERMS = (
    "apikey",
    "credential",
    "credentials",
    "key",
    "secret",
    "token",
)
NORMALIZED_MODEL_CONFIGURATION_MARKERS = frozenset(
    {
        *(
            f"{subject}{term}"
            for subject in MODEL_CONFIGURATION_SUBJECTS
            for term in MODEL_LOCATION_TERMS
        ),
        *(
            f"{subject}{term}"
            for subject in MODEL_CONFIGURATION_SUBJECTS
            for term in MODEL_SECRET_TERMS
        ),
        *(
            f"{subject}{term}"
            for subject in MODEL_CONFIGURATION_SUBJECTS
            for term in ("backup", "failover", "fallback")
        ),
        *(
            f"{term}{subject}"
            for subject in MODEL_CONFIGURATION_SUBJECTS
            for term in ("backup", "failover", "fallback")
        ),
        "allowcloudmodel",
        "allowpublicmodel",
        "allowremoteprovider",
        "cloudmodelallowed",
        "enablecloudmodel",
        "enablepublicmodel",
        "enableremoteprovider",
    }
)
NON_DEPLOYABLE_TOP_LEVELS = frozenset(
    {
        ".agents",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".runtime",
        "docs",
        "samples",
        "tests",
    }
)
DEPLOYABLE_TEXT_SUFFIXES = frozenset(
    {
        "",
        ".bat",
        ".cfg",
        ".cmd",
        ".conf",
        ".css",
        ".env",
        ".html",
        ".ini",
        ".js",
        ".json",
        ".mjs",
        ".properties",
        ".ps1",
        ".py",
        ".sh",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".yaml",
        ".yml",
    }
)


def _python_files(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(path for path in root.rglob("*.py") if path.is_file()))


def _literal_imports(path: Path) -> tuple[tuple[int, str], ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = "." * node.level
            module_name = f"{prefix}{node.module or ''}"
            imports.append((node.lineno, module_name))
            if node.module in {"asyncio", "http", "urllib", "xmlrpc"}:
                imports.extend(
                    (node.lineno, f"{module_name}.{alias.name}")
                    for alias in node.names
                    if alias.name != "*"
                )
        elif isinstance(node, ast.Call) and node.args:
            function = node.func
            is_dynamic_import = (
                isinstance(function, ast.Name) and function.id == "__import__"
            ) or (
                isinstance(function, ast.Attribute) and function.attr == "import_module"
            )
            argument = node.args[0]
            if (
                is_dynamic_import
                and isinstance(argument, ast.Constant)
                and isinstance(argument.value, str)
            ):
                imports.append((node.lineno, argument.value))
    return tuple(imports)


def _matches_prefix(value: str, prefixes: tuple[str, ...]) -> bool:
    return any(value == prefix or value.startswith(f"{prefix}.") for prefix in prefixes)


def _dependency_policy_violations(
    project: dict[str, object],
    *,
    manifest_name: str = "pyproject.toml",
) -> tuple[str, ...]:
    policy = APPROVED_PACKAGING_MANIFESTS.get(manifest_name)
    if policy is None:
        return (f"unapproved packaging manifest {manifest_name}",)
    project_table = project.get("project")
    if not isinstance(project_table, dict):
        return ("project metadata is missing [project]",)
    groups: dict[str, object] = {
        "base": project_table.get("dependencies", ()),
    }
    violations: list[str] = []
    if "dependencies" not in project_table or not isinstance(
        project_table.get("dependencies"),
        list,
    ):
        violations.append("project dependencies must be an explicit list")
    if "dynamic" in project_table:
        violations.append("project dynamic metadata is not allowed")
    optional = project_table.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        return ("project optional-dependencies must be a table",)
    groups.update(optional)
    approved_requirements = policy["requirements"]
    assert isinstance(approved_requirements, dict)
    unexpected_groups = sorted(set(groups) - set(approved_requirements))
    violations.extend(
        f"unapproved dependency group {name}" for name in unexpected_groups
    )
    for group_name, approved in approved_requirements.items():
        raw_requirements = groups.get(group_name, ())
        if not isinstance(raw_requirements, list):
            raw_requirements = (
                tuple(raw_requirements) if isinstance(raw_requirements, tuple) else ()
            )
        actual = {str(requirement).strip() for requirement in raw_requirements}
        for requirement in sorted(actual - approved):
            violations.append(f"{group_name}: unapproved requirement {requirement}")
        for requirement in sorted(approved - actual):
            violations.append(
                f"{group_name}: missing approved requirement {requirement}"
            )
    build_system = project.get("build-system")
    if not isinstance(build_system, dict):
        violations.append("project metadata is missing [build-system]")
    else:
        raw_build_requirements = build_system.get("requires", ())
        actual_build_requirements = (
            {str(item).strip() for item in raw_build_requirements}
            if isinstance(raw_build_requirements, list)
            else set()
        )
        if actual_build_requirements != APPROVED_BUILD_SYSTEM_REQUIREMENTS:
            violations.append(
                "unapproved build-system requirements "
                f"{sorted(actual_build_requirements)}"
            )
        if build_system.get("build-backend") != APPROVED_BUILD_BACKEND:
            violations.append(
                f"unapproved build backend {build_system.get('build-backend')!r}"
            )
        unexpected_build_keys = sorted(
            set(build_system) - {"requires", "build-backend"}
        )
        violations.extend(
            f"unapproved build-system field {name}" for name in unexpected_build_keys
        )
    for executable_field in ("scripts", "gui-scripts", "entry-points"):
        actual = project_table.get(executable_field, {})
        expected = policy.get(executable_field, {})
        if actual != expected:
            violations.append(f"unapproved project {executable_field} {actual!r}")
    tool = project.get("tool", {})
    if tool != policy["tool"]:
        violations.append(
            "tool metadata must match the approved static build and test tables"
        )
    return tuple(violations)


def _dependency_manifest_violations(root: Path) -> tuple[str, ...]:
    discovered: set[str] = set()
    ignored_parts = NON_DEPLOYABLE_TOP_LEVELS | {"__pycache__"}
    for path in root.rglob("*"):
        if not path.is_file() or any(part in ignored_parts for part in path.parts):
            continue
        name = path.name
        is_manifest = (
            name in DEPENDENCY_MANIFEST_NAMES
            or (name.startswith("requirements") and path.suffix in {".in", ".txt"})
            or (name.startswith("environment") and path.suffix in {".yaml", ".yml"})
            or (name.startswith("conda-lock") and path.suffix in {".yaml", ".yml"})
        )
        if is_manifest:
            discovered.add(path.relative_to(root).as_posix())
    approved = (
        set(APPROVED_PACKAGING_MANIFESTS)
        | set(APPROVED_ENVIRONMENT_MANIFESTS)
        | set(APPROVED_NODE_MANIFESTS)
    )
    violations = [
        f"unapproved dependency manifest {name}"
        for name in sorted(discovered - approved)
    ]
    violations.extend(
        f"missing approved dependency manifest {name}"
        for name in sorted(approved - discovered)
    )
    for name in APPROVED_PACKAGING_MANIFESTS:
        path = root / name
        if path.is_file():
            project = tomllib.loads(path.read_text(encoding="utf-8"))
            violations.extend(
                f"{name}: {item}"
                for item in _dependency_policy_violations(
                    project,
                    manifest_name=name,
                )
            )
    for name, expected_lines in APPROVED_ENVIRONMENT_MANIFESTS.items():
        path = root / name
        if (
            path.is_file()
            and tuple(path.read_text(encoding="utf-8").rstrip().splitlines())
            != expected_lines
        ):
            violations.append(
                f"{name}: environment dependencies differ from the approved manifest"
            )
    for name, expected in APPROVED_NODE_MANIFESTS.items():
        path = root / name
        if path.is_file() and json.loads(path.read_text(encoding="utf-8")) != expected:
            violations.append(
                f"{name}: node package metadata differs from the approved manifest"
            )
    return tuple(violations)


def _private_analysis_import_violations(source_root: Path) -> tuple[str, ...]:
    violations: list[str] = []
    forbidden_reflective_members = frozenset(
        {
            "_getframe",
            "ag_code",
            "ag_frame",
            "cr_code",
            "cr_frame",
            "f_builtins",
            "f_code",
            "f_globals",
            "f_locals",
            "gi_code",
            "gi_frame",
            "tb_frame",
        }
    )
    allowed_external_members = {
        "..canonical": frozenset(
            {
                "strict_canonical_json",
                "strict_canonical_json_sha256",
                "validate_prefixed_lowercase_sha256",
            }
        ),
        "..contract_validation": frozenset({"validate_bounded_json_value"}),
        "..public_text": frozenset(
            {
                "contains_filesystem_identity_path",
                "contains_unsafe_identifier_text",
                "has_visible_identity_anchor",
            }
        ),
        "..value_core": frozenset(
            {"MAX_JSON_SAFE_INTEGER", "parse_canonical_decimal_integer"}
        ),
        "__future__": frozenset({"annotations"}),
        "collections.abc": frozenset({"Callable"}),
        "dataclasses": frozenset({"dataclass"}),
        "enum": frozenset({"StrEnum"}),
        "json": frozenset({"JSONDecodeError", "loads"}),
        "typing": frozenset({"Any", "Final"}),
    }
    for path in _python_files(source_root):
        relative = path.relative_to(source_root).as_posix()
        for line, import_name in _literal_imports(path):
            if (
                import_name.startswith("..")
                and import_name not in PRIVATE_ANALYSIS_ALLOWED_PARENT_IMPORTS
            ):
                violations.append(
                    f"{relative}:{line}: import escapes private_analysis {import_name}"
                )
            elif import_name.startswith("."):
                continue
            elif not _matches_prefix(
                import_name,
                PRIVATE_ANALYSIS_ALLOWED_IMPORT_PREFIXES,
            ):
                violations.append(
                    f"{relative}:{line}: unapproved private-analysis import "
                    f"{import_name}"
                )
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                violations.append(
                    f"{relative}:{node.lineno}: module-object imports are forbidden"
                )
            elif isinstance(node, ast.ImportFrom):
                module_key = "." * node.level + (node.module or "")
                if node.level > 0 and node.module is None:
                    violations.append(
                        f"{relative}:{node.lineno}: relative module-object imports "
                        "are forbidden"
                    )
                    continue
                if any(alias.name == "*" for alias in node.names):
                    violations.append(
                        f"{relative}:{node.lineno}: wildcard imports are forbidden"
                    )
                    continue
                reflective = sorted(
                    alias.name
                    for alias in node.names
                    if (alias.name.startswith("__") and alias.name.endswith("__"))
                    or alias.name in forbidden_reflective_members
                )
                if reflective:
                    violations.append(
                        f"{relative}:{node.lineno}: reflective import members are "
                        f"forbidden: {', '.join(reflective)}"
                    )
                    continue
                allowed = allowed_external_members.get(module_key)
                if allowed is None:
                    if node.level != 1:
                        violations.append(
                            f"{relative}:{node.lineno}: unapproved ImportFrom module "
                            f"{module_key}"
                        )
                    continue
                unexpected = sorted(
                    alias.name for alias in node.names if alias.name not in allowed
                )
                if unexpected:
                    violations.append(
                        f"{relative}:{node.lineno}: unapproved members imported from "
                        f"{module_key}: {', '.join(unexpected)}"
                    )
    return tuple(sorted(set(violations)))


def _private_analysis_forbidden_capability(
    node: ast.AST,
    *,
    forbidden_aliases: set[str],
    builtin_namespace_aliases: set[str],
    forbidden_names: frozenset[str],
) -> str | None:
    allowed_dunder_attributes = frozenset(
        {
            "__bases__",
            "__init_subclass__",
            "__name__",
            "__post_init__",
            "__setattr__",
        }
    )
    forbidden_reflective_attributes = frozenset(
        {
            "__builtins__",
            "__class__",
            "__closure__",
            "__code__",
            "__dict__",
            "__getattribute__",
            "__globals__",
            "__mro__",
            "__self__",
            "__subclasses__",
            "__traceback__",
            "_getframe",
            "ag_code",
            "ag_frame",
            "cr_code",
            "cr_frame",
            "f_builtins",
            "f_code",
            "f_globals",
            "f_locals",
            "gi_code",
            "gi_frame",
            "tb_frame",
        }
    )
    if isinstance(node, ast.Attribute):
        if (
            node.attr.startswith("__")
            and node.attr.endswith("__")
            and node.attr not in allowed_dunder_attributes
        ):
            return node.attr
        if node.attr in forbidden_reflective_attributes:
            return node.attr
    if isinstance(node, ast.MatchClass):
        for attribute in node.kwd_attrs:
            if (
                attribute.startswith("__")
                and attribute.endswith("__")
                and attribute not in allowed_dunder_attributes
            ) or attribute in forbidden_reflective_attributes:
                return attribute
    if isinstance(node, ast.Name) and node.id in forbidden_aliases:
        return node.id
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in builtin_namespace_aliases
        and node.attr in forbidden_names
    ):
        return node.attr
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id in builtin_namespace_aliases
        and isinstance(node.slice, ast.Constant)
        and node.slice.value in forbidden_names
    ):
        return str(node.slice.value)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"get", "__getitem__"}
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in builtin_namespace_aliases
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value in forbidden_names
    ):
        return str(node.args[0].value)
    return None


def _private_analysis_dynamic_execution_violations(
    source_root: Path,
) -> tuple[str, ...]:
    violations: list[str] = []
    forbidden_names = frozenset(
        {
            "__import__",
            "__cached__",
            "__file__",
            "__loader__",
            "__name__",
            "__package__",
            "__spec__",
            "compile",
            "eval",
            "exec",
            "getattr",
            "globals",
            "locals",
            "open",
            "vars",
        }
    )
    forbidden_attributes = frozenset({"__import__", "import_module"})
    for path in _python_files(source_root):
        relative = path.relative_to(source_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        forbidden_aliases = set(forbidden_names)
        builtin_namespace_aliases = {"builtins", "__builtins__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                builtin_namespace_aliases.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "builtins"
                )
            elif isinstance(node, ast.ImportFrom) and node.module == "builtins":
                forbidden_aliases.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name in forbidden_names
                )

        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and isinstance(node.value, ast.Name)
                    and node.value.id in builtin_namespace_aliases
                ):
                    namespace_targets = (
                        node.targets if isinstance(node, ast.Assign) else (node.target,)
                    )
                    for target in namespace_targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id not in builtin_namespace_aliases
                        ):
                            builtin_namespace_aliases.add(target.id)
                            changed = True
                if (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and _private_analysis_forbidden_capability(
                        node.value,
                        forbidden_aliases=forbidden_aliases,
                        builtin_namespace_aliases=builtin_namespace_aliases,
                        forbidden_names=forbidden_names,
                    )
                    is not None
                ):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else (node.target,)
                    )
                    for target in targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id not in forbidden_aliases
                        ):
                            forbidden_aliases.add(target.id)
                            changed = True
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            parent = parents.get(node)
            if not isinstance(node, ast.Call):
                if (
                    isinstance(node, ast.Name)
                    and isinstance(node.ctx, ast.Load)
                    and node.id in builtin_namespace_aliases
                ):
                    violations.append(
                        f"{relative}:{node.lineno}: builtin namespace capability "
                        "escapes direct validation"
                    )
                    continue
                capability = _private_analysis_forbidden_capability(
                    node,
                    forbidden_aliases=forbidden_aliases,
                    builtin_namespace_aliases=builtin_namespace_aliases,
                    forbidden_names=forbidden_names,
                )
                if capability is not None and not (
                    isinstance(parent, ast.Call) and parent.func is node
                ):
                    violations.append(
                        f"{relative}:{node.lineno}: dynamic execution capability "
                        "escapes direct validation"
                    )
                continue
            function = node.func
            capability = _private_analysis_forbidden_capability(
                node,
                forbidden_aliases=forbidden_aliases,
                builtin_namespace_aliases=builtin_namespace_aliases,
                forbidden_names=forbidden_names,
            )
            if capability is None:
                capability = _private_analysis_forbidden_capability(
                    function,
                    forbidden_aliases=forbidden_aliases,
                    builtin_namespace_aliases=builtin_namespace_aliases,
                    forbidden_names=forbidden_names,
                )
            if capability is not None:
                violations.append(
                    f"{relative}:{node.lineno}: dynamic execution {capability}"
                )
            elif (
                isinstance(function, ast.Attribute)
                and function.attr in forbidden_attributes
            ):
                violations.append(
                    f"{relative}:{node.lineno}: dynamic execution {function.attr}"
                )
            elif (
                isinstance(function, ast.Name)
                and function.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in forbidden_names | forbidden_attributes
            ):
                violations.append(f"{relative}:{node.lineno}: dynamic import lookup")
    return tuple(sorted(set(violations)))


def _core_dynamic_import_violations(source_root: Path) -> tuple[str, ...]:
    allowed_literal_imports = {
        ("filesystem_lock.py", "exclusive_file_lock", "fcntl"),
        ("filesystem_lock.py", "try_exclusive_file_lock", "fcntl"),
        ("filesystem_lock.py", "try_existing_exclusive_file_lock", "fcntl"),
    }
    allowed_import_module_sites = {
        ("plugin_loading.py", "load_plugin_module"),
        (
            "private_analysis_deployment.py",
            "load_private_analysis_deployment",
        ),
        ("server_cli.py", "_load_identity_resolver"),
    }
    forbidden_loader_import_prefixes = (
        "importlib.machinery",
        "importlib.util",
        "pkgutil",
        "zipimport",
    )
    forbidden_loader_call_names = frozenset(
        {
            "ExtensionFileLoader",
            "FileFinder",
            "PathFinder",
            "SourceFileLoader",
            "SourcelessFileLoader",
            "exec_module",
            "find_loader",
            "find_spec",
            "get_importer",
            "get_loader",
            "iter_importer_modules",
            "iter_importers",
            "iter_modules",
            "load_module",
            "module_for_loader",
            "module_from_spec",
            "resolve_name",
            "spec_from_file_location",
            "spec_from_loader",
            "walk_packages",
            "zipimporter",
        }
    )
    violations: list[str] = []
    for path in _python_files(source_root):
        relative = path.relative_to(source_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }

        def enclosing_function(
            node: ast.AST,
            *,
            parent_map: dict[ast.AST, ast.AST] = parents,
        ) -> str | None:
            parent = parent_map.get(node)
            while parent is not None:
                if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return parent.name
                parent = parent_map.get(parent)
            return None

        import_aliases = {"__import__"}
        builtins_module_aliases = {
            alias.asname or "builtins"
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == "builtins"
        }
        import_aliases.update(
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "builtins"
            for alias in node.names
            if alias.name == "__import__"
        )
        importlib_module_aliases = {
            alias.asname or "importlib"
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == "importlib"
        }
        import_module_aliases = {
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "importlib"
            for alias in node.names
            if alias.name == "import_module"
        }
        loader_callable_aliases = {
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and (
                node.module in {"importlib.machinery", "importlib.util", "pkgutil"}
                or node.module == "zipimport"
            )
            for alias in node.names
            if alias.name in forbidden_loader_call_names
        }
        getattr_aliases = {
            "getattr",
            *(
                alias.asname or alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module == "builtins"
                for alias in node.names
                if alias.name == "getattr"
            ),
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_names = tuple(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported_names = (node.module,)
                if node.module == "importlib":
                    imported_names += tuple(
                        f"importlib.{alias.name}"
                        for alias in node.names
                        if alias.name in {"machinery", "util"}
                    )
            else:
                continue
            for imported_name in imported_names:
                if _matches_prefix(
                    imported_name,
                    forbidden_loader_import_prefixes,
                ):
                    violations.append(
                        f"{relative}:{node.lineno}: unapproved import machinery "
                        f"{imported_name}"
                    )

        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and (
                    (
                        isinstance(node.value, ast.Name)
                        and node.value.id in getattr_aliases
                    )
                    or (
                        isinstance(node.value, ast.Attribute)
                        and node.value.attr == "getattr"
                        and isinstance(node.value.value, ast.Name)
                        and node.value.value.id in builtins_module_aliases
                    )
                ):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else (node.target,)
                    )
                    for target in targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id not in getattr_aliases
                        ):
                            getattr_aliases.add(target.id)
                            changed = True
                if (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and isinstance(node.value, ast.Name)
                    and node.value.id in builtins_module_aliases
                ):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else (node.target,)
                    )
                    for target in targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id not in builtins_module_aliases
                        ):
                            builtins_module_aliases.add(target.id)
                            changed = True
                if (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and isinstance(node.value, ast.Name)
                    and node.value.id in import_aliases
                ):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else (node.target,)
                    )
                    for target in targets:
                        if (
                            isinstance(target, ast.Name)
                            and target.id not in import_aliases
                        ):
                            import_aliases.add(target.id)
                            changed = True
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else (node.target,)
                    )
                    source_is_import_module = (
                        isinstance(node.value, ast.Name)
                        and node.value.id in import_module_aliases
                    ) or (
                        isinstance(node.value, ast.Attribute)
                        and isinstance(node.value.value, ast.Name)
                        and node.value.value.id in importlib_module_aliases
                        and node.value.attr == "import_module"
                    )
                    if source_is_import_module:
                        for target in targets:
                            if (
                                isinstance(target, ast.Name)
                                and target.id not in import_module_aliases
                            ):
                                import_module_aliases.add(target.id)
                                changed = True
                    source_is_builtin_import = (
                        isinstance(node.value, ast.Attribute)
                        and isinstance(node.value.value, ast.Name)
                        and node.value.value.id in builtins_module_aliases
                        and node.value.attr == "__import__"
                    )
                    if source_is_builtin_import:
                        for target in targets:
                            if (
                                isinstance(target, ast.Name)
                                and target.id not in import_aliases
                            ):
                                import_aliases.add(target.id)
                                changed = True
                    source_is_loader_callable = (
                        isinstance(node.value, ast.Name)
                        and node.value.id in loader_callable_aliases
                    ) or (
                        isinstance(node.value, ast.Attribute)
                        and node.value.attr in forbidden_loader_call_names
                    )
                    if source_is_loader_callable:
                        for target in targets:
                            if (
                                isinstance(target, ast.Name)
                                and target.id not in loader_callable_aliases
                            ):
                                loader_callable_aliases.add(target.id)
                                changed = True
        for node in ast.walk(tree):
            parent = parents.get(node)
            if not isinstance(node, ast.Call):
                if (
                    isinstance(node, ast.Name)
                    and isinstance(node.ctx, ast.Load)
                    and node.id in import_aliases
                    and not (isinstance(parent, ast.Call) and parent.func is node)
                ):
                    violations.append(
                        f"{relative}:{node.lineno}: dynamic import capability "
                        "escapes direct validation"
                    )
                continue
            function = node.func
            if isinstance(function, ast.Name) and function.id in import_aliases:
                literal = (
                    node.args[0].value
                    if node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    else None
                )
                if (
                    relative,
                    enclosing_function(node),
                    literal,
                ) not in allowed_literal_imports:
                    violations.append(
                        f"{relative}:{node.lineno}: unapproved dynamic import"
                    )
            elif (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id in builtins_module_aliases
                and function.attr == "__import__"
            ):
                violations.append(
                    f"{relative}:{node.lineno}: unapproved dynamic import"
                )
            elif (
                isinstance(function, ast.Name) and function.id in import_module_aliases
            ):
                if (
                    relative,
                    enclosing_function(node),
                ) not in allowed_import_module_sites:
                    violations.append(
                        f"{relative}:{node.lineno}: unapproved import_module call"
                    )
            elif (
                isinstance(function, ast.Attribute)
                and function.attr == "import_module"
                and isinstance(function.value, ast.Name)
                and function.value.id in importlib_module_aliases
                and (
                    relative,
                    enclosing_function(node),
                )
                not in allowed_import_module_sites
            ):
                violations.append(
                    f"{relative}:{node.lineno}: unapproved import_module call"
                )
            elif (
                isinstance(function, ast.Name)
                and function.id in loader_callable_aliases
            ) or (
                isinstance(function, ast.Attribute)
                and function.attr in forbidden_loader_call_names
            ):
                violations.append(
                    f"{relative}:{node.lineno}: unapproved import machinery call"
                )
            elif (
                (isinstance(function, ast.Name) and function.id in getattr_aliases)
                or (
                    isinstance(function, ast.Attribute)
                    and function.attr == "getattr"
                    and isinstance(function.value, ast.Name)
                    and function.value.id in builtins_module_aliases
                )
            ) and (
                len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value
                in forbidden_loader_call_names | {"__import__", "import_module"}
            ):
                violations.append(
                    f"{relative}:{node.lineno}: unapproved import machinery lookup"
                )
    return tuple(sorted(set(violations)))


def _core_network_import_violations(source_root: Path) -> tuple[str, ...]:
    violations: list[str] = []
    for path in _python_files(source_root):
        relative = path.relative_to(source_root).as_posix()
        allowed = CORE_NETWORK_IMPORT_ALLOWLIST.get(relative, ())
        for line, import_name in _literal_imports(path):
            if not _matches_prefix(import_name, NETWORK_CAPABLE_IMPORT_PREFIXES):
                continue
            if import_name in allowed:
                continue
            violations.append(
                f"{relative}:{line}: unapproved network-capable import {import_name}"
            )
    return tuple(sorted(set(violations)))


def _core_external_import_violations(source_root: Path) -> tuple[str, ...]:
    violations: list[str] = []
    for path in _python_files(source_root):
        relative = path.relative_to(source_root).as_posix()
        for line, import_name in _literal_imports(path):
            if import_name.startswith("."):
                continue
            root = import_name.split(".", 1)[0]
            if (
                root in sys.stdlib_module_names
                or root == "router_dump_analyzer"
                or root in APPROVED_EXTERNAL_IMPORT_ROOTS
            ):
                continue
            violations.append(
                f"{relative}:{line}: undeclared external import {import_name}"
            )
    return tuple(sorted(set(violations)))


def _core_asyncio_usage_violations(source_root: Path) -> tuple[str, ...]:
    violations: list[str] = []
    for path in _python_files(source_root):
        relative = path.relative_to(source_root).as_posix()
        allowed = CORE_ASYNCIO_ATTRIBUTE_ALLOWLIST.get(relative, frozenset())
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        aliases = {
            alias.asname or "asyncio"
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == "asyncio"
        }
        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and isinstance(node.value, ast.Name)
                    and node.value.id in aliases
                ):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else (node.target,)
                    )
                    for target in targets:
                        if isinstance(target, ast.Name) and target.id not in aliases:
                            aliases.add(target.id)
                            changed = True
        parents = {
            child: parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in aliases
                and node.attr not in allowed
            ):
                violations.append(
                    f"{relative}:{node.lineno}: unapproved asyncio operation "
                    f"{node.attr}"
                )
            elif isinstance(node, ast.ImportFrom) and node.module == "asyncio":
                for alias in node.names:
                    if alias.name not in allowed:
                        violations.append(
                            f"{relative}:{node.lineno}: unapproved asyncio import "
                            f"{alias.name}"
                        )
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in aliases
                and (
                    len(node.args) < 2
                    or not isinstance(node.args[1], ast.Constant)
                    or not isinstance(node.args[1].value, str)
                    or node.args[1].value not in allowed
                )
            ):
                violations.append(
                    f"{relative}:{node.lineno}: unapproved dynamic asyncio access"
                )
            elif (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in aliases
            ):
                parent = parents.get(node)
                is_allowed_attribute_receiver = (
                    isinstance(parent, ast.Attribute) and parent.value is node
                )
                is_direct_alias_source = (
                    isinstance(parent, (ast.Assign, ast.AnnAssign))
                    and parent.value is node
                )
                if not is_allowed_attribute_receiver and not is_direct_alias_source:
                    violations.append(
                        f"{relative}:{node.lineno}: asyncio capability escapes "
                        "the allowed operation boundary"
                    )
    return tuple(sorted(set(violations)))


def _deployable_resource_violations(*roots: Path) -> tuple[str, ...]:
    violations: list[str] = []
    markers = (*PUBLIC_MODEL_ENDPOINT_MARKERS, *PUBLIC_MODEL_CONFIGURATION_MARKERS)
    for root in roots:
        paths = (root,) if root.is_file() else root.rglob("*")
        for path in paths:
            relative_to_root = (
                path.relative_to(ROOT)
                if path.is_relative_to(ROOT)
                else path.relative_to(root)
            )
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or path.suffix.casefold() not in DEPLOYABLE_TEXT_SUFFIXES
                or (
                    root == ROOT
                    and relative_to_root.parts
                    and relative_to_root.parts[0] in NON_DEPLOYABLE_TOP_LEVELS
                )
            ):
                continue
            lowered = path.read_text(encoding="utf-8").casefold()
            normalized_tokens = {
                "".join(character for character in token if character.isalnum())
                for token in re.findall(r"[a-z][a-z0-9_.-]*", lowered)
            }
            command_tokens = re.findall(r"[a-z0-9_.\[\]/<>:=+-]+", lowered)
            has_package_install = any(
                command_tokens[index] == "pip"
                and "install" in command_tokens[index + 1 : index + 5]
                for index in range(len(command_tokens))
            ) or any(
                command_tokens[index] in {"poetry", "uv"}
                and "add" in command_tokens[index + 1 : index + 4]
                for index in range(len(command_tokens))
            )
            if has_package_install:
                installed_providers = sorted(
                    PUBLIC_MODEL_PROVIDER_PACKAGE_MARKERS & set(command_tokens)
                )
                violations.extend(
                    f"{relative_to_root.as_posix()}: forbidden public-model "
                    f"package install {provider}"
                    for provider in installed_providers
                )
            for marker in markers:
                if marker in lowered:
                    violations.append(
                        f"{relative_to_root.as_posix()}: forbidden model "
                        f"marker {marker}"
                    )
            for marker in NORMALIZED_MODEL_CONFIGURATION_MARKERS:
                if marker in normalized_tokens:
                    violations.append(
                        f"{relative_to_root.as_posix()}: forbidden normalized "
                        f"model marker {marker}"
                    )
    return tuple(sorted(set(violations)))


def _private_analysis_resource_violations(source_root: Path) -> tuple[str, ...]:
    return tuple(
        sorted(
            path.relative_to(source_root).as_posix()
            for path in source_root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix.casefold() != ".py"
        )
    )


class PrivateAiArchitectureTests(unittest.TestCase):
    def test_private_analysis_policy_is_closed_and_immutable(self) -> None:
        self.assertEqual(
            PRIVATE_ANALYSIS_POLICY_VERSION,
            "router_dump_analyzer.private_analysis_policy.v1",
        )
        self.assertEqual(
            tuple(item.value for item in PrivateAnalysisTransport),
            ("in_process", "local_subprocess"),
        )
        self.assertFalse(PUBLIC_MODEL_API_INTEGRATION_ALLOWED)
        self.assertFalse(ASSISTANT_DIRECT_GROUND_TRUTH_MUTATION_ALLOWED)
        self.assertFalse(ASSISTANT_DIRECT_PLUGIN_AUTHORITY_ALLOWED)

        policy = PrivateAnalysisPolicy(
            transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS,
        )
        self.assertTrue(policy.full_fidelity_workspace_data)
        self.assertFalse(policy.public_model_api_integration_allowed)
        self.assertFalse(policy.direct_ground_truth_mutation_allowed)
        self.assertFalse(policy.direct_plugin_authority_allowed)
        with self.assertRaises(FrozenInstanceError):
            policy.full_fidelity_workspace_data = False  # type: ignore[misc]
        with self.assertRaises(TypeError):
            PrivateAnalysisPolicy(transport="remote")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            PrivateAnalysisPolicy(
                transport=PrivateAnalysisTransport.IN_PROCESS,
                full_fidelity_workspace_data=1,  # type: ignore[arg-type]
            )

    def test_assistant_provenance_cannot_impersonate_fact_provenance(self) -> None:
        assistant_values = {item.value for item in PrivateAnalysisContributionKind}
        report_values = {item.value for item in CorrelationReportProvenanceClass}
        self.assertEqual(
            assistant_values,
            {
                "assistant_suggested",
                "user_approved_derivation",
                "counterfactual",
            },
        )
        self.assertTrue(assistant_values.isdisjoint(report_values))
        self.assertEqual(
            report_values,
            {"plugin_inferred", "user_asserted", "core_corroboration"},
        )

    def test_distribution_dependencies_are_exactly_allowlisted(self) -> None:
        self.assertEqual(_dependency_manifest_violations(ROOT), ())

    def test_core_has_no_unapproved_outbound_network_import(self) -> None:
        self.assertEqual(
            _core_network_import_violations(CORE_SOURCE),
            (),
        )
        self.assertEqual(_core_asyncio_usage_violations(CORE_SOURCE), ())
        self.assertEqual(_core_dynamic_import_violations(CORE_SOURCE), ())
        self.assertEqual(_core_external_import_violations(CORE_SOURCE), ())

    def test_private_analysis_package_has_an_exact_import_boundary(self) -> None:
        self.assertEqual(
            _private_analysis_import_violations(PRIVATE_ANALYSIS_SOURCE),
            (),
        )
        self.assertEqual(
            _private_analysis_dynamic_execution_violations(PRIVATE_ANALYSIS_SOURCE),
            (),
        )
        self.assertEqual(
            _private_analysis_resource_violations(PRIVATE_ANALYSIS_SOURCE),
            (),
        )

    def test_private_analysis_tool_service_has_narrow_trusted_dependencies(
        self,
    ) -> None:
        expected_members = {
            "__future__": {"annotations"},
            "collections.abc": {"Callable"},
            "dataclasses": {"dataclass"},
            "enum": {"StrEnum"},
            "threading": {"Lock"},
            "typing": {"Any", "Final"},
            ".canonical": {"strict_canonical_json"},
            ".private_analysis.contracts": {
                "PrivateAnalysisError",
                "PrivateAnalysisErrorCode",
                "PrivateAnalysisErrorStage",
                "PrivateAnalysisRequest",
                "private_analysis_request_from_json",
                "private_analysis_request_json",
            },
            ".private_analysis.disclosure": {
                "DisclosureDecision",
                "PrivateAnalysisEvidenceClass",
                "WorkspaceDisclosurePolicy",
                "disclosure_scope_digest",
                "evaluate_workspace_disclosure",
            },
            ".private_analysis.evidence": {
                "EvidenceReference",
                "EvidenceScope",
                "evidence_envelope_json",
                "evidence_reference_dict",
                "evidence_reference_from_dict",
                "make_evidence_envelope",
            },
            ".private_analysis.policy": {"PrivateAnalysisPolicy"},
            ".private_analysis.tool_catalog": {
                "MAX_PRIVATE_ANALYSIS_SNAPSHOT_REFERENCES",
                "PrivateAnalysisQueryArguments",
                "PrivateAnalysisReadArguments",
                "PrivateAnalysisToolCall",
                "PrivateAnalysisToolError",
                "PrivateAnalysisToolErrorCode",
                "PrivateAnalysisToolName",
                "PrivateAnalysisToolResult",
                "PrivateAnalysisToolResultKind",
                "default_private_analysis_tool_catalog",
                "make_private_analysis_query_page",
                "private_analysis_tool_call_dict",
                "private_analysis_tool_call_from_dict",
            },
            ".process_control": {"PROCESS_CONTROL_EXCEPTIONS"},
        }
        self.assertEqual(
            {
                name
                for _, name in _literal_imports(PRIVATE_ANALYSIS_TOOL_SERVICE_SOURCE)
            },
            set(expected_members),
        )
        source = PRIVATE_ANALYSIS_TOOL_SERVICE_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(PRIVATE_ANALYSIS_TOOL_SERVICE_SOURCE))
        actual_members: dict[str, set[str]] = {}
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, ast.Import)
            if isinstance(node, ast.ImportFrom):
                module = "." * node.level + (node.module or "")
                actual_members[module] = {alias.name for alias in node.names}
            if isinstance(node, ast.ExceptHandler):
                retained_service_errors = tuple(
                    child
                    for child in ast.walk(node)
                    if isinstance(child, ast.Raise)
                    and isinstance(child.exc, ast.Call)
                    and isinstance(child.exc.func, ast.Name)
                    and child.exc.func.id == "_service_error"
                )
                self.assertEqual(
                    retained_service_errors,
                    (),
                    "service errors must be raised after leaving exception handlers",
                )
        self.assertEqual(actual_members, expected_members)
        for forbidden in (
            "annotation_store",
            "capability_executor",
            "control_plane",
            "plugin_api",
            "revision_store",
            "session_store",
            "sqlite",
            "subprocess",
            "web.",
        ):
            self.assertNotIn(forbidden, source)

    def test_private_analysis_tool_service_has_only_declared_runtime_consumers(
        self,
    ) -> None:
        consumers: list[str] = []
        for path in _python_files(CORE_SOURCE):
            if path == PRIVATE_ANALYSIS_TOOL_SERVICE_SOURCE:
                continue
            for line, imported in _literal_imports(path):
                if imported.endswith("private_analysis_tool_service"):
                    consumers.append(
                        f"{path.relative_to(CORE_SOURCE).as_posix()}:{line}"
                    )
        self.assertEqual(
            {item.split(":", 1)[0] for item in consumers},
            {
                PRIVATE_ANALYSIS_IN_PROCESS_RUNNER_SOURCE.name,
                PRIVATE_ANALYSIS_EXECUTION_SOURCE.name,
                PRIVATE_ANALYSIS_RUNNER_SUPPORT_SOURCE.name,
                "private_analysis_run_store.py",
                "private_analysis_service.py",
                PRIVATE_ANALYSIS_SUBPROCESS_RUNNER_SOURCE.name,
            },
        )

    def test_private_analysis_application_service_has_no_transport_authority(
        self,
    ) -> None:
        source = PRIVATE_ANALYSIS_SERVICE_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(PRIVATE_ANALYSIS_SERVICE_SOURCE))
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, ast.Import)
            if isinstance(node, ast.ImportFrom):
                module = "." * node.level + (node.module or "")
                self.assertNotIn(module, {".plugin_api", ".plugin_validation"})
                self.assertFalse(module.startswith(".web"))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(
                    node.func.id,
                    {
                        "__import__",
                        "compile",
                        "eval",
                        "exec",
                        "open",
                    },
                )
        for forbidden in (
            "api_key",
            "endpoint_url",
            "http://",
            "https://",
            "socket",
            "subprocess",
        ):
            self.assertNotIn(forbidden, source.casefold())

    def test_private_analysis_in_process_runner_has_narrow_authority(self) -> None:
        source = PRIVATE_ANALYSIS_IN_PROCESS_RUNNER_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(
            source,
            filename=str(PRIVATE_ANALYSIS_IN_PROCESS_RUNNER_SOURCE),
        )
        imported: dict[str, set[str]] = {}
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, ast.Import)
            if isinstance(node, ast.ImportFrom):
                module = "." * node.level + (node.module or "")
                imported[module] = {alias.name for alias in node.names}
            if isinstance(node, ast.Call):
                function = node.func
                if isinstance(function, ast.Name):
                    self.assertNotIn(
                        function.id,
                        {
                            "Thread",
                            "Timer",
                            "compile",
                            "eval",
                            "exec",
                            "open",
                            "__import__",
                        },
                    )
        self.assertEqual(
            imported["threading"],
            {"Lock", "get_ident"},
        )
        self.assertEqual(imported["time"], {"monotonic_ns"})
        self.assertEqual(
            set(imported),
            {
                "__future__",
                "collections.abc",
                "dataclasses",
                "enum",
                "threading",
                "time",
                "typing",
                ".canonical",
                ".private_analysis",
                ".private_analysis_runner_support",
                ".private_analysis_tool_service",
                ".process_control",
            },
        )
        for forbidden in (
            "annotation_store",
            "asyncio",
            "capability_executor",
            "concurrent",
            "control_plane",
            "multiprocessing",
            "pathlib",
            "plugin_api",
            "revision_store",
            "session_store",
            "socket",
            "sqlite",
            "subprocess",
            "web.",
        ):
            self.assertNotIn(forbidden, source)

    def test_private_analysis_subprocess_runner_is_the_only_process_launcher(
        self,
    ) -> None:
        subprocess_importers: set[str] = set()
        for path in _python_files(CORE_SOURCE):
            for _line, imported in _literal_imports(path):
                if imported == "subprocess":
                    subprocess_importers.add(path.relative_to(CORE_SOURCE).as_posix())
        self.assertEqual(
            subprocess_importers,
            {PRIVATE_ANALYSIS_SUBPROCESS_RUNNER_SOURCE.name},
        )
        source = PRIVATE_ANALYSIS_SUBPROCESS_RUNNER_SOURCE.read_text(encoding="utf-8")
        self.assertIn("shell=False", source)
        self.assertIn("close_fds=True", source)
        self.assertIn("start_new_session=False", source)
        for forbidden in (
            "annotation_store",
            "asyncio",
            "capability_executor",
            "control_plane",
            "multiprocessing",
            "plugin_api",
            "revision_store",
            "session_store",
            "socket",
            "sqlite",
            "web.",
        ):
            self.assertNotIn(forbidden, source)

    def test_configured_runners_have_only_the_core_execution_consumer(self) -> None:
        consumers: list[str] = []
        for path in _python_files(CORE_SOURCE):
            if path == PRIVATE_ANALYSIS_IN_PROCESS_RUNNER_SOURCE:
                continue
            for line, imported in _literal_imports(path):
                if imported.endswith("private_analysis_in_process_runner"):
                    consumers.append(
                        f"{path.relative_to(CORE_SOURCE).as_posix()}:{line}"
                    )
        self.assertEqual(
            {item.split(":", 1)[0] for item in consumers},
            {PRIVATE_ANALYSIS_EXECUTION_SOURCE.name},
        )

        consumers = []
        for path in _python_files(CORE_SOURCE):
            if path == PRIVATE_ANALYSIS_SUBPROCESS_RUNNER_SOURCE:
                continue
            for line, imported in _literal_imports(path):
                if imported.endswith("private_analysis_subprocess_runner"):
                    consumers.append(
                        f"{path.relative_to(CORE_SOURCE).as_posix()}:{line}"
                    )
        self.assertEqual(
            {item.split(":", 1)[0] for item in consumers},
            {PRIVATE_ANALYSIS_EXECUTION_SOURCE.name},
        )

    def test_private_analysis_execution_has_narrow_local_authority(self) -> None:
        source = PRIVATE_ANALYSIS_EXECUTION_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(PRIVATE_ANALYSIS_EXECUTION_SOURCE))
        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.update(alias.name for alias in node.names)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(
                    node.func.id,
                    {"compile", "eval", "exec", "open", "__import__"},
                )
        self.assertEqual(imported_modules, {"math", "threading", "time"})
        for forbidden in (
            "annotation_store",
            "asyncio",
            "capability_executor",
            "importlib",
            "plugin_api",
            "plugin_loader",
            "requests",
            "socket",
            "subprocess.Popen",
            "urllib",
            "web.",
        ):
            self.assertNotIn(forbidden, source)

    def test_deployable_sources_have_no_model_endpoint_or_key_configuration(
        self,
    ) -> None:
        self.assertEqual(
            _deployable_resource_violations(
                ROOT,
            ),
            (),
        )

    def test_import_guard_detects_alternate_and_indirect_networking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {
                "sdk.py": "import litellm\n",
                "urllib3_client.py": "import urllib3\n",
                "grpc_client.py": "import grpc\n",
                "httpcore_client.py": "import httpcore\n",
                "asyncio_client.py": (
                    "import asyncio\nasync def connect():\n"
                    "    return await asyncio.open_connection('host', 443)\n"
                ),
                "indirect.py": ("from router_dump_analyzer.web import service_api\n"),
                "escape.py": "from ..web import service_api\n",
                "dynamic.py": (
                    "module_name = 'socket'\n"
                    "loader = __import__\n"
                    "client = loader(module_name)\n"
                ),
                "filesystem.py": "reader = open\nreader('secret.dump', 'rb')\n",
                "builtin_lookup.py": (
                    "reader = __builtins__['open']\nreader('secret.dump', 'rb')\n"
                ),
                "builtin_namespace_alias.py": (
                    "runtime = __builtins__\n"
                    "reader = runtime['open']\n"
                    "reader('secret.dump', 'rb')\n"
                ),
                "builtin_method_lookup.py": (
                    "runtime = __builtins__\n"
                    "reader = runtime.get('open')\n"
                    "reader('secret.dump', 'rb')\n"
                    "second = runtime.__getitem__('open')\n"
                    "second('other.dump', 'rb')\n"
                ),
                "builtin_accessor_alias.py": (
                    "key = 'open'\n"
                    "lookup = __builtins__.get\n"
                    "reader = lookup(key)\n"
                    "reader('secret.dump', 'rb')\n"
                ),
                "reflective_builtin_lookup.py": (
                    "first = marker.__builtins__['open']\n"
                    "second = marker.__globals__['__builtins__']['open']\n"
                    "third = len.__self__.open\n"
                ),
                "frame_builtin_lookup.py": (
                    "first = generator.gi_frame.f_builtins['open']\n"
                    "second = error.__traceback__.tb_frame.f_builtins['open']\n"
                ),
                "module_bridge.py": (
                    "import dataclasses\n"
                    "reader = dataclasses.sys.modules['builtins'].open\n"
                ),
                "member_bridge.py": (
                    "from dataclasses import sys\n"
                    "reader = sys.modules['builtins'].open\n"
                ),
                "absolute_submodule_bridge.py": (
                    "from json.decoder import re\n"
                    "reader = re.enum.sys.modules['builtins'].open\n"
                ),
                "parent_member_bridge.py": (
                    "from ..canonical import __builtins__ as runtime\n"
                    "reader = runtime['open']\n"
                ),
                "local_module_bridge.py": (
                    "from . import tool_catalog\n"
                    "reader = tool_catalog.loads.__globals__['__builtins__']['open']\n"
                ),
                "local_member_bridge.py": (
                    "from .tool_catalog import __builtins__ as runtime\n"
                    "reader = runtime['open']\n"
                ),
                "loader_metadata.py": (
                    "first = __loader__.get_data(__file__)\n"
                    "second = __spec__.loader.get_data(__file__)\n"
                ),
                "pattern_reflective_lookup.py": (
                    "match len:\n"
                    "    case object(__self__=namespace):\n"
                    "        reader = namespace.open\n"
                    "match callback:\n"
                    "    case object(__globals__=namespace):\n"
                    "        second = namespace['__builtins__']['open']\n"
                ),
                "reduction_reflective_lookup.py": (
                    "lookup, unused = [].append.__reduce__()\n"
                    "namespace = lookup(len, '__self__')\n"
                    "reader = lookup(namespace, 'open')\n"
                ),
            }
            for name, source in fixtures.items():
                (root / name).write_text(source, encoding="utf-8")
            violations = _private_analysis_import_violations(root)
            dynamic_violations = _private_analysis_dynamic_execution_violations(root)
        for name in fixtures:
            if name in {
                "dynamic.py",
                "filesystem.py",
                "builtin_lookup.py",
                "builtin_namespace_alias.py",
                "builtin_method_lookup.py",
                "builtin_accessor_alias.py",
                "reflective_builtin_lookup.py",
                "frame_builtin_lookup.py",
                "loader_metadata.py",
                "pattern_reflective_lookup.py",
                "reduction_reflective_lookup.py",
            }:
                continue
            self.assertTrue(
                any(item.startswith(f"{name}:") for item in violations),
                f"guard missed {name}: {violations}",
            )
        self.assertTrue(
            any(item.startswith("dynamic.py:") for item in dynamic_violations),
            dynamic_violations,
        )
        self.assertTrue(
            any(item.startswith("filesystem.py:") for item in dynamic_violations),
            dynamic_violations,
        )
        self.assertTrue(
            any(item.startswith("builtin_lookup.py:") for item in dynamic_violations),
            dynamic_violations,
        )
        self.assertTrue(
            any(
                item.startswith("builtin_namespace_alias.py:")
                for item in dynamic_violations
            ),
            dynamic_violations,
        )
        self.assertTrue(
            any(
                item.startswith("builtin_method_lookup.py:")
                for item in dynamic_violations
            ),
            dynamic_violations,
        )
        self.assertTrue(
            any(
                item.startswith("builtin_accessor_alias.py:")
                for item in dynamic_violations
            ),
            dynamic_violations,
        )
        self.assertTrue(
            any(
                item.startswith("reflective_builtin_lookup.py:")
                for item in dynamic_violations
            ),
            dynamic_violations,
        )
        self.assertTrue(
            any(
                item.startswith("frame_builtin_lookup.py:")
                for item in dynamic_violations
            ),
            dynamic_violations,
        )
        self.assertTrue(
            any(item.startswith("loader_metadata.py:") for item in dynamic_violations),
            dynamic_violations,
        )
        self.assertTrue(
            any(
                item.startswith("pattern_reflective_lookup.py:")
                for item in dynamic_violations
            ),
            dynamic_violations,
        )
        self.assertTrue(
            any(
                item.startswith("reduction_reflective_lookup.py:")
                for item in dynamic_violations
            ),
            dynamic_violations,
        )

    def test_asyncio_guard_rejects_network_operations_in_an_allowed_module(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "runtime.py").write_text(
                "import asyncio as aio\n"
                "alias = aio\n"
                "async def connect():\n"
                "    return await alias.open_connection('host', 443)\n",
                encoding="utf-8",
            )
            violations = _core_asyncio_usage_violations(root)
        self.assertEqual(
            violations,
            ("runtime.py:4: unapproved asyncio operation open_connection",),
        )

    def test_network_import_guard_rejects_root_and_submodule_forms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {
                "anyio_client.py": "import anyio\n",
                "mail.py": "import smtplib\n",
                "stream.py": "from asyncio.streams import open_connection\n",
                "xmlrpc.py": "from xmlrpc import client\n",
            }
            for name, source in fixtures.items():
                (root / name).write_text(source, encoding="utf-8")
            violations = _core_network_import_violations(root)
        for name in fixtures:
            self.assertTrue(
                any(item.startswith(f"{name}:") for item in violations),
                f"network guard missed {name}: {violations}",
            )

    def test_external_import_guard_rejects_unknown_provider_imports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("anthropic", "litellm", "openai"):
                (root / f"{name}.py").write_text(
                    f"import {name}\n",
                    encoding="utf-8",
                )
            violations = _core_external_import_violations(root)
        for name in ("anthropic", "litellm", "openai"):
            self.assertTrue(
                any(item.startswith(f"{name}.py:") for item in violations),
                f"external import guard missed {name}: {violations}",
            )

    def test_dynamic_import_guard_rejects_aliases_and_wrong_loader_sites(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {
                "alias.py": (
                    "from importlib import import_module as load\n"
                    "def run(name):\n    return load(name)\n"
                ),
                "assigned.py": (
                    "import importlib\nload = importlib.import_module\n"
                    "def run(name):\n    return load(name)\n"
                ),
                "plugin_loading.py": (
                    "import importlib\ndef unrelated(name):\n"
                    "    return importlib.import_module(name)\n"
                ),
                "builtins_alias.py": (
                    "from builtins import __import__ as load\n"
                    "def run(name):\n    return load(name)\n"
                ),
                "builtins_module.py": (
                    "import builtins as runtime\n"
                    "def run(name):\n    return runtime.__import__(name)\n"
                ),
                "import_module_getattr.py": (
                    "import importlib\n"
                    "def run():\n"
                    "    load = getattr(importlib, 'import_module')\n"
                    "    return load('openai')\n"
                ),
                "import_module_getattr_alias.py": (
                    "import importlib\n"
                    "lookup = getattr\n"
                    "def run():\n"
                    "    load = lookup(importlib, 'import_module')\n"
                    "    return load('openai')\n"
                ),
                "import_module_getattr_import.py": (
                    "from builtins import getattr as lookup\n"
                    "import importlib\n"
                    "def run():\n"
                    "    load = lookup(importlib, 'import_module')\n"
                    "    return load('openai')\n"
                ),
                "builtins_getattr_module.py": (
                    "import builtins as runtime\n"
                    "load = runtime.getattr(runtime, '__import__')\n"
                    "client = load('socket')\n"
                ),
                "builtins_getattr_assignment.py": (
                    "import builtins\n"
                    "runtime = builtins\n"
                    "lookup = runtime.getattr\n"
                    "load = lookup(runtime, '__import__')\n"
                    "client = load('socket')\n"
                ),
                "find_spec.py": (
                    "import importlib\n"
                    "def run(name):\n    return importlib.util.find_spec(name)\n"
                ),
                "module_from_spec.py": (
                    "from importlib.util import module_from_spec as make_module\n"
                    "def run(spec):\n    return make_module(spec)\n"
                ),
                "exec_module.py": (
                    "def run(spec, module):\n"
                    "    return spec.loader.exec_module(module)\n"
                ),
                "pkgutil_loader.py": (
                    "import pkgutil\n"
                    "def run(name):\n    return pkgutil.get_loader(name)\n"
                ),
                "machinery_loader.py": (
                    "from importlib.machinery import SourceFileLoader as Loader\n"
                    "def run(name, path):\n    return Loader(name, path).load_module()\n"
                ),
            }
            for name, source in fixtures.items():
                (root / name).write_text(source, encoding="utf-8")
            violations = _core_dynamic_import_violations(root)
        for name in fixtures:
            self.assertTrue(
                any(item.startswith(f"{name}:") for item in violations),
                f"dynamic import guard missed {name}: {violations}",
            )

    def test_dependency_guard_rejects_unknown_provider_without_knowing_its_name(
        self,
    ) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project["project"]["optional-dependencies"]["private-ai"] = [
            "future-model-provider>=1"
        ]
        violations = _dependency_policy_violations(project)
        self.assertIn("unapproved dependency group private-ai", violations)

    def test_dependency_guard_pins_extras_sources_and_build_requirements(self) -> None:
        original = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        cases = (
            ("fastapi[all]>=0.115,<1", "web"),
            ("fastapi @ https://example.invalid/package.whl", "web"),
        )
        for requirement, group in cases:
            with self.subTest(requirement=requirement):
                project = tomllib.loads(
                    (ROOT / "pyproject.toml").read_text(encoding="utf-8")
                )
                project["project"]["optional-dependencies"][group][0] = requirement
                self.assertTrue(_dependency_policy_violations(project))
        original["build-system"]["requires"].append("future-build-hook")
        self.assertTrue(_dependency_policy_violations(original))
        dynamic = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        dynamic["project"]["dynamic"] = ["dependencies"]
        self.assertIn(
            "project dynamic metadata is not allowed",
            _dependency_policy_violations(dynamic),
        )
        hook = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        hook["tool"]["hatch"]["metadata"] = {"hooks": {"custom": {}}}
        self.assertIn(
            "tool metadata must match the approved static build and test tables",
            _dependency_policy_violations(hook),
        )

    def test_packaging_guard_rejects_executable_metadata_escape_hatches(
        self,
    ) -> None:
        mutations = {
            "backend-path": lambda project: project["build-system"].__setitem__(
                "backend-path", ["build_backend"]
            ),
            "hatch-build-hook": lambda project: project["tool"]["hatch"][
                "build"
            ].__setitem__("hooks", {"custom": {"path": "hook.py"}}),
            "hatch-metadata-hook": lambda project: project["tool"]["hatch"].__setitem__(
                "metadata", {"hooks": {"custom": {"path": "hook.py"}}}
            ),
            "script": lambda project: project["project"]["scripts"].__setitem__(
                "unexpected", "hostile:main"
            ),
            "entry-point": lambda project: project["project"].__setitem__(
                "entry-points", {"future.loader": {"hostile": "hostile:load"}}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                project = tomllib.loads(
                    (ROOT / "pyproject.toml").read_text(encoding="utf-8")
                )
                mutate(project)
                self.assertTrue(_dependency_policy_violations(project))

    def test_dependency_manifest_guard_rejects_new_sources_and_env_changes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in APPROVED_PACKAGING_MANIFESTS:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    (ROOT / name).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            for name, lines in APPROVED_ENVIRONMENT_MANIFESTS.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("\n".join(lines) + "\n", encoding="utf-8")
            (root / "requirements-private-ai.txt").write_text(
                "future-model-provider>=1\n",
                encoding="utf-8",
            )
            env_path = root / "environment.yml"
            env_path.write_text(
                env_path.read_text(encoding="utf-8") + "  - future-model-provider\n",
                encoding="utf-8",
            )
            violations = _dependency_manifest_violations(root)
        self.assertIn(
            "unapproved dependency manifest requirements-private-ai.txt",
            violations,
        )
        self.assertIn(
            "environment.yml: environment dependencies differ from the approved manifest",
            violations,
        )

    def test_resource_guard_detects_generic_endpoint_key_and_fallback(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            fixtures = {
                "endpoint.yaml": "MODEL_URL: https://example.invalid",
                ".env": "LLM_TOKEN=secret",
                "fallback.ts": "const FALLBACK_LLM = true;",
                "openai.env": "OPENAI_BASE_URL=https://example.invalid",
                "azure.yaml": "AZURE_OPENAI_ENDPOINT: https://example.invalid",
                "api.ini": "LLM_API_URL=https://example.invalid",
                "base.json": '{"MODEL_API_BASE": "https://example.invalid"}',
                "failover.cfg": "LLM_FAILOVER=enabled",
                "backup.cfg": "MODEL_BACKUP=enabled",
                "cloud.env": "ALLOW_CLOUD_MODEL=true",
                "provider.env": "REMOTE_PROVIDER_FALLBACK=true",
                "installer.sh": "python -m pip install openai",
            }
            for name, source in fixtures.items():
                (root / name).write_text(source, encoding="utf-8")
            violations = _deployable_resource_violations(root)
        for marker in (
            "modelurl",
            "llmtoken",
            "fallbackllm",
            "openaibaseurl",
            "azureopenaiendpoint",
            "llmapiurl",
            "modelapibase",
            "llmfailover",
            "modelbackup",
            "allowcloudmodel",
            "remoteproviderfallback",
            "package install openai",
        ):
            self.assertTrue(
                any(marker in item for item in violations),
                f"resource guard missed {marker}: {violations}",
            )

    def test_normative_decision_records_every_frozen_boundary(self) -> None:
        document = DECISION_DOCUMENT.read_text(encoding="utf-8")
        normalized_document = " ".join(document.split())
        for required in (
            "no public-provider SDK",
            "trusted in-process runner",
            "local subprocess",
            "assistant_suggested",
            "user-approved derived mapping",
            "counterfactual route never replaces",
            "full-fidelity private analysis",
            "never_assistant",
            "Multi-plug-in prerequisite",
            "requires a new version of this decision",
        ):
            self.assertIn(required, normalized_document)


if __name__ == "__main__":
    unittest.main()
