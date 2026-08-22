#!/usr/bin/env python3
"""Verify that installed Router State Lab packages ship complete PEP 561 data."""

from __future__ import annotations

import argparse
import ast
import importlib.util
from collections.abc import Iterable
from pathlib import Path

DEFAULT_PACKAGES = (
    "router_dump_analyzer",
    "rsl_demo_plugin",
    "rsl_demo_generator",
    "state_dump_generator",
)


def _relative_files(
    root: Path,
    *,
    suffix: str,
) -> frozenset[str]:
    discovered: set[str] = set()

    for child in root.rglob(f"*{suffix}"):
        if child.is_file():
            discovered.add(child.relative_to(root).as_posix())
    return frozenset(discovered)


def verify_installed_type_surface(package_names: Iterable[str]) -> None:
    failures: list[str] = []
    for package_name in package_names:
        specification = importlib.util.find_spec(package_name)
        if specification is None or not specification.submodule_search_locations:
            failures.append(f"{package_name}: installed package was not found")
            continue
        package_roots = tuple(
            Path(location) for location in specification.submodule_search_locations
        )
        markers = tuple(root / "py.typed" for root in package_roots)
        if not any(marker.is_file() for marker in markers):
            failures.append(f"{package_name}: missing py.typed")
        elif any(
            marker.is_file() and marker.read_bytes() != b""
            for marker in markers
        ):
            failures.append(f"{package_name}: py.typed must be empty")

        python_modules = frozenset().union(
            *(_relative_files(root, suffix=".py") for root in package_roots)
        )
        stub_modules = frozenset().union(
            *(_relative_files(root, suffix=".pyi") for root in package_roots)
        )
        expected_stubs = frozenset(
            module.removesuffix(".py") + ".pyi"
            for module in python_modules
        )
        missing = sorted(expected_stubs - stub_modules)
        unexpected = sorted(stub_modules - expected_stubs)
        if missing:
            failures.append(
                f"{package_name}: missing stubs for {', '.join(missing)}"
            )
        if unexpected:
            failures.append(
                f"{package_name}: stubs without runtime modules: "
                + ", ".join(unexpected)
            )
        for root in package_roots:
            for stub_path in sorted(root.rglob("*.pyi")):
                if not stub_path.is_file():
                    continue
                relative = stub_path.relative_to(root).as_posix()
                try:
                    tree = ast.parse(
                        stub_path.read_text(encoding="utf-8"),
                        filename=str(stub_path),
                    )
                except (OSError, UnicodeError, SyntaxError) as error:
                    failures.append(
                        f"{package_name}: invalid stub {relative}: {error}"
                    )
                    continue
                if any(
                    isinstance(node, ast.Name) and node.id == "Incomplete"
                    for node in ast.walk(tree)
                ):
                    failures.append(
                        f"{package_name}: unresolved typing in {relative}"
                    )

    if failures:
        raise SystemExit(
            "installed type-surface check failed:\n- " + "\n- ".join(failures)
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package",
        action="append",
        dest="packages",
        help="package to inspect (repeatable; defaults to all shipped packages)",
    )
    arguments = parser.parse_args()
    verify_installed_type_surface(arguments.packages or DEFAULT_PACKAGES)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
