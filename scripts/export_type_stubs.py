"""Generate or verify the repository's checked-in PEP 561 stub packages.

The exporter never imports repository packages.  Import-free generation matters
because several modules register routes, construct plug-ins, or create process
local secrets at import time.
"""

from __future__ import annotations

import argparse
import ast
import shutil
import subprocess
import sys
import tempfile
from importlib import metadata
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
STUBGEN_VERSION = "1.20.2"
PACKAGE_ROOTS = (
    REPOSITORY_ROOT / "src" / "router_dump_analyzer",
    REPOSITORY_ROOT / "demo" / "rsl_demo_plugin",
    REPOSITORY_ROOT / "demo" / "rsl_demo_generator",
    REPOSITORY_ROOT
    / "state-dump-generator"
    / "src"
    / "state_dump_generator",
)
STUB_SUPPLEMENTS = {
    Path("router_dump_analyzer/runtime.pyi"): (
        "\n# Private type variable used by a public generic method signature.\n"
        "from typing import TypeVar\n"
        "_CachedValue = TypeVar('_CachedValue')\n"
    ),
    Path("router_dump_analyzer/private_analysis/contracts.pyi"): (
        "\n# Importable compatibility value used by another typed core module.\n"
        "LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST: Final[str]\n"
    ),
    Path("router_dump_analyzer/private_analysis_factory_process.pyi"): (
        "\n# Importable cleanup helper used by another typed core module.\n"
        "def private_analysis_factory_process_cleanup_owner(\n"
        "    error: BaseException,\n"
        ") -> PrivateAnalysisFactoryProcessCleanupOwner | None: ...\n"
    ),
}


class StubExportError(RuntimeError):
    """Raised when the checked-in stub surface cannot be generated safely."""


def _terminal_name(expression: ast.expr) -> str | None:
    """Return the final identifier in one decorator, base, or call target."""

    while isinstance(expression, (ast.Call, ast.Subscript)):
        expression = (
            expression.func
            if isinstance(expression, ast.Call)
            else expression.value
        )
    if isinstance(expression, ast.Name):
        return expression.id
    if isinstance(expression, ast.Attribute):
        return expression.attr
    return None


def _is_dataclass(class_node: ast.ClassDef) -> bool:
    return any(
        _terminal_name(decorator) == "dataclass"
        for decorator in class_node.decorator_list
    )


def _dataclass_generates_init(class_node: ast.ClassDef) -> bool:
    for decorator in class_node.decorator_list:
        if _terminal_name(decorator) != "dataclass":
            continue
        if not isinstance(decorator, ast.Call):
            return True
        return not any(
            keyword.arg == "init"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in decorator.keywords
        )
    return False


def _is_field_call(expression: ast.expr | None) -> bool:
    return (
        isinstance(expression, ast.Call)
        and _terminal_name(expression.func) == "field"
    )


def _field_keyword_boolean(
    expression: ast.expr | None,
    keyword_name: str,
) -> bool | None:
    if not _is_field_call(expression):
        return None
    assert isinstance(expression, ast.Call)
    for keyword in expression.keywords:
        if (
            keyword.arg == keyword_name
            and isinstance(keyword.value, ast.Constant)
            and type(keyword.value.value) is bool
        ):
            return keyword.value.value
    return None


def _dataclass_fields(
    class_node: ast.ClassDef,
) -> tuple[tuple[str, str, bool], ...]:
    """Return source-order dataclass fields as (name, annotation, default)."""

    fields: list[tuple[str, str, bool]] = []
    for statement in class_node.body:
        if not isinstance(statement, ast.AnnAssign):
            continue
        if not isinstance(statement.target, ast.Name):
            continue
        name = statement.target.id
        annotation_kind = _terminal_name(statement.annotation)
        if annotation_kind in {"ClassVar", "KW_ONLY"}:
            continue
        if _field_keyword_boolean(statement.value, "init") is False:
            continue
        has_default = statement.value is not None
        if _is_field_call(statement.value):
            assert isinstance(statement.value, ast.Call)
            has_default = any(
                keyword.arg in {"default", "default_factory"}
                for keyword in statement.value.keywords
            )
        fields.append((name, ast.unparse(statement.annotation), has_default))
    return tuple(fields)


def _class_fields(class_node: ast.ClassDef) -> dict[str, ast.AnnAssign]:
    return {
        statement.target.id: statement
        for statement in class_node.body
        if isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
    }


def _has_final_binding(tree: ast.Module) -> bool:
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom) and statement.module in {
            "typing",
            "typing_extensions",
        }:
            if any(
                (alias.asname or alias.name) == "final"
                for alias in statement.names
            ):
                return True
        elif isinstance(statement, ast.Import) and any(
            alias.asname == "final" for alias in statement.names
        ):
            return True
    return False


def _module_bound_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(statement.name)
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else (statement.target,)
            )
            names.update(
                target.id for target in targets if isinstance(target, ast.Name)
            )
        elif isinstance(statement, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in statement.names)
        elif isinstance(statement, ast.Import):
            names.update(
                alias.asname or alias.name.partition(".")[0]
                for alias in statement.names
            )
    return names


def _source_import_for_name(tree: ast.Module, name: str) -> str | None:
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if (alias.asname or alias.name) != name:
                    continue
                module = "." * statement.level + (statement.module or "")
                imported = alias.name
                if alias.asname is not None:
                    imported += f" as {alias.asname}"
                return f"from {module} import {imported}\n"
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                if (alias.asname or alias.name.partition(".")[0]) != name:
                    continue
                imported = alias.name
                if alias.asname is not None:
                    imported += f" as {alias.asname}"
                return f"import {imported}\n"
    return None


def _project_runtime_fidelity(source_path: Path, stub_path: Path) -> None:
    """Restore API facts that import-free stubgen cannot infer safely.

    Stubgen intentionally omits underscore-prefixed dataclass fields, even when
    those fields are parameters of a public generated constructor.  It also
    cannot infer that direct subclasses of ``SealedContractValue`` reject all
    further subclasses at runtime.  Both are part of the public type contract.
    """

    source_tree = ast.parse(source_path.read_text(encoding="utf-8"))
    stub_text = stub_path.read_text(encoding="utf-8")
    stub_tree = ast.parse(stub_text)
    source_classes = {
        statement.name: statement
        for statement in source_tree.body
        if isinstance(statement, ast.ClassDef)
    }
    stub_classes = {
        statement.name: statement
        for statement in stub_tree.body
        if isinstance(statement, ast.ClassDef)
    }
    insertions: dict[int, list[str]] = {}
    replacements: dict[int, tuple[int, str]] = {}
    extra_imports: set[str] = set()
    needs_final_import = False

    source_aliases = {
        statement.target.id: statement
        for statement in source_tree.body
        if isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and _terminal_name(statement.annotation) == "TypeAlias"
        and statement.value is not None
    }
    stub_assignments = {
        statement.target.id: statement
        for statement in stub_tree.body
        if isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
    }
    stub_bindings = _module_bound_names(stub_tree)
    for name, source_alias in source_aliases.items():
        stub_assignment = stub_assignments.get(name)
        if stub_assignment is None:
            continue
        assert source_alias.value is not None
        alias_value = ast.unparse(source_alias.value)
        replacements[stub_assignment.lineno - 1] = (
            stub_assignment.end_lineno or stub_assignment.lineno,
            f"type {name} = {alias_value}\n",
        )
        for referenced_name in {
            node.id
            for node in ast.walk(source_alias.value)
            if isinstance(node, ast.Name)
        } - stub_bindings:
            source_import = _source_import_for_name(
                source_tree,
                referenced_name,
            )
            if source_import is not None:
                extra_imports.add(source_import)

    for name, source_class in source_classes.items():
        stub_class = stub_classes.get(name)
        if stub_class is None:
            continue

        if (
            _dataclass_generates_init(source_class)
            and _is_dataclass(stub_class)
        ):
            source_fields = _dataclass_fields(source_class)
            stub_fields = _class_fields(stub_class)
            source_field_names = [field_name for field_name, _, _ in source_fields]
            for index, (field_name, annotation, has_default) in enumerate(
                source_fields
            ):
                if not field_name.startswith("_") or field_name in stub_fields:
                    continue
                following = next(
                    (
                        stub_fields[candidate]
                        for candidate in source_field_names[index + 1 :]
                        if candidate in stub_fields
                    ),
                    None,
                )
                if following is not None:
                    insertion_line = following.lineno - 1
                else:
                    preceding = next(
                        (
                            stub_fields[candidate]
                            for candidate in reversed(source_field_names[:index])
                            if candidate in stub_fields
                        ),
                        None,
                    )
                    if preceding is not None:
                        insertion_line = (preceding.end_lineno or preceding.lineno)
                    elif stub_class.body:
                        insertion_line = stub_class.body[0].lineno - 1
                    else:  # pragma: no cover - a parsed class always has a body
                        raise StubExportError(
                            f"generated class has no body: {stub_path}:{name}"
                        )
                suffix = " = ..." if has_default else ""
                insertions.setdefault(insertion_line, []).append(
                    f"    {field_name}: {annotation}{suffix}\n"
                )

        sealed = any(
            _terminal_name(base) == "SealedContractValue"
            for base in source_class.bases
        )
        already_final = any(
            _terminal_name(decorator) == "final"
            for decorator in stub_class.decorator_list
        )
        if sealed and not already_final:
            first_line = min(
                [stub_class.lineno]
                + [decorator.lineno for decorator in stub_class.decorator_list]
            )
            insertions.setdefault(first_line - 1, []).append("@final\n")
            needs_final_import = True

    if not insertions and not replacements and not needs_final_import:
        return
    lines = stub_text.splitlines(keepends=True)
    for line_index in sorted(set(insertions) | set(replacements), reverse=True):
        replacement = replacements.get(line_index)
        if replacement is not None:
            end_line, replacement_text = replacement
            lines[line_index:end_line] = [replacement_text]
        if line_index in insertions:
            lines[line_index:line_index] = insertions[line_index]
    imports_to_prepend = sorted(extra_imports)
    if needs_final_import and not _has_final_binding(stub_tree):
        imports_to_prepend.append("from typing import final\n")
    if imports_to_prepend:
        lines[0:0] = imports_to_prepend
    stub_path.write_text("".join(lines), encoding="utf-8", newline="\n")


def _require_supported_stubgen() -> None:
    try:
        actual = metadata.version("mypy")
    except metadata.PackageNotFoundError as exc:
        raise StubExportError(
            "mypy is unavailable; install the repository test extra first"
        ) from exc
    if actual != STUBGEN_VERSION:
        raise StubExportError(
            "stub generation requires mypy "
            f"{STUBGEN_VERSION}, but {actual} is installed"
        )


def _stage_python_sources(destination: Path) -> tuple[Path, ...]:
    """Copy only implementation files so colocated stubs cannot shadow input."""

    staged_packages: list[Path] = []
    for package_root in PACKAGE_ROOTS:
        staged_package = destination / package_root.name
        staged_packages.append(staged_package)
        for source in package_root.rglob("*.py"):
            relative = source.relative_to(package_root)
            staged_source = staged_package / relative
            staged_source.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, staged_source)
    return tuple(staged_packages)


def _generate(destination: Path, source_packages: tuple[Path, ...]) -> None:
    command = [
        sys.executable,
        "-c",
        "from mypy.stubgen import main; main()",
        "--no-import",
        "--output",
        str(destination),
        *(str(package_root) for package_root in source_packages),
    ]
    completed = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
    if completed.returncode != 0:
        detail = completed.stdout.strip()
        raise StubExportError(
            f"stubgen failed with exit code {completed.returncode}: {detail}"
        )

    for source_package in source_packages:
        generated_package = destination / source_package.name
        for source_path in sorted(source_package.rglob("*.py")):
            relative = source_path.relative_to(source_package)
            stub_path = generated_package / relative.with_suffix(".pyi")
            if not stub_path.is_file():
                raise StubExportError(
                    f"stubgen omitted a staged module: {source_path}"
                )
            _project_runtime_fidelity(source_path, stub_path)

    for relative, supplement in STUB_SUPPLEMENTS.items():
        stub_path = destination / relative
        if not stub_path.is_file():
            raise StubExportError(
                f"stub supplement target was not generated: {relative}"
            )
        with stub_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(supplement)


def _stub_files(root: Path) -> dict[Path, str]:
    return {
        path.relative_to(root): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*.pyi"))
    }


def _expected_tree(generated_root: Path, package_root: Path) -> dict[Path, str]:
    generated_package = generated_root / package_root.name
    if not generated_package.is_dir():
        raise StubExportError(
            f"stubgen did not produce the expected {package_root.name!r} package"
        )
    return _stub_files(generated_package)


def _verify(generated_root: Path) -> int:
    problems: list[str] = []
    stub_count = 0
    for package_root in PACKAGE_ROOTS:
        expected = _expected_tree(generated_root, package_root)
        actual = _stub_files(package_root)
        stub_count += len(expected)
        missing = sorted(expected.keys() - actual.keys())
        stale = sorted(actual.keys() - expected.keys())
        changed = sorted(
            relative
            for relative in expected.keys() & actual.keys()
            if expected[relative] != actual[relative]
        )
        for relative in missing:
            problems.append(f"missing: {package_root / relative}")
        for relative in stale:
            problems.append(f"stale: {package_root / relative}")
        for relative in changed:
            problems.append(f"out of date: {package_root / relative}")
        marker = package_root / "py.typed"
        if not marker.is_file():
            problems.append(f"missing: {marker}")
        elif marker.read_bytes() != b"":
            problems.append(f"PEP 561 marker must be empty: {marker}")

    if problems:
        rendered = "\n".join(f"- {problem}" for problem in problems)
        raise StubExportError(
            "checked-in type stubs differ from the generated API surface:\n"
            f"{rendered}\n"
            "Run `python scripts/export_type_stubs.py` and review the result."
        )
    return stub_count


def _write(generated_root: Path) -> int:
    stub_count = 0
    for package_root in PACKAGE_ROOTS:
        expected = _expected_tree(generated_root, package_root)
        stub_count += len(expected)
        for stale in package_root.rglob("*.pyi"):
            relative = stale.relative_to(package_root)
            if relative not in expected:
                stale.unlink()
        for relative, contents in expected.items():
            destination = package_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(contents, encoding="utf-8", newline="\n")
        (package_root / "py.typed").write_bytes(b"")
    return stub_count


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate or verify all checked-in Python API stubs."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that checked-in stubs match import-free generation",
    )
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    try:
        _require_supported_stubgen()
        with tempfile.TemporaryDirectory(prefix="router-dump-stubs-") as temporary:
            temporary_root = Path(temporary)
            source_packages = _stage_python_sources(temporary_root / "source")
            generated_root = temporary_root / "output"
            _generate(generated_root, source_packages)
            count = (
                _verify(generated_root)
                if arguments.check
                else _write(generated_root)
            )
    except (OSError, StubExportError, subprocess.SubprocessError) as exc:
        print(f"type-stub export failed: {exc}", file=sys.stderr)
        return 1

    action = "verified" if arguments.check else "generated"
    print(f"{action} {count} module stubs across {len(PACKAGE_ROOTS)} packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
