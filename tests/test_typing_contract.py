from __future__ import annotations

import ast
import unittest
from collections.abc import Iterable, Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOTS = (
    ROOT / "src" / "router_dump_analyzer",
    ROOT / "demo" / "rsl_demo_plugin",
    ROOT / "demo" / "rsl_demo_generator",
    ROOT / "state-dump-generator" / "src" / "state_dump_generator",
)


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _parse(path: Path) -> ast.Module:
    return ast.parse(
        path.read_text(encoding="utf-8"),
        filename=str(path),
        type_comments=True,
    )


def _assignment_targets(statement: ast.stmt) -> Iterator[ast.expr]:
    if isinstance(statement, ast.Assign):
        yield from statement.targets
    elif isinstance(statement, ast.AnnAssign):
        yield statement.target


def _bound_target_names(target: ast.expr) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.List, ast.Tuple)):
        return {
            name
            for element in target.elts
            for name in _bound_target_names(element)
        }
    return set()


def _is_all_assignment(statement: ast.stmt) -> bool:
    return any(
        isinstance(target, ast.Name) and target.id == "__all__"
        for target in _assignment_targets(statement)
    )


def _literal_all_names(tree: ast.Module) -> tuple[str, ...] | None:
    """Return a literal ``__all__`` or None when the module has none.

    Public export validation must be deterministic and side-effect free, so a
    future dynamically-computed ``__all__`` deliberately fails this contract
    rather than being imported and executed by the test suite.
    """

    assignments = [
        statement for statement in tree.body if _is_all_assignment(statement)
    ]
    if not assignments:
        return None
    if len(assignments) != 1:
        raise AssertionError("__all__ must have exactly one top-level assignment")
    assignment = assignments[0]
    value = assignment.value
    if value is None:
        raise AssertionError("__all__ must have a literal value")
    try:
        evaluated = ast.literal_eval(value)
    except (ValueError, TypeError, SyntaxError) as exc:
        raise AssertionError(
            "__all__ must be a literal list or tuple of strings"
        ) from exc
    if not isinstance(evaluated, (list, tuple)) or any(
        not isinstance(name, str) for name in evaluated
    ):
        raise AssertionError("__all__ must be a literal list or tuple of strings")
    return tuple(evaluated)


def _nested_module_statements(statements: Iterable[ast.stmt]) -> Iterator[ast.stmt]:
    """Yield module-scope statements, including conditional definitions.

    The traversal intentionally does not enter functions or classes. It does
    follow control-flow suites because version and TYPE_CHECKING branches may
    legally define names at module scope in a stub.
    """

    for statement in statements:
        yield statement
        if isinstance(statement, ast.If):
            yield from _nested_module_statements(statement.body)
            yield from _nested_module_statements(statement.orelse)
        elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            yield from _nested_module_statements(statement.body)
            yield from _nested_module_statements(statement.orelse)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            yield from _nested_module_statements(statement.body)
        elif isinstance(statement, ast.Try):
            yield from _nested_module_statements(statement.body)
            for handler in statement.handlers:
                yield from _nested_module_statements(handler.body)
            yield from _nested_module_statements(statement.orelse)
            yield from _nested_module_statements(statement.finalbody)
        elif hasattr(ast, "TryStar") and isinstance(statement, ast.TryStar):
            yield from _nested_module_statements(statement.body)
            for handler in statement.handlers:
                yield from _nested_module_statements(handler.body)
            yield from _nested_module_statements(statement.orelse)
            yield from _nested_module_statements(statement.finalbody)
        elif isinstance(statement, ast.Match):
            for case in statement.cases:
                yield from _nested_module_statements(case.body)


def _stub_bindings(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Return all bound names and locally defined or explicitly exported names."""

    bindings: set[str] = set()
    explicit_reexports: set[str] = set()
    type_alias_node = getattr(ast, "TypeAlias", ())
    for statement in _nested_module_statements(tree.body):
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bindings.add(statement.name)
            explicit_reexports.add(statement.name)
        elif type_alias_node and isinstance(statement, type_alias_node):
            names = _bound_target_names(statement.name)
            bindings.update(names)
            explicit_reexports.update(names)
        elif isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if alias.name == "*":
                    continue
                bound_name = alias.asname or alias.name
                bindings.add(bound_name)
                if alias.asname == alias.name:
                    explicit_reexports.add(bound_name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                bound_name = alias.asname or alias.name.partition(".")[0]
                bindings.add(bound_name)
                if alias.asname == alias.name.partition(".")[0]:
                    explicit_reexports.add(bound_name)
        else:
            for target in _assignment_targets(statement):
                names = _bound_target_names(target)
                bindings.update(names)
                explicit_reexports.update(names)
    return bindings, explicit_reexports


def _module_owned_public_bindings(tree: ast.Module) -> set[str]:
    """Return public names declared by a module rather than imported into it."""

    bindings: set[str] = set()
    type_alias_node = getattr(ast, "TypeAlias", ())
    for statement in _nested_module_statements(tree.body):
        names: set[str] = set()
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(statement.name)
        elif type_alias_node and isinstance(statement, type_alias_node):
            names.update(_bound_target_names(statement.name))
        elif not isinstance(statement, (ast.Import, ast.ImportFrom)):
            for target in _assignment_targets(statement):
                names.update(_bound_target_names(target))
        bindings.update(
            name
            for name in names
            if name != "__all__" and not name.startswith("_")
        )
    return bindings


def _protocol_spellings(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Return direct Protocol names and module aliases that provide Protocol."""

    direct = {"Protocol"}
    modules = {"typing", "typing_extensions"}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom) and statement.module in {
            "typing",
            "typing_extensions",
        }:
            for alias in statement.names:
                if alias.name == "Protocol":
                    direct.add(alias.asname or alias.name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name in {"typing", "typing_extensions"}:
                    modules.add(alias.asname or alias.name)
    return direct, modules


def _is_protocol_base(
    base: ast.expr,
    *,
    direct_names: set[str],
    module_names: set[str],
) -> bool:
    while isinstance(base, ast.Subscript):
        base = base.value
    if isinstance(base, ast.Name):
        return base.id in direct_names
    return (
        isinstance(base, ast.Attribute)
        and base.attr == "Protocol"
        and isinstance(base.value, ast.Name)
        and base.value.id in module_names
    )


def _public_protocol_names(tree: ast.Module) -> set[str]:
    direct_names, module_names = _protocol_spellings(tree)
    return {
        statement.name
        for statement in tree.body
        if isinstance(statement, ast.ClassDef)
        and not statement.name.startswith("_")
        and any(
            _is_protocol_base(
                base,
                direct_names=direct_names,
                module_names=module_names,
            )
            for base in statement.bases
        )
    }


def _terminal_name(expression: ast.expr) -> str | None:
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


def _dataclass_init_field_shapes(
    class_node: ast.ClassDef,
) -> tuple[tuple[str, bool], ...]:
    fields: list[tuple[str, bool]] = []
    for statement in class_node.body:
        if not isinstance(statement, ast.AnnAssign) or not isinstance(
            statement.target,
            ast.Name,
        ):
            continue
        if _terminal_name(statement.annotation) in {"ClassVar", "KW_ONLY"}:
            continue
        value = statement.value
        is_field_call = (
            isinstance(value, ast.Call)
            and _terminal_name(value.func) == "field"
        )
        if is_field_call and any(
            keyword.arg == "init"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in value.keywords
        ):
            continue
        has_default = value is not None
        if is_field_call:
            has_default = any(
                keyword.arg in {"default", "default_factory"}
                for keyword in value.keywords
            )
        fields.append((statement.target.id, has_default))
    return tuple(fields)


def _top_level_classes(tree: ast.Module) -> dict[str, ast.ClassDef]:
    return {
        statement.name: statement
        for statement in tree.body
        if isinstance(statement, ast.ClassDef)
    }


def _contains_incomplete(annotation: ast.expr | None) -> bool:
    return annotation is not None and any(
        isinstance(node, ast.Name) and node.id == "Incomplete"
        for node in ast.walk(annotation)
    )


def _function_annotations(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[ast.expr]:
    arguments = function.args
    for argument in (
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
    ):
        if argument.annotation is not None:
            yield argument.annotation
    for argument in (arguments.vararg, arguments.kwarg):
        if argument is not None and argument.annotation is not None:
            yield argument.annotation
    if function.returns is not None:
        yield function.returns


def _declared_type_alias_names(tree: ast.Module) -> set[str]:
    return {
        statement.target.id
        for statement in tree.body
        if isinstance(statement, ast.AnnAssign)
        and isinstance(statement.target, ast.Name)
        and _terminal_name(statement.annotation) == "TypeAlias"
        and statement.value is not None
    }


def _type_aliases_with_rhs(tree: ast.Module) -> set[str]:
    aliases: set[str] = set()
    type_alias_node = getattr(ast, "TypeAlias", ())
    for statement in tree.body:
        if type_alias_node and isinstance(statement, type_alias_node):
            if isinstance(statement.name, ast.Name):
                aliases.add(statement.name.id)
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and _terminal_name(statement.annotation) == "TypeAlias"
            and statement.value is not None
            and not (
                isinstance(statement.value, ast.Constant)
                and statement.value.value is Ellipsis
            )
        ):
            aliases.add(statement.target.id)
    return aliases


class TypingContractTests(unittest.TestCase):
    def test_each_python_module_has_exactly_one_peer_stub(self) -> None:
        missing: list[str] = []
        orphaned: list[str] = []
        for package_root in PACKAGE_ROOTS:
            source_paths = set(package_root.rglob("*.py"))
            stub_paths = set(package_root.rglob("*.pyi"))
            missing.extend(
                _relative(source_path.with_suffix(".pyi"))
                for source_path in sorted(source_paths)
                if source_path.with_suffix(".pyi") not in stub_paths
            )
            orphaned.extend(
                _relative(stub_path)
                for stub_path in sorted(stub_paths)
                if stub_path.with_suffix(".py") not in source_paths
            )
        self.assertFalse(
            missing,
            "Python modules without peer stubs:\n" + "\n".join(missing),
        )
        self.assertFalse(
            orphaned,
            "Stub modules without runtime peers:\n" + "\n".join(orphaned),
        )

    def test_each_distribution_has_a_pep_561_marker(self) -> None:
        missing = [
            _relative(package_root / "py.typed")
            for package_root in PACKAGE_ROOTS
            if not (package_root / "py.typed").is_file()
        ]
        self.assertFalse(
            missing,
            "Distributions without a py.typed marker:\n" + "\n".join(missing),
        )
        nonempty = [
            _relative(package_root / "py.typed")
            for package_root in PACKAGE_ROOTS
            if (package_root / "py.typed").is_file()
            and (package_root / "py.typed").read_bytes() != b""
        ]
        self.assertFalse(
            nonempty,
            "Complete inline-stub packages must use empty py.typed markers:\n"
            + "\n".join(nonempty),
        )

    def test_every_stub_is_valid_python_312_syntax(self) -> None:
        failures: list[str] = []
        for package_root in PACKAGE_ROOTS:
            for stub_path in sorted(package_root.rglob("*.pyi")):
                try:
                    _parse(stub_path)
                except (SyntaxError, UnicodeError) as exc:
                    failures.append(f"{_relative(stub_path)}: {exc}")
        self.assertFalse(
            failures,
            "Stubs that do not parse:\n" + "\n".join(failures),
        )

    def test_literal_source_exports_are_defined_or_reexported_by_stubs(self) -> None:
        failures: list[str] = []
        for package_root in PACKAGE_ROOTS:
            for source_path in sorted(package_root.rglob("*.py")):
                try:
                    source_exports = _literal_all_names(_parse(source_path))
                except AssertionError as exc:
                    failures.append(f"{_relative(source_path)}: {exc}")
                    continue
                if source_exports is None:
                    continue
                stub_path = source_path.with_suffix(".pyi")
                if not stub_path.is_file():
                    continue
                stub_tree = _parse(stub_path)
                bindings, explicit_reexports = _stub_bindings(stub_tree)
                try:
                    stub_exports = _literal_all_names(stub_tree)
                except AssertionError as exc:
                    failures.append(f"{_relative(stub_path)}: {exc}")
                    continue
                declared_exports = set(stub_exports or ())
                for name in source_exports:
                    if name not in bindings:
                        failures.append(
                            f"{_relative(stub_path)}: {name!r} is not defined"
                        )
                    elif (
                        name not in declared_exports
                        and name not in explicit_reexports
                    ):
                        failures.append(
                            f"{_relative(stub_path)}: {name!r} is not re-exported"
                        )
        self.assertFalse(
            failures,
            "Source __all__ entries missing from the typing surface:\n"
            + "\n".join(failures),
        )

    def test_public_protocol_classes_remain_protocols_in_stubs(self) -> None:
        failures: list[str] = []
        for package_root in PACKAGE_ROOTS:
            for source_path in sorted(package_root.rglob("*.py")):
                source_protocols = _public_protocol_names(_parse(source_path))
                if not source_protocols:
                    continue
                stub_path = source_path.with_suffix(".pyi")
                if not stub_path.is_file():
                    continue
                stub_protocols = _public_protocol_names(_parse(stub_path))
                for name in sorted(source_protocols - stub_protocols):
                    failures.append(
                        f"{_relative(stub_path)}: {name!r} no longer derives "
                        "from Protocol"
                    )
        self.assertFalse(
            failures,
            "Public Protocol definitions lost their structural contract:\n"
            + "\n".join(failures),
        )

    def test_modules_without_all_keep_module_owned_public_bindings(self) -> None:
        failures: list[str] = []
        for package_root in PACKAGE_ROOTS:
            for source_path in sorted(package_root.rglob("*.py")):
                source_tree = _parse(source_path)
                if _literal_all_names(source_tree) is not None:
                    continue
                source_bindings = _module_owned_public_bindings(source_tree)
                stub_path = source_path.with_suffix(".pyi")
                if not stub_path.is_file():
                    continue
                stub_bindings, _ = _stub_bindings(_parse(stub_path))
                for name in sorted(source_bindings - stub_bindings):
                    failures.append(
                        f"{_relative(stub_path)}: {name!r} is not defined"
                    )
        self.assertFalse(
            failures,
            "Public declarations missing from modules without __all__:\n"
            + "\n".join(failures),
        )

    def test_public_dataclass_generated_constructors_match_source(self) -> None:
        failures: list[str] = []
        for package_root in PACKAGE_ROOTS:
            for source_path in sorted(package_root.rglob("*.py")):
                source_classes = _top_level_classes(_parse(source_path))
                stub_path = source_path.with_suffix(".pyi")
                if not stub_path.is_file():
                    continue
                stub_classes = _top_level_classes(_parse(stub_path))
                for name, source_class in source_classes.items():
                    if name.startswith("_") or not _dataclass_generates_init(
                        source_class
                    ):
                        continue
                    stub_class = stub_classes.get(name)
                    if stub_class is None or not _is_dataclass(stub_class):
                        continue
                    source_shape = _dataclass_init_field_shapes(source_class)
                    stub_shape = _dataclass_init_field_shapes(stub_class)
                    if source_shape != stub_shape:
                        failures.append(
                            f"{_relative(stub_path)}:{name}: "
                            f"source {source_shape!r}, stub {stub_shape!r}"
                        )
        self.assertFalse(
            failures,
            "Public dataclass constructor fields differ from runtime:\n"
            + "\n".join(failures),
        )

    def test_runtime_sealed_contracts_are_final_in_stubs(self) -> None:
        failures: list[str] = []
        for package_root in PACKAGE_ROOTS:
            for source_path in sorted(package_root.rglob("*.py")):
                source_classes = _top_level_classes(_parse(source_path))
                sealed_names = {
                    name
                    for name, class_node in source_classes.items()
                    if not name.startswith("_")
                    and any(
                        _terminal_name(base) == "SealedContractValue"
                        for base in class_node.bases
                    )
                }
                if not sealed_names:
                    continue
                stub_path = source_path.with_suffix(".pyi")
                stub_classes = _top_level_classes(_parse(stub_path))
                for name in sorted(sealed_names):
                    stub_class = stub_classes.get(name)
                    if stub_class is None or not any(
                        _terminal_name(decorator) == "final"
                        for decorator in stub_class.decorator_list
                    ):
                        failures.append(
                            f"{_relative(stub_path)}:{name} is not final"
                        )
        self.assertFalse(
            failures,
            "Runtime-sealed contracts open to static subclassing:\n"
            + "\n".join(failures),
        )

    def test_public_stub_annotations_are_not_incomplete(self) -> None:
        failures: list[str] = []
        for package_root in PACKAGE_ROOTS:
            for stub_path in sorted(package_root.rglob("*.pyi")):
                tree = _parse(stub_path)
                literal_exports = _literal_all_names(tree)
                exported = set(literal_exports or ())

                def is_exported(name: str) -> bool:
                    if literal_exports is not None:
                        return name in exported
                    return not name.startswith("_")

                for statement in tree.body:
                    if (
                        isinstance(statement, ast.AnnAssign)
                        and isinstance(statement.target, ast.Name)
                        and is_exported(statement.target.id)
                        and _contains_incomplete(statement.annotation)
                    ):
                        failures.append(
                            f"{_relative(stub_path)}:{statement.target.id}"
                        )
                    elif isinstance(
                        statement,
                        (ast.FunctionDef, ast.AsyncFunctionDef),
                    ) and is_exported(statement.name):
                        if any(
                            _contains_incomplete(annotation)
                            for annotation in _function_annotations(statement)
                        ):
                            failures.append(
                                f"{_relative(stub_path)}:{statement.name}()"
                            )
                    elif isinstance(statement, ast.ClassDef) and is_exported(
                        statement.name
                    ):
                        for member in statement.body:
                            if (
                                isinstance(member, ast.AnnAssign)
                                and isinstance(member.target, ast.Name)
                                and not member.target.id.startswith("_")
                                and _contains_incomplete(member.annotation)
                            ):
                                failures.append(
                                    f"{_relative(stub_path)}:"
                                    f"{statement.name}.{member.target.id}"
                                )
                            elif isinstance(
                                member,
                                (ast.FunctionDef, ast.AsyncFunctionDef),
                            ) and not member.name.startswith("_"):
                                if any(
                                    _contains_incomplete(annotation)
                                    for annotation in _function_annotations(member)
                                ):
                                    failures.append(
                                        f"{_relative(stub_path)}:"
                                        f"{statement.name}.{member.name}()"
                                    )
        self.assertFalse(
            failures,
            "Exported annotations degraded to _typeshed.Incomplete:\n"
            + "\n".join(failures),
        )

    def test_declared_type_aliases_keep_a_stub_rhs(self) -> None:
        failures: list[str] = []
        for package_root in PACKAGE_ROOTS:
            for source_path in sorted(package_root.rglob("*.py")):
                aliases = _declared_type_alias_names(_parse(source_path))
                if not aliases:
                    continue
                stub_path = source_path.with_suffix(".pyi")
                stub_aliases = _type_aliases_with_rhs(_parse(stub_path))
                for name in sorted(aliases - stub_aliases):
                    failures.append(
                        f"{_relative(stub_path)}:{name} has no alias RHS"
                    )
        self.assertFalse(
            failures,
            "Declared source type aliases lost their definitions:\n"
            + "\n".join(failures),
        )


if __name__ == "__main__":
    unittest.main()
