from __future__ import annotations

import ast
import copy
import hashlib
import io
import tokenize
import unittest
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOTS = (
    ROOT / "src" / "router_dump_analyzer",
    ROOT / "demo" / "rsl_demo_plugin",
    ROOT / "demo" / "rsl_demo_generator",
    ROOT / "scripts",
)
MINIMUM_CLONE_TOKENS = 80
MINIMUM_STRUCTURAL_AST_LENGTH = 1_200
IGNORED_TOKEN_TYPES = frozenset(
    {
        tokenize.ENCODING,
        tokenize.COMMENT,
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENDMARKER,
    }
)


def _production_python_files() -> tuple[Path, ...]:
    return tuple(
        sorted(
            path
            for root in PRODUCTION_ROOTS
            for path in root.rglob("*.py")
            if path.is_file() and "__pycache__" not in path.parts
        )
    )


def _significant_tokens(
    path: Path,
) -> tuple[tuple[tuple[int, str], ...], tuple[int, ...]]:
    values: list[tuple[int, str]] = []
    lines: list[int] = []
    source = path.read_text(encoding="utf-8")
    for item in tokenize.generate_tokens(io.StringIO(source).readline):
        if item.type in IGNORED_TOKEN_TYPES:
            continue
        values.append((item.type, item.string))
        lines.append(item.start[0])
    return tuple(values), tuple(lines)


def _rolling_hashes(
    values: tuple[int, ...],
    width: int,
) -> Iterator[tuple[int, int]]:
    if len(values) < width:
        return
    mask = (1 << 64) - 1
    base = 1_000_003
    leading_power = pow(base, width - 1, 1 << 64)
    digest = 0
    for value in values[:width]:
        digest = ((digest * base) + value) & mask
    yield 0, digest
    for index in range(1, len(values) - width + 1):
        digest = (
            (digest - ((values[index - 1] * leading_power) & mask)) * base
            + values[index + width - 1]
        ) & mask
        yield index, digest


def _function_local_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[ast.AST]:
    """Yield executable nodes owned by one function, excluding nested scopes."""

    pending = list(reversed(node.body))
    while pending:
        candidate = pending.pop()
        if isinstance(
            candidate,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            if not isinstance(candidate, ast.Lambda):
                # The declaration name is a binding in the owning scope, but
                # its body belongs to another scope.
                yield candidate
            continue
        yield candidate
        pending.extend(reversed(tuple(ast.iter_child_nodes(candidate))))


_BuiltinCallAliases = tuple[
    frozenset[str],
    frozenset[str],
    frozenset[str],
]


def _builtin_reference_kind(
    value: ast.AST | None,
    *,
    aliases: _BuiltinCallAliases,
) -> str | None:
    """Resolve only names proven to refer to the built-in ``int``/``str``."""

    module_names, integer_names, string_names = aliases
    if isinstance(value, ast.Name):
        if value.id in integer_names:
            return "int"
        if value.id in string_names:
            return "str"
        return None
    if (
        isinstance(value, ast.Attribute)
        and isinstance(value.value, ast.Name)
        and value.value.id in module_names
        and value.attr in {"int", "str"}
    ):
        return value.attr
    return None


def _collect_builtin_call_aliases(
    nodes: Iterator[ast.AST] | tuple[ast.AST, ...] | list[ast.stmt],
    *,
    inherited: _BuiltinCallAliases | None = None,
    shadowed_names: frozenset[str] = frozenset(),
) -> _BuiltinCallAliases:
    """Collect only names proven to retain built-in callable identity."""

    materialized = tuple(nodes)
    if inherited is None:
        module_names: set[str] = set()
        integer_names = {"int"}
        string_names = {"str"}
    else:
        module_names = set(inherited[0])
        integer_names = set(inherited[1])
        string_names = set(inherited[2])

    bound_names = set(shadowed_names)
    for candidate in materialized:
        if isinstance(candidate, ast.Name) and isinstance(candidate.ctx, ast.Store):
            bound_names.add(candidate.id)
        elif (assignment := _assignment_parts(candidate)) is not None:
            bound_names.update(_stored_names(assignment[0]))
        elif isinstance(
            candidate, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            bound_names.add(candidate.name)
        elif isinstance(candidate, ast.Import):
            bound_names.update(
                imported.asname or imported.name.split(".", 1)[0]
                for imported in candidate.names
            )
        elif isinstance(candidate, ast.ImportFrom):
            bound_names.update(
                imported.asname or imported.name for imported in candidate.names
            )

    # Python resolves function locals lexically: a parameter or assignment
    # named ``int``/``str`` shadows the built-in even before its statement.
    module_names.difference_update(bound_names)
    integer_names.difference_update(bound_names)
    string_names.difference_update(bound_names)

    for candidate in materialized:
        if isinstance(candidate, ast.Import):
            for imported in candidate.names:
                if imported.name == "builtins":
                    module_names.add(imported.asname or imported.name)
        elif isinstance(candidate, ast.ImportFrom) and candidate.module == "builtins":
            for imported in candidate.names:
                if imported.name == "int":
                    integer_names.add(imported.asname or imported.name)
                elif imported.name == "str":
                    string_names.add(imported.asname or imported.name)

    # Follow simple aliases such as ``parse_int = builtins.int``. Iterate to a
    # fixed point so one additional alias layer cannot bypass the invariant.
    while True:
        aliases = (
            frozenset(module_names),
            frozenset(integer_names),
            frozenset(string_names),
        )
        changed = False
        for candidate in materialized:
            if isinstance(candidate, ast.Assign):
                targets = candidate.targets
                value = candidate.value
            elif isinstance(candidate, ast.AnnAssign):
                targets = (candidate.target,)
                value = candidate.value
            else:
                continue
            kind = _builtin_reference_kind(value, aliases=aliases)
            if kind is None:
                continue
            destination = integer_names if kind == "int" else string_names
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in destination:
                    destination.add(target.id)
                    changed = True
        if not changed:
            return (
                frozenset(module_names),
                frozenset(integer_names),
                frozenset(string_names),
            )


def _function_parameter_names(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    arguments = node.args
    names = {
        item.arg
        for item in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
    }
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)
    return frozenset(names)


def _is_builtin_call(
    value: ast.AST,
    kind: str,
    *,
    aliases: _BuiltinCallAliases,
) -> bool:
    return (
        isinstance(value, ast.Call)
        and _builtin_reference_kind(value.func, aliases=aliases) == kind
    )


def _value_origins(
    value: ast.AST,
    origins_by_name: dict[str, frozenset[str]],
) -> frozenset[str]:
    """Return symbolic inputs that contribute to one expression's value."""

    if isinstance(value, ast.Name):
        return origins_by_name.get(value.id, frozenset({value.id}))
    if isinstance(value, ast.Constant):
        return frozenset()
    if isinstance(value, ast.IfExp):
        return _value_origins(value.body, origins_by_name).union(
            _value_origins(value.orelse, origins_by_name)
        )
    if isinstance(
        value,
        (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp),
    ):
        projected: tuple[ast.expr, ...]
        if isinstance(value, ast.DictComp):
            projected = (value.key, value.value)
        else:
            projected = (value.elt,)
        return frozenset().union(
            *(_value_origins(item, origins_by_name) for item in projected),
            *(
                _value_origins(item, origins_by_name)
                for generator in value.generators
                for item in (generator.iter, *generator.ifs)
            ),
        )
    if isinstance(value, ast.Attribute):
        return _value_origins(value.value, origins_by_name)
    if isinstance(value, ast.Subscript):
        return _value_origins(value.value, origins_by_name)
    if isinstance(value, ast.Call):
        receiver_origins = (
            _value_origins(value.func.value, origins_by_name)
            if isinstance(value.func, ast.Attribute)
            else frozenset()
        )
        return receiver_origins.union(
            *(
                _value_origins(item, origins_by_name)
                for item in (*value.args, *(item.value for item in value.keywords))
            )
        )
    child_origins = tuple(
        _value_origins(child, origins_by_name)
        for child in ast.iter_child_nodes(value)
        if isinstance(child, ast.expr)
    )
    return frozenset().union(*child_origins) if child_origins else frozenset()


def _assignment_parts(
    node: ast.AST,
) -> tuple[tuple[ast.expr, ...], ast.expr] | None:
    if isinstance(node, ast.Assign):
        return tuple(node.targets), node.value
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return (node.target,), node.value
    if isinstance(node, ast.NamedExpr):
        return (node.target,), node.value
    return None


def _stored_names(targets: tuple[ast.expr, ...]) -> tuple[str, ...]:
    return tuple(
        item.id
        for target in targets
        for item in ast.walk(target)
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store)
    )


def _implements_decimal_integer_grammar(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    inherited_aliases: _BuiltinCallAliases,
) -> bool:
    """Detect a locally reimplemented canonical-decimal parser language."""

    local_nodes = tuple(_function_local_nodes(node))
    aliases = _collect_builtin_call_aliases(
        local_nodes,
        inherited=inherited_aliases,
        shadowed_names=_function_parameter_names(node),
    )

    assignments = tuple(
        parts
        for candidate in local_nodes
        if (parts := _assignment_parts(candidate)) is not None
    )
    origins_by_name: dict[str, frozenset[str]] = {}
    changed = True
    while changed:
        changed = False
        for targets, value in assignments:
            origins = _value_origins(value, origins_by_name)
            if not origins:
                continue
            for name in _stored_names(targets):
                combined = origins_by_name.get(name, frozenset()).union(origins)
                if combined != origins_by_name.get(name):
                    origins_by_name[name] = frozenset(combined)
                    changed = True

    integer_call_origins = tuple(
        _value_origins(candidate.args[0], origins_by_name)
        for candidate in local_nodes
        if _is_builtin_call(candidate, "int", aliases=aliases) and candidate.args
    )
    if not integer_call_origins:
        return False

    def digit_receiver_origins(candidate: ast.AST) -> frozenset[str]:
        if not (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Attribute)
            and candidate.func.attr in {"isdecimal", "isdigit", "isnumeric"}
            and not candidate.args
        ):
            return frozenset()
        receiver = candidate.func.value
        if isinstance(receiver, ast.Name):
            return _value_origins(receiver, origins_by_name)
        if (
            isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Attribute)
            and receiver.func.attr in {"lstrip", "removeprefix"}
            and len(receiver.args) == 1
            and isinstance(receiver.args[0], ast.Constant)
            and receiver.args[0].value in {"-", "+", "+-", "-+"}
        ):
            return _value_origins(receiver.func.value, origins_by_name)
        if (
            isinstance(receiver, ast.Subscript)
            and isinstance(receiver.slice, ast.Slice)
            and isinstance(receiver.slice.lower, ast.Constant)
            and receiver.slice.lower.value == 1
            and receiver.slice.upper is None
            and receiver.slice.step is None
        ):
            return _value_origins(receiver.value, origins_by_name)
        return frozenset()

    def regex_digit_gate_origins(candidate: ast.AST) -> frozenset[str]:
        if not isinstance(candidate, ast.Call) or len(candidate.args) < 2:
            return frozenset()
        callable_name = (
            candidate.func.id
            if isinstance(candidate.func, ast.Name)
            else candidate.func.attr
            if isinstance(candidate.func, ast.Attribute)
            else None
        )
        if callable_name != "fullmatch":
            return frozenset()
        if not (
            isinstance(candidate.func, ast.Name)
            or (
                isinstance(candidate.func, ast.Attribute)
                and isinstance(candidate.func.value, ast.Name)
                and candidate.func.value.id == "re"
            )
        ):
            return frozenset()
        pattern = candidate.args[0]
        if not (
            isinstance(pattern, ast.Constant)
            and isinstance(pattern.value, str)
            and (r"\d" in pattern.value or "[0-9]" in pattern.value)
        ):
            return frozenset()
        return _value_origins(candidate.args[1], origins_by_name)

    def all_digits_gate_origins(candidate: ast.AST) -> frozenset[str]:
        if not (
            isinstance(candidate, ast.Call)
            and isinstance(candidate.func, ast.Name)
            and candidate.func.id == "all"
            and len(candidate.args) == 1
        ):
            return frozenset()
        literals = {
            item.value
            for item in ast.walk(candidate.args[0])
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        }
        if "0123456789" not in literals and not {"0", "9"}.issubset(literals):
            return frozenset()
        return _value_origins(candidate.args[0], origins_by_name)

    digit_gate_origins = tuple(
        origins
        for candidate in local_nodes
        for origins in (
            digit_receiver_origins(candidate),
            regex_digit_gate_origins(candidate),
            all_digits_gate_origins(candidate),
        )
        if origins
    )
    if any(
        parsed_origins.intersection(gate_origins)
        for parsed_origins in integer_call_origins
        for gate_origins in digit_gate_origins
    ):
        return True

    parsed_origins_by_name: dict[str, frozenset[str]] = {}
    changed = True
    while changed:
        changed = False
        for targets, value in assignments:
            parsed_origins = frozenset()
            if _is_builtin_call(value, "int", aliases=aliases) and value.args:
                parsed_origins = _value_origins(value.args[0], origins_by_name)
            elif isinstance(value, ast.Name):
                parsed_origins = parsed_origins_by_name.get(
                    value.id,
                    frozenset(),
                )
            if not parsed_origins:
                continue
            for name in _stored_names(targets):
                combined = parsed_origins_by_name.get(name, frozenset()).union(
                    parsed_origins
                )
                if combined != parsed_origins_by_name.get(name):
                    parsed_origins_by_name[name] = frozenset(combined)
                    changed = True

    def parsed_integer_origins(nested: ast.expr) -> frozenset[str]:
        if isinstance(nested, ast.Name):
            return parsed_origins_by_name.get(nested.id, frozenset())
        if _is_builtin_call(nested, "int", aliases=aliases) and nested.args:
            return _value_origins(nested.args[0], origins_by_name)
        return frozenset()

    def joined_integer_origins(value: ast.JoinedStr) -> frozenset[str]:
        formatted = [
            item for item in value.values if isinstance(item, ast.FormattedValue)
        ]
        static_text = "".join(
            item.value
            for item in value.values
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        )
        if len(formatted) != 1 or static_text:
            return frozenset()
        item = formatted[0]
        if item.format_spec is not None:
            try:
                format_spec = ast.literal_eval(item.format_spec)
            except (ValueError, TypeError):
                return frozenset()
            if format_spec not in {"", "d"}:
                return frozenset()
        return parsed_integer_origins(item.value)

    def stringified_integer_origins(value: ast.expr) -> frozenset[str]:
        if _is_builtin_call(value, "str", aliases=aliases) and len(value.args) == 1:
            return parsed_integer_origins(value.args[0])
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "repr"
            and len(value.args) == 1
        ):
            return parsed_integer_origins(value.args[0])
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "format"
            and len(value.args) in {1, 2}
            and (
                len(value.args) == 1
                or (
                    isinstance(value.args[1], ast.Constant)
                    and value.args[1].value in {"", "d"}
                )
            )
        ):
            return parsed_integer_origins(value.args[0])
        if isinstance(value, ast.JoinedStr):
            return joined_integer_origins(value)
        if (
            isinstance(value, ast.BinOp)
            and isinstance(value.op, ast.Mod)
            and isinstance(value.left, ast.Constant)
            and value.left.value in {"%d", "%i"}
        ):
            return parsed_integer_origins(value.right)
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and isinstance(value.func.value, ast.Constant)
            and value.func.value.value in {"{}", "{:d}"}
            and value.func.attr == "format"
            and len(value.args) == 1
        ):
            return parsed_integer_origins(value.args[0])
        return frozenset()

    for candidate in local_nodes:
        if not isinstance(candidate, ast.Compare):
            continue
        operands = (candidate.left, *candidate.comparators)
        for index, operand in enumerate(operands):
            parsed_origins = stringified_integer_origins(operand)
            if not parsed_origins:
                continue
            if any(
                parsed_origins.intersection(_value_origins(other, origins_by_name))
                for other_index, other in enumerate(operands)
                if other_index != index
            ):
                return True
    return False


def _decimal_integer_grammar_owners(
    source: str,
    *,
    relative_path: str,
) -> tuple[str, ...]:
    """Return qualified declarations that own a decimal parser grammar."""

    tree = ast.parse(source, filename=relative_path)
    module_aliases = _collect_builtin_call_aliases(tree.body)
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    owners: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        inherited_aliases = module_aliases
        enclosing_functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        current: ast.AST = node
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                enclosing_functions.append(current)
        for enclosing in reversed(enclosing_functions):
            inherited_aliases = _collect_builtin_call_aliases(
                _function_local_nodes(enclosing),
                inherited=inherited_aliases,
                shadowed_names=_function_parameter_names(enclosing),
            )
        if not _implements_decimal_integer_grammar(
            node,
            inherited_aliases=inherited_aliases,
        ):
            continue
        names = [node.name]
        current: ast.AST = node
        while current in parents:
            current = parents[current]
            if isinstance(
                current,
                (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                names.append(current.name)
        owners.append(f"{relative_path}:{'.'.join(reversed(names))}")
    return tuple(sorted(owners))


class _StructuralNormalizer(ast.NodeTransformer):
    """Erase cosmetic declaration differences while retaining control flow."""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        normalized = self.generic_visit(node)
        normalized.name = "_"
        return normalized

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        normalized = self.generic_visit(node)
        normalized.name = "_"
        return normalized

    def visit_Name(self, node: ast.Name) -> ast.AST:
        node.id = "_"
        return node

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = "_"
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if node.value is None or isinstance(node.value, bool):
            return node
        replacement_by_type = {
            str: "_",
            bytes: b"_",
            int: 0,
            float: 0.0,
            complex: 0j,
        }
        node.value = replacement_by_type.get(type(node.value), node.value)
        return node


class PythonSourceDeduplicationTests(unittest.TestCase):
    def test_named_string_contract_constants_have_one_owner(self) -> None:
        """Catch duplicated IDs and archive-layout literals below clone size."""

        owners: dict[str, list[tuple[Path, int, str]]] = defaultdict(list)
        for path in _production_python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    targets = node.targets
                    value_node = node.value
                elif isinstance(node, ast.AnnAssign):
                    targets = (node.target,)
                    value_node = node.value
                else:
                    continue
                try:
                    value = ast.literal_eval(value_node)
                except (ValueError, TypeError):
                    continue
                if not isinstance(value, str) or not value:
                    continue
                for target in targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        owners[value].append((path, node.lineno, target.id))

        duplicates = [
            " == ".join(
                f"{path.relative_to(ROOT)}:{line} ({name})"
                for path, line, name in declarations
            )
            for declarations in owners.values()
            if len({path for path, _, _ in declarations}) > 1
        ]
        self.assertEqual(
            [],
            duplicates,
            "named string contract constants have multiple owners:\n"
            + "\n".join(duplicates),
        )

    def test_decimal_integer_grammar_guard_sees_nested_parser_languages(
        self,
    ) -> None:
        source = """
def canonical(value):
    digits = value[1:] if value.startswith("-") else value
    if not digits.isdigit():
        raise ValueError
    return int(value, 10)

def legacy_direct(value):
    if not (
        value.isdigit()
        or (value.startswith("-") and value[1:].isdigit())
    ):
        raise ValueError
    return int(value)

class Decoder:
    @staticmethod
    def round_trip(value):
        parsed = int(value)
        if str(parsed) != value:
            raise ValueError
        return parsed

def load(record):
    def nested_integer(name):
        raw = record.get(name)
        if isinstance(raw, str) and raw.isdecimal():
            return int(raw)
        raise ValueError
    return nested_integer("timestamp_ns")
"""
        self.assertEqual(
            _decimal_integer_grammar_owners(
                source,
                relative_path="synthetic.py",
            ),
            (
                "synthetic.py:Decoder.round_trip",
                "synthetic.py:canonical",
                "synthetic.py:legacy_direct",
                "synthetic.py:load.nested_integer",
            ),
        )

    def test_decimal_integer_grammar_guard_rejects_builtin_alias_mutations(
        self,
    ) -> None:
        source = """
import builtins
import builtins as runtime_builtins
from builtins import int as decimal_int

assigned_int = builtins.int
assigned_str = builtins.str
second_int = assigned_int
second_str = assigned_str

def attribute_duplicate(value):
    parsed = builtins.int(value)
    if builtins.str(parsed) != value:
        raise ValueError
    return parsed

def module_alias_duplicate(value):
    if not value.isdecimal():
        raise ValueError
    return runtime_builtins.int(value)

def imported_callable_duplicate(value):
    parsed = decimal_int(value)
    if str(parsed) != value:
        raise ValueError
    return parsed

def assigned_callable_duplicate(value):
    parsed = assigned_int(value)
    if assigned_str(parsed) != value:
        raise ValueError
    return parsed

def chained_callable_duplicate(value):
    parsed = second_int(value)
    if second_str(parsed) != value:
        raise ValueError
    return parsed
"""
        self.assertEqual(
            _decimal_integer_grammar_owners(
                source,
                relative_path="mutated_plugin.py",
            ),
            (
                "mutated_plugin.py:assigned_callable_duplicate",
                "mutated_plugin.py:attribute_duplicate",
                "mutated_plugin.py:chained_callable_duplicate",
                "mutated_plugin.py:imported_callable_duplicate",
                "mutated_plugin.py:module_alias_duplicate",
            ),
            "builtins-qualified or aliased duplicate parsers escaped the guard",
        )

    def test_decimal_integer_grammar_guard_rejects_equivalent_spellings(
        self,
    ) -> None:
        source = r"""
import re

def inline_sign_slice(value):
    if not value[1:].isdigit():
        raise ValueError
    return int(value)

def stripped_sign(value):
    if not value.lstrip("-").isdecimal():
        raise ValueError
    return int(value)

def regular_expression(value):
    if re.fullmatch(r"-?[0-9]+", value) is None:
        raise ValueError
    return int(value)

def character_range(value):
    if not all("0" <= character <= "9" for character in value):
        raise ValueError
    return int(value)

def formatted_builtin(value):
    parsed = int(value)
    if format(parsed, "d") != value:
        raise ValueError
    return parsed

def formatted_literal(value):
    parsed = int(value)
    if f"{parsed}" != value:
        raise ValueError
    return parsed

def percent_literal(value):
    parsed = int(value)
    if "%d" % parsed != value:
        raise ValueError
    return parsed

def method_format(value):
    parsed = int(value)
    if "{:d}".format(parsed) != value:
        raise ValueError
    return parsed

def repr_round_trip(value):
    parsed = int(value)
    if repr(parsed) != value:
        raise ValueError
    return parsed
"""
        self.assertEqual(
            _decimal_integer_grammar_owners(
                source,
                relative_path="equivalent.py",
            ),
            (
                "equivalent.py:character_range",
                "equivalent.py:formatted_builtin",
                "equivalent.py:formatted_literal",
                "equivalent.py:inline_sign_slice",
                "equivalent.py:method_format",
                "equivalent.py:percent_literal",
                "equivalent.py:regular_expression",
                "equivalent.py:repr_round_trip",
                "equivalent.py:stripped_sign",
            ),
            "equivalent canonical-decimal grammars escaped the guard",
        )

    def test_decimal_integer_grammar_guard_requires_shared_provenance(
        self,
    ) -> None:
        source = """
def unrelated_inputs(code, count):
    if not code.isdigit():
        raise ValueError
    return int(count)

def domain_token_and_count(token, count):
    if not token.isdecimal():
        return None
    return int(count)

def shadowed_callables(value, int, str):
    parsed = int(value)
    if str(parsed) != value:
        raise ValueError
    return parsed

def locally_shadowed_callables(value, custom_int, custom_str):
    int = custom_int
    str = custom_str
    parsed = int(value)
    if str(parsed) != value:
        raise ValueError
    return parsed
"""
        self.assertEqual(
            (),
            _decimal_integer_grammar_owners(
                source,
                relative_path="unrelated.py",
            ),
            "unrelated values or shadowed callables are not parser duplicates",
        )

    def test_decimal_integer_grammar_guard_ignores_unrelated_int_attributes(
        self,
    ) -> None:
        source = """
def domain_decoder(value, decoder):
    if not value.isdecimal():
        raise ValueError
    return decoder.int(value)
"""
        self.assertEqual(
            (),
            _decimal_integer_grammar_owners(
                source,
                relative_path="domain_decoder.py",
            ),
        )

    def test_decimal_integer_grammar_has_one_core_owner(self) -> None:
        owners: list[str] = []
        for path in _production_python_files():
            relative_path = path.relative_to(ROOT).as_posix()
            owners.extend(
                _decimal_integer_grammar_owners(
                    path.read_text(encoding="utf-8"),
                    relative_path=relative_path,
                )
            )

        self.assertEqual(
            ["src/router_dump_analyzer/value_core.py:parse_canonical_decimal_integer"],
            owners,
            "canonical-decimal parsing was reimplemented outside the core owner",
        )

    def test_production_tree_has_no_byte_identical_python_modules(self) -> None:
        by_digest: dict[str, list[Path]] = defaultdict(list)
        for path in _production_python_files():
            by_digest[hashlib.sha256(path.read_bytes()).hexdigest()].append(path)

        duplicates = [
            tuple(path.relative_to(ROOT).as_posix() for path in paths)
            for paths in by_digest.values()
            if len(paths) > 1
        ]
        self.assertEqual(
            [],
            duplicates,
            f"byte-identical Python modules remain: {duplicates}",
        )

    def test_production_tree_has_no_large_cross_file_token_clones(self) -> None:
        files = _production_python_files()
        token_ids: dict[tuple[int, str], int] = {}
        streams: dict[Path, tuple[int, ...]] = {}
        lines: dict[Path, tuple[int, ...]] = {}
        for path in files:
            values, token_lines = _significant_tokens(path)
            streams[path] = tuple(
                token_ids.setdefault(value, len(token_ids) + 1) for value in values
            )
            lines[path] = token_lines

        seen: dict[int, list[tuple[Path, int]]] = defaultdict(list)
        violations: list[str] = []
        for path in files:
            stream = streams[path]
            for index, digest in _rolling_hashes(
                stream,
                MINIMUM_CLONE_TOKENS,
            ):
                window = stream[index : index + MINIMUM_CLONE_TOKENS]
                candidates = seen[digest]
                for prior_path, prior_index in candidates:
                    if (
                        prior_path != path
                        and streams[prior_path][
                            prior_index : prior_index + MINIMUM_CLONE_TOKENS
                        ]
                        == window
                    ):
                        violations.append(
                            f"{prior_path.relative_to(ROOT)}:"
                            f"{lines[prior_path][prior_index]} == "
                            f"{path.relative_to(ROOT)}:{lines[path][index]}"
                        )
                        break
                if not any(candidate_path == path for candidate_path, _ in candidates):
                    candidates.append((path, index))
                if len(violations) >= 20:
                    break
            if len(violations) >= 20:
                break

        self.assertEqual(
            [],
            violations,
            "large copied Python token sequences remain:\n" + "\n".join(violations),
        )

    def test_production_tree_has_no_structural_declaration_copies(self) -> None:
        declarations: dict[str, list[tuple[Path, int, str]]] = defaultdict(list)
        for path in _production_python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(
                    node,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                ):
                    continue
                normalized = _StructuralNormalizer().visit(copy.deepcopy(node))
                structural_ast = ast.dump(
                    normalized,
                    annotate_fields=True,
                    include_attributes=False,
                )
                if len(structural_ast) < MINIMUM_STRUCTURAL_AST_LENGTH:
                    continue
                body = getattr(normalized, "body", ())
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)
                ):
                    del body[0]
                digest = hashlib.sha256(
                    ast.dump(
                        normalized,
                        annotate_fields=True,
                        include_attributes=False,
                    ).encode("utf-8")
                ).hexdigest()
                declarations[digest].append((path, node.lineno, type(node).__name__))

        violations: list[str] = []
        for copies in declarations.values():
            if len({path for path, _, _ in copies}) > 1:
                violations.append(
                    " == ".join(
                        f"{path.relative_to(ROOT)}:{line} ({kind})"
                        for path, line, kind in copies
                    )
                )
        self.assertEqual(
            [],
            violations,
            "production declarations copy the same normalized structure:\n"
            + "\n".join(violations),
        )


if __name__ == "__main__":
    unittest.main()
