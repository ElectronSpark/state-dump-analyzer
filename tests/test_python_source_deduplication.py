from __future__ import annotations

import ast
import copy
import hashlib
import io
import token
import tokenize
import unittest
from collections import defaultdict
from pathlib import Path
from typing import Iterator


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOTS = (
    ROOT / "src" / "router_dump_analyzer",
    ROOT / "demo" / "plugin",
    ROOT / "demo" / "generator",
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
            (
                digest
                - ((values[index - 1] * leading_power) & mask)
            )
            * base
            + values[index + width - 1]
        ) & mask
        yield index, digest


def _signed_decimal_grammar_names(node: ast.AST) -> set[str]:
    """Return variables parsed with ``digits or '-' + digits`` in *node*."""

    plain_digits: set[str] = set()
    negative_prefixes: set[str] = set()
    sliced_digits: set[str] = set()
    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.Call):
            continue
        function = candidate.func
        if not isinstance(function, ast.Attribute):
            continue
        receiver = function.value
        if (
            function.attr == "isdigit"
            and not candidate.args
            and isinstance(receiver, ast.Name)
        ):
            plain_digits.add(receiver.id)
        elif (
            function.attr == "startswith"
            and isinstance(receiver, ast.Name)
            and len(candidate.args) == 1
            and isinstance(candidate.args[0], ast.Constant)
            and candidate.args[0].value == "-"
        ):
            negative_prefixes.add(receiver.id)
        elif (
            function.attr == "isdigit"
            and not candidate.args
            and isinstance(receiver, ast.Subscript)
            and isinstance(receiver.value, ast.Name)
        ):
            sliced_digits.add(receiver.value.id)
    return plain_digits & negative_prefixes & sliced_digits


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

    def test_signed_decimal_integer_grammar_has_one_core_owner(self) -> None:
        owners: list[str] = []
        for path in _production_python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in tree.body:
                if not isinstance(
                    node,
                    (ast.FunctionDef, ast.AsyncFunctionDef),
                ):
                    continue
                if _signed_decimal_grammar_names(node):
                    owners.append(
                        f"{path.relative_to(ROOT).as_posix()}:{node.name}"
                    )

        self.assertEqual(
            ["src/router_dump_analyzer/value_core.py:parse_decimal_integer"],
            owners,
            "signed-decimal parsing was reimplemented outside the core owner",
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
                token_ids.setdefault(value, len(token_ids) + 1)
                for value in values
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
            "large copied Python token sequences remain:\n"
            + "\n".join(violations),
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
                normalized = _StructuralNormalizer().visit(
                    copy.deepcopy(node)
                )
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
                declarations[digest].append(
                    (path, node.lineno, type(node).__name__)
                )

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
