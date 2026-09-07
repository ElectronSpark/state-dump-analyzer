from __future__ import annotations

import ast
import textwrap
import unittest
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from router_dump_analyzer.process_control import PROCESS_CONTROL_EXCEPTIONS

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
PACKAGE_ROOT = SRC_ROOT / "router_dump_analyzer"
PLUGIN_API_MODULE = PACKAGE_ROOT / "plugin_api.py"
PROCESS_CONTROL_MODULE = PACKAGE_ROOT / "process_control.py"
WEB_CONTROL_PLANE_MODULE = PACKAGE_ROOT / "web/control_plane_api.py"

_LIFECYCLE_METHODS = frozenset(
    {"__enter__", "__exit__", "__iter__", "__next__", "close"}
)
_LIFECYCLE_BUILTINS = frozenset({"iter", "next"})
_EAGER_ITERABLE_CONSUMERS = frozenset(
    {"all", "any", "list", "max", "min", "sorted", "sum", "tuple"}
)

# This committed floor is intentionally independent of discovery.  Deriving
# the expected module set from the same census would let one blind spot remove
# both the evidence and its expectation.  Counts may grow without maintenance;
# lowering a floor requires an explicit review of the removed boundary.
_CENSUS_FLOOR_BY_MODULE = {
    # Step 3 validates and snapshots the schema before indexing it, so the
    # former second executor.schema descriptor read no longer exists. That
    # removed a core snapshot access, not a plug-in invocation boundary.
    "src/router_dump_analyzer/capability_executor.py": 11,
    "src/router_dump_analyzer/ingestion.py": 7,
    # Registration moved intact out of the queue. Keep independent floors
    # for its six manifest/probe boundaries and the queue's three boundaries.
    "src/router_dump_analyzer/ingestion_pipeline.py": 3,
    "src/router_dump_analyzer/plugin_registration.py": 6,
    "src/router_dump_analyzer/multi_node_route.py": 2,
    "src/router_dump_analyzer/normalized_data.py": 3,
    "src/router_dump_analyzer/plugin_loading.py": 3,
    "src/router_dump_analyzer/plugin_validation.py": 2,
    "src/router_dump_analyzer/runtime.py": 6,
    "src/router_dump_analyzer/server_cli.py": 2,
    "src/router_dump_analyzer/temporal_topology.py": 1,
    "src/router_dump_analyzer/web/control_plane_api.py": 1,
    # Temporal/topology/route providers now all delegate through the one
    # shared runtime boundary instead of calling three provider methods
    # directly.  The lower count records that deliberate centralization.
    "src/router_dump_analyzer/web/runtime_api.py": 1,
}


@dataclass(frozen=True, slots=True)
class _DeclaredContract:
    """Executable extension vocabulary derived from source declarations."""

    primary_hooks: frozenset[str]
    primary_descriptors: frozenset[str]
    iterable_hooks: frozenset[str]
    protocol_members: dict[str, frozenset[str]]
    callable_aliases: frozenset[str]


@dataclass(frozen=True, slots=True)
class _BoundarySite:
    filename: str
    line: int
    column: int
    label: str
    guarded: bool
    explanation: str

    def display(self) -> str:
        state = "guarded" if self.guarded else "UNGUARDED"
        return (
            f"{self.filename}:{self.line}:{self.column + 1}: {state}: "
            f"{self.label} ({self.explanation})"
        )


def _dotted_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _annotation_names(node: ast.AST | None) -> frozenset[str]:
    if node is None:
        return frozenset()
    return frozenset(
        child.id for child in ast.walk(node) if isinstance(child, ast.Name)
    )


def _string_literals(node: ast.AST) -> frozenset[str]:
    return frozenset(
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    )


def _class_is_protocol(node: ast.ClassDef) -> bool:
    return any(_dotted_name(base).endswith("Protocol") for base in node.bases)


def _extension_protocol(node: ast.ClassDef, *, primary: bool) -> bool:
    """Classify executable extension protocols without a module allowlist.

    ``AnalyzerPlugin`` and its base are the normative source.  Other protocols
    qualify only when their own declaration says that a plug-in, external
    provider, or external identity resolver supplies the implementation.  The
    latter makes the census cover runtime/provider boundaries without turning
    ordinary core protocols (for example ``RevisionStore``) into plug-ins.
    """

    if primary:
        return node.name in {
            "AnalyzerPlugin",
            "AnalyzerPluginBase",
            "FederationLinkerPlugin",
        }
    if not _class_is_protocol(node):
        return False
    documentation = (ast.get_docstring(node) or "").casefold()
    return (
        "plug-in" in documentation
        or "plugin" in documentation
        or "outside this router" in documentation
        or "device/input-specific" in documentation
    )


def _derive_declared_contract(source_paths: Iterable[Path]) -> _DeclaredContract:
    """Derive hook/descriptor names from declarations, never source modules.

    The old guard enumerated the three files it wanted to pass.  This guard
    instead parses the normative ``plugin_api.py`` constants and Protocol/base
    declarations, then augments receiver typing from explicitly external
    Protocol declarations found while walking all source files.
    """

    plugin_tree = ast.parse(
        PLUGIN_API_MODULE.read_text(encoding="utf-8"),
        filename=PLUGIN_API_MODULE.relative_to(ROOT).as_posix(),
    )
    primary_hooks: set[str] = set()
    descriptors: set[str] = set()
    iterable_hooks: set[str] = set()
    descriptor_types: set[str] = set()

    contract_constant_names = {
        "REQUIRED_PLUGIN_HOOKS",
        "PLUGIN_CAPABILITY_HOOKS",
        "INPUT_PARSER_HOOKS",
    }
    for node in plugin_tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
            if any(
                isinstance(target, ast.Name)
                and target.id in contract_constant_names
                for target in targets
            ):
                value = node.value
                if value is not None:
                    primary_hooks.update(_string_literals(value))

    for node in plugin_tree.body:
        if not isinstance(node, ast.ClassDef) or node.name not in {
            "AnalyzerPlugin",
            "AnalyzerPluginBase",
        }:
            continue
        for member in node.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not member.name.startswith("_"):
                    primary_hooks.add(member.name)
                    rendered_return = (
                        ast.unparse(member.returns) if member.returns is not None else ""
                    )
                    if "Iterable" in rendered_return or "Iterator" in rendered_return:
                        iterable_hooks.add(member.name)
            elif isinstance(member, ast.AnnAssign) and isinstance(
                member.target, ast.Name
            ):
                descriptors.add(member.target.id)
                descriptor_types.update(_annotation_names(member.annotation))

    # A plug-in descriptor can itself execute code (notably
    # PluginManifest.supports). Derive those methods from the descriptor's
    # declared type rather than keeping another handwritten method list.
    for node in plugin_tree.body:
        if not isinstance(node, ast.ClassDef) or node.name not in descriptor_types:
            continue
        for member in node.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and not (
                member.name.startswith("_")
            ):
                primary_hooks.add(member.name)

    protocol_members: dict[str, frozenset[str]] = {}
    callable_aliases: set[str] = set()
    for path in source_paths:
        tree = ast.parse(
            path.read_text(encoding="utf-8"),
            filename=path.relative_to(ROOT).as_posix(),
        )
        is_primary = path.resolve() == PLUGIN_API_MODULE.resolve()
        module_documentation = (ast.get_docstring(tree) or "").casefold()
        externally_owned_module = any(
            token in module_documentation
            for token in ("plug-in", "plugin", "external provider")
        )
        if externally_owned_module:
            for statement in tree.body:
                if (
                    isinstance(statement, (ast.Assign, ast.AnnAssign))
                    and statement.value is not None
                    and "Callable" in ast.unparse(statement.value)
                ):
                    targets = (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else (statement.target,)
                    )
                    callable_aliases.update(
                        target.id
                        for target in targets
                        if isinstance(target, ast.Name)
                    )
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or not _extension_protocol(
                node, primary=is_primary
            ):
                continue
            members: set[str] = set()
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not member.name.startswith("_") or member.name == "__call__":
                        members.add(member.name)
                elif isinstance(member, ast.AnnAssign) and isinstance(
                    member.target, ast.Name
                ):
                    members.add(member.target.id)
            if members:
                protocol_members[node.name] = frozenset(members)

    return _DeclaredContract(
        primary_hooks=frozenset(primary_hooks),
        primary_descriptors=frozenset(descriptors),
        iterable_hooks=frozenset(iterable_hooks),
        protocol_members=protocol_members,
        callable_aliases=frozenset(callable_aliases),
    )


def _handler_name(handler: ast.ExceptHandler) -> str:
    return _dotted_name(handler.type) if handler.type is not None else ""


def _boundary_problem(boundary: ast.Try) -> str | None:
    handler_names = tuple(_handler_name(handler) for handler in boundary.handlers)
    try:
        process_index = handler_names.index("PROCESS_CONTROL_EXCEPTIONS")
        base_index = handler_names.index("BaseException")
    except ValueError:
        return "lacks the shared process-control/BaseException boundary"
    process_handler = boundary.handlers[process_index]
    reraises = any(
        isinstance(node, ast.Raise) and node.exc is None
        for node in ast.walk(process_handler)
    )
    if process_index >= base_index:
        return "handles BaseException before process controls"
    if not reraises:
        return "swallows a process-control exception"
    base_handler = boundary.handlers[base_index]
    if any(
        isinstance(node, ast.Raise) and node.exc is None
        for node in ast.walk(base_handler)
    ):
        return "rethrows rather than contains a non-process BaseException"
    return None


def _build_parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def _function_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {
        argument.arg
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
    } | ({node.args.vararg.arg} if node.args.vararg is not None else set()) | (
        {node.args.kwarg.arg} if node.args.kwarg is not None else set()
    )


def _direct_boundary_wrappers(tree: ast.Module) -> set[str]:
    wrappers: set[str] = set()
    for function in (
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        parameters = _function_parameters(function)
        for boundary in (
            node for node in ast.walk(function) if isinstance(node, ast.Try)
        ):
            if _boundary_problem(boundary) is not None:
                continue
            calls_parameter = any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in parameters
                for statement in boundary.body
                for node in ast.walk(statement)
            )
            if calls_parameter:
                wrappers.add(function.name)
                break
    return wrappers


def _wrapper_names(tree: ast.Module) -> frozenset[str]:
    """Discover direct and delegating boundary adapters to a fixed point."""

    wrappers = _direct_boundary_wrappers(tree)
    functions = tuple(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    changed = True
    while changed:
        changed = False
        for function in functions:
            if function.name in wrappers:
                continue
            parameters = _function_parameters(function)
            delegates = any(
                isinstance(call, ast.Call)
                and _dotted_name(call.func).split(".")[-1] in wrappers
                and any(
                    isinstance(argument, ast.Name) and argument.id in parameters
                    for argument in call.args
                )
                for call in ast.walk(function)
                if isinstance(call, ast.Call)
            )
            if delegates:
                wrappers.add(function.name)
                changed = True
    return frozenset(wrappers)


def _enclosing_class(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.ClassDef):
            return current.name
    return ""


def _enclosing_functions(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    result: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.append(current)
    return tuple(result)


def _parameter_types(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, frozenset[str]]:
    result: dict[str, frozenset[str]] = {}
    for argument in (
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ):
        result[argument.arg] = _annotation_names(argument.annotation)
    return result


def _root_name(node: ast.AST) -> str:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _receiver_types(
    owner: ast.AST,
    *,
    site: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> frozenset[str]:
    root = _root_name(owner)
    for function in _enclosing_functions(site, parents):
        types = _parameter_types(function).get(root)
        if types:
            return types
    return frozenset()


def _internal_snapshot_receiver(
    owner: ast.AST,
    *,
    site: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    if "snapshot" in _dotted_name(owner).casefold():
        return True
    types = _receiver_types(owner, site=site, parents=parents)
    return any("Snapshot" in name or name.startswith("_Validated") for name in types)


def _is_contract_receiver(
    owner: ast.AST,
    member: str,
    *,
    site: ast.AST,
    parents: dict[ast.AST, ast.AST],
    contract: _DeclaredContract,
) -> bool:
    if (
        member in contract.primary_descriptors
        and _dotted_name(owner) == "self"
    ):
        # A core adapter's snapshotted descriptor is data, not a fresh
        # plug-in descriptor execution. ``self.plugin.manifest`` still counts.
        return False
    types = _receiver_types(owner, site=site, parents=parents)
    if any(
        member in contract.protocol_members.get(type_name, ()) for type_name in types
    ):
        return True
    if types and not any(
        type_name in contract.protocol_members for type_name in types
    ):
        return False
    if _internal_snapshot_receiver(owner, site=site, parents=parents):
        return False
    # Primary analyzer hook names are intentionally receiver-name independent.
    # A locally declared, explicitly typed core class is excluded; an untyped
    # receiver is retained so renaming ``plugin`` to ``adapter`` cannot evade
    # discovery.
    return member in contract.primary_hooks or member in contract.primary_descriptors


def _delegated_to_wrapper(
    node: ast.AST,
    *,
    tree: ast.Module,
    parents: dict[ast.AST, ast.AST],
    wrappers: frozenset[str],
) -> bool:
    child = node
    while child in parents:
        parent = parents[child]
        if isinstance(parent, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
            owner = parents.get(parent)
            if (
                isinstance(parent, ast.Lambda)
                and isinstance(owner, ast.Call)
                and _dotted_name(owner.func).split(".")[-1] in wrappers
            ):
                return True
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # A local function is guarded when the function object is
                # handed to a discovered boundary adapter in the same module.
                return any(
                    isinstance(call, ast.Call)
                    and _dotted_name(call.func).split(".")[-1] in wrappers
                    and any(
                        isinstance(argument, ast.Name)
                        and argument.id == parent.name
                        for argument in call.args
                    )
                    for call in ast.walk(tree)
                    if isinstance(call, ast.Call)
                )
        if (
            isinstance(parent, ast.Call)
            and _dotted_name(parent.func).split(".")[-1] in wrappers
        ):
            return True
        child = parent
    return False


def _lexical_boundary(
    node: ast.AST,
    *,
    parents: dict[ast.AST, ast.AST],
) -> ast.Try | None:
    child = node
    nearest: ast.Try | None = None
    while child in parents:
        parent = parents[child]
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return nearest
        if isinstance(parent, ast.Try) and child in parent.body:
            if nearest is None:
                nearest = parent
            if _boundary_problem(parent) is None:
                return parent
        child = parent
    return nearest


def _target_key(node: ast.AST) -> str:
    if isinstance(node, (ast.Name, ast.Attribute)):
        return _dotted_name(node)
    return ""


def _scoped_target_key(
    node: ast.AST,
    *,
    site: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> str:
    key = _target_key(node)
    if not key:
        return ""
    if key.startswith("self."):
        return f"class:{_enclosing_class(site, parents)}:{key}"
    functions = _enclosing_functions(site, parents)
    if functions:
        return f"function:{functions[0].lineno}:{key}"
    return f"module:{key}"


def _loading_import_semantics(
    tree: ast.Module,
) -> tuple[frozenset[str], frozenset[str]]:
    """Derive loading callables and entry-point types from imports.

    This is intentionally based on the imported objects, not a source-module
    allowlist or local variable spelling.  Aliased ``importlib`` imports and
    both qualified and direct ``EntryPoint`` annotations therefore retain the
    same meaning.
    """

    import_module_callables: set[str] = set()
    entry_point_types: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name
                if alias.name == "importlib":
                    import_module_callables.add(f"{local}.import_module")
                elif alias.name == "importlib.metadata":
                    entry_point_types.add(f"{local}.EntryPoint")
        elif isinstance(statement, ast.ImportFrom):
            module = statement.module or ""
            for alias in statement.names:
                local = alias.asname or alias.name
                if module == "importlib" and alias.name == "import_module":
                    import_module_callables.add(local)
                elif module == "importlib" and alias.name == "metadata":
                    entry_point_types.add(f"{local}.EntryPoint")
                elif module == "importlib.metadata" and alias.name == "EntryPoint":
                    entry_point_types.add(local)
    return frozenset(import_module_callables), frozenset(entry_point_types)


def _annotation_dotted_names(node: ast.AST | None) -> frozenset[str]:
    if node is None:
        return frozenset()
    return frozenset(
        dotted
        for child in ast.walk(node)
        if isinstance(child, (ast.Name, ast.Attribute))
        if (dotted := _dotted_name(child))
    )


def _function_mentions_entry_point(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    entry_point_types: frozenset[str],
) -> bool:
    annotations = (
        *(argument.annotation for argument in function.args.posonlyargs),
        *(argument.annotation for argument in function.args.args),
        *(argument.annotation for argument in function.args.kwonlyargs),
        function.args.vararg.annotation if function.args.vararg is not None else None,
        function.args.kwarg.annotation if function.args.kwarg is not None else None,
        function.returns,
    )
    return any(
        bool(_annotation_dotted_names(annotation) & entry_point_types)
        for annotation in annotations
    )


def _is_import_module_call(
    node: ast.Call,
    *,
    import_module_callables: frozenset[str],
) -> bool:
    return _dotted_name(node.func) in import_module_callables


def _candidate_nodes(
    tree: ast.Module,
    *,
    contract: _DeclaredContract,
    wrappers: frozenset[str],
) -> tuple[tuple[ast.AST, str], ...]:
    """Return a defensible, deliberately bounded static census.

    Caught shapes: direct hook/descriptor access regardless of receiver name;
    literal and typed-dynamic ``getattr``; one-scope aliases and bound methods;
    callbacks stored on attributes; iterator/context lifecycle operations;
    comprehensions, generator expressions, eager iterable builtins, starred
    expansion, ``yield from``, and iterable unpacking; typed
    ``EntryPoint.load``; imported ``import_module`` callables; attributes of
    their returned modules; and process-entry/ASGI call graphs whose value can
    be traced in the same module. Explicit blind spots are reflection
    through ``eval``/native or custom ``__import__`` machinery, opaque-container
    or cross-module callback transport, and monkey-patching after the census.
    Those shapes are covered by behavioral hostile-plug-in tests, not falsely
    claimed here.
    """

    parents = _build_parents(tree)
    import_module_callables, entry_point_types = _loading_import_semantics(tree)
    candidates: dict[int, tuple[ast.AST, str]] = {}
    callback_targets: dict[str, str] = {}
    lazy_targets: set[str] = set()
    external_value_targets: set[str] = set()
    external_members = frozenset(
        member
        for members in contract.protocol_members.values()
        for member in members
    )
    executable_member_names = external_members | _LIFECYCLE_METHODS
    dynamic_descriptor_parameters: set[tuple[int, str]] = set()
    dynamic_descriptor_functions: set[str] = set()
    functions = tuple(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    functions_by_name: dict[
        str,
        list[ast.FunctionDef | ast.AsyncFunctionDef],
    ] = {}
    for function in functions:
        functions_by_name.setdefault(function.name, []).append(function)

    assignments = tuple(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None
    )
    loading_callable_targets: dict[str, str] = {}
    for _pass in range(4):
        for assignment in assignments:
            value = assignment.value
            targets = (
                assignment.targets
                if isinstance(assignment, ast.Assign)
                else (assignment.target,)
            )
            target_keys = tuple(
                filter(
                    None,
                    (
                        _scoped_target_key(
                            target,
                            site=assignment,
                            parents=parents,
                        )
                        for target in targets
                    ),
                )
            )
            source_key = _scoped_target_key(
                value,
                site=assignment,
                parents=parents,
            )
            kind = loading_callable_targets.get(source_key)
            if _dotted_name(value) in import_module_callables:
                kind = "dynamic module import"
            elif (
                isinstance(value, ast.Attribute)
                and value.attr == "load"
                and any(
                    _function_mentions_entry_point(
                        function,
                        entry_point_types=entry_point_types,
                    )
                    for function in _enclosing_functions(value, parents)
                )
            ):
                kind = "entry-point load"
            if kind is not None:
                for target_key in target_keys:
                    loading_callable_targets[target_key] = kind

    loaded_module_targets: set[str] = set()
    for _pass in range(4):
        for assignment in assignments:
            value = assignment.value
            targets = (
                assignment.targets
                if isinstance(assignment, ast.Assign)
                else (assignment.target,)
            )
            target_keys = tuple(
                filter(
                    None,
                    (
                        _scoped_target_key(
                            target,
                            site=assignment,
                            parents=parents,
                        )
                        for target in targets
                    ),
                )
            )
            value_key = _scoped_target_key(
                value,
                site=assignment,
                parents=parents,
            )
            from_import = isinstance(value, ast.Call) and (
                _is_import_module_call(
                    value,
                    import_module_callables=import_module_callables,
                )
                or loading_callable_targets.get(
                    _scoped_target_key(
                        value.func,
                        site=value,
                        parents=parents,
                    )
                )
                == "dynamic module import"
            )
            if from_import or value_key in loaded_module_targets:
                loaded_module_targets.update(target_keys)
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        called_name = _dotted_name(call.func).split(".")[-1]
        for function in functions_by_name.get(called_name, ()):
            positional = (
                *function.args.posonlyargs,
                *function.args.args,
            )
            for index, argument in enumerate(call.args):
                if (
                    index < len(positional)
                    and isinstance(argument, ast.Constant)
                    and isinstance(argument.value, str)
                    and argument.value in executable_member_names
                ):
                    dynamic_descriptor_parameters.add(
                        (function.lineno, positional[index].arg)
                    )
                    dynamic_descriptor_functions.add(function.name)

    stored_callback_attributes: set[tuple[str, str]] = set()
    callable_field_names: set[str] = set()
    for class_node in (
        node for node in tree.body if isinstance(node, ast.ClassDef)
    ):
        class_documentation = (ast.get_docstring(class_node) or "").casefold()
        if not any(
            token in class_documentation
            for token in ("plug-in", "plugin", "external provider")
        ):
            continue
        callable_field_names.update(
            field.target.id
            for field in class_node.body
            if isinstance(field, ast.AnnAssign)
            and isinstance(field.target, ast.Name)
            and bool(_annotation_names(field.annotation) & contract.callable_aliases)
        )
    for class_node in (
        node for node in tree.body if isinstance(node, ast.ClassDef)
    ):
        class_documentation = (ast.get_docstring(class_node) or "").casefold()
        externally_owned_class = any(
            token in class_documentation
            for token in ("plug-in", "plugin", "external provider")
        )
        if not externally_owned_class:
            continue
        for method in (
            node
            for node in class_node.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            annotated_callbacks = {
                argument.arg
                for argument in (
                    *method.args.posonlyargs,
                    *method.args.args,
                    *method.args.kwonlyargs,
                )
                if (
                    "Callable" in _annotation_names(argument.annotation)
                    or bool(
                        _annotation_names(argument.annotation)
                        & contract.callable_aliases
                    )
                )
            }
            callback_names = set(annotated_callbacks)
            assignments = tuple(
                node
                for node in ast.walk(method)
                if isinstance(node, (ast.Assign, ast.AnnAssign))
            )
            for _pass in range(3):
                for assignment in assignments:
                    value = assignment.value
                    targets = (
                        assignment.targets
                        if isinstance(assignment, ast.Assign)
                        else (assignment.target,)
                    )
                    if (
                        isinstance(value, ast.Attribute)
                        and value.attr in callable_field_names
                    ):
                        callback_names.update(
                            target.id
                            for target in targets
                            if isinstance(target, ast.Name)
                        )
                    if isinstance(value, ast.Name) and value.id in callback_names:
                        callback_names.update(
                            target.id
                            for target in targets
                            if isinstance(target, ast.Name)
                        )
                        stored_callback_attributes.update(
                            (class_node.name, _dotted_name(target))
                            for target in targets
                            if _dotted_name(target).startswith("self.")
                        )

    def add(node: ast.AST, label: str) -> None:
        candidates[id(node)] = (node, label)

    def scoped_key(node: ast.AST, *, site: ast.AST) -> str:
        return _scoped_target_key(node, site=site, parents=parents)

    # Iterate to a small fixed point so ``a = plugin.hook; b = a`` and a
    # generator derived from ``b()`` remain visible.
    for _pass in range(4):
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                parent = parents.get(node)
                normalized = node.attr.lstrip("_")
                enclosing_class = _enclosing_class(node, parents)
                is_private_plugin_callback = (
                    normalized in contract.primary_hooks
                    and "Plugin" in enclosing_class
                )
                if (
                    scoped_key(node.value, site=node) in loaded_module_targets
                    and not (
                        isinstance(parent, ast.Call)
                        and isinstance(parent.func, ast.Name)
                        and parent.func.id == "getattr"
                    )
                ):
                    add(node, f"loaded module attribute {_dotted_name(node)}")
                if node.attr in callable_field_names:
                    if isinstance(parent, ast.Call) and parent.func is node:
                        add(parent, f"declared callable field {_dotted_name(node)}()")
                    else:
                        add(node, f"declared callable descriptor {_dotted_name(node)}")
                if (
                    _is_contract_receiver(
                        node.value,
                        node.attr,
                        site=node,
                        parents=parents,
                        contract=contract,
                    )
                    or is_private_plugin_callback
                ):
                    if isinstance(parent, ast.Call) and parent.func is node:
                        add(parent, f"call {_dotted_name(node)}()")
                    elif not (
                        isinstance(parent, ast.Call)
                        and isinstance(parent.func, ast.Name)
                        and parent.func.id == "getattr"
                    ) and not (
                        isinstance(parent, ast.Attribute)
                        and isinstance(parents.get(parent), ast.Call)
                        and parents[parent].func is parent
                    ):
                        add(node, f"descriptor {_dotted_name(node)}")

            if isinstance(node, ast.Call):
                dotted = _dotted_name(node.func)
                enclosing = _enclosing_functions(node, parents)
                loading_callback_kind = loading_callable_targets.get(
                    scoped_key(node.func, site=node)
                )
                if loading_callback_kind is not None:
                    add(node, f"aliased {loading_callback_kind} {_target_key(node.func)}()")
                if _is_import_module_call(
                    node,
                    import_module_callables=import_module_callables,
                ):
                    add(node, f"dynamic module import {dotted}()")
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "load"
                    and any(
                        _function_mentions_entry_point(
                            function,
                            entry_point_types=entry_point_types,
                        )
                        for function in enclosing
                    )
                ):
                    add(node, f"entry-point load {dotted}()")
                if (
                    isinstance(node.func, ast.Name)
                    and enclosing
                    and enclosing[0].name in wrappers
                    and node.func.id in _function_parameters(enclosing[0])
                    and node.func.id not in {"self", "cls"}
                    and (
                        "Callable"
                        in _parameter_types(enclosing[0]).get(
                            node.func.id,
                            frozenset(),
                        )
                        or _lexical_boundary(node, parents=parents) is not None
                    )
                ):
                    add(node, f"boundary callback parameter {node.func.id}()")
                if (
                    isinstance(node.func, ast.Attribute)
                    and (
                        _enclosing_class(node, parents),
                        _dotted_name(node.func),
                    )
                    in stored_callback_attributes
                ):
                    add(node, f"stored plug-in callback {dotted}()")
                if isinstance(node.func, ast.Name) and node.func.id == "getattr" and (
                    len(node.args) >= 2
                ):
                    owner, requested = node.args[:2]
                    if scoped_key(owner, site=node) in loaded_module_targets:
                        add(node, "loaded module dynamic attribute getattr(...)")
                    if isinstance(requested, ast.Constant) and isinstance(
                        requested.value, str
                    ):
                        if _is_contract_receiver(
                            owner,
                            requested.value,
                            site=node,
                            parents=parents,
                            contract=contract,
                        ):
                            add(node, f"dynamic descriptor getattr(..., {requested.value!r})")
                    else:
                        typed_dynamic = any(
                            type_name in contract.protocol_members
                            for type_name in _receiver_types(
                                owner, site=node, parents=parents
                            )
                        )
                        enclosing = _enclosing_functions(node, parents)
                        derived_dynamic = bool(
                            isinstance(requested, ast.Name)
                            and enclosing
                            and (enclosing[0].lineno, requested.id)
                            in dynamic_descriptor_parameters
                        )
                        if typed_dynamic or derived_dynamic:
                            add(node, "typed dynamic descriptor getattr(..., name)")

                if isinstance(node.func, ast.Attribute):
                    member = node.func.attr
                    owner_text = _dotted_name(node.func.value).casefold()
                    owner_leaf = owner_text.split(".")[-1]
                    if member == "get":
                        owner_hint = (
                            scoped_key(node.func.value, site=node)
                            in external_value_targets
                        )
                    elif member == "open":
                        owner_hint = "runtime" in owner_leaf
                    elif member == "__call__":
                        owner_hint = "resolver" in owner_leaf
                    else:
                        owner_hint = any(
                            token in owner_text
                            for token in (
                                "plugin",
                                "provider",
                                "resolver",
                                "policy",
                                "source",
                            )
                        )
                    if (
                        member in external_members
                        and member not in contract.primary_hooks
                        and member not in contract.primary_descriptors
                        and (
                        owner_hint
                        or any(
                            member
                            in contract.protocol_members.get(type_name, ())
                            for type_name in _receiver_types(
                                node.func.value,
                                site=node,
                                parents=parents,
                            )
                        )
                        )
                    ):
                        add(node, f"external protocol call {dotted}()")
                elif isinstance(node.func, ast.Name):
                    enclosing = _enclosing_functions(node, parents)
                    if enclosing:
                        parameter_types = _parameter_types(enclosing[0]).get(
                            node.func.id,
                            frozenset(),
                        )
                        documentation = (ast.get_docstring(enclosing[0]) or "").casefold()
                        if (
                            node.func.id == "resolver"
                            and "Callable" in parameter_types
                            and "identity provider" in documentation
                        ):
                            add(
                                node,
                                f"external callable parameter {node.func.id}()",
                            )
                callback_key = scoped_key(node.func, site=node)
                if callback_key in callback_targets:
                    add(node, f"bound callback {_target_key(node.func)}()")
                    if callback_targets[callback_key] in contract.iterable_hooks:
                        parent = parents.get(node)
                        if isinstance(parent, (ast.Assign, ast.AnnAssign)):
                            targets = (
                                parent.targets
                                if isinstance(parent, ast.Assign)
                                else (parent.target,)
                            )
                            lazy_targets.update(
                                filter(
                                    None,
                                    (
                                        scoped_key(target, site=parent)
                                        for target in targets
                                    ),
                                )
                            )
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in _LIFECYCLE_BUILTINS
                    and node.args
                    and scoped_key(node.args[0], site=node) in lazy_targets
                ):
                    add(node, f"lazy lifecycle {node.func.id}()")
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id in _EAGER_ITERABLE_CONSUMERS
                    and node.args
                    and scoped_key(node.args[0], site=node) in lazy_targets
                ):
                    add(node, f"lazy consumption {node.func.id}()")
                if isinstance(node.func, ast.Attribute):
                    owner_key = scoped_key(node.func.value, site=node)
                    if (
                        owner_key in lazy_targets
                        and node.func.attr in _LIFECYCLE_METHODS
                    ):
                        add(node, f"lazy lifecycle {dotted}()")

            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if value is None:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else (node.target,)
                target_keys = tuple(
                    filter(
                        None,
                        (scoped_key(target, site=node) for target in targets),
                    )
                )
                source_key = scoped_key(value, site=node)
                if source_key in callback_targets:
                    for target_key in target_keys:
                        callback_targets[target_key] = callback_targets[source_key]
                if source_key in lazy_targets:
                    lazy_targets.update(target_keys)
                    if any(
                        isinstance(target, (ast.List, ast.Tuple))
                        for target in targets
                    ):
                        add(node, "lazy consumption iterable unpacking")
                if isinstance(value, ast.Attribute):
                    normalized = value.attr.lstrip("_")
                    if value.attr in external_members:
                        external_value_targets.update(target_keys)
                    if normalized in contract.primary_hooks and (
                        _is_contract_receiver(
                            value.value,
                            value.attr,
                            site=value,
                            parents=parents,
                            contract=contract,
                        )
                        or "Plugin" in _enclosing_class(value, parents)
                    ):
                        for target_key in target_keys:
                            callback_targets[target_key] = normalized
                if isinstance(value, ast.Call):
                    called = scoped_key(value.func, site=value)
                    if called in callback_targets and callback_targets[called] in (
                        contract.iterable_hooks
                    ):
                        lazy_targets.update(target_keys)
                    if (
                        isinstance(value.func, ast.Attribute)
                        and value.func.attr in contract.iterable_hooks
                        and _is_contract_receiver(
                            value.func.value,
                            value.func.attr,
                            site=value,
                            parents=parents,
                            contract=contract,
                        )
                    ):
                        lazy_targets.update(target_keys)
                    if (
                        isinstance(value.func, ast.Name)
                        and value.func.id == "iter"
                        and value.args
                        and scoped_key(value.args[0], site=value) in lazy_targets
                    ):
                        lazy_targets.update(target_keys)
                    if (
                        isinstance(value.func, (ast.Name, ast.Attribute))
                        and _dotted_name(value.func).split(".")[-1]
                        in dynamic_descriptor_functions
                    ):
                        literal_members = tuple(
                            argument.value
                            for argument in value.args
                            if isinstance(argument, ast.Constant)
                            and isinstance(argument.value, str)
                            and argument.value in executable_member_names
                        )
                        if literal_members:
                            selected_member = literal_members[-1]
                            for target_key in target_keys:
                                callback_targets[target_key] = selected_member
                            if selected_member == "open":
                                lazy_targets.update(target_keys)

            if (
                isinstance(node, (ast.For, ast.AsyncFor))
                and scoped_key(node.iter, site=node) in lazy_targets
            ):
                add(node, "lazy lifecycle for-iteration")
            if isinstance(
                node,
                (ast.DictComp, ast.GeneratorExp, ast.ListComp, ast.SetComp),
            ):
                for generator in node.generators:
                    if scoped_key(generator.iter, site=node) in lazy_targets:
                        add(
                            node,
                            "lazy consumption "
                            f"{type(node).__name__.casefold()}",
                        )
            if (
                isinstance(node, ast.Starred)
                and isinstance(node.ctx, ast.Load)
                and scoped_key(node.value, site=node) in lazy_targets
            ):
                add(node, "lazy consumption starred expansion")
            if (
                isinstance(node, ast.YieldFrom)
                and scoped_key(node.value, site=node) in lazy_targets
            ):
                add(node, "lazy consumption yield from")
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if scoped_key(item.context_expr, site=node) in lazy_targets:
                        add(node, "lazy lifecycle context enter/exit")

    return tuple(
        sorted(
            candidates.values(),
            key=lambda item: (
                getattr(item[0], "lineno", 0),
                getattr(item[0], "col_offset", 0),
                item[1],
            ),
        )
    )


def _process_fence_reachable_functions(tree: ast.Module) -> frozenset[str]:
    """Return helpers reached below a valid executable-process fence.

    Executable entry functions are derived from the conventional
    ``if __name__ == '__main__'`` call, not from filenames.  Only calls made
    inside a structurally valid process-control/BaseException ``try`` seed the
    graph; an unrelated fence elsewhere in the entry function proves nothing.
    """

    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    executable_entries: set[str] = set()
    for statement in tree.body:
        if not isinstance(statement, ast.If):
            continue
        test_literals = _string_literals(statement.test)
        test_names = {
            node.id for node in ast.walk(statement.test) if isinstance(node, ast.Name)
        }
        if "__main__" not in test_literals or "__name__" not in test_names:
            continue
        executable_entries.update(
            _dotted_name(call.func).split(".")[-1]
            for body_statement in statement.body
            for call in ast.walk(body_statement)
            if isinstance(call, ast.Call)
            and _dotted_name(call.func).split(".")[-1] in functions
        )

    protected_roots: set[str] = set()
    for entry_name in executable_entries:
        entry = functions[entry_name]
        for boundary in (
            node for node in ast.walk(entry) if isinstance(node, ast.Try)
        ):
            if _boundary_problem(boundary) is not None:
                continue
            protected_roots.update(
                _dotted_name(call.func).split(".")[-1]
                for body_statement in boundary.body
                for call in ast.walk(body_statement)
                if isinstance(call, ast.Call)
                and _dotted_name(call.func).split(".")[-1] in functions
            )

    class _DirectCallVisitor(ast.NodeVisitor):
        def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            self.root = root
            self.called: set[str] = set()

        def visit_Call(self, node: ast.Call) -> None:
            called = _dotted_name(node.func).split(".")[-1]
            if called in functions:
                self.called.add(called)
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is self.root:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(
            self,
            node: ast.AsyncFunctionDef,
        ) -> None:
            if node is self.root:
                self.generic_visit(node)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            del node

    call_graph: dict[str, frozenset[str]] = {}
    for name, function in functions.items():
        visitor = _DirectCallVisitor(function)
        visitor.visit(function)
        call_graph[name] = frozenset(visitor.called)

    reachable = set(protected_roots)
    changed = True
    while changed:
        changed = False
        discovered = {
            callee for caller in reachable for callee in call_graph.get(caller, ())
        }
        if not discovered.issubset(reachable):
            reachable.update(discovered)
            changed = True
    return frozenset(reachable)


def _route_fence_reachable_functions(tree: ast.Module) -> frozenset[str]:
    """Return helpers demonstrably executed below a bounded APIRoute.

    A fence elsewhere in a module proves nothing about an unrelated helper.
    This graph starts only at endpoints registered on an ``APIRouter`` whose
    ``route_class`` is a structurally valid process-control/BaseException
    fence, then follows direct module-function calls to a fixed point.
    """

    guarded_route_classes = {
        node.name
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and any(_dotted_name(base).endswith("APIRoute") for base in node.bases)
        and any(
            isinstance(boundary, ast.Try)
            and _boundary_problem(boundary) is None
            for boundary in ast.walk(node)
        )
    }
    guarded_routers: set[str] = set()
    for statement in tree.body:
        if not isinstance(statement, ast.Assign) or not isinstance(
            statement.value,
            ast.Call,
        ):
            continue
        if _dotted_name(statement.value.func).split(".")[-1] != "APIRouter":
            continue
        route_class = next(
            (
                _dotted_name(keyword.value).split(".")[-1]
                for keyword in statement.value.keywords
                if keyword.arg == "route_class"
            ),
            "",
        )
        if route_class not in guarded_route_classes:
            continue
        guarded_routers.update(
            target.id for target in statement.targets if isinstance(target, ast.Name)
        )

    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    reachable = {
        function.name
        for function in functions.values()
        if any(
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and _dotted_name(decorator.func.value) in guarded_routers
            for decorator in function.decorator_list
        )
    }

    class _DirectCallVisitor(ast.NodeVisitor):
        def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            self.root = root
            self.called: set[str] = set()

        def visit_Call(self, node: ast.Call) -> None:
            called = _dotted_name(node.func).split(".")[-1]
            if called in functions:
                self.called.add(called)
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is self.root:
                self.generic_visit(node)

        def visit_AsyncFunctionDef(
            self,
            node: ast.AsyncFunctionDef,
        ) -> None:
            if node is self.root:
                self.generic_visit(node)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            del node

    call_graph: dict[str, frozenset[str]] = {}
    for name, function in functions.items():
        visitor = _DirectCallVisitor(function)
        visitor.visit(function)
        call_graph[name] = frozenset(visitor.called)

    changed = True
    while changed:
        changed = False
        discovered = {
            callee
            for caller in reachable
            for callee in call_graph.get(caller, ())
        }
        if not discovered.issubset(reachable):
            reachable.update(discovered)
            changed = True
    return frozenset(reachable)


def _module_census(
    source: str,
    *,
    filename: str,
    contract: _DeclaredContract,
) -> tuple[_BoundarySite, ...]:
    tree = ast.parse(source, filename=filename)
    parents = _build_parents(tree)
    wrappers = _wrapper_names(tree)
    route_fence_reachable = _route_fence_reachable_functions(tree)
    process_fence_reachable = _process_fence_reachable_functions(tree)
    sites: list[_BoundarySite] = []
    for node, label in _candidate_nodes(
        tree,
        contract=contract,
        wrappers=wrappers,
    ):
        boundary = _lexical_boundary(node, parents=parents)
        if boundary is not None:
            problem = _boundary_problem(boundary)
            guarded = problem is None
            explanation = "process-control-first BaseException boundary" if guarded else problem
        elif _delegated_to_wrapper(
            node,
            tree=tree,
            parents=parents,
            wrappers=wrappers,
        ):
            guarded = True
            explanation = "delegated to a derived boundary adapter"
        elif (
            _enclosing_functions(node, parents)
            and _enclosing_functions(node, parents)[-1].name
            in route_fence_reachable
        ):
            guarded = True
            explanation = "reachable beneath a derived ASGI route fence"
        elif (
            _enclosing_functions(node, parents)
            and _enclosing_functions(node, parents)[-1].name
            in process_fence_reachable
        ):
            guarded = True
            explanation = "reachable beneath a derived executable-process fence"
        else:
            guarded = False
            explanation = "no containing or delegated boundary"
        sites.append(
            _BoundarySite(
                filename=filename,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
                label=label,
                guarded=guarded,
                explanation=explanation or "invalid boundary",
            )
        )
    return tuple(sites)


def _source_census(
    paths: Iterable[Path],
    *,
    contract: _DeclaredContract | None = None,
) -> tuple[_BoundarySite, ...]:
    source_paths = tuple(sorted(paths))
    active_contract = contract or _derive_declared_contract(source_paths)
    sites: list[_BoundarySite] = []
    for path in source_paths:
        # plugin_api.py declares the plug-in side of the contract; containment
        # belongs at outer core invocation sites, not inside protocol/defaults.
        if path.resolve() == PLUGIN_API_MODULE.resolve():
            continue
        sites.extend(
            _module_census(
                path.read_text(encoding="utf-8"),
                filename=path.relative_to(ROOT).as_posix(),
                contract=active_contract,
            )
        )
    return tuple(sites)


def _guard_violations(
    source: str,
    *,
    filename: str,
    contract: _DeclaredContract | None = None,
) -> tuple[str, ...]:
    active_contract = contract or _derive_declared_contract(
        tuple(sorted(SRC_ROOT.rglob("*.py")))
    )
    return tuple(
        site.display()
        for site in _module_census(
            source,
            filename=filename,
            contract=active_contract,
        )
        if not site.guarded
    )


class PluginProcessBoundaryGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source_paths = tuple(sorted(SRC_ROOT.rglob("*.py")))
        cls.contract = _derive_declared_contract(cls.source_paths)

    def test_shared_process_control_vocabulary_is_dependency_free(self) -> None:
        tree = ast.parse(
            PROCESS_CONTROL_MODULE.read_text(encoding="utf-8"),
            filename=PROCESS_CONTROL_MODULE.relative_to(ROOT).as_posix(),
        )
        imports = tuple(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        )
        self.assertTrue(
            all(
                isinstance(node, ast.ImportFrom) and node.module == "__future__"
                for node in imports
            )
        )
        self.assertEqual(
            PROCESS_CONTROL_EXCEPTIONS,
            (KeyboardInterrupt, SystemExit, GeneratorExit),
        )

    def test_web_control_plane_uses_the_shared_process_control_vocabulary(
        self,
    ) -> None:
        tree = ast.parse(
            WEB_CONTROL_PLANE_MODULE.read_text(encoding="utf-8"),
            filename=WEB_CONTROL_PLANE_MODULE.relative_to(ROOT).as_posix(),
        )
        shared_imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "router_dump_analyzer.process_control"
            for alias in node.names
        }
        self.assertIn("PROCESS_CONTROL_EXCEPTIONS", shared_imports)
        self.assertFalse(
            any(
                isinstance(node, ast.Name) and node.id == "_PROCESS_CONTROL_EXCEPTIONS"
                for node in ast.walk(tree)
            )
        )

    def test_contract_is_derived_from_normative_declarations(self) -> None:
        self.assertGreaterEqual(len(self.contract.primary_hooks), 13)
        self.assertIn("describe", self.contract.primary_hooks)
        self.assertIn("resolve_forwarding_step", self.contract.primary_hooks)
        self.assertIn("manifest", self.contract.primary_descriptors)
        self.assertIn("AnalyzerPlugin", self.contract.protocol_members)
        self.assertIn("PluginRuntimeCapability", self.contract.protocol_members)
        self.assertIn("ControlPlaneIdentityResolver", self.contract.protocol_members)

    def test_adversarial_violations_fail_in_previously_unscanned_modules(self) -> None:
        """Prove filename/module location cannot evade the source-wide guard."""

        shapes = {
            "unguarded": """
def invoke(adapter):
    return adapter.describe()
""",
            "ordinary-only": """
def invoke(adapter):
    try:
        return adapter.describe()
    except Exception:
        return None
""",
            "swallowed-control": """
def invoke(adapter):
    try:
        return adapter.describe()
    except PROCESS_CONTROL_EXCEPTIONS:
        return None
    except BaseException:
        return None
""",
            "reversed-order": """
def invoke(adapter):
    try:
        return adapter.describe()
    except BaseException:
        return None
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
""",
        }
        filenames = ("ingestion.py", "runtime.py", "web/runtime_api.py")
        for filename in filenames:
            for shape, body in shapes.items():
                with self.subTest(filename=filename, shape=shape):
                    source = textwrap.dedent(body)
                    violations = _guard_violations(
                        source,
                        filename=filename,
                        contract=self.contract,
                    )
                    self.assertEqual(len(violations), 1, violations)
                    self.assertIn("describe", violations[0])

    def test_adversarial_loading_primitives_require_the_shared_boundary(self) -> None:
        """Loading is executable extension code even before a hook is visible."""

        operations = {
            "entry-point-load": ("return entry_point.load()", 1),
            "entry-point-bound-method": (
                "loader = entry_point.load\nreturn loader()",
                1,
            ),
            "module-import": ("return importlib.import_module(module_name)", 1),
            "module-import-alias": (
                "importer = importlib.import_module\nreturn importer(module_name)",
                1,
            ),
            "module-getattr": (
                (
                    "module = importlib.import_module(module_name)\n"
                    "return getattr(module, attribute)"
                ),
                2,
            ),
            "module-getattr-through-alias": (
                (
                    "importer = importlib.import_module\n"
                    "module = importer(module_name)\n"
                    "return getattr(module, attribute)"
                ),
                2,
            ),
            "module-attribute": (
                (
                    "module = importlib.import_module(module_name)\n"
                    "return module.plugin"
                ),
                2,
            ),
        }
        wrappers = {
            "unguarded": "{operation}",
            "ordinary-only": (
                "try:\n{operation}\n"
                "except Exception:\n    return None"
            ),
            "swallowed-control": (
                "try:\n{operation}\n"
                "except PROCESS_CONTROL_EXCEPTIONS:\n    return None\n"
                "except BaseException:\n    return None"
            ),
            "reversed-order": (
                "try:\n{operation}\n"
                "except BaseException:\n    return None\n"
                "except PROCESS_CONTROL_EXCEPTIONS:\n    raise"
            ),
        }
        prelude = (
            "import importlib\n"
            "from importlib import metadata\n\n"
            "def invoke(entry_point: metadata.EntryPoint, module_name, attribute):\n"
        )
        for operation_name, (operation, expected_sites) in operations.items():
            for shape, wrapper in wrappers.items():
                with self.subTest(operation=operation_name, shape=shape):
                    indented_operation = textwrap.indent(operation, "    ")
                    body = wrapper.format(operation=indented_operation)
                    source = prelude + textwrap.indent(body, "    ") + "\n"
                    violations = _guard_violations(
                        source,
                        filename="extension_loader.py",
                        contract=self.contract,
                    )
                    self.assertEqual(len(violations), expected_sites, violations)

    def test_adversarial_process_cli_loading_fence_is_not_optional(self) -> None:
        """A process entry that reaches a derived loader needs its final fence."""

        wrappers = {
            "unguarded": "return run()",
            "ordinary-only": (
                "try:\n    return run()\n"
                "except Exception:\n    return None"
            ),
            "swallowed-control": (
                "try:\n    return run()\n"
                "except PROCESS_CONTROL_EXCEPTIONS:\n    return None\n"
                "except BaseException:\n    return None"
            ),
            "reversed-order": (
                "try:\n    return run()\n"
                "except BaseException:\n    return None\n"
                "except PROCESS_CONTROL_EXCEPTIONS:\n    raise"
            ),
        }
        prelude = (
            "import importlib\n\n"
            "def run():\n"
            "    return importlib.import_module('hostile_plugin')\n\n"
            "def main():\n"
        )
        epilogue = "\nif __name__ == '__main__':\n    main()\n"
        for shape, body in wrappers.items():
            with self.subTest(shape=shape):
                source = prelude + textwrap.indent(body, "    ") + epilogue
                violations = _guard_violations(
                    source,
                    filename="extension_cli.py",
                    contract=self.contract,
                )
                self.assertEqual(len(violations), 1, violations)

        valid_body = (
            "try:\n    return run()\n"
            "except PROCESS_CONTROL_EXCEPTIONS:\n    raise\n"
            "except BaseException:\n    return None"
        )
        valid_source = prelude + textwrap.indent(valid_body, "    ") + epilogue
        valid_sites = _module_census(
            valid_source,
            filename="extension_cli.py",
            contract=self.contract,
        )
        self.assertEqual(len(valid_sites), 1, valid_sites)
        self.assertTrue(valid_sites[0].guarded, valid_sites[0].display())
        self.assertIn("executable-process fence", valid_sites[0].explanation)

    def test_alias_bound_callback_and_lazy_lifecycle_shapes_are_discovered(self) -> None:
        """Exercise the guard's stated intra-procedural data-flow envelope."""

        source = """
def invoke(adapter):
    bound = adapter.locate_inputs
    saved = bound
    rows = saved(None)
    iterator = iter(rows)
    next(iterator)
    iterator.close()
    with rows:
        pass
"""
        sites = _module_census(
            source,
            filename="runtime.py",
            contract=self.contract,
        )
        labels = "\n".join(site.label for site in sites)
        self.assertIn("descriptor adapter.locate_inputs", labels)
        self.assertIn("bound callback saved()", labels)
        self.assertIn("lazy lifecycle iter()", labels)
        self.assertIn("lazy lifecycle next()", labels)
        self.assertIn("lazy lifecycle iterator.close()", labels)
        self.assertIn("lazy lifecycle context enter/exit", labels)
        self.assertTrue(all(not site.guarded for site in sites), labels)

    def test_every_declared_lazy_consumption_form_is_discovered(self) -> None:
        """Pin every stream-consumption form claimed by the architecture."""

        forms = (
            ("list comprehension", "result = [item for item in rows]"),
            ("set comprehension", "result = {item for item in rows}"),
            ("dict comprehension", "result = {item: item for item in rows}"),
            ("generator expression", "result = (item for item in rows)"),
            ("list()", "result = list(rows)"),
            ("tuple()", "result = tuple(rows)"),
            ("sorted()", "result = sorted(rows)"),
            ("starred list", "result = [*rows]"),
            ("yield from", "yield from rows"),
            ("next()", "result = next(rows)"),
            ("iter()", "result = iter(rows)"),
            ("tuple unpacking", "first, second = rows"),
            ("any()", "result = any(rows)"),
            ("all()", "result = all(rows)"),
            ("sum()", "result = sum(rows)"),
            ("min()", "result = min(rows)"),
            ("max()", "result = max(rows)"),
        )
        template = """
def invoke(adapter):
    try:
        rows = adapter.locate_inputs(None)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:
        return bounded_failure()
    {consumer}
"""
        for label, consumer in forms:
            with self.subTest(form=label):
                violations = _guard_violations(
                    textwrap.dedent(template).format(consumer=consumer),
                    filename="ingestion.py",
                    contract=self.contract,
                )
                self.assertTrue(
                    any("lazy" in violation for violation in violations),
                    f"{label} escaped the lazy-consumption census: {violations}",
                )

    def test_unrelated_helper_is_not_covered_by_a_module_route_fence(self) -> None:
        """A valid APIRoute fence is not a module-wide exemption."""

        source = """
class BoundedRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()
        async def bounded(request):
            try:
                return await original(request)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException:
                return bounded_failure()
        return bounded

router = APIRouter(route_class=BoundedRoute)

@router.get("/")
def endpoint():
    return 1

def unrelated(adapter):
    return adapter.describe()
"""
        violations = _guard_violations(
            textwrap.dedent(source),
            filename="web/runtime_api.py",
            contract=self.contract,
        )
        self.assertEqual(len(violations), 1, violations)
        self.assertIn("adapter.describe", violations[0])

    def test_generic_callback_wrapper_is_counted_as_a_guarded_boundary(self) -> None:
        source = """
def invoke_callback(callback: Callable[[], object]):
    try:
        return callback()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:
        return bounded_failure()
"""
        sites = _module_census(
            textwrap.dedent(source),
            filename="normalized_data.py",
            contract=self.contract,
        )
        callback_sites = tuple(
            site for site in sites if "boundary callback parameter" in site.label
        )
        self.assertEqual(len(callback_sites), 1, sites)
        self.assertTrue(callback_sites[0].guarded, callback_sites[0].display())

    def test_stored_plugin_callback_is_counted_guarded_and_unguarded(self) -> None:
        template = """
class Adapter:
    \"\"\"Core adapter for a plug-in-owned callback.\"\"\"

    def __init__(self, callback: Callable[[], object]):
        self._callback = callback

    def invoke(self):
{body}
"""
        guarded_body = """        try:
            return self._callback()
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:
            return bounded_failure()
"""
        unguarded_body = "        return self._callback()\n"
        for expected_guarded, body in (
            (True, guarded_body),
            (False, unguarded_body),
        ):
            with self.subTest(guarded=expected_guarded):
                sites = _module_census(
                    textwrap.dedent(template).format(body=body.rstrip()),
                    filename="multi_node_route.py",
                    contract=self.contract,
                )
                callback_sites = tuple(
                    site
                    for site in sites
                    if "stored plug-in callback" in site.label
                )
                self.assertEqual(len(callback_sites), 1, sites)
                self.assertEqual(callback_sites[0].guarded, expected_guarded)

    def test_all_derived_core_plugin_invocations_use_the_shared_boundary(self) -> None:
        """Assert the derived whole-source census, with readable evidence."""

        sites = _source_census(self.source_paths, contract=self.contract)
        module_counts = Counter(
            site.filename.replace("\\", "/") for site in sites
        )
        for module, floor in _CENSUS_FLOOR_BY_MODULE.items():
            self.assertGreaterEqual(
                module_counts[module],
                floor,
                "plug-in boundary census floor regressed: "
                f"{module} discovered {module_counts[module]}, expected at least "
                f"{floor}; total discovered {len(sites)}; per-module "
                f"{dict(sorted(module_counts.items()))}",
            )
        guarded = tuple(site for site in sites if site.guarded)
        violations = tuple(site for site in sites if not site.guarded)
        census = "\n".join(site.display() for site in sites)
        self.assertGreater(
            len(sites),
            0,
            "derived plug-in execution census unexpectedly found no boundaries",
        )
        covered_files = {Path(site.filename).name for site in sites}
        self.assertTrue(
            {
                "plugin_loading.py",
                "normalized_data.py",
                "temporal_topology.py",
                "multi_node_route.py",
            }.issubset(covered_files),
            f"provider/callback census coverage regressed: {sorted(covered_files)}",
        )
        loading_sites = tuple(
            site
            for site in sites
            if site.filename.endswith("plugin_loading.py")
            and any(
                token in site.label
                for token in (
                    "entry-point load",
                    "dynamic module import",
                    "loaded module",
                )
            )
        )
        self.assertEqual(
            len(loading_sites),
            3,
            "the installed/direct loading census must cover entry-point load, "
            "module initialization, and module attribute resolution",
        )
        self.assertEqual(
            len(sites),
            len(guarded),
            f"{len(sites)} boundaries discovered / {len(guarded)} guarded\n{census}",
        )
        self.assertEqual(
            violations,
            (),
            f"{len(sites)} boundaries discovered / {len(guarded)} guarded\n{census}",
        )


if __name__ == "__main__":
    unittest.main()
