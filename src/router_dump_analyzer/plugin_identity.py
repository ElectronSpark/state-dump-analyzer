"""Deterministic executable identities for locally importable code."""

from __future__ import annotations

import abc
import ast
import builtins
import dataclasses as _dataclasses
import dis
import hashlib
import inspect
import io
import os
import stat
import struct
import sys
import threading
import tokenize
import weakref
from dataclasses import dataclass, field, is_dataclass
from dataclasses import fields as dataclass_fields
from enum import Enum
from pathlib import Path
from types import CodeType, FunctionType, GenericAlias, MappingProxyType, ModuleType
from typing import Any, cast

MAX_PLUGIN_PACKAGE_FILES = 4_096
MAX_PLUGIN_PACKAGE_PATHS = 8_192
MAX_PLUGIN_PACKAGE_BYTES: int = 128 * 1024 * 1024
MAX_PLUGIN_PACKAGE_FILE_BYTES: int = 32 * 1024 * 1024
MAX_PLUGIN_PACKAGE_PATH_BYTES = 4_096

_IGNORED_DIRECTORY_NAMES = {
    "__pycache__",
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
}
_FINGERPRINT_SCHEMA = b"router_dump_analyzer.plugin_executable.v3\0"
_MODULE_TARGET_FINGERPRINT_SCHEMA = (
    b"router_dump_analyzer.module_target_executable.v3\0"
)
_CALLABLE_CODE_FINGERPRINT_SCHEMA = (
    b"router_dump_analyzer.callable_code.v2\0"
)
_CALLABLE_TARGET_FINGERPRINT_SCHEMA = (
    b"router_dump_analyzer.callable_target_executable.v1\0"
)
_CALLABLE_SOURCE_SCOPE_FINGERPRINT_SCHEMA = (
    b"router_dump_analyzer.callable_source_scope.v1\0"
)
_SOURCE_ONLY_SCOPE_CACHE_MARKER = "\0callable-source-only\0"
_RETAINED_CAPABILITY_TOKEN_KEY = os.urandom(32)
_MAX_RETAINED_CAPABILITY_WEAK_ENTRIES = 16_384
_MAX_RETAINED_CAPABILITY_STRONG_ENTRIES = 1_024
_RETAINED_CAPABILITY_TOKEN_LOCK = threading.RLock()
_RETAINED_CAPABILITY_WEAK_TOKENS: dict[
    int,
    tuple[weakref.ReferenceType[object], bytes],
] = {}
_RETAINED_CAPABILITY_STRONG_TOKENS: dict[int, tuple[object, bytes]] = {}
_MAX_TARGET_CODE_OBJECTS = 2_048
_MAX_TARGET_VALUE_NODES = 32_768
_MAX_TARGET_VALUE_DEPTH = 64
_MAX_TARGET_VALUE_BYTES = 32 * 1024 * 1024
_MAX_TARGET_SOURCE_BYTES = 16 * 1024 * 1024
_CANONICAL_HIDDEN_BUILTIN_TYPES = frozenset(
    {
        MappingProxyType,
        type({}.items()),
        type({}.keys()),
        type({}.values()),
    }
)
_PLATFORM_UNAVAILABLE_LOCAL_IMPORTS = frozenset(
    {
        ("pathlib", "Path.group", "grp"),
        ("pathlib", "Path.owner", "pwd"),
    }
    if os.name == "nt"
    else ()
)


class PluginExecutableIdentityError(ValueError):
    """An importable plug-in executable cannot be fingerprinted safely."""


@dataclass(frozen=True, slots=True)
class _PackageEntry:
    """One path-independent package identity input.

    Regular files carry a local path whose bytes are hashed. Ordinary
    directories carry their normalized name and type without a file path. A
    contained symbolic-link or junction alias carries only its normalized
    package-local target. The target's bytes are hashed through its canonical
    package path; the alias itself is never traversed, so reparse cycles cannot
    recurse.
    """

    relative: str
    path: Path | None
    entry_kind: str = "file"
    alias_kind: str | None = None
    alias_target: str | None = None


@dataclass(frozen=True, slots=True)
class _ExecutableScope:
    """The complete import scope represented by one executable identity."""

    kind: str
    logical_name: str
    roots: tuple[Path, ...]


@dataclass(slots=True)
class _NativeExportIndex:
    """One bounded identity index for a native module namespace."""

    module: ModuleType
    namespace: dict[str, object]
    snapshot: tuple[tuple[object, object], ...]
    exports: dict[int, tuple[object, tuple[str, ...]]]


@dataclass(frozen=True, slots=True)
class _FunctionDependencyAnalysis:
    """One immutable bytecode-dependency analysis retained for an attestation."""

    function: FunctionType
    code: CodeType
    global_names: tuple[str, ...]
    global_attribute_paths: tuple[tuple[str, ...], ...]
    has_runtime_imports: bool


@dataclass(frozen=True, slots=True)
class _DeclaredCodeCacheEntry:
    """One exact source snapshot backing locally cached declarations."""

    source_identity: str
    source_stat_identity: tuple[int, int, int, int, int]
    code_objects: tuple[CodeType, ...]


@dataclass(frozen=True, slots=True)
class _DeclaredAstCacheEntry:
    """One exact, bounded source AST retained for local-import analysis."""

    source_identity: str
    source_stat_identity: tuple[int, int, int, int, int]
    functions: tuple[
        tuple[str, ast.FunctionDef | ast.AsyncFunctionDef],
        ...,
    ]


@dataclass(frozen=True, slots=True)
class _OwnedDescriptorAccessor:
    """One accessor admitted only through an exact static descriptor owner."""

    owner: type[Any]
    name: str
    descriptor: object
    slot: str
    accessor: FunctionType


@dataclass(frozen=True, slots=True)
class _OwnedStaticDescriptor:
    """One exact class slot authorizing inspection of descriptor accessors."""

    owner: type[Any]
    name: str
    descriptor: object
    accessors: tuple[tuple[str, FunctionType | None], ...]


@dataclass(slots=True)
class _TargetIdentityBudget:
    """Bound recursive code/value work for one live target attestation."""

    code_objects: int = 0
    value_nodes: int = 0
    value_bytes: int = 0
    declared_code_cache: dict[tuple[str, Path], _DeclaredCodeCacheEntry] = field(
        default_factory=dict
    )
    declared_ast_cache: dict[tuple[str, Path], _DeclaredAstCacheEntry] = field(
        default_factory=dict
    )
    batch_declared_code_cache: dict[
        tuple[str, Path, str], tuple[CodeType, ...]
    ] | None = None
    class_cache: dict[int, str] = field(default_factory=dict)
    class_snapshots: dict[
        int,
        tuple[type[Any], tuple[tuple[str, object], ...]],
    ] = field(default_factory=dict)
    active_classes: set[int] = field(default_factory=set)
    object_cache: dict[int, str] = field(default_factory=dict)
    active_objects: set[int] = field(default_factory=set)
    active_dependency_leaves: set[int] = field(default_factory=set)
    dependency_class_cache: dict[
        tuple[int, bool],
        tuple[type[Any], str, tuple[tuple[str, object], ...]],
    ] = field(default_factory=dict)
    object_snapshots: dict[int, tuple[tuple[object, object], ...]] = field(
        default_factory=dict
    )
    object_refs: dict[int, object] = field(default_factory=dict)
    native_export_indexes: dict[int, _NativeExportIndex] = field(
        default_factory=dict
    )
    function_dependency_analyses: dict[int, _FunctionDependencyAnalysis] = field(
        default_factory=dict
    )
    owned_descriptor_accessors: dict[int, list[_OwnedDescriptorAccessor]] = field(
        default_factory=dict
    )
    owned_static_descriptors: dict[int, list[_OwnedStaticDescriptor]] = field(
        default_factory=dict
    )
    module_source_paths: dict[
        int,
        tuple[ModuleType, object, object, object, Path | None],
    ] = field(default_factory=dict)
    object_source_paths: dict[int, tuple[object, str | None, Path | None]] = field(
        default_factory=dict
    )
    derived_cache_slots: list[tuple[ModuleType, str, object]] = field(
        default_factory=list
    )
    allow_runtime_closures: bool = False
    allow_unbound_source_objects: bool = False
    leaf_external_references: bool = False
    bind_exact_object_tokens: bool = False
    root_scope_identity: str | None = None
    external_class_member_runtime_depth: int = 0


@dataclass(frozen=True, slots=True)
class _RuntimeImportBinding:
    """One statically bound local import without executing an importer."""

    module_name: str
    attribute_path: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _StaticAttributeResolution:
    """One final exact static attribute and the slot that supplied it."""

    value: object
    owner: object | None
    name: str | None
    descriptor: object


def executable_plugin_fingerprint(plugin: Any) -> str | None:
    """Return a bounded digest of an importable plug-in's executable scope.

    ``None`` means the object's defining module has no inspectable local file.
    Once a local scope is identified, unsafe paths, changing files, or
    resource-bound violations raise :class:`PluginExecutableIdentityError`.
    """

    module_name = _plugin_module_name(plugin)
    if module_name is None:
        return None
    module = sys.modules.get(module_name)
    source_path = _module_source_path(plugin, module)
    if source_path is None:
        return None
    return _executable_scope_fingerprint(module_name, source_path)


def executable_callable_fingerprint(callback: Any) -> str:
    """Return a bounded identity for one same-process executable callback.

    Unlike :func:`executable_module_target_fingerprint`, this entry point does
    not require a module attribute by which the callback can be imported in a
    fresh process.  It is intended for a registration that retains the exact
    live callback and revalidates that same object immediately before invoking
    it.  Source code, defaults, referenced globals and imports, ordinary
    closure cells, function-owned state, and callable class/instance state all
    participate.  Every captured value must itself have exact, bounded
    provenance; otherwise the callback is deliberately ineligible.
    """

    if not callable(callback):
        raise PluginExecutableIdentityError("callback target is not callable")
    budget = _TargetIdentityBudget(
        allow_runtime_closures=True,
        allow_unbound_source_objects=True,
        bind_exact_object_tokens=True,
    )
    scope_cache: dict[str, str] = {}
    callable_cache: dict[int, str] = {}
    active_callables: set[int] = set()
    receiver: object | None = None
    if inspect.ismethod(callback):
        function = callback.__func__
        receiver = callback.__self__
        target_kind = "bound-method"
        implementation: object = function
    elif type(callback) is FunctionType:
        function = callback
        target_kind = "function"
        implementation = function
    elif inspect.isclass(callback):
        function = None
        target_kind = "class"
        implementation = callback
    else:
        function = None
        target_kind = "instance"
        implementation = type(callback)
    module_name = getattr(implementation, "__module__", None)
    qualified_name = getattr(implementation, "__qualname__", None)
    if (
        type(module_name) is not str
        or not module_name
        or type(qualified_name) is not str
        or not qualified_name
    ):
        raise PluginExecutableIdentityError(
            "callback target has no exact implementation provenance"
        )
    module = sys.modules.get(module_name)
    source_path = _object_source_path(implementation, budget=budget)
    module_source = (
        _module_file_source_path(module, budget=budget)
        if isinstance(module, ModuleType)
        else None
    )
    if (
        not isinstance(module, ModuleType)
        or source_path is None
        or module_source is None
        or source_path != module_source
    ):
        raise PluginExecutableIdentityError(
            "callback target has no exact source-file provenance"
        )
    scope_identity = _source_module_identity(module_name, module_source)
    budget.root_scope_identity = scope_identity
    budget.leaf_external_references = True
    scope_cache[_SOURCE_ONLY_SCOPE_CACHE_MARKER] = "1"
    scope_cache[_scope_cache_key(module_name, module_source)] = scope_identity
    if function is not None:
        runtime_identity = _function_runtime_identity(
            function,
            module=module,
            module_name=module_name,
            qualified_name=qualified_name,
            source_path=module_source,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
        )
        if receiver is not None:
            receiver_digest = hashlib.sha256()
            _update_global_reference(
                receiver_digest,
                receiver,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=module_name.split(".", maxsplit=1)[0],
                depth=1,
            )
            runtime_identity = f"{runtime_identity}:{receiver_digest.hexdigest()}"
    elif inspect.isclass(callback):
        runtime_identity = _class_runtime_identity(
            callback,
            module_name=module_name,
            qualified_name=qualified_name,
            source_path=module_source,
            budget=budget,
            scope_cache=scope_cache,
        )
    else:
        runtime_identity = _instance_runtime_identity(
            callback,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=module_name.split(".", maxsplit=1)[0],
            depth=0,
        )
    _verify_native_export_indexes(budget)
    _verify_function_dependency_analyses(budget)
    _verify_dependency_class_caches(budget)
    _verify_source_path_caches(budget)
    _verify_derived_cache_slots(budget)
    digest = hashlib.sha256()
    digest.update(_CALLABLE_TARGET_FINGERPRINT_SCHEMA)
    _update_exact_object_token(digest, callback, budget=budget)
    for value in (
        scope_identity,
        module_name,
        qualified_name,
        target_kind,
        runtime_identity,
    ):
        _digest_field(digest, value.encode("utf-8"))
    result = f"callable-sha256:{digest.hexdigest()}"
    _verify_class_identity_caches(budget)
    _verify_object_identity_caches(budget)
    return result


def executable_module_target_fingerprint(
    module_name: str,
    attribute: str,
    target: Any,
    *,
    _batch_declared_code_cache: dict[
        tuple[str, Path, str], tuple[CodeType, ...]
    ]
    | None = None,
) -> str:
    """Fingerprint exact import provenance plus bounded module/package bytes.

    Source-backed module functions/classes must exactly match the target.
    Module-level instances bind their implementation type independently. Live
    Python code, defaults, annotations, safe globals, and nested code objects
    participate so environment-selected behavior cannot hide behind unchanged
    source bytes. Dynamic aliases, closures, runtime-created code, unsafe globals,
    built-ins, and sourceless extensions are deliberately unverifiable.
    """

    if (
        type(module_name) is not str
        or not module_name
        or any(not component.isidentifier() for component in module_name.split("."))
    ):
        raise PluginExecutableIdentityError("module target has an invalid module")
    if (
        type(attribute) is not str
        or not attribute
        or any(not component.isidentifier() for component in attribute.split("."))
    ):
        raise PluginExecutableIdentityError("module target has an invalid attribute")
    module = sys.modules.get(module_name)
    if not isinstance(module, ModuleType):
        raise PluginExecutableIdentityError(
            "module target has no exact imported module provenance"
        )
    if _static_import_target(module, attribute) is not target:
        raise PluginExecutableIdentityError(
            "module target is dynamic or does not have static import provenance"
        )
    budget = _TargetIdentityBudget(
        batch_declared_code_cache=_batch_declared_code_cache
    )
    module_source = _module_file_source_path(module, budget=budget)
    if module_source is None:
        raise PluginExecutableIdentityError(
            "module target has no exact source-file provenance"
        )
    target_scope = _executable_scope_fingerprint(module_name, module_source)
    root_source_identity = _source_module_identity(module_name, module_source)
    scope_cache = {
        _SOURCE_ONLY_SCOPE_CACHE_MARKER: "1",
        _scope_cache_key(module_name, module_source): root_source_identity,
    }
    budget.leaf_external_references = True
    budget.root_scope_identity = root_source_identity
    if type(target) is FunctionType:
        target_kind = "function"
        defining_module = getattr(target, "__module__", None)
        qualified_name = getattr(target, "__qualname__", None)
        if defining_module != module_name or qualified_name != attribute:
            raise PluginExecutableIdentityError(
                "module target does not match its exact import provenance"
            )
        defining_path = _object_source_path(target, budget=budget)
        if defining_path is None or defining_path != module_source:
            raise PluginExecutableIdentityError(
                "module target has no exact source-file provenance"
            )
        implementation_scope = target_scope
        runtime_identity = _function_runtime_identity(
            target,
            module=module,
            module_name=module_name,
            qualified_name=attribute,
            source_path=module_source,
            budget=budget,
            scope_cache=scope_cache,
        )
    elif inspect.isclass(target):
        target_kind = "class"
        defining_module = getattr(target, "__module__", None)
        qualified_name = getattr(target, "__qualname__", None)
        if defining_module != module_name or qualified_name != attribute:
            raise PluginExecutableIdentityError(
                "module target does not match its exact import provenance"
            )
        defining_path = _object_source_path(target, budget=budget)
        if defining_path is None or defining_path != module_source:
            raise PluginExecutableIdentityError(
                "module target has no exact source-file provenance"
            )
        implementation_scope = target_scope
        runtime_identity = _class_runtime_identity(
            target,
            module_name=module_name,
            qualified_name=attribute,
            source_path=module_source,
            budget=budget,
            scope_cache=scope_cache,
        )
    else:
        target_kind = "instance"
        implementation = type(target)
        defining_module = getattr(implementation, "__module__", None)
        qualified_name = getattr(implementation, "__qualname__", None)
        if (
            type(defining_module) is not str
            or not defining_module
            or type(qualified_name) is not str
            or not qualified_name
        ):
            raise PluginExecutableIdentityError(
                "module target instance has no exact implementation provenance"
            )
        implementation_module = sys.modules.get(defining_module)
        if not isinstance(implementation_module, ModuleType):
            raise PluginExecutableIdentityError(
                "module target implementation module is unavailable"
            )
        defining_path = _object_source_path(implementation, budget=budget)
        implementation_source = _module_file_source_path(
            implementation_module,
            budget=budget,
        )
        if (
            defining_path is None
            or implementation_source is None
            or defining_path != implementation_source
        ):
            raise PluginExecutableIdentityError(
                "module target implementation has no exact source provenance"
            )
        implementation_scope = _executable_scope_fingerprint(
            defining_module,
            implementation_source,
        )
        scope_cache[_scope_cache_key(defining_module, implementation_source)] = (
            implementation_scope
        )
        runtime_identity = _instance_runtime_identity(
            target,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=module_name.split(".", maxsplit=1)[0],
            depth=0,
        )
    _verify_native_export_indexes(budget)
    _verify_function_dependency_analyses(budget)
    _verify_dependency_class_caches(budget)
    _verify_source_path_caches(budget)
    _verify_derived_cache_slots(budget)
    digest = hashlib.sha256()
    digest.update(_MODULE_TARGET_FINGERPRINT_SCHEMA)
    for value in (
        target_scope,
        implementation_scope,
        module_name,
        attribute,
        defining_module,
        qualified_name,
        target_kind,
        runtime_identity,
    ):
        _digest_field(digest, value.encode("utf-8"))
    result = f"target-sha256:{digest.hexdigest()}"
    _verify_class_identity_caches(budget)
    _verify_object_identity_caches(budget)
    return result


def _static_import_target(module: ModuleType, attribute: str) -> object:
    selected: object = module
    missing = object()
    for component in attribute.split("."):
        if isinstance(selected, ModuleType) or inspect.isclass(selected):
            candidate = vars(selected).get(component, missing)
        else:
            return missing
        if candidate is missing:
            return missing
        if isinstance(candidate, (classmethod, staticmethod)):
            candidate = candidate.__func__
        selected = candidate
    return selected


def _module_file_source_path(
    module: ModuleType,
    *,
    budget: _TargetIdentityBudget | None = None,
) -> Path | None:
    object_key = id(module)
    if budget is not None:
        cached = budget.module_source_paths.get(object_key)
        if cached is not None:
            if cached[0] is not module:
                raise PluginExecutableIdentityError(
                    "module target source-path cache is inconsistent"
                )
            return cached[4]
    module_name = getattr(module, "__name__", None)
    registry_name = getattr(getattr(module, "__spec__", None), "name", None)
    module_file = getattr(module, "__file__", None)
    result = (
        _resolved_source_path((module_file,))
        if isinstance(module_file, str) and module_file
        else None
    )
    if budget is not None:
        budget.module_source_paths[object_key] = (
            module,
            module_name,
            registry_name,
            module_file,
            result,
        )
    return result


def _object_source_path(
    value: object,
    *,
    budget: _TargetIdentityBudget | None = None,
) -> Path | None:
    object_key = id(value)
    if budget is not None:
        cached = budget.object_source_paths.get(object_key)
        if cached is not None:
            if cached[0] is not value:
                raise PluginExecutableIdentityError(
                    "module target object source-path cache is inconsistent"
                )
            return cached[2]
    try:
        source = inspect.getsourcefile(value)
    except (OSError, TypeError):
        source = None
    result = _resolved_source_path((source,)) if source else None
    if budget is not None:
        budget.object_source_paths[object_key] = (value, source, result)
    return result


def _update_runtime_closure_reference(
    digest: Any,
    value: object,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    """Bind one live closure cell without snapshotting operational state."""

    if type(value) in {tuple, frozenset}:
        _consume_target_budget(budget, depth=depth)
        _digest_field(digest, b"runtime-closure-container")
        _digest_field(digest, type(value).__name__.encode("ascii"))
        encoded_items: list[bytes] = []
        for item in value:
            item_digest = hashlib.sha256()
            _update_runtime_closure_reference(
                item_digest,
                item,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
            encoded_items.append(item_digest.digest())
        if type(value) is frozenset:
            encoded_items.sort()
        for encoded in encoded_items:
            _digest_field(digest, encoded)
        return
    parameters = getattr(type(value), "__dataclass_params__", None)
    frozen_dataclass = is_dataclass(value) and getattr(parameters, "frozen", False)
    if (
        value is None
        or value is NotImplemented
        or type(value) in {bool, int, float, complex, str, bytes, dict, list}
        or type(value) is FunctionType
        or isinstance(value, (ModuleType, Enum))
        or inspect.isclass(value)
        or inspect.ismethod(value)
        or inspect.isbuiltin(value)
        or inspect.ismethoddescriptor(value)
        or frozen_dataclass
    ):
        _update_global_reference(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth,
        )
        return
    _update_retained_capability_reference(
        digest,
        value,
        budget=budget,
        scope_cache=scope_cache,
        identity_root=identity_root,
        depth=depth,
    )


def _update_retained_capability_reference(
    digest: Any,
    value: object,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    identity_root: str,
    depth: int,
) -> None:
    """Bind an exact retained object and its implementation, not live internals."""

    _consume_target_budget(budget, depth=depth)
    if _update_external_exported_dependency(
        digest,
        value,
        budget=budget,
        scope_cache=scope_cache,
        identity_root=identity_root,
        depth=depth,
    ):
        return
    implementation = type(value)
    module_name = getattr(implementation, "__module__", None)
    qualified_name = getattr(implementation, "__qualname__", None)
    if (
        type(module_name) is not str
        or not module_name
        or type(qualified_name) is not str
        or not qualified_name
    ):
        raise PluginExecutableIdentityError(
            "callback closure capability has no exact implementation provenance"
        )
    _digest_field(digest, b"retained-closure-capability")
    _digest_field(digest, module_name.encode("utf-8"))
    _digest_field(digest, qualified_name.encode("utf-8"))
    _update_retained_capability_token(digest, value)
    if module_name == "builtins":
        if vars(builtins).get(qualified_name) is not implementation:
            raise PluginExecutableIdentityError(
                "callback closure capability has unverifiable built-in provenance"
            )
        _digest_field(digest, b"built-in")
        return
    module = sys.modules.get(module_name)
    if not isinstance(module, ModuleType):
        raise PluginExecutableIdentityError(
            "callback closure capability implementation is not exactly loaded"
        )
    implementation_source = _object_source_path(implementation, budget=budget)
    module_source = _module_file_source_path(module, budget=budget)
    if (
        implementation_source is not None
        and module_source is not None
        and implementation_source == module_source
    ):
        statically_exported = (
            _static_import_target(module, qualified_name) is implementation
        )
        declared_unbound = (
            budget.allow_unbound_source_objects
            and len(
                _declared_code_objects(
                    module_name=module_name,
                    qualified_name=qualified_name,
                    source_path=module_source,
                    budget=budget,
                )
            )
            == 1
        )
        if not (statically_exported or declared_unbound):
            raise PluginExecutableIdentityError(
                "callback closure capability implementation is not declared exactly"
            )
        _digest_field(
            digest,
            _cached_scope_identity(
                module_name,
                module_source,
                scope_cache,
            ).encode("ascii"),
        )
        return
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None)
    exports = _native_export_names(
        module,
        implementation,
        budget=budget,
        depth=depth + 1,
    )
    if origin not in {"built-in", "frozen"} or not exports:
        raise PluginExecutableIdentityError(
            "callback closure capability implementation is unverifiable"
        )
    _digest_field(digest, str(origin).encode("ascii"))
    for export_name in exports:
        _digest_field(digest, export_name.encode("utf-8"))


def _update_external_exported_dependency(
    digest: Any,
    value: object,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    identity_root: str,
    depth: int,
) -> bool:
    """Bind one exact external source export as an explicit trust boundary."""

    exported_module_name = getattr(value, "__module__", None)
    exported_name = getattr(value, "__qualname__", None) or getattr(
        value,
        "__name__",
        None,
    )
    exported_module = sys.modules.get(exported_module_name)
    exported_source = (
        _module_file_source_path(exported_module, budget=budget)
        if isinstance(exported_module, ModuleType)
        else None
    )
    if (
        type(exported_module_name) is str
        and exported_module_name.split(".", maxsplit=1)[0] != identity_root
        and type(exported_name) is str
        and isinstance(exported_module, ModuleType)
        and exported_source is not None
        and _static_import_target(exported_module, exported_name) is value
    ):
        exported_type = type(value)
        type_module = getattr(exported_type, "__module__", None)
        type_name = getattr(exported_type, "__qualname__", None)
        if type(type_module) is not str or type(type_name) is not str:
            raise PluginExecutableIdentityError(
                "module target singleton external dependency is unverifiable"
            )
        _digest_field(digest, b"dependency-external-exported-object")
        _digest_field(digest, exported_module_name.encode("utf-8"))
        _digest_field(digest, exported_name.encode("utf-8"))
        _digest_field(digest, type_module.encode("utf-8"))
        _digest_field(digest, type_name.encode("utf-8"))
        _digest_field(
            digest,
            _cached_scope_identity(
                exported_module_name,
                exported_source,
                scope_cache,
            ).encode("ascii"),
        )
        if type(value) is FunctionType:
            globals_module_name = value.__globals__.get("__name__")
            globals_module = sys.modules.get(globals_module_name)
            if not (
                isinstance(globals_module, ModuleType)
                and vars(globals_module) is value.__globals__
            ):
                frozen_prefix = "<frozen "
                code_filename = value.__code__.co_filename
                frozen_module_name = (
                    code_filename[len(frozen_prefix) : -1]
                    if code_filename.startswith(frozen_prefix)
                    and code_filename.endswith(">")
                    else None
                )
                frozen_module = sys.modules.get(frozen_module_name)
                if (
                    type(frozen_module_name) is str
                    and isinstance(frozen_module, ModuleType)
                    and vars(frozen_module) is value.__globals__
                ):
                    globals_module_name = frozen_module_name
                    globals_module = frozen_module
            if (
                type(globals_module_name) is not str
                or not isinstance(globals_module, ModuleType)
                or vars(globals_module) is not value.__globals__
                or value.__builtins__ is not vars(builtins)
                or value.__closure__ is not None
            ):
                raise PluginExecutableIdentityError(
                    "module target singleton external function is unverifiable"
                )
            globals_source = _module_file_source_path(
                globals_module,
                budget=budget,
            )
            globals_origin = getattr(
                getattr(globals_module, "__spec__", None),
                "origin",
                None,
            )
            if globals_source is None and globals_origin not in {"built-in", "frozen"}:
                raise PluginExecutableIdentityError(
                    "module target singleton external function is sourceless"
                )
            _digest_field(digest, b"dependency-external-exported-function")
            _digest_field(digest, globals_module_name.encode("utf-8"))
            if globals_source is None:
                _digest_field(digest, str(globals_origin).encode("ascii"))
            else:
                _digest_field(
                    digest,
                    _cached_scope_identity(
                        globals_module_name,
                        globals_source,
                        scope_cache,
                    ).encode("ascii"),
                )
            selected_code = value.__code__
            _update_code_object(
                digest,
                selected_code,
                budget=budget,
                depth=depth + 1,
            )
            _update_runtime_defaults(
                digest,
                value.__defaults__,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache={},
                active_callables=set(),
                identity_root=identity_root,
                depth=depth + 1,
                label="external dependency positional defaults",
            )
            _update_runtime_mapping(
                digest,
                value.__kwdefaults__,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache={},
                active_callables=set(),
                identity_root=identity_root,
                depth=depth + 1,
                label="external dependency keyword defaults",
            )
            _update_runtime_mapping(
                digest,
                value.__dict__,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache={},
                active_callables=set(),
                identity_root=identity_root,
                depth=depth + 1,
                label="external dependency function state",
            )
            _update_annotation_shape(digest, value.__annotations__, budget=budget)
            if value.__code__ is not selected_code:
                raise PluginExecutableIdentityError(
                    "module target singleton external function changed"
                )
        return True
    if inspect.isclass(value) or type(value) is FunctionType:
        return False
    implementation = type(value)
    implementation_module_name = getattr(implementation, "__module__", None)
    implementation_name = getattr(implementation, "__qualname__", None)
    implementation_module = sys.modules.get(implementation_module_name)
    if (
        type(implementation_module_name) is not str
        or implementation_module_name.split(".", maxsplit=1)[0] == identity_root
        or type(implementation_name) is not str
        or not isinstance(implementation_module, ModuleType)
        or _static_import_target(implementation_module, implementation_name)
        is not implementation
    ):
        return False
    namespace = vars(implementation_module)
    snapshot = _snapshot_runtime_dict(
        namespace,
        budget=budget,
        depth=depth + 1,
        label="module target external dependency namespace",
    )
    export_names = tuple(
        sorted(
            name
            for name, candidate in snapshot
            if type(name) is str and candidate is value
        )
    )
    if not export_names:
        _verify_dict_snapshot(namespace, snapshot)
        return False
    implementation_source = _module_file_source_path(
        implementation_module,
        budget=budget,
    )
    origin = getattr(getattr(implementation_module, "__spec__", None), "origin", None)
    if implementation_source is None and origin not in {"built-in", "frozen"}:
        raise PluginExecutableIdentityError(
            "module target singleton external export is sourceless"
        )
    _digest_field(digest, b"dependency-external-exported-instance")
    _digest_field(digest, implementation_module_name.encode("utf-8"))
    _digest_field(digest, implementation_name.encode("utf-8"))
    for export_name in export_names:
        _digest_field(digest, export_name.encode("utf-8"))
    if implementation_source is None:
        _digest_field(digest, str(origin).encode("ascii"))
    else:
        _digest_field(
            digest,
            _cached_scope_identity(
                implementation_module_name,
                implementation_source,
                scope_cache,
            ).encode("ascii"),
        )
    _verify_dict_snapshot(namespace, snapshot)
    return True


def _retire_retained_capability_reference(
    object_key: int,
    reference: weakref.ReferenceType[object],
) -> None:
    """Retire exactly one dead weak entry without touching its replacement."""

    with _RETAINED_CAPABILITY_TOKEN_LOCK:
        current = _RETAINED_CAPABILITY_WEAK_TOKENS.get(object_key)
        if current is not None and current[0] is reference:
            del _RETAINED_CAPABILITY_WEAK_TOKENS[object_key]


def _update_retained_capability_token(digest: Any, value: object) -> None:
    """Seal one exact live object without exposing an address or raw token."""

    with _RETAINED_CAPABILITY_TOKEN_LOCK:
        # Use the interpreter's real identity primitive rather than this
        # module's global ``id`` lookup.  Runtime identity caches deliberately
        # remain patchable for allocator-reuse tests; the token registry must
        # retain O(1) lookup even when those caches are forced to collide.
        object_key = builtins.id(value)
        token: bytes | None = None
        weak_entry = _RETAINED_CAPABILITY_WEAK_TOKENS.get(object_key)
        if weak_entry is not None:
            reference, candidate_token = weak_entry
            candidate = reference()
            if candidate is value:
                token = candidate_token
            elif candidate is None:
                # A delayed callback may leave a dead entry visible briefly.
                # Delete only the exact entry observed under this lock before
                # allowing a newly allocated object to reuse its address.
                current = _RETAINED_CAPABILITY_WEAK_TOKENS.get(object_key)
                if current is weak_entry:
                    del _RETAINED_CAPABILITY_WEAK_TOKENS[object_key]
            else:
                raise PluginExecutableIdentityError(
                    "callback retained-capability identity key collided"
                )
        strong_entry = _RETAINED_CAPABILITY_STRONG_TOKENS.get(object_key)
        if token is None and strong_entry is not None:
            candidate, candidate_token = strong_entry
            if candidate is value:
                token = candidate_token
            else:
                raise PluginExecutableIdentityError(
                    "callback retained-capability identity key collided"
                )
        if token is None:
            try:
                reference = weakref.ref(
                    value,
                    lambda selected, key=object_key: (
                        _retire_retained_capability_reference(key, selected)
                    ),
                )
            except TypeError:
                if (
                    len(_RETAINED_CAPABILITY_STRONG_TOKENS)
                    >= _MAX_RETAINED_CAPABILITY_STRONG_ENTRIES
                ):
                    raise PluginExecutableIdentityError(
                        "callback retained-capability identity exceeds the "
                        "strong registry limit"
                    )
                token = os.urandom(32)
                _RETAINED_CAPABILITY_STRONG_TOKENS[object_key] = (value, token)
            else:
                if (
                    len(_RETAINED_CAPABILITY_WEAK_TOKENS)
                    >= _MAX_RETAINED_CAPABILITY_WEAK_ENTRIES
                ):
                    raise PluginExecutableIdentityError(
                        "callback retained-capability identity exceeds the weak "
                        "registry limit"
                    )
                token = os.urandom(32)
                _RETAINED_CAPABILITY_WEAK_TOKENS[object_key] = (reference, token)
        seal = hashlib.blake2b(
            token,
            key=_RETAINED_CAPABILITY_TOKEN_KEY,
            digest_size=32,
            person=b"rda-cap-v2",
        ).digest()
    _digest_field(digest, seal)


def _update_exact_object_token(
    digest: Any,
    value: object,
    *,
    budget: _TargetIdentityBudget,
) -> None:
    """Bind one traversed authority to its exact same-process generation."""

    if not budget.bind_exact_object_tokens:
        return
    _digest_field(digest, b"exact-retained-object")
    _update_retained_capability_token(digest, value)


def _is_executable_authority(value: object) -> bool:
    """Return whether replacing ``value`` can replace executable authority."""

    if callable(value) or isinstance(value, (classmethod, staticmethod, property)):
        return True
    if (
        inspect.ismethoddescriptor(value)
        or inspect.ismemberdescriptor(value)
        or inspect.isgetsetdescriptor(value)
    ):
        return True
    return any(
        "__get__" in vars(owner)
        or "__set__" in vars(owner)
        or "__delete__" in vars(owner)
        for owner in type(value).__mro__
    )


def _is_identity_bound_receiver(value: object) -> bool:
    """Return whether an attribute traversal retains ``value`` as a receiver."""

    return not (
        value is None
        or value is NotImplemented
        or type(value)
        in {
            bool,
            int,
            float,
            complex,
            str,
            bytes,
            tuple,
            frozenset,
            dict,
            list,
        }
    )


def _function_runtime_identity(
    function: FunctionType,
    *,
    module: ModuleType,
    module_name: str,
    qualified_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget | None = None,
    scope_cache: dict[str, str] | None = None,
    callable_cache: dict[int, str] | None = None,
    active_callables: set[int] | None = None,
    closure_owner: type[Any] | None = None,
    identity_root: str | None = None,
    depth: int = 0,
) -> str:
    frozen_runtime_globals = (
        budget is not None
        and budget.allow_unbound_source_objects
        and function.__globals__.get("__name__") == module_name
        and all(
            code.co_filename.startswith("<frozen ")
            for code in _walk_code_objects(function.__code__)
        )
    )
    if (
        function.__globals__ is not vars(module)
        and not frozen_runtime_globals
    ) or function.__builtins__ is not vars(builtins):
        raise PluginExecutableIdentityError(
            "module target function has noncanonical globals or built-ins"
        )
    if budget is None:
        budget = _TargetIdentityBudget()
    if scope_cache is None:
        scope_cache = {}
    if callable_cache is None:
        callable_cache = {}
    if active_callables is None:
        active_callables = set()
    if identity_root is None:
        identity_root = module_name.split(".", maxsplit=1)[0]
    closure = function.__closure__
    type_parameter_closure: tuple[tuple[str, object], ...] = ()
    runtime_closure: tuple[tuple[str, object], ...] = ()
    if closure:
        if (
            closure_owner is not None
            and function.__code__.co_freevars == ("__class__",)
            and len(closure) == 1
        ):
            try:
                closure_value = closure[0].cell_contents
            except ValueError as error:
                raise PluginExecutableIdentityError(
                    "module target function has an empty closure"
                ) from error
            if closure_value is not closure_owner:
                raise PluginExecutableIdentityError(
                    "module target function has an unsafe class closure"
                )
        elif budget.allow_runtime_closures:
            if len(function.__code__.co_freevars) != len(closure):
                raise PluginExecutableIdentityError(
                    "module target function closure shape is unverifiable"
                )
            selected_runtime_values: list[tuple[str, object]] = []
            for name, cell in zip(
                function.__code__.co_freevars,
                closure,
                strict=True,
            ):
                try:
                    closure_value = cell.cell_contents
                except ValueError as error:
                    raise PluginExecutableIdentityError(
                        "module target function has an empty closure"
                    ) from error
                selected_runtime_values.append((name, closure_value))
            runtime_closure = tuple(selected_runtime_values)
        else:
            type_parameters = getattr(function, "__type_params__", ())
            if type(type_parameters) is not tuple:
                raise PluginExecutableIdentityError(
                    "module target function type parameters are unverifiable"
                )
            type_parameter_by_name = {
                getattr(parameter, "__name__", None): parameter
                for parameter in type_parameters
            }
            if len(function.__code__.co_freevars) != len(closure):
                raise PluginExecutableIdentityError(
                    "module target function closure shape is unverifiable"
                )
            selected_parameters: list[tuple[str, object]] = []
            for name, cell in zip(
                function.__code__.co_freevars,
                closure,
                strict=True,
            ):
                try:
                    closure_value = cell.cell_contents
                except ValueError as error:
                    raise PluginExecutableIdentityError(
                        "module target function has an empty closure"
                    ) from error
                if type_parameter_by_name.get(name) is not closure_value:
                    raise PluginExecutableIdentityError(
                        "module target functions with unsafe closures are unverifiable"
                    )
                selected_parameters.append((name, closure_value))
            type_parameter_closure = tuple(selected_parameters)
    _consume_target_budget(budget, depth=depth)
    function_key = id(function)
    cached = callable_cache.get(function_key)
    if cached is not None:
        return cached
    if function_key in active_callables:
        cycle = hashlib.sha256()
        cycle.update(_CALLABLE_CODE_FINGERPRINT_SCHEMA)
        _digest_field(cycle, b"recursive-reference")
        _digest_field(cycle, module_name.encode("utf-8"))
        _digest_field(cycle, qualified_name.encode("utf-8"))
        return cycle.hexdigest()
    active_callables.add(function_key)
    code_identity = _declared_runtime_code_identity(
        function.__code__,
        module_name=module_name,
        qualified_name=qualified_name,
        source_path=source_path,
        budget=budget,
    )
    digest = hashlib.sha256()
    digest.update(_CALLABLE_CODE_FINGERPRINT_SCHEMA)
    _update_exact_object_token(digest, function, budget=budget)
    for value in (module_name, qualified_name, code_identity):
        _digest_field(digest, value.encode("utf-8"))
    for name, parameter in type_parameter_closure:
        parameter_kind = type(parameter)
        parameter_module = getattr(parameter_kind, "__module__", None)
        parameter_name = getattr(parameter_kind, "__qualname__", None)
        if type(parameter_module) is not str or type(parameter_name) is not str:
            raise PluginExecutableIdentityError(
                "module target function type parameter is unverifiable"
            )
        _digest_field(digest, b"type-parameter-closure")
        _digest_field(digest, name.encode("utf-8"))
        _digest_field(digest, parameter_module.encode("utf-8"))
        _digest_field(digest, parameter_name.encode("utf-8"))
    for name, value in runtime_closure:
        _digest_field(digest, b"runtime-closure")
        _digest_field(digest, name.encode("utf-8"))
        _update_runtime_closure_reference(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
    _update_runtime_defaults(
        digest,
        function.__defaults__,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth + 1,
        label="positional defaults",
    )
    _update_runtime_mapping(
        digest,
        function.__kwdefaults__,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth + 1,
        label="keyword defaults",
    )
    _update_runtime_mapping(
        digest,
        function.__dict__,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth + 1,
        label="function state",
    )
    _update_annotation_shape(digest, function.__annotations__, budget=budget)
    try:
        _update_runtime_import_references(
            digest,
            function,
            module=module,
            module_name=module_name,
            source_path=source_path,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
        dependencies = _function_dependency_analysis(
            function,
            budget=budget,
            depth=depth + 1,
        )
        for name in dependencies.global_names:
            if name == "__import__":
                raise PluginExecutableIdentityError(
                    "module target uses a dynamic import API"
                )
            if name in function.__globals__:
                value = function.__globals__[name]
            elif name in function.__builtins__:
                value = function.__builtins__[name]
            else:
                raise PluginExecutableIdentityError(
                    "module target references an unresolved global"
                )
            _digest_field(digest, name.encode("utf-8"))
            _update_global_reference(
                digest,
                value,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
        for path in dependencies.global_attribute_paths:
            if path in {
                ("builtins", "__import__"),
                ("importlib", "import_module"),
            }:
                raise PluginExecutableIdentityError(
                    "module target uses a dynamic import API"
                )
            if path[0] in function.__globals__:
                selected = function.__globals__[path[0]]
            else:
                selected = function.__builtins__[path[0]]
            _digest_field(digest, b"attribute-path")
            for component in path:
                _digest_field(digest, component.encode("utf-8"))
            _update_static_attribute_path(
                digest,
                selected,
                path[1:],
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
        result = digest.hexdigest()
        callable_cache[function_key] = result
        return result
    finally:
        active_callables.discard(function_key)


def _class_runtime_identity(
    implementation: type[Any],
    *,
    module_name: str,
    qualified_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget | None = None,
    scope_cache: dict[str, str] | None = None,
    callable_cache: dict[int, str] | None = None,
    active_callables: set[int] | None = None,
    class_cache: dict[int, str] | None = None,
    active_classes: set[int] | None = None,
    identity_root: str | None = None,
    depth: int = 0,
    allow_declared_implementation: bool = False,
) -> str:
    module = sys.modules.get(module_name)
    if budget is None:
        budget = _TargetIdentityBudget()
    if not isinstance(module, ModuleType) or (
        _static_import_target(module, qualified_name) is not implementation
        and not budget.allow_unbound_source_objects
        and not allow_declared_implementation
    ):
        raise PluginExecutableIdentityError(
            "module target class has no exact static provenance"
        )
    if scope_cache is None:
        scope_cache = {}
    if callable_cache is None:
        callable_cache = {}
    if active_callables is None:
        active_callables = set()
    if class_cache is None:
        class_cache = budget.class_cache
    if active_classes is None:
        active_classes = budget.active_classes
    if identity_root is None:
        identity_root = module_name.split(".", maxsplit=1)[0]
    _consume_target_budget(budget, depth=depth)
    class_key = id(implementation)
    cached = class_cache.get(class_key)
    if cached is not None:
        _verify_cached_class_snapshot(
            implementation,
            budget=budget,
            label="module target cached class",
        )
        return cached
    if class_key in active_classes:
        cycle = hashlib.sha256()
        cycle.update(_CALLABLE_CODE_FINGERPRINT_SCHEMA)
        _digest_field(cycle, b"recursive-class-reference")
        _digest_field(cycle, module_name.encode("utf-8"))
        _digest_field(cycle, qualified_name.encode("utf-8"))
        return cycle.hexdigest()
    active_classes.add(class_key)
    declared = _declared_code_objects(
        module_name=module_name,
        qualified_name=qualified_name,
        source_path=source_path,
        budget=budget,
    )
    runtime_only_class = (
        len(declared) == 0
        and budget.allow_unbound_source_objects
        and isinstance(module, ModuleType)
        and _static_import_target(module, qualified_name) is implementation
    )
    if len(declared) != 1 and not runtime_only_class:
        raise PluginExecutableIdentityError(
            "module target class declaration is missing or ambiguous"
        )
    digest = hashlib.sha256()
    digest.update(_CALLABLE_CODE_FINGERPRINT_SCHEMA)
    _update_exact_object_token(digest, implementation, budget=budget)
    _digest_field(digest, b"class")
    _digest_field(digest, module_name.encode("utf-8"))
    _digest_field(digest, qualified_name.encode("utf-8"))
    if runtime_only_class:
        _digest_field(digest, b"runtime-only-static-class")
    else:
        _update_code_object(digest, declared[0], budget=budget, depth=0)
    members = _bounded_class_members(
        implementation,
        budget=budget,
        depth=depth + 1,
        label="module target class",
    )
    try:
        metaclass = type(implementation)
        _update_class_dependency(
            digest,
            metaclass,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
            label="metaclass",
        )
        for base in implementation.__bases__:
            _update_class_dependency(
                digest,
                base,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
                label="base",
            )
        generated_abc_members = _update_abc_class_contract(
            digest,
            implementation,
            budget=budget,
            scope_cache=scope_cache,
            depth=depth + 1,
        )
        generated_enum_members = _update_enum_class_contract(
            digest,
            implementation,
            budget=budget,
            depth=depth + 1,
        )
        generated_dataclass_methods = _update_dataclass_class_contract(
            digest,
            implementation,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
        for name, value in members:
            if name in generated_abc_members or name in generated_enum_members:
                continue
            if name not in {
                "__annotations__",
                "__classcell__",
                "__dataclass_fields__",
                "__dataclass_params__",
                "__dict__",
                "__doc__",
                "__module__",
                "__qualname__",
                "__slots__",
                "__weakref__",
            } and _is_executable_authority(value):
                _update_exact_object_token(digest, value, budget=budget)
            functions: tuple[tuple[str, FunctionType], ...]
            if type(value) is FunctionType:
                functions = (("method", value),)
            elif isinstance(value, staticmethod):
                functions = (("static-method", value.__func__),)
            elif isinstance(value, classmethod):
                functions = (("class-method", value.__func__),)
            elif isinstance(value, property):
                functions = tuple(
                    (label, function)
                    for label, function in (
                        ("property-get", value.fget),
                        ("property-set", value.fset),
                        ("property-delete", value.fdel),
                    )
                    if function is not None
                )
            else:
                functions = ()
            if functions:
                _digest_field(digest, b"class-member")
                _digest_field(digest, name.encode("utf-8"))
                for label, function in functions:
                    if type(function) is not FunctionType:
                        _digest_field(digest, label.encode("ascii"))
                        _update_global_reference(
                            digest,
                            function,
                            budget=budget,
                            scope_cache=scope_cache,
                            callable_cache=callable_cache,
                            active_callables=active_callables,
                            identity_root=identity_root,
                            depth=depth + 1,
                        )
                        continue
                    if name in generated_dataclass_methods:
                        _digest_field(digest, label.encode("ascii"))
                        _update_dataclass_generated_method(
                            digest,
                            function,
                            owner=implementation,
                            name=name,
                            budget=budget,
                            scope_cache=scope_cache,
                            callable_cache=callable_cache,
                            active_callables=active_callables,
                            identity_root=identity_root,
                            depth=depth + 1,
                        )
                        continue
                    function_module = getattr(function, "__module__", None)
                    function_name = getattr(function, "__qualname__", None)
                    function_source = _object_source_path(function, budget=budget)
                    if (
                        function_module != module_name
                        or type(function_name) is not str
                        or (
                            function_source != source_path
                            and not (
                                runtime_only_class
                                and function.__code__.co_filename.startswith(
                                    "<frozen "
                                )
                            )
                        )
                    ):
                        raise PluginExecutableIdentityError(
                            "module target class contains an unverifiable callable"
                        )
                    _digest_field(digest, label.encode("ascii"))
                    _digest_field(
                        digest,
                        _function_runtime_identity(
                            function,
                            module=module,
                            module_name=module_name,
                            qualified_name=function_name,
                            source_path=source_path,
                            budget=budget,
                            scope_cache=scope_cache,
                            callable_cache=callable_cache,
                            active_callables=active_callables,
                            closure_owner=implementation,
                            identity_root=identity_root,
                            depth=depth + 1,
                        ).encode("ascii"),
                    )
            elif _descriptor_accessor_snapshot(value) is not None:
                _digest_field(digest, b"class-owned-static-descriptor")
                _digest_field(digest, name.encode("utf-8"))
                _update_static_attribute_value(
                    digest,
                    value,
                    descriptor_owner=implementation,
                    descriptor_name=name,
                    resolved_descriptor=value,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
            elif (
                inspect.isclass(value)
                and getattr(value, "__module__", None) == module_name
                and getattr(value, "__qualname__", "").startswith(
                    f"{qualified_name}."
                )
            ):
                nested_source = _object_source_path(value, budget=budget)
                if nested_source is None or nested_source != source_path:
                    raise PluginExecutableIdentityError(
                        "module target class contains an unverifiable nested class"
                    )
                _digest_field(digest, b"nested-class")
                _digest_field(digest, name.encode("utf-8"))
                _digest_field(
                    digest,
                    _class_runtime_identity(
                        value,
                        module_name=module_name,
                        qualified_name=value.__qualname__,
                        source_path=source_path,
                        budget=budget,
                        scope_cache=scope_cache,
                        callable_cache=callable_cache,
                        active_callables=active_callables,
                        class_cache=class_cache,
                        active_classes=active_classes,
                        identity_root=identity_root,
                        depth=depth + 1,
                    ).encode("ascii"),
                )
            elif name in {
                "__annotations__",
                "__classcell__",
                "__dataclass_fields__",
                "__dataclass_params__",
                "__dict__",
                "__doc__",
                "__module__",
                "__qualname__",
                "__slots__",
                "__weakref__",
            } or inspect.ismemberdescriptor(value) or inspect.isgetsetdescriptor(
                value
            ):
                continue
            else:
                _digest_field(digest, b"class-state-member")
                _digest_field(digest, name.encode("utf-8"))
                _update_global_reference(
                    digest,
                    value,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
        _verify_class_member_snapshot(
            implementation,
            members,
            label="module target class",
        )
        result = digest.hexdigest()
        budget.class_snapshots[class_key] = (implementation, members)
        class_cache[class_key] = result
        return result
    finally:
        active_classes.discard(class_key)


def _update_abc_class_contract(
    digest: Any,
    implementation: type[Any],
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    depth: int,
) -> frozenset[str]:
    if not isinstance(implementation, abc.ABCMeta):
        return frozenset()
    abc_state = vars(implementation).get("_abc_impl")
    if abc_state is None:
        return frozenset()
    try:
        before = abc._get_dump(implementation)
    except (AttributeError, TypeError) as error:
        raise PluginExecutableIdentityError(
            "module target abstract class registry is unverifiable"
        ) from error
    _consume_target_budget(budget, depth=depth)
    registered = _snapshot_abc_registry(before[0])
    _consume_target_nodes(
        budget,
        count=len(registered),
        depth=depth + 1,
    )
    _digest_field(digest, b"abstract-class-registry")
    coordinates: list[tuple[str, str, str, bytes]] = []
    for _reference, selected in registered:
        selected_module = getattr(selected, "__module__", None)
        selected_name = getattr(selected, "__qualname__", None)
        if type(selected_module) is not str or type(selected_name) is not str:
            raise PluginExecutableIdentityError(
                "module target abstract class registry member is unverifiable"
            )
        selected_module_value = sys.modules.get(selected_module)
        selected_source = (
            _module_file_source_path(selected_module_value, budget=budget)
            if isinstance(selected_module_value, ModuleType)
            else None
        )
        generation_digest = hashlib.sha256()
        _update_exact_object_token(
            generation_digest,
            selected,
            budget=budget,
        )
        generation_identity = generation_digest.digest()
        if (
            selected in _CANONICAL_HIDDEN_BUILTIN_TYPES
            and selected_module == "builtins"
            and selected_source is None
        ):
            coordinates.append(
                ("builtins", selected_name, "native", generation_identity)
            )
            continue
        if selected_source is None:
            raise PluginExecutableIdentityError(
                "module target abstract class registry member is unverifiable"
            )
        if (
            not budget.bind_exact_object_tokens
            and (
                not isinstance(selected_module_value, ModuleType)
                or _static_import_target(selected_module_value, selected_name)
                is not selected
            )
        ):
            raise PluginExecutableIdentityError(
                "module target abstract class registry member has no exact "
                "static provenance"
            )
        coordinates.append(
            (
                selected_module,
                selected_name,
                _cached_scope_identity(
                    selected_module,
                    selected_source,
                    scope_cache,
                ),
                generation_identity,
            )
        )
    for (
        selected_module,
        selected_name,
        selected_scope,
        generation_identity,
    ) in sorted(coordinates):
        _digest_field(digest, selected_module.encode("utf-8"))
        _digest_field(digest, selected_name.encode("utf-8"))
        _digest_field(digest, selected_scope.encode("ascii"))
        if budget.bind_exact_object_tokens:
            _digest_field(digest, generation_identity)
    try:
        after = abc._get_dump(implementation)
    except (AttributeError, TypeError) as error:
        raise PluginExecutableIdentityError(
            "module target abstract class registry changed while fingerprinting"
        ) from error
    # Positive/negative caches and the process-global invalidation counter are
    # derived acceleration state.  Retain each exact referent and weak-reference
    # generation instead: equality on either object can be controlled by a
    # registered class's metaclass and cannot attest registry continuity.
    if not _abc_registry_matches_snapshot(registered, after[0]):
        raise PluginExecutableIdentityError(
            "module target abstract class registry changed while fingerprinting"
        )
    return frozenset({"_abc_impl"})


def _snapshot_abc_registry(
    registry: Any,
) -> tuple[tuple[Any, type[Any]], ...]:
    """Retain exact live ABC registrations without invoking referent equality."""

    try:
        references = tuple(registry)
    except (RuntimeError, TypeError) as error:
        raise PluginExecutableIdentityError(
            "module target abstract class registry changed while fingerprinting"
        ) from error
    snapshot: list[tuple[Any, type[Any]]] = []
    for reference in references:
        try:
            selected = reference()
        except TypeError as error:
            raise PluginExecutableIdentityError(
                "module target abstract class registry changed while fingerprinting"
            ) from error
        if not inspect.isclass(selected):
            raise PluginExecutableIdentityError(
                "module target abstract class registry changed while fingerprinting"
            )
        snapshot.append((reference, selected))
    return tuple(snapshot)


def _abc_registry_matches_snapshot(
    expected: tuple[tuple[Any, type[Any]], ...],
    registry: Any,
) -> bool:
    """Compare exact referents and registration generations, never equality."""

    current = _snapshot_abc_registry(registry)
    if len(current) != len(expected):
        return False
    current_by_referent = {
        builtins.id(referent): (reference, referent)
        for reference, referent in current
    }
    if len(current_by_referent) != len(current):
        return False
    for expected_reference, expected_referent in expected:
        selected = current_by_referent.get(builtins.id(expected_referent))
        if (
            selected is None
            or selected[0] is not expected_reference
            or selected[1] is not expected_referent
        ):
            return False
    return True


def _update_enum_class_contract(
    digest: Any,
    implementation: type[Any],
    *,
    budget: _TargetIdentityBudget,
    depth: int,
) -> frozenset[str]:
    """Model EnumMeta-generated state without trusting mutable cache layouts."""

    try:
        is_enum = issubclass(implementation, Enum)
    except TypeError:
        is_enum = False
    if not is_enum:
        return frozenset()
    members = implementation.__members__
    if type(members) is not MappingProxyType:
        raise PluginExecutableIdentityError(
            "module target enumeration member view is noncanonical"
        )
    declared_member_names = vars(implementation).get("_member_names_")
    declared_member_map = vars(implementation).get("_member_map_")
    if (
        type(declared_member_names) is not list
        or type(declared_member_map) is not dict
        or tuple(declared_member_map) != tuple(members)
        or any(declared_member_map[name] is not members[name] for name in members)
        or any(
            type(name) is not str
            or name not in members
            or members[name].name != name
            for name in declared_member_names
        )
    ):
        raise PluginExecutableIdentityError(
            "module target enumeration caches do not match its members"
        )
    _consume_target_budget(budget, depth=depth)
    _digest_field(digest, b"enumeration-contract")
    for name, member in members.items():
        if (
            type(name) is not str
            or type(member.name) is not str
        ):
            raise PluginExecutableIdentityError(
                "module target enumeration member is noncanonical"
            )
        _digest_field(digest, name.encode("utf-8"))
        _digest_field(digest, member.name.encode("utf-8"))
        _update_stable_value(
            digest,
            member.value,
            budget=budget,
            depth=depth + 1,
        )
    managed = {
        "_generate_next_value_",
        "_new_member_",
        "_use_args_",
        "_member_names_",
        "_member_map_",
        "_value2member_map_",
        "_hashable_values_",
        "_unhashable_values_",
        "_unhashable_values_map_",
        "_member_type_",
        "_value_repr_",
        "__new__",
        *members,
    }
    for name, value in vars(implementation).items():
        if name in managed:
            continue
        for base in implementation.__mro__[1:]:
            inherited = vars(base).get(name, _ENUM_MISSING)
            if inherited is value:
                managed.add(name)
                _digest_field(digest, b"enumeration-inherited-member")
                _digest_field(digest, name.encode("utf-8"))
                _digest_field(digest, base.__module__.encode("utf-8"))
                _digest_field(digest, base.__qualname__.encode("utf-8"))
                break
    return frozenset(managed)


_ENUM_MISSING = object()


def _update_dataclass_class_contract(
    digest: Any,
    implementation: type[Any],
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> frozenset[str]:
    """Model generated dataclass behavior from its closed declaration state."""

    parameters = vars(implementation).get("__dataclass_params__")
    declared_fields = vars(implementation).get("__dataclass_fields__")
    if parameters is None or declared_fields is None:
        return frozenset()
    if type(declared_fields) is not dict:
        raise PluginExecutableIdentityError(
            "module target dataclass fields are noncanonical"
        )
    _consume_target_budget(budget, depth=depth)
    _digest_field(digest, b"dataclass-contract")
    parameter_names = (
        "init",
        "repr",
        "eq",
        "order",
        "unsafe_hash",
        "frozen",
        "match_args",
        "kw_only",
        "slots",
        "weakref_slot",
    )
    parameter_values: dict[str, bool] = {}
    for name in parameter_names:
        value = getattr(parameters, name, False)
        if type(value) is not bool:
            raise PluginExecutableIdentityError(
                "module target dataclass parameters are noncanonical"
            )
        parameter_values[name] = value
        _digest_field(digest, name.encode("ascii"))
        _digest_field(digest, b"1" if value else b"0")
    # Reserve a shared node for every reflection-visible Field before walking
    # or sorting the mutable declaration dictionary.  A valid dataclass can
    # contain many ClassVar/InitVar entries that ``dataclasses.fields`` hides,
    # so the public filtered view is not a safe bound for this work.
    _consume_target_nodes(
        budget,
        count=len(declared_fields),
        depth=depth + 1,
    )
    try:
        declared_snapshot = tuple(declared_fields.items())
    except RuntimeError as error:
        raise PluginExecutableIdentityError(
            "module target dataclass fields changed while fingerprinting"
        ) from error
    bounded_fields: list[tuple[str, bytes, _dataclasses.Field[Any], bytes]] = []
    for name, item in declared_snapshot:
        if type(name) is not str:
            raise PluginExecutableIdentityError(
                "module target dataclass fields are noncanonical"
            )
        if not isinstance(item, _dataclasses.Field) or item.name != name:
            raise PluginExecutableIdentityError(
                "module target dataclass field declaration is unverifiable"
            )
        if len(name) > _MAX_TARGET_VALUE_BYTES:
            raise PluginExecutableIdentityError(
                "module target exceeds the recursive runtime-byte limit"
            )
        encoded_name = name.encode("utf-8")
        _consume_target_bytes(budget, len(encoded_name))
        metadata_digest = hashlib.sha256()
        _update_dataclass_field_metadata(
            metadata_digest,
            item.metadata,
            budget=budget,
            depth=depth + 2,
        )
        bounded_fields.append(
            (name, encoded_name, item, metadata_digest.digest())
        )
    _verify_dict_snapshot(declared_fields, declared_snapshot)
    for name, encoded_name, item, metadata_identity in sorted(
        bounded_fields,
        key=lambda selected: selected[0],
    ):
        _digest_field(digest, b"dataclass-field")
        _digest_field(digest, encoded_name)
        _digest_field(digest, metadata_identity)
        for option_name in ("init", "repr", "compare", "kw_only"):
            option = getattr(item, option_name, False)
            if type(option) is not bool:
                raise PluginExecutableIdentityError(
                    "module target dataclass field options are noncanonical"
                )
            _digest_field(digest, option_name.encode("ascii"))
            _digest_field(digest, b"1" if option else b"0")
        hash_option = item.hash
        if hash_option is not None and type(hash_option) is not bool:
            raise PluginExecutableIdentityError(
                "module target dataclass field hash option is noncanonical"
            )
        _digest_field(
            digest,
            b"hash:none"
            if hash_option is None
            else (b"hash:1" if hash_option else b"hash:0"),
        )
        for label, value in (
            ("default", item.default),
            ("default-factory", item.default_factory),
        ):
            _digest_field(digest, label.encode("ascii"))
            if value is _dataclasses.MISSING:
                _digest_field(digest, b"missing")
            else:
                _update_global_reference(
                    digest,
                    value,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
    generated: set[str] = set()
    if parameter_values["init"]:
        generated.add("__init__")
    if parameter_values["repr"]:
        generated.add("__repr__")
    if parameter_values["eq"]:
        generated.add("__eq__")
    if parameter_values["order"]:
        generated.update({"__lt__", "__le__", "__gt__", "__ge__"})
    if parameter_values["unsafe_hash"] or (
        parameter_values["eq"] and parameter_values["frozen"]
    ):
        generated.add("__hash__")
    if parameter_values["frozen"]:
        generated.update({"__setattr__", "__delattr__"})
    if parameter_values["slots"]:
        generated.update({"__getstate__", "__setstate__"})
    return frozenset(
        name
        for name in generated
        if type(vars(implementation).get(name)) is FunctionType
    )


def _update_dataclass_field_metadata(
    digest: Any,
    metadata: object,
    *,
    budget: _TargetIdentityBudget,
    depth: int,
) -> None:
    """Digest one immutable Field.metadata view with bounded canonical values."""

    _consume_target_budget(budget, depth=depth)
    if type(metadata) is not MappingProxyType:
        raise PluginExecutableIdentityError(
            "module target dataclass field metadata is noncanonical"
        )
    _consume_target_nodes(
        budget,
        count=len(metadata),
        depth=depth + 1,
    )
    try:
        snapshot = tuple(metadata.items())
    except RuntimeError as error:
        raise PluginExecutableIdentityError(
            "module target dataclass field metadata changed while fingerprinting"
        ) from error
    _digest_field(digest, b"dataclass-field-metadata")
    _digest_field(digest, len(snapshot).to_bytes(8, "big", signed=False))
    encoded_items: list[tuple[bytes, bytes]] = []
    for key, value in snapshot:
        key_digest = hashlib.sha256()
        _update_stable_value(
            key_digest,
            key,
            budget=budget,
            depth=depth + 1,
        )
        value_digest = hashlib.sha256()
        _update_stable_value(
            value_digest,
            value,
            budget=budget,
            depth=depth + 1,
        )
        encoded_items.append((key_digest.digest(), value_digest.digest()))
    for key_identity, value_identity in sorted(encoded_items):
        _digest_field(digest, key_identity)
        _digest_field(digest, value_identity)
    try:
        current = tuple(metadata.items())
    except RuntimeError as error:
        raise PluginExecutableIdentityError(
            "module target dataclass field metadata changed while fingerprinting"
        ) from error
    if len(current) != len(snapshot) or any(
        current_key is not selected_key or current_value is not selected_value
        for (current_key, current_value), (selected_key, selected_value) in zip(
            current,
            snapshot,
            strict=True,
        )
    ):
        raise PluginExecutableIdentityError(
            "module target dataclass field metadata changed while fingerprinting"
        )


def _update_dataclass_generated_method(
    digest: Any,
    function: FunctionType,
    *,
    owner: type[Any],
    name: str,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    _consume_target_budget(budget, depth=depth)
    if name == "__getstate__":
        if function is not _dataclasses._dataclass_getstate:
            raise PluginExecutableIdentityError(
                "module target dataclass generated method was replaced"
            )
        _digest_field(digest, b"dataclasses:_dataclass_getstate")
        return
    if name == "__setstate__":
        if function is not _dataclasses._dataclass_setstate:
            raise PluginExecutableIdentityError(
                "module target dataclass generated method was replaced"
            )
        _digest_field(digest, b"dataclasses:_dataclass_setstate")
        return
    code = function.__code__
    if name == "__repr__":
        valid_shape = (
            code.co_name == "wrapper"
            and code.co_qualname == "_recursive_repr.<locals>.wrapper"
            and code.co_freevars == ("repr_running", "user_function")
        )
    else:
        valid_shape = (
            code.co_filename == "<string>"
            and code.co_name == name
            and code.co_qualname == f"__create_fn__.<locals>.{name}"
        )
    if (
        not valid_shape
        or function.__module__ != owner.__module__
        or function.__qualname__ != f"{owner.__qualname__}.{name}"
    ):
        raise PluginExecutableIdentityError(
            "module target dataclass generated method was replaced"
        )
    _digest_field(digest, b"dataclass-generated-method")
    _digest_field(digest, name.encode("ascii"))
    _update_code_object(digest, code, budget=budget, depth=depth + 1)
    _update_runtime_defaults(
        digest,
        function.__defaults__,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth + 1,
        label="generated positional defaults",
    )
    _update_runtime_mapping(
        digest,
        function.__kwdefaults__,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth + 1,
        label="generated keyword defaults",
    )
    closure = function.__closure__ or ()
    repr_user_function: FunctionType | None = None
    if len(closure) != len(code.co_freevars):
        raise PluginExecutableIdentityError(
            "module target dataclass generated closure is unverifiable"
        )
    for closure_name, cell in zip(code.co_freevars, closure, strict=True):
        try:
            value = cell.cell_contents
        except ValueError as error:
            raise PluginExecutableIdentityError(
                "module target dataclass generated closure is empty"
            ) from error
        _digest_field(digest, closure_name.encode("utf-8"))
        if value is owner:
            _digest_field(digest, b"owner-class")
        elif (
            closure_name == "cls"
            and name in {"__setattr__", "__delattr__"}
            and inspect.isclass(value)
            and value.__module__ == owner.__module__
            and value.__qualname__ == owner.__qualname__
            and "__slots__" in vars(owner)
            and vars(value).get("__dataclass_fields__")
            is vars(owner).get("__dataclass_fields__")
            and vars(value).get("__dataclass_params__")
            is vars(owner).get("__dataclass_params__")
        ):
            # ``dataclass(slots=True, frozen=True)`` replaces the declared
            # class after generating these methods, whose ``cls`` cell keeps
            # the pre-slot class.  The shared dataclass model plus exact
            # module/qualname makes that replacement structural and bounded.
            _digest_field(digest, b"pre-slot-owner-class")
        elif value is object:
            _digest_field(digest, b"builtins:object")
        elif value is _dataclasses.FrozenInstanceError:
            _digest_field(digest, b"dataclasses:FrozenInstanceError")
        elif closure_name == "repr_running":
            if type(value) is not set or value:
                raise PluginExecutableIdentityError(
                    "module target dataclass repr state is not idle"
                )
            _digest_field(digest, b"empty-repr-state")
        elif closure_name == "user_function" and type(value) is FunctionType:
            user_code = value.__code__
            if (
                user_code.co_filename != "<string>"
                or user_code.co_name != "__repr__"
                or user_code.co_qualname != "__create_fn__.<locals>.__repr__"
            ):
                raise PluginExecutableIdentityError(
                    "module target dataclass repr function was replaced"
                )
            repr_user_function = value
            _update_code_object(
                digest,
                user_code,
                budget=budget,
                depth=depth + 1,
            )
        else:
            _update_global_reference(
                digest,
                value,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
    if name == "__repr__":
        if function.__dict__ != {"__wrapped__": repr_user_function}:
            raise PluginExecutableIdentityError(
                "module target dataclass repr wrapper state was replaced"
            )
        _digest_field(digest, b"dataclass-repr-wrapper-state")
    else:
        _update_runtime_mapping(
            digest,
            function.__dict__,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
            label="generated function state",
        )


def _update_class_dependency(
    digest: Any,
    implementation: type[Any],
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
    label: str,
) -> None:
    _digest_field(digest, label.encode("ascii"))
    if implementation is type(Enum):
        _update_enum_metaclass_dependency(
            digest,
            implementation,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth,
        )
        return
    _update_global_reference(
        digest,
        implementation,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth,
    )


def _update_enum_metaclass_dependency(
    digest: Any,
    implementation: type[Any],
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    """Bind Enum's generated metaclass without walking conversion utilities."""

    _consume_target_budget(budget, depth=depth)
    _update_exact_object_token(digest, implementation, budget=budget)
    module_name = implementation.__module__
    qualified_name = implementation.__qualname__
    module = sys.modules.get(module_name)
    source_path = _object_source_path(implementation, budget=budget)
    module_source = (
        _module_file_source_path(module, budget=budget)
        if isinstance(module, ModuleType)
        else None
    )
    if (
        not isinstance(module, ModuleType)
        or _static_import_target(module, qualified_name) is not implementation
        or source_path is None
        or module_source is None
        or source_path != module_source
    ):
        raise PluginExecutableIdentityError(
            "module target enumeration metaclass dependency is unverifiable"
        )
    _digest_field(digest, b"canonical-enumeration-metaclass")
    _digest_field(digest, module_name.encode("utf-8"))
    _digest_field(digest, qualified_name.encode("utf-8"))
    _digest_field(
        digest,
        _cached_scope_identity(
            module_name,
            module_source,
            scope_cache,
        ).encode("ascii"),
    )
    members = _bounded_class_members(
        implementation,
        budget=budget,
        depth=depth + 1,
        label="module target enumeration metaclass",
    )
    for name, value in members:
        if _is_executable_authority(value):
            _update_exact_object_token(digest, value, budget=budget)
        _digest_field(digest, name.encode("utf-8"))
        if name == "__call__" and type(value) is FunctionType:
            _update_external_class_member_function(
                digest,
                value,
                label="enumeration-metaclass-call",
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
        elif type(value) is FunctionType:
            _update_code_object(
                digest,
                value.__code__,
                budget=budget,
                depth=depth + 1,
            )
        elif isinstance(value, (classmethod, staticmethod)) and type(
            value.__func__
        ) is FunctionType:
            _update_code_object(
                digest,
                value.__func__.__code__,
                budget=budget,
                depth=depth + 1,
            )
        else:
            value_type = type(value)
            _digest_field(digest, value_type.__module__.encode("utf-8"))
            _digest_field(digest, value_type.__qualname__.encode("utf-8"))
    _verify_class_member_snapshot(
        implementation,
        members,
        label="module target enumeration metaclass",
    )


def _declared_runtime_code_identity(
    runtime_code: CodeType,
    *,
    module_name: str,
    qualified_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
    allow_frozen_module: bool = False,
) -> str:
    runtime_codes = _walk_code_objects(runtime_code)
    frozen_runtime = (
        budget.allow_unbound_source_objects or allow_frozen_module
    ) and all(code.co_filename.startswith("<frozen ") for code in runtime_codes)
    for code in runtime_codes:
        code_source = _resolved_source_path((code.co_filename,))
        if not frozen_runtime and (code_source is None or code_source != source_path):
            raise PluginExecutableIdentityError(
                "module target contains code without exact source provenance"
            )
    runtime_digest = hashlib.sha256()
    _update_code_object(runtime_digest, runtime_code, budget=budget, depth=0)
    identity = runtime_digest.hexdigest()
    if frozen_runtime:
        return identity
    declared = _declared_code_objects(
        module_name=module_name,
        qualified_name=qualified_name,
        source_path=source_path,
        budget=budget,
    )
    matching = 0
    for code in declared:
        candidate_digest = hashlib.sha256()
        _update_code_object(
            candidate_digest,
            code,
            budget=_TargetIdentityBudget(),
            depth=0,
        )
        if candidate_digest.hexdigest() == identity:
            matching += 1
    if matching != 1:
        raise PluginExecutableIdentityError(
            "module target function is runtime-created, changed, or ambiguous"
        )
    return identity


def _declared_code_objects(
    *,
    module_name: str,
    qualified_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
) -> tuple[CodeType, ...]:
    local_cache_key = (module_name, source_path)
    local_cached = budget.declared_code_cache.get(local_cache_key)
    if local_cached is not None:
        return tuple(
            code
            for code in local_cached.code_objects
            if code.co_qualname == qualified_name
        )
    source, source_stat_identity = _read_regular_source_snapshot(source_path)
    source_identity = _source_module_identity_from_bytes(module_name, source)
    batch_cache_key = (module_name, source_path, source_identity)
    batch_cache = budget.batch_declared_code_cache
    code_objects: tuple[CodeType, ...] | None = (
        batch_cache.get(batch_cache_key)
        if batch_cache is not None
        else None
    )
    if code_objects is None:
        try:
            module_code = compile(
                source,
                f"<{module_name}>",
                "exec",
                dont_inherit=True,
                optimize=sys.flags.optimize,
            )
        except (MemoryError, OverflowError, SyntaxError, ValueError) as error:
            raise PluginExecutableIdentityError(
                "module target source cannot be compiled deterministically"
            ) from error
        code_objects = _walk_code_objects(module_code)
        if batch_cache is not None:
            batch_cache[batch_cache_key] = code_objects
    budget.declared_code_cache[local_cache_key] = _DeclaredCodeCacheEntry(
        source_identity=source_identity,
        source_stat_identity=source_stat_identity,
        code_objects=code_objects,
    )
    return tuple(
        code
        for code in code_objects
        if code.co_qualname == qualified_name
    )


def _walk_code_objects(root: CodeType) -> tuple[CodeType, ...]:
    result: list[CodeType] = []
    pending = [root]
    while pending:
        code = pending.pop()
        result.append(code)
        if len(result) > _MAX_TARGET_CODE_OBJECTS:
            raise PluginExecutableIdentityError(
                "module target exceeds the recursive code-object limit"
            )
        pending.extend(
            value for value in code.co_consts if type(value) is CodeType
        )
    return tuple(result)


def _loaded_global_dependencies(
    root: CodeType,
) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...], bool]:
    """Collect one code graph's global names and attribute paths in one pass."""

    names: set[str] = set()
    paths: set[tuple[str, ...]] = set()
    has_runtime_imports = False
    for code in _walk_code_objects(root):
        try:
            instructions = tuple(dis.get_instructions(code))
            for index, instruction in enumerate(instructions):
                if instruction.opname in {"IMPORT_NAME", "IMPORT_FROM"}:
                    has_runtime_imports = True
                if instruction.opname == "LOAD_GLOBAL" and type(instruction.argval) is str:
                    names.add(instruction.argval)
                if instruction.opname not in {"LOAD_GLOBAL", "LOAD_NAME"}:
                    continue
                if type(instruction.argval) is not str:
                    continue
                path = [instruction.argval]
                candidate_index = index + 1
                while candidate_index < len(instructions):
                    candidate = instructions[candidate_index]
                    if candidate.opname not in {"LOAD_ATTR", "LOAD_METHOD"}:
                        break
                    if type(candidate.argval) is not str:
                        break
                    path.append(candidate.argval)
                    candidate_index += 1
                if len(path) > 1:
                    paths.add(tuple(path))
        except (IndexError, TypeError, ValueError) as error:
            raise PluginExecutableIdentityError(
                "module target bytecode cannot be inspected safely"
            ) from error
    return tuple(sorted(names)), tuple(sorted(paths)), has_runtime_imports


def _function_dependency_analysis(
    function: FunctionType,
    *,
    budget: _TargetIdentityBudget,
    depth: int,
) -> _FunctionDependencyAnalysis:
    """Analyze one function's immutable code graph once per attestation."""

    function_key = builtins.id(function)
    cached = budget.function_dependency_analyses.get(function_key)
    if cached is not None:
        if cached.function is not function:
            raise PluginExecutableIdentityError(
                "module target function dependency cache is inconsistent"
            )
        if function.__code__ is not cached.code:
            raise PluginExecutableIdentityError(
                "module target function code changed while fingerprinting"
            )
        return cached
    if len(budget.function_dependency_analyses) >= _MAX_TARGET_CODE_OBJECTS:
        raise PluginExecutableIdentityError(
            "module target exceeds the function dependency-analysis limit"
        )
    code = function.__code__
    (
        global_names,
        global_attribute_paths,
        has_runtime_imports,
    ) = _loaded_global_dependencies(code)
    retained_references = (
        1
        + len(global_names)
        + sum(len(path) for path in global_attribute_paths)
    )
    _consume_target_nodes(
        budget,
        count=retained_references,
        depth=depth,
    )
    if function.__code__ is not code:
        raise PluginExecutableIdentityError(
            "module target function code changed while fingerprinting"
        )
    analysis = _FunctionDependencyAnalysis(
        function,
        code,
        global_names,
        global_attribute_paths,
        has_runtime_imports,
    )
    budget.function_dependency_analyses[function_key] = analysis
    return analysis


def _update_runtime_import_references(
    digest: Any,
    function: FunctionType,
    *,
    module: ModuleType,
    module_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    """Bind local import bytecode to exact, already-loaded runtime objects.

    Executing an import merely to fingerprint it would move arbitrary module
    side effects ahead of the callback.  We instead recover ordinary import
    bindings from the exact source declaration, require every dependency to
    already have canonical ``sys.modules`` provenance, and attest only the
    statically selected attributes the callback reads.  Rebinding, mutation,
    wildcard imports, bare module escape, and dynamic import APIs fail closed.
    """

    dependencies = _function_dependency_analysis(
        function,
        budget=budget,
        depth=depth,
    )
    if not dependencies.has_runtime_imports:
        return
    target = _declared_function_ast(
        module_name=module_name,
        qualified_name=function.__code__.co_qualname,
        source_path=source_path,
        budget=budget,
    )
    bounded_nodes: list[ast.AST] = []
    for node in ast.walk(target):
        _consume_target_budget(budget, depth=depth)
        bounded_nodes.append(node)
    nodes = tuple(bounded_nodes)
    parents: dict[ast.AST, ast.AST] = {
        child: parent
        for parent in nodes
        for child in ast.iter_child_nodes(parent)
    }
    bindings: dict[str, _RuntimeImportBinding] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _valid_dotted_import_name(alias.name):
                    raise PluginExecutableIdentityError(
                        "module target contains an invalid local import"
                    )
                bound_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                selected_module = alias.name if alias.asname else bound_name
                _record_runtime_import_binding(
                    bindings,
                    bound_name,
                    _RuntimeImportBinding(selected_module, ()),
                )
        elif isinstance(node, ast.ImportFrom):
            imported_module = _resolve_relative_import_name(
                module,
                module_name=module_name,
                requested=node.module or "",
                level=node.level,
            )
            for alias in node.names:
                if alias.name == "*":
                    raise PluginExecutableIdentityError(
                        "module target contains an unverifiable wildcard import"
                    )
                if not alias.name.isidentifier():
                    raise PluginExecutableIdentityError(
                        "module target contains an invalid imported attribute"
                    )
                bound_name = alias.asname or alias.name
                _record_runtime_import_binding(
                    bindings,
                    bound_name,
                    _RuntimeImportBinding(imported_module, (alias.name,)),
                )
    if not bindings:
        raise PluginExecutableIdentityError(
            "module target import bytecode has no exact source binding"
        )
    _reject_dynamic_import_calls(nodes, bindings)
    bound_names = frozenset(bindings)
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id in bound_names:
                raise PluginExecutableIdentityError(
                    "module target rebinds a local import"
                )
        elif isinstance(node, ast.arg) and node.arg in bound_names:
            raise PluginExecutableIdentityError(
                "module target shadows a local import with an argument"
            )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node is not target and node.name in bound_names:
                raise PluginExecutableIdentityError(
                    "module target shadows a local import with a declaration"
                )
        elif isinstance(node, ast.ExceptHandler):
            if node.name in bound_names:
                raise PluginExecutableIdentityError(
                    "module target shadows a local import in an exception handler"
                )
        elif isinstance(node, (ast.Global, ast.Nonlocal)) and any(
            name in bound_names for name in node.names
        ):
            raise PluginExecutableIdentityError(
                "module target gives a local import dynamic scope"
            )
    usage_paths: dict[str, set[tuple[str, ...]]] = {
        name: set() for name in bindings
    }
    for node in nodes:
        if not (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in bindings
        ):
            continue
        selected: ast.AST = node
        path: list[str] = []
        parent = parents.get(selected)
        while isinstance(parent, ast.Attribute) and parent.value is selected:
            path.append(parent.attr)
            selected = parent
            parent = parents.get(selected)
        selected_context = getattr(selected, "ctx", ast.Load())
        if isinstance(selected_context, (ast.Store, ast.Del)):
            raise PluginExecutableIdentityError(
                "module target mutates a locally imported dependency"
            )
        usage_paths[node.id].add(tuple(path))
    for bound_name in sorted(bindings):
        binding = bindings[bound_name]
        paths = usage_paths[bound_name]
        if not paths:
            raise PluginExecutableIdentityError(
                "module target has a side-effect-only local import"
            )
        imported_module = sys.modules.get(binding.module_name)
        if not isinstance(imported_module, ModuleType):
            unavailable_coordinate = (
                getattr(function, "__module__", None),
                getattr(function, "__qualname__", None),
                binding.module_name,
            )
            if (
                budget.external_class_member_runtime_depth > 0
                and unavailable_coordinate in _PLATFORM_UNAVAILABLE_LOCAL_IMPORTS
            ):
                _digest_field(digest, b"platform-unavailable-runtime-import")
                _digest_field(digest, bound_name.encode("utf-8"))
                _digest_field(digest, binding.module_name.encode("utf-8"))
                for path in sorted(paths):
                    for component in binding.attribute_path + path:
                        _digest_field(digest, component.encode("utf-8"))
                continue
            raise PluginExecutableIdentityError(
                "module target local import is not already exactly loaded"
            )
        _digest_field(digest, b"runtime-import")
        _digest_field(digest, bound_name.encode("utf-8"))
        _digest_field(digest, binding.module_name.encode("utf-8"))
        _update_global_reference(
            digest,
            imported_module,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
        for path in sorted(paths):
            selected_path = binding.attribute_path + path
            if not selected_path:
                raise PluginExecutableIdentityError(
                    "module target lets a locally imported module escape"
                )
            if (
                binding.module_name == "importlib"
                and selected_path == ("import_module",)
            ):
                raise PluginExecutableIdentityError(
                    "module target uses a dynamic import API"
                )
            selected_authorities: list[object] = []
            resolution = _resolve_static_attribute_path(
                imported_module,
                selected_path,
                authorities=(
                    selected_authorities
                    if budget.bind_exact_object_tokens
                    else None
                ),
            )
            selected_value = resolution.value
            if isinstance(selected_value, ModuleType):
                raise PluginExecutableIdentityError(
                    "module target lets a locally imported module escape"
                )
            _digest_field(digest, b"runtime-import-path")
            for component in selected_path:
                _digest_field(digest, component.encode("utf-8"))
            for authority in selected_authorities:
                _digest_field(digest, b"runtime-import-authority")
                _update_exact_object_token(digest, authority, budget=budget)
            _update_static_attribute_value(
                digest,
                selected_value,
                descriptor_owner=resolution.owner,
                descriptor_name=resolution.name,
                resolved_descriptor=resolution.descriptor,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )


def _declared_function_ast(
    *,
    module_name: str,
    qualified_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    cache_key = (module_name, source_path)
    cached = budget.declared_ast_cache.get(cache_key)
    if cached is None:
        source, source_stat_identity = _read_regular_source_snapshot(source_path)
        _consume_target_bytes(budget, len(source))
        _preflight_python_source_tokens(source, budget=budget)
        try:
            tree = ast.parse(source, filename=f"<{module_name}>")
        except (MemoryError, SyntaxError, ValueError) as error:
            raise PluginExecutableIdentityError(
                "module target source cannot be parsed deterministically"
            ) from error
        for _node in ast.walk(tree):
            _consume_target_budget(budget, depth=0)
        cached = _DeclaredAstCacheEntry(
            source_identity=_source_module_identity_from_bytes(
                module_name,
                source,
            ),
            source_stat_identity=source_stat_identity,
            functions=_qualified_function_nodes(tree),
        )
        budget.declared_ast_cache[cache_key] = cached
    matches = tuple(
        node
        for candidate_name, node in cached.functions
        if candidate_name == qualified_name
    )
    if len(matches) != 1:
        raise PluginExecutableIdentityError(
            "module target function import scope is missing or ambiguous"
        )
    return matches[0]


def _preflight_python_source_tokens(
    source: bytes,
    *,
    budget: _TargetIdentityBudget,
) -> None:
    """Reject lexically oversized source before CPython builds its full AST."""

    remaining_nodes = _MAX_TARGET_VALUE_NODES - budget.value_nodes
    if remaining_nodes < 0:
        raise PluginExecutableIdentityError(
            "module target exceeds the recursive value limit"
        )
    token_count = 0
    try:
        for _token in tokenize.tokenize(io.BytesIO(source).readline):
            token_count += 1
            if token_count > remaining_nodes:
                raise PluginExecutableIdentityError(
                    "module target exceeds the recursive value limit"
                )
    except (IndentationError, SyntaxError, tokenize.TokenError) as error:
        raise PluginExecutableIdentityError(
            "module target source cannot be tokenized deterministically"
        ) from error


def _qualified_function_nodes(
    tree: ast.Module,
) -> tuple[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef], ...]:
    result: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []

    def visit_body(
        body: list[ast.stmt],
        *,
        prefix: str,
        parent_kind: str,
    ) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not prefix:
                    selected_name = node.name
                elif parent_kind == "function":
                    selected_name = f"{prefix}.<locals>.{node.name}"
                else:
                    selected_name = f"{prefix}.{node.name}"
                result.append((selected_name, node))
                visit_body(
                    node.body,
                    prefix=selected_name,
                    parent_kind="function",
                )
            elif isinstance(node, ast.ClassDef):
                if not prefix:
                    selected_name = node.name
                elif parent_kind == "function":
                    selected_name = f"{prefix}.<locals>.{node.name}"
                else:
                    selected_name = f"{prefix}.{node.name}"
                visit_body(
                    node.body,
                    prefix=selected_name,
                    parent_kind="class",
                )

    visit_body(tree.body, prefix="", parent_kind="module")
    return tuple(result)


def _valid_dotted_import_name(value: str) -> bool:
    return bool(value) and all(part.isidentifier() for part in value.split("."))


def _resolve_relative_import_name(
    module: ModuleType,
    *,
    module_name: str,
    requested: str,
    level: int,
) -> str:
    if getattr(module, "__name__", None) != module_name:
        raise PluginExecutableIdentityError(
            "module target relative import has no exact module context"
        )
    if type(level) is not int or level < 0:
        raise PluginExecutableIdentityError(
            "module target contains an invalid relative import"
        )
    if requested and not _valid_dotted_import_name(requested):
        raise PluginExecutableIdentityError(
            "module target contains an invalid local import"
        )
    if level == 0:
        if not requested:
            raise PluginExecutableIdentityError(
                "module target contains an empty absolute import"
            )
        return requested
    package = getattr(module, "__package__", None)
    if (
        type(package) is not str
        or not package
        or not _valid_dotted_import_name(package)
    ):
        raise PluginExecutableIdentityError(
            "module target relative import has no exact package context"
        )
    package_parts = package.split(".")
    retained = len(package_parts) - level + 1
    if retained <= 0:
        raise PluginExecutableIdentityError(
            "module target relative import escapes its package"
        )
    resolved_parts = package_parts[:retained]
    if requested:
        resolved_parts.extend(requested.split("."))
    resolved = ".".join(resolved_parts)
    if not _valid_dotted_import_name(resolved):
        raise PluginExecutableIdentityError(
            "module target relative import cannot be resolved exactly"
        )
    return resolved


def _record_runtime_import_binding(
    bindings: dict[str, _RuntimeImportBinding],
    name: str,
    binding: _RuntimeImportBinding,
) -> None:
    if not name.isidentifier():
        raise PluginExecutableIdentityError(
            "module target contains an invalid local import binding"
        )
    existing = bindings.get(name)
    if existing is not None and existing != binding:
        raise PluginExecutableIdentityError(
            "module target conditionally rebinds a local import"
        )
    bindings[name] = binding


def _reject_dynamic_import_calls(
    nodes: tuple[ast.AST, ...],
    bindings: dict[str, _RuntimeImportBinding],
) -> None:
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Name):
            if function.id == "__import__":
                raise PluginExecutableIdentityError(
                    "module target uses a dynamic import API"
                )
            binding = bindings.get(function.id)
            if (
                binding is not None
                and binding.module_name == "importlib"
                and binding.attribute_path == ("import_module",)
            ):
                raise PluginExecutableIdentityError(
                    "module target uses a dynamic import API"
                )
        elif (
            isinstance(function, ast.Attribute)
            and function.attr in {"__import__", "import_module"}
        ):
            root: ast.AST = function.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and (
                root.id == "builtins"
                or (
                    root.id in bindings
                    and bindings[root.id].module_name == "importlib"
                )
            ):
                raise PluginExecutableIdentityError(
                    "module target uses a dynamic import API"
                )


def _update_static_attribute_path(
    digest: Any,
    root: object,
    path: tuple[str, ...],
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    _consume_target_budget(budget, depth=depth)
    selected_authorities: list[object] = []
    resolution = _resolve_static_attribute_path(
        root,
        path,
        authorities=(
            selected_authorities if budget.bind_exact_object_tokens else None
        ),
    )
    for authority in selected_authorities:
        _digest_field(digest, b"attribute-path-authority")
        _update_exact_object_token(digest, authority, budget=budget)
    _update_static_attribute_value(
        digest,
        resolution.value,
        descriptor_owner=resolution.owner,
        descriptor_name=resolution.name,
        resolved_descriptor=resolution.descriptor,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth + 1,
    )


def _resolve_static_attribute_path(
    root: object,
    path: tuple[str, ...],
    *,
    authorities: list[object] | None = None,
) -> _StaticAttributeResolution:
    selected = root
    owner: object | None = None
    name: str | None = None
    descriptor = root
    missing = object()
    for index, component in enumerate(path):
        receiver = selected
        name = component
        if isinstance(selected, ModuleType):
            candidate = vars(selected).get(component, missing)
        elif inspect.isclass(selected):
            try:
                candidate = inspect.getattr_static(selected, component)
            except AttributeError:
                candidate = missing
        else:
            try:
                candidate = inspect.getattr_static(selected, component)
            except (AttributeError, TypeError):
                candidate = missing
        if candidate is missing:
            raise PluginExecutableIdentityError(
                "module target dereferences a dynamic global attribute"
            )
        owner = _static_attribute_owner(receiver, component, candidate)
        descriptor = candidate
        retains_receiver = index + 1 < len(path) and _is_identity_bound_receiver(
            candidate
        )
        if authorities is not None and (
            retains_receiver or _is_executable_authority(candidate)
        ):
            authorities.append(candidate)
        if isinstance(candidate, (classmethod, staticmethod)):
            candidate = candidate.__func__
        selected = candidate
    return _StaticAttributeResolution(selected, owner, name, descriptor)


def _static_attribute_owner(
    receiver: object,
    name: str,
    candidate: object,
) -> object:
    """Locate the exact namespace slot used by a static attribute lookup."""

    if isinstance(receiver, ModuleType):
        return receiver
    if not inspect.isclass(receiver):
        try:
            state = object.__getattribute__(receiver, "__dict__")
        except AttributeError:
            state = None
        missing = object()
        if type(state) is dict and state.get(name, missing) is candidate:
            return receiver
        owners = type(receiver).__mro__
    else:
        owners = (*receiver.__mro__, *type(receiver).__mro__)
    for owner in owners:
        if vars(owner).get(name) is candidate:
            return owner
    return receiver


def _declares_exact_stateless_singleton(
    *,
    module_name: str,
    attribute: str,
    implementation_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
) -> bool:
    """Recognize one literal ``name = Class()`` module declaration."""

    source = _read_regular_source_bytes(source_path)
    _consume_target_bytes(budget, len(source))
    try:
        tree = ast.parse(source, filename=f"<{module_name}>")
    except (MemoryError, SyntaxError, ValueError) as error:
        raise PluginExecutableIdentityError(
            "module target singleton source cannot be parsed deterministically"
        ) from error
    matches = 0
    for statement in tree.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            target = statement.target
            value = statement.value
        if not (
            isinstance(target, ast.Name)
            and target.id == attribute
            and isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == implementation_name
            and not value.args
            and not value.keywords
        ):
            continue
        matches += 1
    return matches == 1


def _single_closure_cell_contains(
    function: FunctionType,
    expected: object,
) -> bool:
    closure = function.__closure__
    if closure is None or len(closure) != 1:
        return False
    try:
        return closure[0].cell_contents is expected
    except ValueError:
        return False


def _update_contextmanager_function_dependency(
    digest: Any,
    function: FunctionType,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    identity_root: str,
    expand_same_root: bool,
    depth: int,
) -> bool:
    """Bind a canonical ``contextmanager`` wrapper and its declared generator."""

    wrapped = function.__dict__.get("__wrapped__")
    if type(wrapped) is not FunctionType:
        return False
    module_name = wrapped.__module__
    qualified_name = wrapped.__qualname__
    module = sys.modules.get(module_name)
    source_path = (
        _module_file_source_path(module, budget=budget)
        if isinstance(module, ModuleType)
        else None
    )
    contextlib_module = sys.modules.get("contextlib")
    contextlib_source = (
        _module_file_source_path(contextlib_module, budget=budget)
        if isinstance(contextlib_module, ModuleType)
        else None
    )
    if (
        type(module_name) is not str
        or type(qualified_name) is not str
        or not isinstance(module, ModuleType)
        or source_path is None
        or not isinstance(contextlib_module, ModuleType)
        or contextlib_source is None
        or _static_import_target(module, qualified_name) is not function
        or function.__code__.co_qualname != "contextmanager.<locals>.helper"
        or function.__code__.co_freevars != ("func",)
        or not _single_closure_cell_contains(function, wrapped)
        or function.__dict__ != {"__wrapped__": wrapped}
        or function.__globals__ is not vars(contextlib_module)
        or function.__builtins__ is not vars(builtins)
        or function.__module__ != module_name
        or function.__qualname__ != qualified_name
        or function.__annotations__ is not wrapped.__annotations__
        or wrapped.__globals__ is not vars(module)
        or wrapped.__builtins__ is not vars(builtins)
        or wrapped.__defaults__ is not None
        or wrapped.__kwdefaults__ is not None
        or wrapped.__closure__ is not None
        or wrapped.__dict__
        or getattr(wrapped, "__type_params__", ())
        or _object_source_path(wrapped, budget=budget) != source_path
    ):
        raise PluginExecutableIdentityError(
            "module target singleton contextmanager dependency is unverifiable"
        )
    _digest_field(digest, b"dependency-contextmanager")
    _digest_field(
        digest,
        _cached_scope_identity("contextlib", contextlib_source, scope_cache).encode(
            "ascii"
        ),
    )
    _digest_field(
        digest,
        _declared_runtime_code_identity(
            function.__code__,
            module_name="contextlib",
            qualified_name=function.__code__.co_qualname,
            source_path=contextlib_source,
            budget=budget,
        ).encode("ascii"),
    )
    _digest_field(
        digest,
        _declared_runtime_code_identity(
            wrapped.__code__,
            module_name=module_name,
            qualified_name=qualified_name,
            source_path=source_path,
            budget=budget,
        ).encode("ascii"),
    )
    _update_annotation_shape(digest, wrapped.__annotations__, budget=budget)
    if expand_same_root and module_name.split(".", maxsplit=1)[0] == identity_root:
        _update_source_function_dependency_leaves(
            digest,
            wrapped,
            module=module,
            module_name=module_name,
            source_path=source_path,
            budget=budget,
            scope_cache=scope_cache,
            identity_root=identity_root,
            expand_same_root=True,
            depth=depth + 1,
        )
    if (
        function.__dict__.get("__wrapped__") is not wrapped
        or not _single_closure_cell_contains(function, wrapped)
    ):
        raise PluginExecutableIdentityError(
            "module target singleton contextmanager dependency changed"
        )
    return True


def _update_source_dependency_leaf(
    digest: Any,
    value: object,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    identity_root: str,
    expand_same_root: bool,
    depth: int,
) -> None:
    """Bind one directly loaded dependency without expanding its internals."""

    if value is None or value is NotImplemented or type(value) in {
        bool,
        int,
        float,
        complex,
        str,
        bytes,
    }:
        _update_stable_value(digest, value, budget=budget, depth=depth)
        return
    if type(value) in {tuple, frozenset}:
        _consume_target_budget(budget, depth=depth)
        _digest_field(digest, b"dependency-container")
        _digest_field(digest, type(value).__name__.encode("ascii"))
        item_digests: list[bytes] = []
        for item in value:
            item_digest = hashlib.sha256()
            _update_source_dependency_leaf(
                item_digest,
                item,
                budget=budget,
                scope_cache=scope_cache,
                identity_root=identity_root,
                expand_same_root=expand_same_root,
                depth=depth + 1,
            )
            item_digests.append(item_digest.digest())
        if type(value) is frozenset:
            item_digests.sort()
        for item_digest in item_digests:
            _digest_field(digest, item_digest)
        return
    if type(value) is dict:
        _update_runtime_dict(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=identity_root,
            depth=depth,
        )
        return
    if type(value) is list:
        _update_runtime_list(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=identity_root,
            depth=depth,
        )
        return
    if type(value) is GenericAlias:
        _consume_target_budget(budget, depth=depth)
        origin = value.__origin__
        arguments = value.__args__
        _digest_field(digest, b"dependency-generic-alias")
        _update_source_dependency_leaf(
            digest,
            origin,
            budget=budget,
            scope_cache=scope_cache,
            identity_root=identity_root,
            expand_same_root=expand_same_root,
            depth=depth + 1,
        )
        _update_source_dependency_leaf(
            digest,
            arguments,
            budget=budget,
            scope_cache=scope_cache,
            identity_root=identity_root,
            expand_same_root=expand_same_root,
            depth=depth + 1,
        )
        if value.__origin__ is not origin or value.__args__ != arguments:
            raise PluginExecutableIdentityError(
                "module target generic alias changed while fingerprinting"
            )
        return
    implementation = type(value)
    if (
        getattr(implementation, "__module__", None) == "_contextvars"
        and getattr(implementation, "__qualname__", None) == "ContextVar"
    ):
        implementation_module = sys.modules.get("_contextvars")
        origin = getattr(
            getattr(implementation_module, "__spec__", None),
            "origin",
            None,
        )
        if (
            not isinstance(implementation_module, ModuleType)
            or _static_import_target(implementation_module, "ContextVar")
            is not implementation
            or origin not in {"built-in", "frozen"}
            or type(value.name) is not str
        ):
            raise PluginExecutableIdentityError(
                "module target context variable dependency is unverifiable"
            )
        _digest_field(digest, b"dependency-context-variable")
        _digest_field(digest, value.name.encode("utf-8"))
        _digest_field(digest, str(origin).encode("ascii"))
        return
    if _is_canonical_lru_cache_wrapper(value):
        _update_lru_cache_wrapper_reference(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=identity_root,
            depth=depth,
        )
        return
    if inspect.ismethod(value):
        function = value.__func__
        receiver = value.__self__
        method_name = getattr(function, "__name__", None)
        descriptor = (
            vars(receiver).get(method_name)
            if inspect.isclass(receiver) and type(method_name) is str
            else None
        )
        if (
            type(function) is FunctionType
            and inspect.isclass(receiver)
            and isinstance(descriptor, classmethod)
            and descriptor.__func__ is function
        ):
            _digest_field(digest, b"dependency-bound-class-method")
            _update_source_dependency_leaf(
                digest,
                function,
                budget=budget,
                scope_cache=scope_cache,
                identity_root=identity_root,
                expand_same_root=expand_same_root,
                depth=depth + 1,
            )
            _update_source_dependency_leaf(
                digest,
                receiver,
                budget=budget,
                scope_cache=scope_cache,
                identity_root=identity_root,
                expand_same_root=expand_same_root,
                depth=depth + 1,
            )
            if vars(receiver).get(method_name) is not descriptor:
                raise PluginExecutableIdentityError(
                    "module target bound class method changed while fingerprinting"
                )
            return
        _update_global_reference(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=identity_root,
            depth=depth,
        )
        return
    if (
        getattr(type(value), "__module__", None) == "enum"
        and getattr(type(value), "__qualname__", None) == "property"
    ):
        enum_module = sys.modules.get("enum")
        state = _instance_dictionary_state(value)
        if not isinstance(enum_module, ModuleType) or state is None:
            raise PluginExecutableIdentityError(
                "module target enumeration descriptor is unverifiable"
            )
        snapshot = _snapshot_runtime_dict(
            state,
            budget=budget,
            depth=depth + 1,
            label="module target enumeration descriptor",
        )
        owner_name = state.get("clsname")
        descriptor_name = state.get("name")
        owner = (
            vars(enum_module).get(owner_name)
            if type(owner_name) is str
            else None
        )
        enum_source = _module_file_source_path(enum_module, budget=budget)
        if (
            type(descriptor_name) is not str
            or not inspect.isclass(owner)
            or vars(owner).get(descriptor_name) is not value
            or enum_source is None
        ):
            raise PluginExecutableIdentityError(
                "module target enumeration descriptor has no exact owner"
            )
        _digest_field(digest, b"dependency-enumeration-descriptor")
        _digest_field(digest, owner_name.encode("utf-8"))
        _digest_field(digest, descriptor_name.encode("utf-8"))
        _digest_field(
            digest,
            _cached_scope_identity("enum", enum_source, scope_cache).encode("ascii"),
        )
        for name, item in sorted(snapshot):
            if type(name) is not str:
                raise PluginExecutableIdentityError(
                    "module target enumeration descriptor state is noncanonical"
                )
            _digest_field(digest, name.encode("utf-8"))
            if name in {"fget", "fset", "fdel"} and item is not None:
                expected_accessor_name = f"{owner_name}.{descriptor_name}"
                if (
                    type(item) is not FunctionType
                    or item.__module__ != "enum"
                    or item.__qualname__ != expected_accessor_name
                    or item.__globals__ is not vars(enum_module)
                    or item.__builtins__ is not vars(builtins)
                    or item.__closure__ is not None
                    or _object_source_path(item, budget=budget) != enum_source
                ):
                    raise PluginExecutableIdentityError(
                        "module target enumeration descriptor accessor is unverifiable"
                    )
                _digest_field(
                    digest,
                    _declared_runtime_code_identity(
                        item.__code__,
                        module_name="enum",
                        qualified_name=expected_accessor_name,
                        source_path=enum_source,
                        budget=budget,
                    ).encode("ascii"),
                )
                _update_runtime_defaults(
                    digest,
                    item.__defaults__,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache={},
                    active_callables=set(),
                    identity_root=identity_root,
                    depth=depth + 1,
                    label="enumeration descriptor positional defaults",
                )
                _update_runtime_mapping(
                    digest,
                    item.__kwdefaults__,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache={},
                    active_callables=set(),
                    identity_root=identity_root,
                    depth=depth + 1,
                    label="enumeration descriptor keyword defaults",
                )
                _update_annotation_shape(digest, item.__annotations__, budget=budget)
            else:
                _update_stable_value(
                    digest,
                    item,
                    budget=budget,
                    depth=depth + 1,
                )
        _verify_dict_snapshot(state, snapshot)
        return
    if inspect.ismemberdescriptor(value) or inspect.isgetsetdescriptor(value):
        owner = getattr(value, "__objclass__", None)
        descriptor_name = getattr(value, "__name__", None)
        if (
            not inspect.isclass(owner)
            or type(descriptor_name) is not str
            or inspect.getattr_static(owner, descriptor_name, None) is not value
        ):
            raise PluginExecutableIdentityError(
                "module target singleton descriptor dependency is unverifiable"
            )
        owner_module_name = getattr(owner, "__module__", None)
        owner_name = getattr(owner, "__qualname__", None)
        owner_module = sys.modules.get(owner_module_name)
        if (
            type(owner_module_name) is not str
            or type(owner_name) is not str
            or not isinstance(owner_module, ModuleType)
            or _static_import_target(owner_module, owner_name) is not owner
        ):
            raise PluginExecutableIdentityError(
                "module target singleton descriptor owner is unverifiable"
            )
        owner_source = _module_file_source_path(owner_module, budget=budget)
        if owner_source is None:
            owner_origin = getattr(
                getattr(owner_module, "__spec__", None),
                "origin",
                None,
            )
            if owner_origin not in {"built-in", "frozen"}:
                raise PluginExecutableIdentityError(
                    "module target singleton descriptor owner is sourceless"
                )
            owner_identity = str(owner_origin)
        else:
            owner_identity = _cached_scope_identity(
                owner_module_name,
                owner_source,
                scope_cache,
            )
        _digest_field(digest, b"dependency-static-member-descriptor")
        _digest_field(digest, owner_module_name.encode("utf-8"))
        _digest_field(digest, owner_name.encode("utf-8"))
        _digest_field(digest, descriptor_name.encode("utf-8"))
        _digest_field(digest, owner_identity.encode("ascii"))
        return
    if inspect.ismethoddescriptor(value):
        _update_global_reference(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=identity_root,
            depth=depth,
        )
        return
    dataclass_parameters = getattr(type(value), "__dataclass_params__", None)
    if is_dataclass(value) and getattr(dataclass_parameters, "frozen", False):
        _update_global_reference(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=identity_root,
            depth=depth,
        )
        return
    if isinstance(value, Enum):
        _update_global_reference(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=identity_root,
            depth=depth,
        )
        return
    if isinstance(value, ModuleType):
        module_name = getattr(value, "__name__", None)
        if type(module_name) is not str or sys.modules.get(module_name) is not value:
            raise PluginExecutableIdentityError(
                "module target singleton dependency module is unverifiable"
            )
        source_path = _module_file_source_path(value, budget=budget)
        if source_path is None:
            origin = getattr(getattr(value, "__spec__", None), "origin", None)
            if origin not in {"built-in", "frozen"}:
                raise PluginExecutableIdentityError(
                    "module target singleton dependency module is sourceless"
                )
            _digest_field(digest, b"dependency-native-module")
            _digest_field(digest, module_name.encode("utf-8"))
            _digest_field(digest, str(origin).encode("ascii"))
            return
        _digest_field(digest, b"dependency-source-module")
        _digest_field(digest, module_name.encode("utf-8"))
        _digest_field(
            digest,
            _cached_scope_identity(module_name, source_path, scope_cache).encode(
                "ascii"
            ),
        )
        return
    if type(value) is FunctionType and _update_external_exported_dependency(
        digest,
        value,
        budget=budget,
        scope_cache=scope_cache,
        identity_root=identity_root,
        depth=depth,
    ):
        return
    if type(value) is FunctionType and _update_contextmanager_function_dependency(
        digest,
        value,
        budget=budget,
        scope_cache=scope_cache,
        identity_root=identity_root,
        expand_same_root=expand_same_root,
        depth=depth,
    ):
        return
    if type(value) is FunctionType:
        module_name = getattr(value, "__module__", None)
        qualified_name = getattr(value, "__qualname__", None)
        module = sys.modules.get(module_name)
        source_path = _object_source_path(value, budget=budget)
        module_source = (
            _module_file_source_path(module, budget=budget)
            if isinstance(module, ModuleType)
            else None
        )
        if (
            type(module_name) is not str
            or type(qualified_name) is not str
            or not isinstance(module, ModuleType)
            or module_source is None
            or source_path != module_source
            or _static_import_target(module, qualified_name) is not value
            or value.__globals__ is not vars(module)
            or value.__builtins__ is not vars(builtins)
            or value.__closure__ is not None
            or getattr(value, "__type_params__", ())
        ):
            raise PluginExecutableIdentityError(
                "module target singleton function dependency is unverifiable"
            )
        _digest_field(digest, b"dependency-source-function")
        _digest_field(digest, module_name.encode("utf-8"))
        _digest_field(digest, qualified_name.encode("utf-8"))
        _digest_field(
            digest,
            _cached_scope_identity(module_name, module_source, scope_cache).encode(
                "ascii"
            ),
        )
        _digest_field(
            digest,
            _declared_runtime_code_identity(
                value.__code__,
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=module_source,
                budget=budget,
            ).encode("ascii"),
        )
        _update_runtime_defaults(
            digest,
            value.__defaults__,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=module_name.split(".", maxsplit=1)[0],
            depth=depth + 1,
            label="singleton dependency positional defaults",
        )
        _update_runtime_mapping(
            digest,
            value.__kwdefaults__,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=module_name.split(".", maxsplit=1)[0],
            depth=depth + 1,
            label="singleton dependency keyword defaults",
        )
        _update_runtime_mapping(
            digest,
            value.__dict__,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=module_name.split(".", maxsplit=1)[0],
            depth=depth + 1,
            label="singleton dependency function state",
        )
        _update_annotation_shape(digest, value.__annotations__, budget=budget)
        if expand_same_root and module_name.split(".", maxsplit=1)[0] == identity_root:
            leaf_key = id(value)
            if leaf_key in budget.active_dependency_leaves:
                _digest_field(digest, b"same-root-function-cycle")
                _digest_field(digest, module_name.encode("utf-8"))
                _digest_field(digest, qualified_name.encode("utf-8"))
            else:
                budget.active_dependency_leaves.add(leaf_key)
                try:
                    _update_source_function_dependency_leaves(
                        digest,
                        value,
                        module=module,
                        module_name=module_name,
                        source_path=module_source,
                        budget=budget,
                        scope_cache=scope_cache,
                        identity_root=identity_root,
                        expand_same_root=True,
                        depth=depth + 1,
                    )
                finally:
                    budget.active_dependency_leaves.discard(leaf_key)
        return
    if inspect.isbuiltin(value):
        module_name = getattr(value, "__module__", None)
        qualified_name = getattr(value, "__qualname__", None) or getattr(
            value,
            "__name__",
            None,
        )
        module = sys.modules.get(module_name)
        origin = (
            getattr(getattr(module, "__spec__", None), "origin", None)
            if isinstance(module, ModuleType)
            else None
        )
        extension_suffix = (
            Path(origin).suffix.lower() if type(origin) is str else ""
        )
        native_origin = origin in {"built-in", "frozen"} or extension_suffix in {
            ".dll",
            ".dylib",
            ".pyd",
            ".so",
        }
        if (
            type(module_name) is not str
            or type(qualified_name) is not str
            or not isinstance(module, ModuleType)
            or not native_origin
            or _static_import_target(module, qualified_name) is not value
        ):
            raise PluginExecutableIdentityError(
                "module target singleton native dependency is unverifiable"
            )
        _digest_field(digest, b"dependency-native-callable")
        _digest_field(digest, module_name.encode("utf-8"))
        _digest_field(digest, qualified_name.encode("utf-8"))
        origin_kind = (
            str(origin)
            if origin in {"built-in", "frozen"}
            else f"extension:{extension_suffix}"
        )
        _digest_field(digest, origin_kind.encode("ascii"))
        return
    if inspect.isclass(value) and _update_external_exported_dependency(
        digest,
        value,
        budget=budget,
        scope_cache=scope_cache,
        identity_root=identity_root,
        depth=depth,
    ):
        # Third-party and standard-library exports are a separately loaded
        # trust boundary.  Bind their exact live export coordinate and source
        # identity without recursively absorbing the external implementation
        # graph into the plug-in's executable identity.
        return
    if inspect.isclass(value):
        module_name = getattr(value, "__module__", None)
        qualified_name = getattr(value, "__qualname__", None)
        if type(module_name) is not str or type(qualified_name) is not str:
            raise PluginExecutableIdentityError(
                "module target singleton class dependency is unverifiable"
            )
        if module_name == "builtins":
            if vars(builtins).get(qualified_name) is not value:
                raise PluginExecutableIdentityError(
                    "module target singleton built-in dependency is replaced"
                )
            _digest_field(digest, b"dependency-builtin-class")
            _digest_field(digest, qualified_name.encode("utf-8"))
            return
        module = sys.modules.get(module_name)
        module_source = (
            _module_file_source_path(module, budget=budget)
            if isinstance(module, ModuleType)
            else None
        )
        if (
            not isinstance(module, ModuleType)
            or module_source is None
            or _object_source_path(value, budget=budget) != module_source
            or _static_import_target(module, qualified_name) is not value
        ):
            raise PluginExecutableIdentityError(
                "module target singleton class dependency is unverifiable"
            )
        if (
            module_name.split(".", maxsplit=1)[0] != identity_root
            and bool(getattr(value, "__flags__", 0) & 0x100)
        ):
            # CPython's immutable-type flag makes the live native class shape
            # non-rebindable.  Its exact exported coordinate and owning source
            # module were validated above, so expanding native descriptors
            # would add no authority while recursively opening the stdlib.
            _digest_field(digest, b"dependency-external-immutable-class")
            _digest_field(digest, module_name.encode("utf-8"))
            _digest_field(digest, qualified_name.encode("utf-8"))
            _digest_field(
                digest,
                _cached_scope_identity(
                    module_name,
                    module_source,
                    scope_cache,
                ).encode("ascii"),
            )
            return
        same_root = module_name.split(".", maxsplit=1)[0] == identity_root
        if same_root:
            declared = _declared_code_objects(
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=module_source,
                budget=budget,
            )
            if len(declared) != 1:
                raise PluginExecutableIdentityError(
                    "module target singleton class dependency is ambiguous"
                )
        _digest_field(digest, b"dependency-source-class")
        _digest_field(digest, module_name.encode("utf-8"))
        _digest_field(digest, qualified_name.encode("utf-8"))
        _digest_field(
            digest,
            _cached_scope_identity(module_name, module_source, scope_cache).encode(
                "ascii"
            ),
        )
        if (
            expand_same_root
            and same_root
        ):
            _update_dependency_class_shape(
                digest,
                value,
                module=module,
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=module_source,
                budget=budget,
                scope_cache=scope_cache,
                identity_root=identity_root,
                expand_dependencies=True,
                depth=depth + 1,
            )
        else:
            _update_dependency_class_shape(
                digest,
                value,
                module=module,
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=module_source,
                budget=budget,
                scope_cache=scope_cache,
                identity_root=identity_root,
                expand_dependencies=False,
                depth=depth + 1,
            )
        return
    if _update_external_exported_dependency(
        digest,
        value,
        budget=budget,
        scope_cache=scope_cache,
        identity_root=identity_root,
        depth=depth,
    ):
        return
    implementation = type(value)
    implementation_module_name = getattr(implementation, "__module__", None)
    implementation_name = getattr(implementation, "__qualname__", None)
    implementation_module = sys.modules.get(implementation_module_name)
    implementation_source = (
        _module_file_source_path(implementation_module, budget=budget)
        if isinstance(implementation_module, ModuleType)
        else None
    )
    if (
        type(implementation_module_name) is str
        and implementation_module_name.split(".", maxsplit=1)[0] == identity_root
        and type(implementation_name) is str
        and isinstance(implementation_module, ModuleType)
        and implementation_source is not None
        and _object_source_path(implementation, budget=budget)
        == implementation_source
        and _static_import_target(implementation_module, implementation_name)
        is implementation
    ):
        _digest_field(digest, b"dependency-same-root-instance")
        instance_key = id(value)
        if instance_key in budget.active_dependency_leaves:
            _digest_field(digest, b"same-root-instance-cycle")
            _digest_field(digest, implementation_module_name.encode("utf-8"))
            _digest_field(digest, implementation_name.encode("utf-8"))
            return
        budget.active_dependency_leaves.add(instance_key)
        try:
            _update_dependency_class_shape(
                digest,
                implementation,
                module=implementation_module,
                module_name=implementation_module_name,
                qualified_name=implementation_name,
                source_path=implementation_source,
                budget=budget,
                scope_cache=scope_cache,
                identity_root=identity_root,
                expand_dependencies=True,
                depth=depth + 1,
            )
            state = _instance_dictionary_state(value)
            snapshot: tuple[tuple[object, object], ...] = ()
            if state is not None:
                snapshot = _snapshot_runtime_dict(
                    state,
                    budget=budget,
                    depth=depth + 1,
                    label="module target singleton dependency state",
                )
                if any(type(name) is not str for name, _item in snapshot):
                    raise PluginExecutableIdentityError(
                        "module target singleton dependency state is noncanonical"
                    )
                for name, item in sorted(cast(tuple[tuple[str, object], ...], snapshot)):
                    _digest_field(digest, b"dependency-instance-dict")
                    _digest_field(digest, name.encode("utf-8"))
                    _update_source_dependency_leaf(
                        digest,
                        item,
                        budget=budget,
                        scope_cache=scope_cache,
                        identity_root=identity_root,
                        expand_same_root=True,
                        depth=depth + 1,
                    )
                _verify_dict_snapshot(state, snapshot)
            seen_names = {
                name for name, _item in snapshot if type(name) is str
            }
            slot_snapshot: list[tuple[str, object, object]] = []
            for name, descriptor in _instance_state_descriptors(implementation):
                if name in seen_names:
                    continue
                try:
                    item = descriptor.__get__(value, implementation)
                except AttributeError:
                    continue
                except Exception as error:
                    raise PluginExecutableIdentityError(
                        "module target singleton dependency slot is unverifiable"
                    ) from error
                _digest_field(digest, b"dependency-instance-slot")
                _digest_field(digest, name.encode("utf-8"))
                _update_source_dependency_leaf(
                    digest,
                    item,
                    budget=budget,
                    scope_cache=scope_cache,
                    identity_root=identity_root,
                    expand_same_root=True,
                    depth=depth + 1,
                )
                slot_snapshot.append((name, descriptor, item))
            for name, descriptor, item in slot_snapshot:
                try:
                    current = descriptor.__get__(value, implementation)
                except Exception as error:
                    raise PluginExecutableIdentityError(
                        "module target singleton dependency slot changed"
                    ) from error
                if current is not item:
                    raise PluginExecutableIdentityError(
                        "module target singleton dependency slot changed"
                    )
        finally:
            budget.active_dependency_leaves.discard(instance_key)
        return
    raise PluginExecutableIdentityError(
        "module target singleton dependency has no bounded source provenance"
    )


def _update_source_function_dependency_leaves(
    digest: Any,
    function: FunctionType,
    *,
    module: ModuleType,
    module_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    identity_root: str,
    expand_same_root: bool,
    depth: int,
) -> None:
    analysis = _function_dependency_analysis(function, budget=budget, depth=depth)
    if analysis.has_runtime_imports:
        _digest_field(digest, b"singleton-method-runtime-imports")
        _update_runtime_import_references(
            digest,
            function,
            module=module,
            module_name=module_name,
            source_path=source_path,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache={},
            active_callables=set(),
            identity_root=identity_root,
            depth=depth + 1,
        )
    source = _read_regular_source_bytes(source_path)
    _consume_target_bytes(budget, len(source))
    try:
        tree = ast.parse(source, filename=f"<{module_name}>")
    except (MemoryError, SyntaxError, ValueError) as error:
        raise PluginExecutableIdentityError(
            "module target singleton dependency source cannot be parsed"
        ) from error
    bindings: dict[str, tuple[str, str | None, str | None]] = {}
    package_parts = module_name.split(".")[:-1]
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bindings[statement.name] = ("local", None, statement.name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                bound = alias.asname or alias.name.split(".", maxsplit=1)[0]
                bindings[bound] = ("import-module", alias.name, None)
        elif isinstance(statement, ast.ImportFrom):
            if statement.level:
                keep = len(package_parts) - (statement.level - 1)
                if keep < 0:
                    continue
                selected_parts = package_parts[:keep]
                if statement.module:
                    selected_parts.extend(statement.module.split("."))
                imported_module_name = ".".join(selected_parts)
            else:
                imported_module_name = statement.module or ""
            for alias in statement.names:
                if alias.name == "*":
                    continue
                bindings[alias.asname or alias.name] = (
                    "import-attribute",
                    imported_module_name,
                    alias.name,
                )
        elif isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = ("assigned", None, None)
        elif isinstance(statement, ast.AnnAssign) and isinstance(
            statement.target, ast.Name
        ):
            bindings[statement.target.id] = ("assigned", None, None)

    def validate_binding(name: str, value: object) -> None:
        binding = bindings.get(name)
        if binding is None:
            raise PluginExecutableIdentityError(
                "module target singleton dependency has no static source binding"
            )
        kind, imported_module_name, imported_attribute = binding
        if kind in {"local", "assigned"}:
            if vars(module).get(name) is not value:
                raise PluginExecutableIdentityError(
                    "module target singleton local dependency is replaced"
                )
            return
        imported_module = sys.modules.get(imported_module_name)
        if not isinstance(imported_module, ModuleType):
            raise PluginExecutableIdentityError(
                "module target singleton imported dependency is unavailable"
            )
        if kind == "import-module":
            expected = imported_module
        else:
            assert imported_attribute is not None
            expected = _static_import_target(imported_module, imported_attribute)
        if expected is not value:
            raise PluginExecutableIdentityError(
                "module target singleton imported dependency is replaced"
            )

    for name in analysis.global_names:
        if name in function.__globals__:
            value = function.__globals__[name]
            validate_binding(name, value)
        elif name in function.__builtins__:
            value = function.__builtins__[name]
        else:
            raise PluginExecutableIdentityError(
                "module target singleton method has an unresolved dependency"
            )
        _digest_field(digest, b"singleton-method-global")
        _digest_field(digest, name.encode("utf-8"))
        _update_source_dependency_leaf(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            identity_root=identity_root,
            expand_same_root=expand_same_root,
            depth=depth + 1,
        )
    for path in analysis.global_attribute_paths:
        if path[0] in function.__globals__:
            root = function.__globals__[path[0]]
            validate_binding(path[0], root)
        else:
            root = function.__builtins__.get(path[0])
        if root is None:
            raise PluginExecutableIdentityError(
                "module target singleton method has an unresolved attribute dependency"
            )
        resolution = _resolve_static_attribute_path(root, path[1:])
        _digest_field(digest, b"singleton-method-attribute")
        for component in path:
            _digest_field(digest, component.encode("utf-8"))
        _update_source_dependency_leaf(
            digest,
            resolution.value,
            budget=budget,
            scope_cache=scope_cache,
            identity_root=identity_root,
            expand_same_root=expand_same_root,
            depth=depth + 1,
        )


def _update_dependency_class_shape(
    digest: Any,
    implementation: type[Any],
    *,
    module: ModuleType,
    module_name: str,
    qualified_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    identity_root: str,
    expand_dependencies: bool,
    depth: int,
) -> None:
    """Memoize one exact class shape while retaining a live member snapshot."""

    cache_key = (id(implementation), expand_dependencies)
    cached = budget.dependency_class_cache.get(cache_key)
    if cached is not None:
        selected, identity, members = cached
        if selected is not implementation:
            raise PluginExecutableIdentityError(
                "module target dependency class cache is inconsistent"
            )
        _verify_class_member_snapshot(
            implementation,
            members,
            label="module target cached dependency class",
        )
        _digest_field(digest, b"cached-dependency-class-shape")
        _digest_field(digest, identity.encode("ascii"))
        return
    shape_digest = hashlib.sha256()
    _update_dependency_class_shape_uncached(
        shape_digest,
        implementation,
        module=module,
        module_name=module_name,
        qualified_name=qualified_name,
        source_path=source_path,
        budget=budget,
        scope_cache=scope_cache,
        identity_root=identity_root,
        expand_dependencies=expand_dependencies,
        depth=depth,
    )
    try:
        members = tuple(vars(implementation).items())
    except RuntimeError as error:
        raise PluginExecutableIdentityError(
            "module target dependency class changed while caching"
        ) from error
    _verify_class_member_snapshot(
        implementation,
        members,
        label="module target dependency class",
    )
    identity = shape_digest.hexdigest()
    budget.dependency_class_cache[cache_key] = (
        implementation,
        identity,
        members,
    )
    _digest_field(digest, b"dependency-class-shape")
    _digest_field(digest, identity.encode("ascii"))


def _update_dependency_class_shape_uncached(
    digest: Any,
    implementation: type[Any],
    *,
    module: ModuleType,
    module_name: str,
    qualified_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    identity_root: str,
    expand_dependencies: bool,
    depth: int,
) -> None:
    """Attest current class members; recurse only inside the identity root."""

    leaf_key = id(implementation)
    if leaf_key in budget.active_dependency_leaves:
        _digest_field(digest, b"dependency-class-cycle")
        _digest_field(digest, module_name.encode("utf-8"))
        _digest_field(digest, qualified_name.encode("utf-8"))
        return
    budget.active_dependency_leaves.add(leaf_key)
    try:
        declared = _declared_code_objects(
            module_name=module_name,
            qualified_name=qualified_name,
            source_path=source_path,
            budget=budget,
        )
        if len(declared) != 1:
            raise PluginExecutableIdentityError(
                "module target dependency class declaration is ambiguous"
            )
        _update_code_object(digest, declared[0], budget=budget, depth=depth + 1)
        members = _bounded_class_members(
            implementation,
            budget=budget,
            depth=depth + 1,
            label="module target dependency class",
        )
        generated_abc_members = _update_abc_class_contract(
            digest,
            implementation,
            budget=budget,
            scope_cache=scope_cache,
            depth=depth + 1,
        )
        generated_enum_members = _update_enum_class_contract(
            digest,
            implementation,
            budget=budget,
            depth=depth + 1,
        )
        generated_dataclass_methods: set[str] = set()
        if is_dataclass(implementation):
            generated_dataclass_methods = _update_dataclass_class_contract(
                digest,
                implementation,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache={},
                active_callables=set(),
                identity_root=identity_root,
                depth=depth + 1,
            )
        for name, member in members:
            if name in generated_abc_members or name in generated_enum_members:
                continue
            if name in {
                "__annotations__",
                "__classcell__",
                "__dataclass_fields__",
                "__dataclass_params__",
                "__dict__",
                "__doc__",
                "__module__",
                "__qualname__",
                "__slots__",
                "__weakref__",
            } or name in generated_dataclass_methods:
                continue
            functions: tuple[tuple[str, FunctionType], ...]
            if type(member) is FunctionType:
                functions = (("method", member),)
            elif isinstance(member, staticmethod):
                functions = (("static-method", member.__func__),)
            elif isinstance(member, classmethod):
                functions = (("class-method", member.__func__),)
            elif isinstance(member, property):
                functions = tuple(
                    (label, selected)
                    for label, selected in (
                        ("property-get", member.fget),
                        ("property-set", member.fset),
                        ("property-delete", member.fdel),
                    )
                    if type(selected) is FunctionType
                )
            else:
                functions = ()
            if functions:
                _digest_field(digest, b"dependency-class-member")
                _digest_field(digest, name.encode("utf-8"))
                for label, function in functions:
                    if _update_contextmanager_function_dependency(
                        digest,
                        function,
                        budget=budget,
                        scope_cache=scope_cache,
                        identity_root=identity_root,
                        expand_same_root=expand_dependencies,
                        depth=depth + 1,
                    ):
                        _digest_field(digest, label.encode("ascii"))
                        continue
                    expected_name = f"{qualified_name}.{name}"
                    closure = function.__closure__
                    class_closure = (
                        closure is not None
                        and len(closure) == 1
                        and function.__code__.co_freevars == ("__class__",)
                        and _single_closure_cell_contains(function, implementation)
                    )
                    if (
                        function.__module__ != module_name
                        or function.__qualname__ != expected_name
                        or function.__globals__ is not vars(module)
                        or function.__builtins__ is not vars(builtins)
                        or _object_source_path(function, budget=budget) != source_path
                        or (closure is not None and not class_closure)
                        or getattr(function, "__type_params__", ())
                    ):
                        raise PluginExecutableIdentityError(
                            "module target dependency class member is unverifiable"
                        )
                    _digest_field(digest, label.encode("ascii"))
                    _digest_field(
                        digest,
                        _declared_runtime_code_identity(
                            function.__code__,
                            module_name=module_name,
                            qualified_name=expected_name,
                            source_path=source_path,
                            budget=budget,
                        ).encode("ascii"),
                    )
                    _update_runtime_defaults(
                        digest,
                        function.__defaults__,
                        budget=budget,
                        scope_cache=scope_cache,
                        callable_cache={},
                        active_callables=set(),
                        identity_root=identity_root,
                        depth=depth + 1,
                        label="dependency member positional defaults",
                    )
                    _update_runtime_mapping(
                        digest,
                        function.__kwdefaults__,
                        budget=budget,
                        scope_cache=scope_cache,
                        callable_cache={},
                        active_callables=set(),
                        identity_root=identity_root,
                        depth=depth + 1,
                        label="dependency member keyword defaults",
                    )
                    _update_runtime_mapping(
                        digest,
                        function.__dict__,
                        budget=budget,
                        scope_cache=scope_cache,
                        callable_cache={},
                        active_callables=set(),
                        identity_root=identity_root,
                        depth=depth + 1,
                        label="dependency member state",
                    )
                    _update_annotation_shape(
                        digest,
                        function.__annotations__,
                        budget=budget,
                    )
                    if expand_dependencies:
                        _update_source_function_dependency_leaves(
                            digest,
                            function,
                            module=module,
                            module_name=module_name,
                            source_path=source_path,
                            budget=budget,
                            scope_cache=scope_cache,
                            identity_root=identity_root,
                            expand_same_root=True,
                            depth=depth + 1,
                        )
                continue
            if inspect.ismemberdescriptor(member) or inspect.isgetsetdescriptor(member):
                continue
            if member is None or member is NotImplemented or type(member) in {
                bool,
                int,
                float,
                complex,
                str,
                bytes,
            }:
                _digest_field(digest, name.encode("utf-8"))
                _update_stable_value(digest, member, budget=budget, depth=depth + 1)
                continue
            if type(member) in {tuple, frozenset, dict, list}:
                _digest_field(digest, name.encode("utf-8"))
                _update_source_dependency_leaf(
                    digest,
                    member,
                    budget=budget,
                    scope_cache=scope_cache,
                    identity_root=identity_root,
                    expand_same_root=expand_dependencies,
                    depth=depth + 1,
                )
                continue
            if inspect.isclass(member):
                _digest_field(digest, name.encode("utf-8"))
                _update_source_dependency_leaf(
                    digest,
                    member,
                    budget=budget,
                    scope_cache=scope_cache,
                    identity_root=identity_root,
                    expand_same_root=expand_dependencies,
                    depth=depth + 1,
                )
                continue
            if not expand_dependencies:
                member_type = type(member)
                type_module = getattr(member_type, "__module__", None)
                type_name = getattr(member_type, "__qualname__", None)
                if type(type_module) is not str or type(type_name) is not str:
                    raise PluginExecutableIdentityError(
                        "module target dependency class has unverifiable external state"
                    )
                # External libraries are a separately verified source trust
                # boundary. Bind the current member's closed runtime type while
                # avoiding a recursive walk through unrelated stdlib state.
                _digest_field(digest, b"external-class-opaque-member")
                _digest_field(digest, name.encode("utf-8"))
                _digest_field(digest, type_module.encode("utf-8"))
                _digest_field(digest, type_name.encode("utf-8"))
                continue
            raise PluginExecutableIdentityError(
                "module target dependency class has unsupported live state"
            )
        _verify_class_member_snapshot(
            implementation,
            members,
            label="module target dependency class",
        )
    finally:
        budget.active_dependency_leaves.discard(leaf_key)


def _source_singleton_class_shape_identity(
    implementation: type[Any],
    *,
    module: ModuleType,
    module_name: str,
    qualified_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    depth: int,
) -> str:
    """Bind a narrow source-declared singleton class without dependency walk."""

    declared = _declared_code_objects(
        module_name=module_name,
        qualified_name=qualified_name,
        source_path=source_path,
        budget=budget,
    )
    if len(declared) != 1:
        raise PluginExecutableIdentityError(
            "module target singleton class declaration is missing or ambiguous"
        )
    members = _bounded_class_members(
        implementation,
        budget=budget,
        depth=depth + 1,
        label="module target singleton class",
    )
    digest = hashlib.sha256()
    digest.update(_CALLABLE_CODE_FINGERPRINT_SCHEMA)
    _digest_field(digest, b"same-root-stateless-singleton-class")
    _digest_field(digest, module_name.encode("utf-8"))
    _digest_field(digest, qualified_name.encode("utf-8"))
    _update_code_object(digest, declared[0], budget=budget, depth=depth + 1)
    for name, member in members:
        if name in {
            "__annotations__",
            "__classcell__",
            "__dict__",
            "__doc__",
            "__module__",
            "__qualname__",
            "__slots__",
            "__weakref__",
        }:
            continue
        functions: tuple[tuple[str, FunctionType], ...]
        if type(member) is FunctionType:
            functions = (("method", member),)
        elif isinstance(member, staticmethod):
            functions = (("static-method", member.__func__),)
        elif isinstance(member, classmethod):
            functions = (("class-method", member.__func__),)
        elif isinstance(member, property):
            functions = tuple(
                (label, selected)
                for label, selected in (
                    ("property-get", member.fget),
                    ("property-set", member.fset),
                    ("property-delete", member.fdel),
                )
                if type(selected) is FunctionType
            )
        else:
            functions = ()
        if functions:
            _digest_field(digest, b"class-member")
            _digest_field(digest, name.encode("utf-8"))
            for label, function in functions:
                expected_name = f"{qualified_name}.{name}"
                function_source = _object_source_path(function, budget=budget)
                wrapped = function.__dict__.get("__wrapped__")
                if function_source == source_path:
                    if (
                        function.__module__ != module_name
                        or function.__qualname__ != expected_name
                        or function.__globals__ is not vars(module)
                        or function.__builtins__ is not vars(builtins)
                        or function.__closure__ is not None
                        or getattr(function, "__type_params__", ())
                    ):
                        raise PluginExecutableIdentityError(
                            "module target singleton method authority is unverifiable"
                        )
                    selected = function
                    code_identity = _declared_runtime_code_identity(
                        selected.__code__,
                        module_name=module_name,
                        qualified_name=expected_name,
                        source_path=source_path,
                        budget=budget,
                    )
                    _update_runtime_defaults(
                        digest,
                        function.__defaults__,
                        budget=budget,
                        scope_cache={},
                        callable_cache={},
                        active_callables=set(),
                        identity_root=module_name.split(".", maxsplit=1)[0],
                        depth=depth + 1,
                        label="singleton method positional defaults",
                    )
                    _update_runtime_mapping(
                        digest,
                        function.__kwdefaults__,
                        budget=budget,
                        scope_cache={},
                        callable_cache={},
                        active_callables=set(),
                        identity_root=module_name.split(".", maxsplit=1)[0],
                        depth=depth + 1,
                        label="singleton method keyword defaults",
                    )
                    _update_runtime_mapping(
                        digest,
                        function.__dict__,
                        budget=budget,
                        scope_cache={},
                        callable_cache={},
                        active_callables=set(),
                        identity_root=module_name.split(".", maxsplit=1)[0],
                        depth=depth + 1,
                        label="singleton method state",
                    )
                    _update_annotation_shape(
                        digest,
                        function.__annotations__,
                        budget=budget,
                    )
                    _update_source_function_dependency_leaves(
                        digest,
                        function,
                        module=module,
                        module_name=module_name,
                        source_path=source_path,
                        budget=budget,
                        scope_cache=scope_cache,
                        identity_root=module_name.split(".", maxsplit=1)[0],
                        expand_same_root=True,
                        depth=depth + 1,
                    )
                elif (
                    type(wrapped) is FunctionType
                    and function.__code__.co_qualname
                    == "contextmanager.<locals>.helper"
                    and function.__code__.co_freevars == ("func",)
                    and _single_closure_cell_contains(function, wrapped)
                    and function.__dict__ == {"__wrapped__": wrapped}
                    and wrapped.__module__ == module_name
                    and wrapped.__qualname__ == expected_name
                    and _object_source_path(wrapped, budget=budget) == source_path
                ):
                    contextlib_module = sys.modules.get("contextlib")
                    contextlib_source = (
                        _module_file_source_path(contextlib_module, budget=budget)
                        if isinstance(contextlib_module, ModuleType)
                        else None
                    )
                    if (
                        not isinstance(contextlib_module, ModuleType)
                        or contextlib_source is None
                        or function.__globals__ is not vars(contextlib_module)
                        or function.__builtins__ is not vars(builtins)
                        or function.__module__ != module_name
                        or function.__qualname__ != expected_name
                        or function.__annotations__ is not wrapped.__annotations__
                        or wrapped.__globals__ is not vars(module)
                        or wrapped.__builtins__ is not vars(builtins)
                        or wrapped.__defaults__ is not None
                        or wrapped.__kwdefaults__ is not None
                        or wrapped.__closure__ is not None
                        or wrapped.__dict__
                        or getattr(wrapped, "__type_params__", ())
                    ):
                        raise PluginExecutableIdentityError(
                            "module target singleton contextmanager is unverifiable"
                        )
                    _digest_field(
                        digest,
                        _source_module_identity("contextlib", contextlib_source).encode(
                            "ascii"
                        ),
                    )
                    _digest_field(
                        digest,
                        _declared_runtime_code_identity(
                            function.__code__,
                            module_name="contextlib",
                            qualified_name=function.__code__.co_qualname,
                            source_path=contextlib_source,
                            budget=budget,
                        ).encode("ascii"),
                    )
                    code_identity = _declared_runtime_code_identity(
                        wrapped.__code__,
                        module_name=module_name,
                        qualified_name=expected_name,
                        source_path=source_path,
                        budget=budget,
                    )
                    _update_annotation_shape(
                        digest,
                        wrapped.__annotations__,
                        budget=budget,
                    )
                    _update_source_function_dependency_leaves(
                        digest,
                        wrapped,
                        module=module,
                        module_name=module_name,
                        source_path=source_path,
                        budget=budget,
                        scope_cache=scope_cache,
                        identity_root=module_name.split(".", maxsplit=1)[0],
                        expand_same_root=True,
                        depth=depth + 1,
                    )
                else:
                    raise PluginExecutableIdentityError(
                        "module target singleton class contains an unverifiable callable"
                    )
                _digest_field(digest, label.encode("ascii"))
                _digest_field(digest, code_identity.encode("ascii"))
            continue
        if member is None or member is NotImplemented or type(member) in {
            bool,
            int,
            float,
            complex,
            str,
            bytes,
            tuple,
            frozenset,
        }:
            _digest_field(digest, name.encode("utf-8"))
            _update_stable_value(digest, member, budget=budget, depth=depth + 1)
            continue
        raise PluginExecutableIdentityError(
            "module target singleton class has unsupported runtime state"
        )
    _verify_class_member_snapshot(
        implementation,
        members,
        label="module target singleton class",
    )
    return digest.hexdigest()


def _update_same_root_stateless_singleton(
    digest: Any,
    value: object,
    *,
    descriptor_owner: object | None,
    descriptor_name: str | None,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    identity_root: str,
    depth: int,
) -> bool:
    """Bind one exact same-package ``name = Class()`` dependency as a leaf."""

    if (
        not isinstance(descriptor_owner, ModuleType)
        or type(descriptor_name) is not str
        or vars(descriptor_owner).get(descriptor_name) is not value
        or callable(value)
        or isinstance(value, (ModuleType, Enum))
    ):
        return False
    owner_name = descriptor_owner.__name__
    implementation = type(value)
    module_name = getattr(implementation, "__module__", None)
    qualified_name = getattr(implementation, "__qualname__", None)
    if (
        type(module_name) is not str
        or module_name.split(".", maxsplit=1)[0] != identity_root
        or owner_name.split(".", maxsplit=1)[0] != identity_root
        or type(qualified_name) is not str
        or "." in qualified_name
    ):
        return False
    module = sys.modules.get(module_name)
    owner_source = _module_file_source_path(descriptor_owner, budget=budget)
    module_source = (
        _module_file_source_path(module, budget=budget)
        if isinstance(module, ModuleType)
        else None
    )
    state = _instance_dictionary_state(value)
    state_descriptors = _instance_state_descriptors(implementation)
    if state != {} or state_descriptors:
        # This leaf is intentionally narrower than the existing instance
        # attestation. Stateful same-root instances retain that established
        # path rather than becoming ineligible merely because they are stored
        # in a module slot.
        return False
    if (
        not isinstance(module, ModuleType)
        or owner_source is None
        or module_source is None
        or _object_source_path(implementation, budget=budget) != module_source
        or _static_import_target(module, qualified_name) is not implementation
        or not _declares_exact_stateless_singleton(
            module_name=owner_name,
            attribute=descriptor_name,
            implementation_name=qualified_name,
            source_path=owner_source,
            budget=budget,
        )
    ):
        raise PluginExecutableIdentityError(
            "module target same-root singleton is not an exact stateless declaration"
        )
    _consume_target_budget(budget, depth=depth)
    _digest_field(digest, b"same-root-stateless-module-singleton")
    for coordinate in (owner_name, descriptor_name, module_name, qualified_name):
        _digest_field(digest, coordinate.encode("utf-8"))
    _digest_field(
        digest,
        _cached_scope_identity(owner_name, owner_source, scope_cache).encode("ascii"),
    )
    if module_name != owner_name:
        _digest_field(
            digest,
            _cached_scope_identity(module_name, module_source, scope_cache).encode(
                "ascii"
            ),
        )
    _digest_field(
        digest,
        _source_singleton_class_shape_identity(
            implementation,
            module=module,
            module_name=module_name,
            qualified_name=qualified_name,
            source_path=module_source,
            budget=budget,
            scope_cache=scope_cache,
            depth=depth + 1,
        ).encode("ascii"),
    )
    if _instance_dictionary_state(value) != {}:
        raise PluginExecutableIdentityError(
            "module target same-root singleton changed while fingerprinting"
        )
    return True


def _update_static_attribute_value(
    digest: Any,
    value: object,
    *,
    descriptor_owner: object | None,
    descriptor_name: str | None,
    resolved_descriptor: object,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    if _is_executable_authority(value):
        _update_exact_object_token(digest, value, budget=budget)
    if _update_same_root_stateless_singleton(
        digest,
        value,
        descriptor_owner=descriptor_owner,
        descriptor_name=descriptor_name,
        budget=budget,
        scope_cache=scope_cache,
        identity_root=identity_root,
        depth=depth + 1,
    ):
        return
    owned_descriptor = _owned_static_descriptor(
        value,
        owner=descriptor_owner,
        name=descriptor_name,
        resolved_descriptor=resolved_descriptor,
    )
    if owned_descriptor is not None:
        owner_module = getattr(owned_descriptor.owner, "__module__", None)
        owner_name = getattr(owned_descriptor.owner, "__qualname__", None)
        if type(owner_module) is not str or type(owner_name) is not str:
            raise PluginExecutableIdentityError(
                "module target descriptor owner is unverifiable"
            )
        _digest_field(digest, b"owned-static-descriptor")
        _digest_field(digest, owner_module.encode("utf-8"))
        _digest_field(digest, owner_name.encode("utf-8"))
        _digest_field(digest, owned_descriptor.name.encode("utf-8"))
        bindings = _activate_owned_static_descriptor(owned_descriptor, budget=budget)
        try:
            _update_global_reference(
                digest,
                value,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
            _verify_owned_static_descriptor(owned_descriptor)
        finally:
            _deactivate_owned_static_descriptor(
                owned_descriptor,
                bindings,
                budget=budget,
            )
        return
    if inspect.isbuiltin(value) or inspect.ismethoddescriptor(value):
        owner = getattr(value, "__objclass__", None)
        owner_module = getattr(owner, "__module__", None)
        owner_name = getattr(owner, "__qualname__", None)
        module_name = getattr(value, "__module__", None)
        value_name = getattr(value, "__qualname__", None) or getattr(
            value, "__name__", None
        )
        if type(value_name) is not str or not value_name:
            raise PluginExecutableIdentityError(
                "module target references an unverifiable native attribute"
            )
        _digest_field(digest, b"native-attribute")
        for coordinate in (module_name, owner_module, owner_name, value_name):
            _digest_field(
                digest,
                b"" if coordinate is None else str(coordinate).encode("utf-8"),
            )
        return
    _update_global_reference(
        digest,
        value,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth + 1,
    )


def _descriptor_accessor_snapshot(
    descriptor: object,
) -> tuple[tuple[str, FunctionType | None], ...] | None:
    """Read plain accessor storage without invoking custom attribute access."""

    if not any(
        "__get__" in vars(owner)
        or "__set__" in vars(owner)
        or "__delete__" in vars(owner)
        for owner in type(descriptor).__mro__
    ):
        return None
    try:
        state = object.__getattribute__(descriptor, "__dict__")
    except AttributeError:
        state = None
    except Exception as error:
        raise PluginExecutableIdentityError(
            "module target descriptor accessor state is unverifiable"
        ) from error
    if state is not None and type(state) is not dict:
        return None
    missing = object()
    accessors: list[tuple[str, FunctionType | None]] = []
    found = False
    implementation = type(descriptor)
    for slot in ("fget", "fset", "fdel"):
        selected = state.get(slot, missing) if state is not None else missing
        if selected is missing:
            try:
                storage = inspect.getattr_static(implementation, slot)
            except AttributeError:
                storage = missing
            if storage is not missing and (
                inspect.ismemberdescriptor(storage)
                or inspect.isgetsetdescriptor(storage)
            ):
                try:
                    selected = storage.__get__(descriptor, implementation)
                except Exception as error:
                    raise PluginExecutableIdentityError(
                        "module target descriptor accessor state is unverifiable"
                    ) from error
        if selected is missing:
            accessors.append((slot, None))
            continue
        found = True
        if selected is not None and type(selected) is not FunctionType:
            return None
        accessors.append((slot, selected))
    return tuple(accessors) if found else None


def _owned_static_descriptor(
    value: object,
    *,
    owner: object | None,
    name: str | None,
    resolved_descriptor: object,
) -> _OwnedStaticDescriptor | None:
    """Return a descriptor context only for its exact resolved class slot."""

    accessors = _descriptor_accessor_snapshot(value)
    if (
        accessors is None
        or not inspect.isclass(owner)
        or type(name) is not str
        or not name
        or resolved_descriptor is not value
    ):
        return None
    selected = _exact_static_class_member(owner, name)
    if selected is not value:
        raise PluginExecutableIdentityError(
            "module target descriptor changed while fingerprinting"
        )
    return _OwnedStaticDescriptor(owner, name, value, accessors)


def _exact_static_class_member(owner: type[Any], name: str) -> object | None:
    try:
        return inspect.getattr_static(owner, name)
    except (AttributeError, TypeError):
        return None


def _verify_owned_static_descriptor(context: _OwnedStaticDescriptor) -> None:
    if _exact_static_class_member(context.owner, context.name) is not context.descriptor:
        raise PluginExecutableIdentityError(
            "module target descriptor changed while fingerprinting"
        )
    current = _descriptor_accessor_snapshot(context.descriptor)
    if current is None or len(current) != len(context.accessors) or any(
        current_slot != selected_slot or current_accessor is not selected_accessor
        for (current_slot, current_accessor), (
            selected_slot,
            selected_accessor,
        ) in zip(current, context.accessors, strict=True)
    ):
        raise PluginExecutableIdentityError(
            "module target descriptor changed while fingerprinting"
        )


def _activate_owned_static_descriptor(
    context: _OwnedStaticDescriptor,
    *,
    budget: _TargetIdentityBudget,
) -> tuple[_OwnedDescriptorAccessor, ...]:
    descriptor_key = builtins.id(context.descriptor)
    budget.owned_static_descriptors.setdefault(descriptor_key, []).append(context)
    bindings: list[_OwnedDescriptorAccessor] = []
    for slot, accessor in context.accessors:
        if accessor is None:
            continue
        binding = _OwnedDescriptorAccessor(
            context.owner,
            context.name,
            context.descriptor,
            slot,
            accessor,
        )
        budget.owned_descriptor_accessors.setdefault(
            builtins.id(accessor), []
        ).append(binding)
        bindings.append(binding)
    return tuple(bindings)


def _deactivate_owned_static_descriptor(
    context: _OwnedStaticDescriptor,
    bindings: tuple[_OwnedDescriptorAccessor, ...],
    *,
    budget: _TargetIdentityBudget,
) -> None:
    for binding in reversed(bindings):
        key = builtins.id(binding.accessor)
        selected = budget.owned_descriptor_accessors.get(key)
        if selected is None:
            continue
        for index in range(len(selected) - 1, -1, -1):
            if selected[index] is binding:
                del selected[index]
                break
        if not selected:
            budget.owned_descriptor_accessors.pop(key, None)
    descriptor_key = builtins.id(context.descriptor)
    selected_contexts = budget.owned_static_descriptors.get(descriptor_key)
    if selected_contexts is not None:
        for index in range(len(selected_contexts) - 1, -1, -1):
            if selected_contexts[index] is context:
                del selected_contexts[index]
                break
        if not selected_contexts:
            budget.owned_static_descriptors.pop(descriptor_key, None)


def _active_owned_static_descriptor(
    descriptor: object,
    *,
    budget: _TargetIdentityBudget,
) -> _OwnedStaticDescriptor | None:
    contexts = budget.owned_static_descriptors.get(builtins.id(descriptor), ())
    for context in reversed(contexts):
        if context.descriptor is descriptor:
            _verify_owned_static_descriptor(context)
            return context
    return None


def _active_owned_descriptor_accessor(
    accessor: object,
    *,
    budget: _TargetIdentityBudget,
) -> _OwnedDescriptorAccessor | None:
    bindings = budget.owned_descriptor_accessors.get(builtins.id(accessor), ())
    for binding in reversed(bindings):
        if binding.accessor is not accessor:
            continue
        context = _active_owned_static_descriptor(
            binding.descriptor,
            budget=budget,
        )
        if context is None:
            continue
        if any(
            slot == binding.slot and selected is accessor
            for slot, selected in context.accessors
        ):
            return binding
    return None


def _update_code_object(
    digest: Any,
    code: CodeType,
    *,
    budget: _TargetIdentityBudget,
    depth: int,
) -> None:
    _consume_target_budget(budget, depth=depth, code=True)
    _digest_field(digest, b"code")
    for value in (
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
    ):
        _digest_field(digest, value.to_bytes(8, "big", signed=False))
    for name in (code.co_name, code.co_qualname):
        encoded = name.encode("utf-8")
        _consume_target_bytes(budget, len(encoded))
        _digest_field(digest, encoded)
    _digest_field(digest, code.co_firstlineno.to_bytes(8, "big", signed=False))
    for values in (code.co_names, code.co_varnames, code.co_freevars, code.co_cellvars):
        _digest_field(digest, len(values).to_bytes(8, "big", signed=False))
        for value in values:
            encoded = value.encode("utf-8")
            _consume_target_bytes(budget, len(encoded))
            _digest_field(digest, encoded)
    for encoded in (code.co_code, code.co_exceptiontable, code.co_linetable):
        _consume_target_bytes(budget, len(encoded))
        _digest_field(digest, encoded)
    _digest_field(digest, len(code.co_consts).to_bytes(8, "big", signed=False))
    for value in code.co_consts:
        _update_stable_value(digest, value, budget=budget, depth=depth + 1)


def _snapshot_runtime_dict(
    value: dict[Any, Any],
    *,
    budget: _TargetIdentityBudget,
    depth: int,
    label: str,
) -> tuple[tuple[Any, Any], ...]:
    """Capture an exact dict while enforcing the work bound incrementally."""

    retained: list[tuple[Any, Any]] = []
    try:
        expected_count = len(value)
        _consume_target_nodes(budget, count=expected_count, depth=depth)
        for key, item in value.items():
            if len(retained) >= expected_count:
                raise PluginExecutableIdentityError(
                    f"{label} changed while fingerprinting"
                )
            retained.append((key, item))
        if len(retained) != expected_count:
            raise PluginExecutableIdentityError(
                f"{label} changed while fingerprinting"
            )
    except RuntimeError as error:
        raise PluginExecutableIdentityError(
            f"{label} changed while fingerprinting"
        ) from error
    return tuple(retained)


def _update_runtime_defaults(
    digest: Any,
    value: tuple[Any, ...] | None,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
    label: str,
) -> None:
    if value is None:
        _digest_field(digest, f"{label}:none".encode())
        return
    if type(value) is not tuple:
        raise PluginExecutableIdentityError(
            f"module target {label} are not canonical values"
        )
    _digest_field(digest, label.encode("utf-8"))
    _update_global_reference(
        digest,
        value,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth,
    )


def _update_runtime_mapping(
    digest: Any,
    value: dict[str, Any] | None,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
    label: str,
) -> None:
    if value is None:
        _digest_field(digest, f"{label}:none".encode())
        return
    if type(value) is not dict:
        raise PluginExecutableIdentityError(
            f"module target {label} do not have canonical names"
        )
    snapshot = _snapshot_runtime_dict(
        value,
        budget=budget,
        depth=depth,
        label=f"module target {label}",
    )
    if any(type(key) is not str for key, _item in snapshot):
        raise PluginExecutableIdentityError(
            f"module target {label} do not have canonical names"
        )
    _digest_field(digest, label.encode("utf-8"))
    for key, item in sorted(snapshot):
        encoded = key.encode("utf-8")
        _consume_target_bytes(budget, len(encoded))
        _digest_field(digest, encoded)
        _update_global_reference(
            digest,
            item,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
    _verify_dict_snapshot(value, snapshot)


def _update_annotation_shape(
    digest: Any,
    value: dict[str, Any],
    *,
    budget: _TargetIdentityBudget,
) -> None:
    if type(value) is not dict:
        raise PluginExecutableIdentityError(
            "module target annotations do not have canonical names"
        )
    snapshot = _snapshot_runtime_dict(
        value,
        budget=budget,
        depth=1,
        label="module target annotations",
    )
    if any(type(key) is not str for key, _item in snapshot):
        raise PluginExecutableIdentityError(
            "module target annotations do not have canonical names"
        )
    _digest_field(digest, b"annotation-names")
    for key, _item in sorted(snapshot):
        encoded = key.encode("utf-8")
        _consume_target_bytes(budget, len(encoded))
        _digest_field(digest, encoded)
    _verify_dict_snapshot(value, snapshot)


def _update_stable_value(
    digest: Any,
    value: object,
    *,
    budget: _TargetIdentityBudget,
    depth: int,
) -> None:
    _consume_target_budget(budget, depth=depth)
    if value is None:
        _digest_field(digest, b"none")
    elif value is Ellipsis:
        _digest_field(digest, b"ellipsis")
    elif value is NotImplemented:
        _digest_field(digest, b"not-implemented")
    elif type(value) is bool:
        _digest_field(digest, b"bool:1" if value else b"bool:0")
    elif type(value) is int:
        if value.bit_length() > _MAX_TARGET_VALUE_BYTES * 8:
            raise PluginExecutableIdentityError(
                "module target contains an oversized runtime integer"
            )
        encoded = str(value).encode("ascii")
        _consume_target_bytes(budget, len(encoded))
        _digest_field(digest, b"int")
        _digest_field(digest, encoded)
    elif type(value) is float:
        _digest_field(digest, b"float")
        _digest_field(digest, struct.pack(">d", value))
    elif type(value) is complex:
        _digest_field(digest, b"complex")
        _digest_field(digest, struct.pack(">dd", value.real, value.imag))
    elif type(value) is str:
        if len(value) > _MAX_TARGET_VALUE_BYTES:
            raise PluginExecutableIdentityError(
                "module target contains an oversized runtime string"
            )
        encoded = value.encode("utf-8")
        _consume_target_bytes(budget, len(encoded))
        _digest_field(digest, b"str")
        _digest_field(digest, encoded)
    elif type(value) is bytes:
        _consume_target_bytes(budget, len(value))
        _digest_field(digest, b"bytes")
        _digest_field(digest, value)
    elif type(value) is tuple:
        _digest_field(digest, b"tuple")
        _digest_field(digest, len(value).to_bytes(8, "big", signed=False))
        for item in value:
            _update_stable_value(digest, item, budget=budget, depth=depth + 1)
    elif type(value) is frozenset:
        _digest_field(digest, b"frozenset")
        item_digests: list[bytes] = []
        for item in value:
            item_digest = hashlib.sha256()
            _update_stable_value(
                item_digest,
                item,
                budget=budget,
                depth=depth + 1,
            )
            item_digests.append(item_digest.digest())
        for encoded in sorted(item_digests):
            _digest_field(digest, encoded)
    elif type(value) is CodeType:
        _update_code_object(digest, value, budget=budget, depth=depth + 1)
    else:
        raise PluginExecutableIdentityError(
            "module target contains a mutable or unsupported runtime value"
        )


def _update_runtime_dict(
    digest: Any,
    value: dict[object, object],
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    _consume_target_budget(budget, depth=depth)
    object_key = id(value)
    cached = budget.object_cache.get(object_key)
    if cached is not None:
        _verify_cached_object_snapshot(value, budget=budget)
        _digest_field(digest, b"cached-dict")
        _digest_field(digest, cached.encode("ascii"))
        return
    if object_key in budget.active_objects:
        raise PluginExecutableIdentityError(
            "module target contains cyclic mutable runtime state"
        )
    budget.active_objects.add(object_key)
    try:
        try:
            items = tuple(value.items())
        except RuntimeError as error:
            raise PluginExecutableIdentityError(
                "module target runtime mapping changed while fingerprinting"
            ) from error
        result_digest = hashlib.sha256()
        result_digest.update(_CALLABLE_CODE_FINGERPRINT_SCHEMA)
        _digest_field(result_digest, b"runtime-dict")
        _digest_field(
            result_digest,
            len(items).to_bytes(8, "big", signed=False),
        )
        encoded_items: list[tuple[bytes, bytes]] = []
        for key, item in items:
            key_digest = hashlib.sha256()
            _update_global_reference(
                key_digest,
                key,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
            item_digest = hashlib.sha256()
            _update_global_reference(
                item_digest,
                item,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
            encoded_items.append((key_digest.digest(), item_digest.digest()))
        for key_digest, item_digest in sorted(encoded_items):
            _digest_field(result_digest, key_digest)
            _digest_field(result_digest, item_digest)
        _verify_dict_snapshot(value, items)
        result = result_digest.hexdigest()
        budget.object_cache[object_key] = result
        budget.object_refs[object_key] = value
        budget.object_snapshots[object_key] = items
        _digest_field(digest, b"dict")
        _digest_field(digest, result.encode("ascii"))
    finally:
        budget.active_objects.discard(object_key)


def _update_runtime_list(
    digest: Any,
    value: list[object],
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    _consume_target_budget(budget, depth=depth)
    object_key = id(value)
    if object_key in budget.active_objects:
        raise PluginExecutableIdentityError(
            "module target contains cyclic mutable runtime state"
        )
    budget.active_objects.add(object_key)
    try:
        snapshot = tuple(value)
        _digest_field(digest, b"runtime-list")
        _digest_field(digest, len(snapshot).to_bytes(8, "big", signed=False))
        for item in snapshot:
            _update_global_reference(
                digest,
                item,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
        if len(value) != len(snapshot) or any(
            current is not selected
            for current, selected in zip(value, snapshot, strict=True)
        ):
            raise PluginExecutableIdentityError(
                "module target runtime list changed while fingerprinting"
            )
    finally:
        budget.active_objects.discard(object_key)


def _update_bound_native_method(
    digest: Any,
    value: object,
    *,
    receiver: object,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    _consume_target_budget(budget, depth=depth)
    name = getattr(value, "__name__", None)
    qualified_name = getattr(value, "__qualname__", None)
    if type(name) is not str or not name or type(qualified_name) is not str:
        raise PluginExecutableIdentityError(
            "module target references an unverifiable bound native method"
        )
    try:
        descriptor = inspect.getattr_static(type(receiver), name)
    except (AttributeError, TypeError) as error:
        raise PluginExecutableIdentityError(
            "module target references a dynamic bound native method"
        ) from error
    if not (
        inspect.ismethoddescriptor(descriptor)
        or inspect.isbuiltin(descriptor)
        or inspect.ismemberdescriptor(descriptor)
    ):
        raise PluginExecutableIdentityError(
            "module target references an unverifiable bound native descriptor"
        )
    _update_exact_object_token(digest, descriptor, budget=budget)
    _digest_field(digest, b"bound-native-method")
    _digest_field(digest, name.encode("utf-8"))
    _digest_field(digest, qualified_name.encode("utf-8"))
    _update_global_reference(
        digest,
        receiver,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth + 1,
    )


def _instance_runtime_identity(
    value: object,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
    allow_declared_implementation: bool = False,
) -> str:
    _consume_target_budget(budget, depth=depth)
    object_key = id(value)
    cached = budget.object_cache.get(object_key)
    if cached is not None:
        _verify_cached_object_snapshot(value, budget=budget)
        return cached
    if object_key in budget.active_objects:
        raise PluginExecutableIdentityError(
            "module target contains cyclic instance runtime state"
        )
    implementation = type(value)
    module_name = getattr(implementation, "__module__", None)
    qualified_name = getattr(implementation, "__qualname__", None)
    if (
        type(module_name) is not str
        or not module_name
        or type(qualified_name) is not str
        or not qualified_name
    ):
        raise PluginExecutableIdentityError(
            "module target instance has no exact implementation provenance"
        )
    module = sys.modules.get(module_name)
    if not isinstance(module, ModuleType):
        raise PluginExecutableIdentityError(
            "module target instance implementation module is unavailable"
        )
    module_source = _module_file_source_path(module, budget=budget)
    implementation_source = _object_source_path(implementation, budget=budget)
    spec = getattr(module, "__spec__", None)
    native_origin = getattr(spec, "origin", None)
    native_exports = (
        _native_export_names(
            module,
            implementation,
            budget=budget,
            depth=depth + 1,
        )
        if native_origin in {"built-in", "frozen"}
        else ()
    )
    declared_implementation = (
        allow_declared_implementation
        and module_source is not None
        and implementation_source is not None
        and implementation_source == module_source
        and len(
            _declared_code_objects(
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=module_source,
                budget=budget,
            )
        )
        == 1
    )
    if (
        _static_import_target(module, qualified_name) is not implementation
        and not (
            native_origin in {"built-in", "frozen"}
            and native_exports
        )
        and not budget.allow_unbound_source_objects
        and not declared_implementation
    ):
        raise PluginExecutableIdentityError(
            "module target instance implementation is dynamically selected"
        )
    source_backed = (
        module_source is not None
        and implementation_source is not None
        and implementation_source == module_source
    )
    native_built_in = (
        module_source is None
        and implementation_source is None
        and native_origin in {"built-in", "frozen"}
    )
    if not (source_backed or native_built_in):
        raise PluginExecutableIdentityError(
            "module target instance implementation is unverifiable"
        )
    budget.active_objects.add(object_key)
    try:
        result_digest = hashlib.sha256()
        result_digest.update(_CALLABLE_CODE_FINGERPRINT_SCHEMA)
        _update_exact_object_token(result_digest, value, budget=budget)
        _update_exact_object_token(result_digest, implementation, budget=budget)
        _digest_field(result_digest, b"runtime-instance")
        _digest_field(result_digest, module_name.encode("utf-8"))
        _digest_field(result_digest, qualified_name.encode("utf-8"))
        python_class = False
        if source_backed:
            assert module_source is not None
            _digest_field(
                result_digest,
                _cached_scope_identity(
                    module_name,
                    module_source,
                    scope_cache,
                ).encode("ascii"),
            )
            declared = _declared_code_objects(
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=module_source,
                budget=budget,
            )
            if len(declared) == 1:
                python_class = True
                _digest_field(
                    result_digest,
                    _class_runtime_identity(
                        implementation,
                        module_name=module_name,
                        qualified_name=qualified_name,
                        source_path=module_source,
                        budget=budget,
                        scope_cache=scope_cache,
                        callable_cache=callable_cache,
                        active_callables=active_callables,
                        class_cache=budget.class_cache,
                        active_classes=budget.active_classes,
                        identity_root=identity_root,
                        depth=depth + 1,
                        allow_declared_implementation=declared_implementation,
                    ).encode("ascii"),
                )
            elif declared:
                raise PluginExecutableIdentityError(
                    "module target instance class declaration is ambiguous"
                )
            else:
                _digest_field(result_digest, b"native-exported-class")
        else:
            _digest_field(result_digest, str(native_origin).encode("ascii"))
            for export_name in native_exports:
                _digest_field(result_digest, export_name.encode("utf-8"))

        state = _instance_dictionary_state(value)
        snapshot: tuple[tuple[object, object], ...] = ()
        state_members = 0
        if state is not None:
            snapshot = cast(
                tuple[tuple[str, object], ...],
                _snapshot_runtime_dict(
                    state,
                    budget=budget,
                    depth=depth + 1,
                    label="module target instance state",
                ),
            )
            if any(type(name) is not str for name, _item in snapshot):
                raise PluginExecutableIdentityError(
                    "module target instance has noncanonical state names"
                )
            _digest_field(result_digest, b"instance-dict")
            for name, item in sorted(snapshot):
                encoded = name.encode("utf-8")
                _consume_target_bytes(budget, len(encoded))
                _digest_field(result_digest, encoded)
                _update_global_reference(
                    result_digest,
                    item,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
                state_members += 1
            _verify_dict_snapshot(state, snapshot)

        seen_state_names = {
            name for name, _item in snapshot if type(name) is str
        }
        for name, descriptor in _instance_state_descriptors(implementation):
            if name in seen_state_names:
                continue
            try:
                item = descriptor.__get__(value, implementation)
            except AttributeError:
                continue
            except Exception as error:
                raise PluginExecutableIdentityError(
                    "module target instance descriptor state is unverifiable"
                ) from error
            _digest_field(result_digest, b"instance-slot")
            _digest_field(result_digest, name.encode("utf-8"))
            _update_global_reference(
                result_digest,
                item,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
            state_members += 1
        if not python_class and state is None and state_members == 0:
            raise PluginExecutableIdentityError(
                "module target references opaque native instance state"
            )
        result = result_digest.hexdigest()
        budget.object_cache[object_key] = result
        budget.object_refs[object_key] = value
        if state is not None:
            budget.object_snapshots[object_key] = snapshot
        return result
    finally:
        budget.active_objects.discard(object_key)


def _instance_dictionary_state(value: object) -> dict[str, object] | None:
    try:
        state = object.__getattribute__(value, "__dict__")
    except AttributeError:
        return None
    except Exception as error:
        raise PluginExecutableIdentityError(
            "module target instance dictionary state is unverifiable"
        ) from error
    if type(state) is not dict:
        raise PluginExecutableIdentityError(
            "module target instance dictionary state is noncanonical"
        )
    return state


def _instance_state_descriptors(
    implementation: type[object],
) -> tuple[tuple[str, object], ...]:
    selected: dict[str, object] = {}
    for owner in reversed(implementation.__mro__):
        for name, descriptor in vars(owner).items():
            if name in {"__class__", "__dict__", "__weakref__"}:
                continue
            if inspect.ismemberdescriptor(descriptor) or inspect.isgetsetdescriptor(
                descriptor
            ):
                selected[name] = descriptor
    return tuple(sorted(selected.items()))


def _verify_dict_snapshot(
    value: dict[Any, Any],
    snapshot: tuple[tuple[Any, Any], ...],
) -> None:
    _verify_exact_mapping_snapshot(
        value,
        snapshot,
        label="module target runtime mapping",
    )


def _verify_exact_mapping_snapshot(
    value: Any,
    snapshot: tuple[tuple[Any, Any], ...],
    *,
    label: str,
) -> None:
    """Verify mapping entries by exact key/value identity and iteration order."""

    missing = object()
    try:
        if len(value) != len(snapshot):
            raise PluginExecutableIdentityError(
                f"{label} changed while fingerprinting"
            )
        current = iter(value.items())
        for selected_key, selected_item in snapshot:
            pair = next(current, missing)
            if pair is missing:
                raise PluginExecutableIdentityError(
                    f"{label} changed while fingerprinting"
                )
            current_key, current_item = pair
            if current_key is not selected_key or current_item is not selected_item:
                raise PluginExecutableIdentityError(
                    f"{label} changed while fingerprinting"
                )
        if next(current, missing) is not missing:
            raise PluginExecutableIdentityError(
                f"{label} changed while fingerprinting"
            )
    except (RuntimeError, TypeError) as error:
        raise PluginExecutableIdentityError(
            f"{label} changed while fingerprinting"
        ) from error


def _same_exact_unordered_objects(
    current: tuple[object, ...],
    expected: tuple[object, ...],
) -> bool:
    """Compare retained objects as an unordered collection using only identity."""

    if len(current) != len(expected):
        return False
    expected_by_identity = {builtins.id(item): item for item in expected}
    if len(expected_by_identity) != len(expected):
        return False
    missing = object()
    for item in current:
        selected = expected_by_identity.pop(builtins.id(item), missing)
        if selected is missing or selected is not item:
            return False
    return not expected_by_identity


def _verify_cached_object_snapshot(
    value: object,
    *,
    budget: _TargetIdentityBudget,
) -> None:
    object_key = id(value)
    if budget.object_refs.get(object_key) is not value:
        raise PluginExecutableIdentityError(
            "module target runtime identity cache is inconsistent"
        )
    snapshot = budget.object_snapshots.get(object_key)
    if snapshot is None:
        return
    state = value if type(value) is dict else _instance_dictionary_state(value)
    if state is None:
        raise PluginExecutableIdentityError(
            "module target instance state changed while fingerprinting"
        )
    _verify_dict_snapshot(state, snapshot)


def _is_canonical_lru_cache_wrapper(value: object) -> bool:
    module = sys.modules.get("functools")
    return (
        isinstance(module, ModuleType)
        and inspect.isclass(vars(module).get("_lru_cache_wrapper"))
        and type(value) is vars(module)["_lru_cache_wrapper"]
    )


def _update_lru_cache_wrapper_reference(
    digest: Any,
    value: object,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    """Bind an LRU wrapper's function/configuration, excluding cache history."""

    _consume_target_budget(budget, depth=depth)
    object_key = id(value)
    cached = budget.object_cache.get(object_key)
    if cached is not None:
        _verify_cached_object_snapshot(value, budget=budget)
        _digest_field(digest, b"cached-lru-wrapper")
        _digest_field(digest, cached.encode("ascii"))
        return
    if object_key in budget.active_objects:
        _digest_field(digest, b"lru-wrapper-cycle")
        _update_exact_object_token(digest, value, budget=budget)
        return
    module = sys.modules.get("functools")
    module_source = (
        _module_file_source_path(module, budget=budget)
        if isinstance(module, ModuleType)
        else None
    )
    if (
        not isinstance(module, ModuleType)
        or module_source is None
        or type(value) is not vars(module).get("_lru_cache_wrapper")
    ):
        raise PluginExecutableIdentityError(
            "module target references an unverifiable LRU cache wrapper"
        )
    state = _instance_dictionary_state(value)
    if state is None:
        raise PluginExecutableIdentityError(
            "module target LRU cache wrapper has no inspectable configuration"
        )
    snapshot = _snapshot_runtime_dict(
        state,
        budget=budget,
        depth=depth + 1,
        label="module target LRU cache wrapper",
    )
    wrapped = state.get("__wrapped__")
    cache_parameters = state.get("cache_parameters")
    if type(wrapped) is not FunctionType or type(cache_parameters) is not FunctionType:
        raise PluginExecutableIdentityError(
            "module target LRU cache wrapper configuration is unverifiable"
        )
    wrapped_module_name = getattr(wrapped, "__module__", None)
    wrapped_name = getattr(wrapped, "__qualname__", None)
    wrapped_module = sys.modules.get(wrapped_module_name)
    wrapped_source = _object_source_path(wrapped, budget=budget)
    cache_parameters_source = _object_source_path(cache_parameters, budget=budget)
    if (
        type(wrapped_module_name) is not str
        or type(wrapped_name) is not str
        or not isinstance(wrapped_module, ModuleType)
        or wrapped_source is None
        or cache_parameters.__globals__ is not vars(module)
        or cache_parameters_source != module_source
    ):
        raise PluginExecutableIdentityError(
            "module target LRU cache wrapper functions are unverifiable"
        )
    budget.active_objects.add(object_key)
    try:
        result_digest = hashlib.sha256()
        result_digest.update(_CALLABLE_CODE_FINGERPRINT_SCHEMA)
        _update_exact_object_token(result_digest, value, budget=budget)
        _digest_field(result_digest, b"lru-cache-wrapper")
        _digest_field(
            result_digest,
            _cached_scope_identity(
                "functools",
                module_source,
                scope_cache,
            ).encode("ascii"),
        )
        _digest_field(
            result_digest,
            _external_function_leaf_identity(
                cache_parameters,
                module=module,
                module_name="functools",
                qualified_name=cache_parameters.__qualname__,
                source_path=module_source,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            ).encode("ascii"),
        )
        wrapped_module_source = _module_file_source_path(
            wrapped_module,
            budget=budget,
        )
        if wrapped_module_source is None or wrapped_source != wrapped_module_source:
            raise PluginExecutableIdentityError(
                "module target LRU cache wrapped function is unverifiable"
            )
        _digest_field(
            result_digest,
            _external_function_leaf_identity(
                wrapped,
                module=wrapped_module,
                module_name=wrapped_module_name,
                qualified_name=wrapped_name,
                source_path=wrapped_module_source,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            ).encode("ascii"),
        )
        for name, item in sorted(snapshot):
            if name in {"__wrapped__", "cache_parameters"}:
                continue
            if type(name) is not str:
                raise PluginExecutableIdentityError(
                    "module target LRU cache wrapper has noncanonical state names"
                )
            encoded = name.encode("utf-8")
            _consume_target_bytes(budget, len(encoded))
            _digest_field(result_digest, encoded)
            if name == "__annotations__":
                _update_annotation_shape(result_digest, item, budget=budget)
            else:
                _update_global_reference(
                    result_digest,
                    item,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
        _verify_dict_snapshot(state, snapshot)
        result = result_digest.hexdigest()
        budget.object_cache[object_key] = result
        budget.object_refs[object_key] = value
        budget.object_snapshots[object_key] = snapshot
        _digest_field(digest, b"lru-wrapper")
        _digest_field(digest, result.encode("ascii"))
    finally:
        budget.active_objects.discard(object_key)


def _update_global_reference(
    digest: Any,
    value: object,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    if _is_executable_authority(value):
        _update_exact_object_token(digest, value, budget=budget)
    if (
        value is None
        or value is NotImplemented
        or type(value) in {bool, int, float, complex, str, bytes}
    ):
        _update_stable_value(digest, value, budget=budget, depth=depth)
        return
    if type(value) is slice:
        _consume_target_budget(budget, depth=depth)
        _digest_field(digest, b"slice")
        for item in (value.start, value.stop, value.step):
            _update_global_reference(
                digest,
                item,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
        return
    if type(value) in {tuple, frozenset}:
        _consume_target_budget(budget, depth=depth)
        _digest_field(digest, type(value).__name__.encode("ascii"))
        encoded_items: list[bytes] = []
        for item in value:
            item_digest = hashlib.sha256()
            _update_global_reference(
                item_digest,
                item,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
            encoded_items.append(item_digest.digest())
        if type(value) is frozenset:
            encoded_items.sort()
        for encoded in encoded_items:
            _digest_field(digest, encoded)
        return
    if isinstance(value, tuple):
        implementation = type(value)
        module_name = getattr(implementation, "__module__", None)
        module = sys.modules.get(module_name)
        native_origin = (
            getattr(getattr(module, "__spec__", None), "origin", None)
            if isinstance(module, ModuleType)
            else None
        )
        native_exports = (
            _native_export_names(
                module,
                value,
                budget=budget,
                depth=depth + 1,
            )
            if isinstance(module, ModuleType)
            and native_origin in {"built-in", "frozen"}
            else ()
        )
        if native_exports:
            _consume_target_budget(budget, depth=depth)
            snapshot = tuple(value)
            _digest_field(digest, b"native-tuple-singleton")
            _digest_field(digest, module_name.encode("utf-8"))
            _digest_field(digest, implementation.__qualname__.encode("utf-8"))
            _digest_field(digest, str(native_origin).encode("ascii"))
            for export_name in native_exports:
                _digest_field(digest, export_name.encode("utf-8"))
            for item in snapshot:
                _update_global_reference(
                    digest,
                    item,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
            current = tuple(value)
            if len(current) != len(snapshot) or any(
                current_item is not selected_item
                for current_item, selected_item in zip(
                    current,
                    snapshot,
                    strict=True,
                )
            ):
                raise PluginExecutableIdentityError(
                    "module target native tuple changed while fingerprinting"
                )
            return
    if type(value) is MappingProxyType:
        _consume_target_budget(budget, depth=depth)
        object_key = id(value)
        if object_key in budget.active_objects:
            _digest_field(digest, b"mapping-proxy-cycle")
            return
        budget.active_objects.add(object_key)
        try:
            try:
                snapshot = tuple(value.items())
            except RuntimeError as error:
                raise PluginExecutableIdentityError(
                    "module target mapping proxy changed while fingerprinting"
                ) from error
            _digest_field(digest, b"mapping-proxy")
            encoded_items: list[tuple[bytes, bytes]] = []
            for key, item in snapshot:
                key_digest = hashlib.sha256()
                _update_global_reference(
                    key_digest,
                    key,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
                item_digest = hashlib.sha256()
                _update_global_reference(
                    item_digest,
                    item,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
                encoded_items.append((key_digest.digest(), item_digest.digest()))
            for key_digest, item_digest in sorted(encoded_items):
                _digest_field(digest, key_digest)
                _digest_field(digest, item_digest)
            _verify_exact_mapping_snapshot(
                value,
                snapshot,
                label="module target mapping proxy",
            )
        finally:
            budget.active_objects.discard(object_key)
        return
    if type(value) is set:
        _consume_target_budget(budget, depth=depth)
        try:
            snapshot = tuple(value)
        except RuntimeError as error:
            raise PluginExecutableIdentityError(
                "module target runtime set changed while fingerprinting"
            ) from error
        _digest_field(digest, b"runtime-set")
        encoded_items: list[bytes] = []
        for item in snapshot:
            item_digest = hashlib.sha256()
            _update_global_reference(
                item_digest,
                item,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
            encoded_items.append(item_digest.digest())
        for encoded in sorted(encoded_items):
            _digest_field(digest, encoded)
        try:
            current = tuple(value)
        except RuntimeError as error:
            raise PluginExecutableIdentityError(
                "module target runtime set changed while fingerprinting"
            ) from error
        if not _same_exact_unordered_objects(current, snapshot):
            raise PluginExecutableIdentityError(
                "module target runtime set changed while fingerprinting"
            )
        return
    if type(value) is dict:
        _update_runtime_dict(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth,
        )
        return
    if type(value) is list:
        _update_runtime_list(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth,
        )
        return
    if _is_canonical_lru_cache_wrapper(value):
        _update_lru_cache_wrapper_reference(
            digest,
            value,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth,
        )
        return
    if isinstance(value, ModuleType):
        _consume_target_budget(budget, depth=depth)
        name = getattr(value, "__name__", None)
        if type(name) is not str or not name or sys.modules.get(name) is not value:
            raise PluginExecutableIdentityError(
                "module target references an unverifiable module global"
            )
        _digest_field(digest, b"module")
        _digest_field(digest, name.encode("utf-8"))
        source = _module_file_source_path(value, budget=budget)
        if source is None:
            spec = getattr(value, "__spec__", None)
            origin = getattr(spec, "origin", None)
            if origin not in {"built-in", "frozen"}:
                raise PluginExecutableIdentityError(
                    "module target references a sourceless module global"
                )
            _digest_field(digest, str(origin).encode("ascii"))
        else:
            _digest_field(
                digest,
                _cached_scope_identity(name, source, scope_cache).encode("ascii"),
             )
        return
    if is_dataclass(value) and not inspect.isclass(value):
        implementation = type(value)
        parameters = getattr(implementation, "__dataclass_params__", None)
        if parameters is None or parameters.frozen is not True:
            raise PluginExecutableIdentityError(
                "module target references a mutable dataclass global"
            )
        implementation_module = getattr(implementation, "__module__", None)
        implementation_name = getattr(implementation, "__qualname__", None)
        module = sys.modules.get(implementation_module)
        implementation_source = _object_source_path(implementation, budget=budget)
        module_source = (
            _module_file_source_path(module, budget=budget)
            if isinstance(module, ModuleType)
            else None
        )
        if (
            type(implementation_module) is not str
            or type(implementation_name) is not str
            or not isinstance(module, ModuleType)
            or _static_import_target(module, implementation_name) is not implementation
            or implementation_source is None
            or module_source is None
            or implementation_source != module_source
        ):
            raise PluginExecutableIdentityError(
                "module target references an unverifiable dataclass global"
            )
        _consume_target_budget(budget, depth=depth)
        _digest_field(digest, b"frozen-dataclass")
        _digest_field(digest, implementation_module.encode("utf-8"))
        _digest_field(digest, implementation_name.encode("utf-8"))
        _digest_field(
            digest,
            _cached_scope_identity(
                implementation_module,
                module_source,
                scope_cache,
            ).encode("ascii"),
        )
        for item in dataclass_fields(value):
            _digest_field(digest, item.name.encode("utf-8"))
            _update_global_reference(
                digest,
                object.__getattribute__(value, item.name),
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
        return
    if inspect.ismethod(value):
        function = value.__func__
        receiver = value.__self__
        if type(function) is not FunctionType or receiver is None:
            raise PluginExecutableIdentityError(
                "module target references an unverifiable bound method"
            )
        _consume_target_budget(budget, depth=depth)
        _digest_field(digest, b"bound-python-method")
        _update_global_reference(
            digest,
            function,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
        if id(receiver) in budget.active_objects:
            receiver_type = type(receiver)
            _digest_field(digest, b"active-bound-receiver")
            _digest_field(digest, receiver_type.__module__.encode("utf-8"))
            _digest_field(digest, receiver_type.__qualname__.encode("utf-8"))
        else:
            _update_global_reference(
                digest,
                receiver,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
        return
    descriptor_owner = getattr(value, "__objclass__", None)
    descriptor_name = getattr(value, "__name__", None)
    if (
        inspect.ismethoddescriptor(value)
        and inspect.isclass(descriptor_owner)
        and type(descriptor_name) is str
        and descriptor_name
    ):
        owner = descriptor_owner
        name = descriptor_name
        try:
            selected_descriptor = inspect.getattr_static(owner, name)
        except (AttributeError, TypeError) as error:
            raise PluginExecutableIdentityError(
                "module target references a dynamic native descriptor"
            ) from error
        if selected_descriptor is not value:
            raise PluginExecutableIdentityError(
                "module target references a replaced native descriptor"
            )
        _consume_target_budget(budget, depth=depth)
        _digest_field(digest, b"native-method-descriptor")
        _digest_field(digest, name.encode("utf-8"))
        _update_global_reference(
            digest,
            owner,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
        return
    if inspect.isbuiltin(value) and getattr(value, "__self__", None) is not None:
        receiver = value.__self__
        if not isinstance(receiver, ModuleType):
            _update_bound_native_method(
                digest,
                value,
                receiver=receiver,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth,
            )
            return
    if inspect.isbuiltin(value):
        reference_module = getattr(value, "__module__", None)
        reference_name = getattr(value, "__qualname__", None)
        if (
            type(reference_module) is not str
            or type(reference_name) is not str
            or not reference_name
            or "." in reference_name
        ):
            raise PluginExecutableIdentityError(
                "module target references an unverifiable built-in global "
                f"of type {reference_name}"
            )
        reference_module_value = sys.modules.get(reference_module)
        if reference_module == "builtins":
            if vars(builtins).get(reference_name) is not value:
                raise PluginExecutableIdentityError(
                    "module target references an unverifiable built-in global"
                )
        elif (
            not isinstance(reference_module_value, ModuleType)
            or vars(reference_module_value).get(reference_name) is not value
        ):
            raise PluginExecutableIdentityError(
                "module target references an unverifiable native global"
            )
        _consume_target_budget(budget, depth=depth)
        _digest_field(digest, b"built-in")
        _digest_field(digest, reference_module.encode("utf-8"))
        _digest_field(digest, reference_name.encode("utf-8"))
        if isinstance(reference_module_value, ModuleType):
            source = _module_file_source_path(
                reference_module_value,
                budget=budget,
            )
            if source is not None:
                _digest_field(
                    digest,
                    _cached_scope_identity(
                        reference_module,
                        source,
                        scope_cache,
                    ).encode("ascii"),
                )
        return
    if isinstance(value, Enum):
        owner = type(value)
        owner_module = getattr(owner, "__module__", None)
        owner_name = getattr(owner, "__qualname__", None)
        member_name = getattr(value, "name", None)
        if (
            type(owner_module) is not str
            or type(owner_name) is not str
            or type(member_name) is not str
            or type(owner.__members__) is not MappingProxyType
            or owner.__members__.get(member_name) is not value
        ):
            raise PluginExecutableIdentityError(
                "module target references an unverifiable enumeration member"
            )
        owner_module_value = sys.modules.get(owner_module)
        owner_source = _object_source_path(owner, budget=budget)
        module_source = (
            _module_file_source_path(owner_module_value, budget=budget)
            if isinstance(owner_module_value, ModuleType)
            else None
        )
        if (
            not isinstance(owner_module_value, ModuleType)
            or _static_import_target(owner_module_value, owner_name) is not owner
            or owner_source is None
            or module_source is None
            or owner_source != module_source
        ):
            raise PluginExecutableIdentityError(
                "module target references an unverifiable enumeration type"
            )
        _digest_field(digest, b"enumeration-member")
        _digest_field(digest, owner_module.encode("utf-8"))
        _digest_field(digest, owner_name.encode("utf-8"))
        _digest_field(digest, member_name.encode("utf-8"))
        _digest_field(
            digest,
            _cached_scope_identity(
                owner_module,
                module_source,
                scope_cache,
            ).encode("ascii"),
        )
        _update_stable_value(digest, value.value, budget=budget, depth=depth + 1)
        return
    descriptor_accessors = _descriptor_accessor_snapshot(value)
    owned_static_descriptor = _active_owned_static_descriptor(
        value,
        budget=budget,
    )
    if (
        not budget.allow_unbound_source_objects
        and descriptor_accessors is not None
        and owned_static_descriptor is None
    ):
        raise PluginExecutableIdentityError(
            "module target references an unowned descriptor alias"
        )
    _consume_target_budget(budget, depth=depth)
    reference_type = value if inspect.isclass(value) else type(value)
    if type(value) is FunctionType or inspect.isclass(value):
        reference_type = value
    reference_module = getattr(reference_type, "__module__", None)
    reference_name = getattr(reference_type, "__qualname__", None)
    if (
        type(reference_module) is not str
        or type(reference_name) is not str
        or not reference_module
        or not reference_name
    ):
        raise PluginExecutableIdentityError(
            "module target references an unsafe global value"
        )
    _consume_target_bytes(
        budget,
        len(reference_module.encode("utf-8"))
        + len(reference_name.encode("utf-8")),
    )
    _digest_field(digest, b"reference")
    _digest_field(digest, reference_module.encode("utf-8"))
    _digest_field(digest, reference_name.encode("utf-8"))
    if reference_module == "builtins":
        canonical_class = (
            inspect.isclass(value)
            and vars(builtins).get(reference_name) is value
        )
        owned_descriptor_instance = (
            owned_static_descriptor is not None
            and vars(builtins).get(reference_name) is reference_type
        )
        if not (canonical_class or owned_descriptor_instance):
            raise PluginExecutableIdentityError(
                "module target references an unverifiable built-in global "
                f"of type {reference_name}"
            )
        if canonical_class:
            return
    reference_module_value = sys.modules.get(reference_module)
    reference_source = _object_source_path(reference_type, budget=budget)
    module_source = (
        _module_file_source_path(reference_module_value, budget=budget)
        if isinstance(reference_module_value, ModuleType)
        else None
    )
    spec = (
        getattr(reference_module_value, "__spec__", None)
        if isinstance(reference_module_value, ModuleType)
        else None
    )
    native_origin = getattr(spec, "origin", None)
    native_exports = (
        _native_export_names(
            reference_module_value,
            reference_type,
            budget=budget,
            depth=depth + 1,
        )
        if isinstance(reference_module_value, ModuleType)
        and native_origin in {"built-in", "frozen"}
        else ()
    )
    has_static_provenance = (
        isinstance(reference_module_value, ModuleType)
        and (
            _static_import_target(reference_module_value, reference_name)
            is reference_type
            or (
                native_origin in {"built-in", "frozen"}
                and bool(native_exports)
            )
        )
    )
    owned_descriptor_accessor = _active_owned_descriptor_accessor(
        value,
        budget=budget,
    )
    has_declared_unbound_provenance = (
        owned_descriptor_accessor is not None
        or (
            budget.allow_unbound_source_objects
            and isinstance(reference_module_value, ModuleType)
            and reference_source is not None
            and module_source is not None
            and reference_source == module_source
            and len(
                _declared_code_objects(
                    module_name=reference_module,
                    qualified_name=reference_name,
                    source_path=module_source,
                    budget=budget,
                )
            )
            == 1
        )
    )
    has_source_provenance = (
        reference_source is not None
        and module_source is not None
        and reference_source == module_source
        and (has_static_provenance or has_declared_unbound_provenance)
    )
    has_native_provenance = (
        has_static_provenance
        and native_origin in {"built-in", "frozen"}
    )
    if not (has_source_provenance or has_native_provenance):
        raise PluginExecutableIdentityError(
            "module target references an unverifiable global implementation"
        )
    reference_scope_identity: str | None = None
    if module_source is not None:
        reference_scope_identity = _cached_scope_identity(
            reference_module,
            module_source,
            scope_cache,
        )
        _digest_field(
            digest,
            reference_scope_identity.encode("ascii"),
        )
    else:
        _digest_field(digest, str(native_origin).encode("ascii"))
        for export_name in native_exports:
            _digest_field(digest, export_name.encode("utf-8"))
    if (
        budget.leaf_external_references
        and has_native_provenance
        and module_source is None
        and owned_static_descriptor is None
    ):
        # Native leaves have no inspectable instance state.  Importable module
        # targets must therefore stop at deterministic native provenance so a
        # spawned child can reproduce their identity.  Same-process callbacks
        # additionally bind the exact retained authority; only that entry point
        # enables exact-object tokens.
        _digest_field(digest, b"native-authority-leaf")
        if budget.bind_exact_object_tokens:
            _digest_field(digest, b"retained-native-capability")
            _update_exact_object_token(digest, value, budget=budget)
        return
    external_leaf = (
        budget.leaf_external_references
        and reference_scope_identity is not None
        and budget.root_scope_identity is not None
        and reference_scope_identity != budget.root_scope_identity
    )
    if (
        budget.external_class_member_runtime_depth > 0
        and inspect.isclass(value)
    ):
        # A member's full runtime walk separately resolves every statically
        # loaded attribute path.  Stop an unqualified class global at its exact
        # class/scope authority here so unrelated methods on utility classes do
        # not recursively expand the entire loaded application graph.
        _digest_field(digest, b"external-member-class-reference")
        return
    if external_leaf and type(value) is FunctionType:
        assert module_source is not None
        _digest_field(
            digest,
            _external_function_leaf_identity(
                value,
                module=reference_module_value,
                module_name=reference_module,
                qualified_name=reference_name,
                source_path=module_source,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            ).encode("ascii"),
        )
        return
    if external_leaf and inspect.isclass(value):
        assert module_source is not None
        _digest_field(
            digest,
            _external_class_leaf_identity(
                value,
                module_name=reference_module,
                qualified_name=reference_name,
                source_path=module_source,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            ).encode("ascii"),
        )
        return
    if external_leaf and budget.bind_exact_object_tokens:
        assert module_source is not None
        _digest_field(digest, b"retained-external-capability")
        _update_exact_object_token(digest, value, budget=budget)
        _digest_field(
            digest,
            _external_class_leaf_identity(
                reference_type,
                module_name=reference_module,
                qualified_name=reference_name,
                source_path=module_source,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            ).encode("ascii"),
        )
        return
    if type(value) is FunctionType:
        assert module_source is not None
        _digest_field(
            digest,
            _function_runtime_identity(
                value,
                module=reference_module_value,
                module_name=reference_module,
                qualified_name=reference_name,
                source_path=module_source,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                closure_owner=(
                    owned_descriptor_accessor.owner
                    if owned_descriptor_accessor is not None
                    else None
                ),
                identity_root=identity_root,
                depth=depth + 1,
            ).encode("ascii"),
        )
    elif inspect.isclass(value):
        if module_source is None:
            _digest_field(digest, b"native-exported-class")
        else:
            _digest_field(
                digest,
                _class_runtime_identity(
                    value,
                    module_name=reference_module,
                    qualified_name=reference_name,
                    source_path=module_source,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    class_cache=budget.class_cache,
                    active_classes=budget.active_classes,
                    identity_root=identity_root,
                    depth=depth + 1,
                ).encode("ascii"),
            )
    else:
        _digest_field(
            digest,
            _instance_runtime_identity(
                value,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            ).encode("ascii"),
        )


def _update_external_runtime_defaults(
    digest: Any,
    value: tuple[Any, ...] | None,
    *,
    function: FunctionType,
    module: ModuleType,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
    label: str,
) -> None:
    """Bind defaults, including source-module singleton sentinels."""

    if value is None:
        _digest_field(digest, f"{label}:none".encode())
        return
    if type(value) is not tuple:
        raise PluginExecutableIdentityError(
            f"module target {label} are not canonical values"
        )
    _digest_field(digest, label.encode("utf-8"))
    _consume_target_budget(budget, depth=depth)
    _digest_field(digest, b"tuple")
    for item in value:
        item_digest = hashlib.sha256()
        _update_external_function_owned_reference(
            item_digest,
            item,
            function=function,
            module=module,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
        _digest_field(digest, item_digest.digest())


def _update_external_runtime_mapping(
    digest: Any,
    value: dict[str, Any] | None,
    *,
    function: FunctionType,
    module: ModuleType,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
    label: str,
) -> None:
    """Bind function-owned mappings through external singleton provenance."""

    if value is None:
        _digest_field(digest, f"{label}:none".encode())
        return
    if type(value) is not dict:
        raise PluginExecutableIdentityError(
            f"module target {label} do not have canonical names"
        )
    _consume_target_budget(budget, depth=depth)
    snapshot = _snapshot_runtime_dict(
        value,
        budget=budget,
        depth=depth,
        label=f"module target {label}",
    )
    if any(type(key) is not str for key, _item in snapshot):
        raise PluginExecutableIdentityError(
            f"module target {label} do not have canonical names"
        )
    _digest_field(digest, label.encode("utf-8"))
    for key, item in sorted(snapshot):
        encoded = key.encode("utf-8")
        _consume_target_bytes(budget, len(encoded))
        _digest_field(digest, encoded)
        _update_external_function_owned_reference(
            digest,
            item,
            function=function,
            module=module,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
    _verify_dict_snapshot(value, snapshot)


def _external_function_leaf_identity(
    function: FunctionType,
    *,
    module: ModuleType,
    module_name: str,
    qualified_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> str:
    """Attest an external callable as a retained executable authority leaf."""

    _consume_target_budget(budget, depth=depth)
    function_key = id(function)
    cached = callable_cache.get(function_key)
    if cached is not None:
        return cached
    if function_key in active_callables:
        cycle = hashlib.sha256()
        _digest_field(cycle, b"external-leaf-cycle")
        _digest_field(cycle, module_name.encode("utf-8"))
        _digest_field(cycle, qualified_name.encode("utf-8"))
        return cycle.hexdigest()
    if function.__builtins__ is not vars(builtins):
        raise PluginExecutableIdentityError(
            "module target external function has noncanonical built-ins"
        )
    if function.__globals__ is not vars(module) and not (
        function.__globals__.get("__name__") == module_name
        and all(
            code.co_filename.startswith("<frozen ")
            for code in _walk_code_objects(function.__code__)
        )
    ):
        raise PluginExecutableIdentityError(
            "module target external function has noncanonical globals"
        )
    active_callables.add(function_key)
    try:
        digest = hashlib.sha256()
        digest.update(_CALLABLE_CODE_FINGERPRINT_SCHEMA)
        _update_exact_object_token(digest, function, budget=budget)
        _digest_field(digest, b"external-authority-leaf")
        _digest_field(digest, module_name.encode("utf-8"))
        _digest_field(digest, qualified_name.encode("utf-8"))
        _digest_field(
            digest,
            _declared_runtime_code_identity(
                function.__code__,
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=source_path,
                budget=budget,
                allow_frozen_module=(
                    getattr(getattr(module, "__spec__", None), "origin", None)
                    == "frozen"
                ),
            ).encode("ascii"),
        )
        _update_external_runtime_defaults(
            digest,
            function.__defaults__,
            function=function,
            module=module,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
            label="external positional defaults",
        )
        _update_external_runtime_mapping(
            digest,
            function.__kwdefaults__,
            function=function,
            module=module,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
            label="external keyword defaults",
        )
        _update_external_runtime_mapping(
            digest,
            function.__dict__,
            function=function,
            module=module,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
            label="external function state",
        )
        _update_annotation_shape(digest, function.__annotations__, budget=budget)
        closure = function.__closure__ or ()
        if len(closure) != len(function.__code__.co_freevars):
            raise PluginExecutableIdentityError(
                "module target external function closure is unverifiable"
            )
        for name, cell in zip(
            function.__code__.co_freevars,
            closure,
            strict=True,
        ):
            try:
                value = cell.cell_contents
            except ValueError as error:
                raise PluginExecutableIdentityError(
                    "module target external function closure is empty"
                ) from error
            _digest_field(digest, name.encode("utf-8"))
            _update_external_function_owned_reference(
                digest,
                value,
                function=function,
                module=module,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
        _update_runtime_import_references(
            digest,
            function,
            module=module,
            module_name=module_name,
            source_path=source_path,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
        dependencies = _function_dependency_analysis(
            function,
            budget=budget,
            depth=depth + 1,
        )
        for name in dependencies.global_names:
            if name == "__import__":
                raise PluginExecutableIdentityError(
                    "module target uses a dynamic import API"
                )
            if name in function.__globals__:
                selected = function.__globals__[name]
            elif name in function.__builtins__:
                selected = function.__builtins__[name]
            else:
                raise PluginExecutableIdentityError(
                    "module target references an unresolved global"
                )
            _digest_field(digest, name.encode("utf-8"))
            _update_external_function_global_reference(
                digest,
                selected,
                module=module,
                name=name,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
        for path in dependencies.global_attribute_paths:
            if path in {
                ("builtins", "__import__"),
                ("importlib", "import_module"),
            }:
                raise PluginExecutableIdentityError(
                    "module target uses a dynamic import API"
                )
            if path[0] in function.__globals__:
                selected = function.__globals__[path[0]]
            else:
                selected = function.__builtins__[path[0]]
            _digest_field(digest, b"attribute-path")
            for component in path:
                _digest_field(digest, component.encode("utf-8"))
            _update_static_attribute_path(
                digest,
                selected,
                path[1:],
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            )
        result = digest.hexdigest()
        callable_cache[function_key] = result
        return result
    finally:
        active_callables.discard(function_key)


def _update_external_function_global_reference(
    digest: Any,
    value: object,
    *,
    module: ModuleType,
    name: str,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    """Bind a source-declared opaque sentinel by its authoritative slot."""

    if (
        module.__name__ == "re"
        and name in {"_cache", "_cache2"}
        and type(value) is dict
        and vars(module).get(name) is value
    ):
        _consume_target_budget(budget, depth=depth)
        _digest_field(digest, b"derived-regular-expression-cache")
        _digest_field(digest, name.encode("ascii"))
        budget.derived_cache_slots.append((module, name, value))
        return
    implementation = type(value)
    implementation_name = getattr(implementation, "__qualname__", None)
    module_source = _module_file_source_path(module, budget=budget)
    implementation_source = _object_source_path(implementation, budget=budget)
    source_singleton = (
        not inspect.isclass(value)
        and not isinstance(value, (ModuleType, Enum))
        and type(value)
        not in {
            bool,
            int,
            float,
            complex,
            str,
            bytes,
            tuple,
            frozenset,
            list,
            dict,
            FunctionType,
        }
        and vars(module).get(name) is value
        and implementation.__module__ == module.__name__
        and type(implementation_name) is str
        and module_source is not None
        and implementation_source == module_source
        and len(
            _declared_code_objects(
                module_name=module.__name__,
                qualified_name=implementation_name,
                source_path=module_source,
                budget=budget,
            )
        )
        == 1
    )
    if source_singleton:
        _consume_target_budget(budget, depth=depth)
        _digest_field(digest, b"external-module-source-singleton")
        _digest_field(digest, module.__name__.encode("utf-8"))
        _digest_field(digest, name.encode("utf-8"))
        _update_exact_object_token(digest, value, budget=budget)
        _digest_field(
            digest,
            _instance_runtime_identity(
                value,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
                allow_declared_implementation=True,
            ).encode("ascii"),
        )
        return
    if (
        (
            type(value) is object
            or type(value) in _CANONICAL_HIDDEN_BUILTIN_TYPES
            or (
                inspect.isclass(value)
                and value in _CANONICAL_HIDDEN_BUILTIN_TYPES
            )
        )
        and vars(module).get(name) is value
    ):
        _consume_target_budget(budget, depth=depth)
        implementation = value if inspect.isclass(value) else type(value)
        _digest_field(digest, b"external-module-opaque-sentinel")
        _digest_field(digest, module.__name__.encode("utf-8"))
        _digest_field(digest, name.encode("utf-8"))
        _digest_field(digest, implementation.__module__.encode("utf-8"))
        _digest_field(digest, implementation.__qualname__.encode("utf-8"))
        _update_exact_object_token(digest, value, budget=budget)
        return
    _update_global_reference(
        digest,
        value,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth,
    )


def _update_external_function_owned_reference(
    digest: Any,
    value: object,
    *,
    function: FunctionType,
    module: ModuleType,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    """Resolve a function-owned value through any loaded authoritative slot."""

    dependencies = _function_dependency_analysis(
        function,
        budget=budget,
        depth=depth,
    )
    for name in dependencies.global_names:
        if (
            function.__globals__.get(name) is value
            and vars(module).get(name) is value
        ):
            _update_external_function_global_reference(
                digest,
                value,
                module=module,
                name=name,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth,
            )
            return
    _update_global_reference(
        digest,
        value,
        budget=budget,
        scope_cache=scope_cache,
        callable_cache=callable_cache,
        active_callables=active_callables,
        identity_root=identity_root,
        depth=depth,
    )


def _external_class_leaf_identity(
    implementation: type[Any],
    *,
    module_name: str,
    qualified_name: str,
    source_path: Path,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> str:
    """Attest external class code/configuration without volatile instances."""

    _consume_target_budget(budget, depth=depth)
    class_key = id(implementation)
    cached = budget.class_cache.get(class_key)
    if cached is not None:
        _verify_cached_class_snapshot(
            implementation,
            budget=budget,
            label="module target cached external class",
        )
        return cached
    if class_key in budget.active_classes:
        cycle = hashlib.sha256()
        _digest_field(cycle, b"external-class-leaf-cycle")
        _digest_field(cycle, module_name.encode("utf-8"))
        _digest_field(cycle, qualified_name.encode("utf-8"))
        return cycle.hexdigest()
    budget.active_classes.add(class_key)
    try:
        digest = hashlib.sha256()
        digest.update(_CALLABLE_CODE_FINGERPRINT_SCHEMA)
        _update_exact_object_token(digest, implementation, budget=budget)
        _digest_field(digest, b"external-class-authority-leaf")
        _digest_field(digest, module_name.encode("utf-8"))
        _digest_field(digest, qualified_name.encode("utf-8"))
        members = _bounded_class_members(
            implementation,
            budget=budget,
            depth=depth + 1,
            label="module target external class",
        )
        declared = _declared_code_objects(
            module_name=module_name,
            qualified_name=qualified_name,
            source_path=source_path,
            budget=budget,
        )
        if len(declared) == 1:
            _update_code_object(digest, declared[0], budget=budget, depth=depth + 1)
        elif len(declared) == 0:
            _digest_field(digest, b"static-runtime-class")
        else:
            raise PluginExecutableIdentityError(
                "module target external class declaration is ambiguous"
            )
        _update_class_dependency(
            digest,
            type(implementation),
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
            label="external-metaclass",
        )
        for base in implementation.__bases__:
            _update_class_dependency(
                digest,
                base,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
                label="external-base",
            )
        generated_abc_members = _update_abc_class_contract(
            digest,
            implementation,
            budget=budget,
            scope_cache=scope_cache,
            depth=depth + 1,
        )
        generated_enum_members = _update_enum_class_contract(
            digest,
            implementation,
            budget=budget,
            depth=depth + 1,
        )
        generated_dataclass_methods = _update_dataclass_class_contract(
            digest,
            implementation,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
        for name, value in members:
            if (
                name in generated_abc_members
                or name in generated_enum_members
                or name
                in {
                "__annotations__",
                "__classcell__",
                "__dataclass_fields__",
                "__dataclass_params__",
                "__dict__",
                "__doc__",
                "__module__",
                "__qualname__",
                "__slots__",
                "__weakref__",
                }
            ):
                continue
            primitive_member = value is None or value is NotImplemented or type(
                value
            ) in {
                bool,
                int,
                float,
                complex,
                str,
                bytes,
                tuple,
                frozenset,
            }
            if budget.bind_exact_object_tokens and not primitive_member:
                # A same-process callback retains the exact external class
                # member it inspected.  Its operational internals may change,
                # but replacing even a code-equivalent function, descriptor,
                # native lock, or source-backed delegate must invalidate the
                # callback registration.  Importable module targets omit this
                # process-local token and retain deterministic provenance only.
                _digest_field(digest, b"retained-external-class-member")
                _update_exact_object_token(digest, value, budget=budget)
            if inspect.ismemberdescriptor(value) or inspect.isgetsetdescriptor(value):
                continue
            _digest_field(digest, name.encode("utf-8"))
            selected_functions: tuple[tuple[str, FunctionType], ...]
            if type(value) is FunctionType:
                selected_functions = (("method", value),)
            elif isinstance(value, staticmethod):
                selected_functions = (("static-method", value.__func__),)
            elif isinstance(value, classmethod):
                selected_functions = (("class-method", value.__func__),)
            elif isinstance(value, property):
                selected_functions = tuple(
                    (label, selected)
                    for label, selected in (
                        ("property-get", value.fget),
                        ("property-set", value.fset),
                        ("property-delete", value.fdel),
                    )
                    if type(selected) is FunctionType
                )
                wrapped = value.fget
                if (
                    not selected_functions
                    and wrapped is not None
                    and type(getattr(wrapped, "__wrapped__", None)) is FunctionType
                ):
                    selected_functions = (("property-wrapped", wrapped.__wrapped__),)
            else:
                selected_functions = ()
            if selected_functions:
                for label, selected in selected_functions:
                    if name in generated_dataclass_methods:
                        _digest_field(digest, label.encode("ascii"))
                        _update_dataclass_generated_method(
                            digest,
                            selected,
                            owner=implementation,
                            name=name,
                            budget=budget,
                            scope_cache=scope_cache,
                            callable_cache=callable_cache,
                            active_callables=active_callables,
                            identity_root=identity_root,
                            depth=depth + 1,
                        )
                        continue
                    _update_external_class_member_function(
                        digest,
                        selected,
                        label=label,
                        budget=budget,
                        scope_cache=scope_cache,
                        callable_cache=callable_cache,
                        active_callables=active_callables,
                        identity_root=identity_root,
                        depth=depth + 1,
                    )
                continue
            if _descriptor_accessor_snapshot(value) is not None:
                _digest_field(digest, b"class-owned-static-descriptor")
                _update_static_attribute_value(
                    digest,
                    value,
                    descriptor_owner=implementation,
                    descriptor_name=name,
                    resolved_descriptor=value,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
                continue
            if (
                primitive_member
                or isinstance(value, ModuleType)
                or inspect.ismethod(value)
                or inspect.isbuiltin(value)
                or inspect.ismethoddescriptor(value)
            ):
                _update_global_reference(
                    digest,
                    value,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
            else:
                _update_external_class_member_provenance(
                    digest,
                    value,
                    budget=budget,
                    scope_cache=scope_cache,
                    callable_cache=callable_cache,
                    active_callables=active_callables,
                    identity_root=identity_root,
                    depth=depth + 1,
                )
        _verify_class_member_snapshot(
            implementation,
            members,
            label="module target external class",
        )
        result = digest.hexdigest()
        budget.class_snapshots[class_key] = (implementation, members)
        budget.class_cache[class_key] = result
        return result
    finally:
        budget.active_classes.discard(class_key)


def _bounded_class_members(
    implementation: type[Any],
    *,
    budget: _TargetIdentityBudget,
    depth: int,
    label: str,
) -> tuple[tuple[str, object], ...]:
    """Snapshot and bound a class namespace before performing any sorting."""

    namespace = vars(implementation)
    if type(namespace) is not MappingProxyType:
        raise PluginExecutableIdentityError(f"{label} namespace is noncanonical")
    _consume_target_nodes(budget, count=len(namespace), depth=depth)
    try:
        snapshot = tuple(namespace.items())
    except RuntimeError as error:
        raise PluginExecutableIdentityError(
            f"{label} changed while fingerprinting"
        ) from error
    members: list[tuple[str, object]] = []
    for name, value in snapshot:
        if type(name) is not str:
            raise PluginExecutableIdentityError(
                f"{label} has a noncanonical member name"
            )
        encoded_name = name.encode("utf-8")
        _consume_target_bytes(budget, len(encoded_name))
        members.append((name, value))
    members.sort(key=lambda item: item[0])
    bounded = tuple(members)
    _verify_class_member_snapshot(implementation, bounded, label=label)
    return bounded


def _verify_class_member_snapshot(
    implementation: type[Any],
    snapshot: tuple[tuple[str, object], ...],
    *,
    label: str,
) -> None:
    namespace = vars(implementation)
    if type(namespace) is not MappingProxyType or len(namespace) != len(snapshot):
        raise PluginExecutableIdentityError(f"{label} changed while fingerprinting")
    missing = object()
    try:
        for name, value in snapshot:
            if namespace.get(name, missing) is not value:
                raise PluginExecutableIdentityError(
                    f"{label} changed while fingerprinting"
                )
    except (KeyError, RuntimeError, TypeError) as error:
        raise PluginExecutableIdentityError(
            f"{label} changed while fingerprinting"
        ) from error


def _update_external_class_member_function(
    digest: Any,
    function: FunctionType,
    *,
    label: str,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    """Bind a class member through the complete function-runtime traversal."""

    module_name = getattr(function, "__module__", None)
    qualified_name = getattr(function, "__qualname__", None)
    module = sys.modules.get(module_name)
    source_path = _object_source_path(function, budget=budget)
    module_source = (
        _module_file_source_path(module, budget=budget)
        if isinstance(module, ModuleType)
        else None
    )
    frozen_module_function = (
        isinstance(module, ModuleType)
        and getattr(getattr(module, "__spec__", None), "origin", None) == "frozen"
        and all(
            code.co_filename.startswith("<frozen ")
            for code in _walk_code_objects(function.__code__)
        )
    )
    if (
        type(module_name) is not str
        or type(qualified_name) is not str
        or not isinstance(module, ModuleType)
        or module_source is None
        or (
            source_path != module_source
            and not frozen_module_function
        )
    ):
        raise PluginExecutableIdentityError(
            "module target external class contains an unverifiable callable"
        )
    _digest_field(digest, label.encode("ascii"))
    _digest_field(
        digest,
        _cached_scope_identity(
            module_name,
            module_source,
            scope_cache,
        ).encode("ascii"),
    )
    budget.external_class_member_runtime_depth += 1
    try:
        identity = _external_function_leaf_identity(
            function,
            module=module,
            module_name=module_name,
            qualified_name=qualified_name,
            source_path=module_source,
            budget=budget,
            scope_cache=scope_cache,
            callable_cache=callable_cache,
            active_callables=active_callables,
            identity_root=identity_root,
            depth=depth + 1,
        )
    except PluginExecutableIdentityError as error:
        raise PluginExecutableIdentityError(
            "module target external class member is unverifiable: "
            f"{module_name}.{qualified_name}: {error}"
        ) from error
    finally:
        budget.external_class_member_runtime_depth -= 1
    _digest_field(digest, identity.encode("ascii"))


def _update_external_class_member_provenance(
    digest: Any,
    value: object,
    *,
    budget: _TargetIdentityBudget,
    scope_cache: dict[str, str],
    callable_cache: dict[int, str],
    active_callables: set[int],
    identity_root: str,
    depth: int,
) -> None:
    """Bind opaque class configuration to deterministic implementation code."""

    _consume_target_budget(budget, depth=depth)
    implementation = value if inspect.isclass(value) else type(value)
    module_name = getattr(implementation, "__module__", None)
    qualified_name = getattr(implementation, "__qualname__", None)
    if (
        type(module_name) is not str
        or not module_name
        or type(qualified_name) is not str
        or not qualified_name
    ):
        raise PluginExecutableIdentityError(
            "module target external class member has no exact type provenance"
        )
    encoded_module = module_name.encode("utf-8")
    encoded_name = qualified_name.encode("utf-8")
    _consume_target_bytes(budget, len(encoded_module) + len(encoded_name))
    _digest_field(digest, b"external-class-member-provenance")
    _digest_field(digest, encoded_module)
    _digest_field(digest, encoded_name)
    if module_name == "builtins":
        if vars(builtins).get(qualified_name) is not implementation:
            raise PluginExecutableIdentityError(
                "module target external class member has unverifiable built-in "
                f"type provenance: {qualified_name}"
            )
        _digest_field(digest, b"built-in-type")
        return
    module = sys.modules.get(module_name)
    if not isinstance(module, ModuleType):
        raise PluginExecutableIdentityError(
            "module target external class member type is not exactly loaded"
        )
    implementation_source = _object_source_path(implementation, budget=budget)
    module_source = _module_file_source_path(module, budget=budget)
    spec = getattr(module, "__spec__", None)
    native_origin = getattr(spec, "origin", None)
    native_exports = (
        _native_export_names(
            module,
            implementation,
            budget=budget,
            depth=depth + 1,
        )
        if native_origin in {"built-in", "frozen"}
        else ()
    )
    statically_exported = _static_import_target(module, qualified_name) is implementation
    declared_unbound = (
        budget.allow_unbound_source_objects
        and implementation_source is not None
        and module_source is not None
        and implementation_source == module_source
        and len(
            _declared_code_objects(
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=module_source,
                budget=budget,
            )
        )
        == 1
    )
    if (
        implementation_source is not None
        and module_source is not None
        and implementation_source == module_source
        and (statically_exported or declared_unbound)
    ):
        _digest_field(
            digest,
            _cached_scope_identity(
                module_name,
                module_source,
                scope_cache,
            ).encode("ascii"),
        )
        _digest_field(
            digest,
            _external_class_leaf_identity(
                implementation,
                module_name=module_name,
                qualified_name=qualified_name,
                source_path=module_source,
                budget=budget,
                scope_cache=scope_cache,
                callable_cache=callable_cache,
                active_callables=active_callables,
                identity_root=identity_root,
                depth=depth + 1,
            ).encode("ascii"),
        )
        return
    if native_origin in {"built-in", "frozen"} and native_exports:
        _digest_field(digest, str(native_origin).encode("ascii"))
        for export_name in native_exports:
            _digest_field(digest, export_name.encode("utf-8"))
        return
    raise PluginExecutableIdentityError(
        "module target external class member type provenance is unverifiable"
    )


def _cached_scope_identity(
    module_name: str,
    source_path: Path,
    cache: dict[str, str],
) -> str:
    key = _scope_cache_key(module_name, source_path)
    value = cache.get(key)
    if value is None:
        if cache.get(_SOURCE_ONLY_SCOPE_CACHE_MARKER) == "1":
            value = _source_module_identity(module_name, source_path)
        else:
            value = _executable_scope_fingerprint(module_name, source_path)
        cache[key] = value
    return value


def _native_export_names(
    module: ModuleType,
    value: object,
    *,
    budget: _TargetIdentityBudget,
    depth: int,
) -> tuple[str, ...]:
    """Return native aliases through one shared, bounded module index."""

    index = _native_export_index(module, budget=budget, depth=depth)
    selected = index.exports.get(builtins.id(value))
    if selected is None:
        return ()
    candidate, names = selected
    if candidate is not value:
        raise PluginExecutableIdentityError(
            "module target native export identity cache is inconsistent"
        )
    return names


def _native_export_index(
    module: ModuleType,
    *,
    budget: _TargetIdentityBudget,
    depth: int,
) -> _NativeExportIndex:
    module_key = builtins.id(module)
    cached = budget.native_export_indexes.get(module_key)
    if cached is not None:
        if cached.module is not module:
            raise PluginExecutableIdentityError(
                "module target native module identity cache is inconsistent"
            )
        return cached
    return _build_native_export_index(module, budget=budget, depth=depth)


def _build_native_export_index(
    module: ModuleType,
    *,
    budget: _TargetIdentityBudget,
    depth: int,
) -> _NativeExportIndex:
    """Index a native namespace once, charging all work before sorting."""

    if type(module) is not ModuleType:
        raise PluginExecutableIdentityError(
            "module target native module has no exact loaded provenance"
        )
    module_name = getattr(module, "__name__", None)
    spec = getattr(module, "__spec__", None)
    if (
        type(module_name) is not str
        or not module_name
        or sys.modules.get(module_name) is not module
        or getattr(spec, "origin", None) not in {"built-in", "frozen"}
    ):
        raise PluginExecutableIdentityError(
            "module target native module has no exact loaded provenance"
        )
    namespace = vars(module)
    if type(namespace) is not dict:
        raise PluginExecutableIdentityError(
            "module target native module namespace is noncanonical"
        )
    snapshot = _snapshot_runtime_dict(
        namespace,
        budget=budget,
        depth=depth,
        label="module target native module",
    )
    aliases: dict[int, tuple[object, list[str]]] = {}
    for name, candidate in snapshot:
        if type(name) is not str:
            raise PluginExecutableIdentityError(
                "module target native module has a noncanonical export name"
            )
        encoded_name = name.encode("utf-8")
        _consume_target_bytes(budget, len(encoded_name))
        candidate_key = builtins.id(candidate)
        selected = aliases.get(candidate_key)
        if selected is None:
            aliases[candidate_key] = (candidate, [name])
        elif selected[0] is candidate:
            selected[1].append(name)
        else:  # pragma: no cover - impossible while both objects are retained
            raise PluginExecutableIdentityError(
                "module target native export identity key collided"
            )
    exports = {
        candidate_key: (candidate, tuple(sorted(names)))
        for candidate_key, (candidate, names) in aliases.items()
    }
    index = _NativeExportIndex(module, namespace, snapshot, exports)
    _verify_native_export_index(index)
    budget.native_export_indexes[builtins.id(module)] = index
    return index


def _verify_native_export_index(index: _NativeExportIndex) -> None:
    module_name = getattr(index.module, "__name__", None)
    if (
        type(index.module) is not ModuleType
        or type(index.namespace) is not dict
        or type(module_name) is not str
        or sys.modules.get(module_name) is not index.module
        or vars(index.module) is not index.namespace
        or len(index.namespace) != len(index.snapshot)
    ):
        raise PluginExecutableIdentityError(
            "module target native module changed while fingerprinting"
        )
    missing = object()
    try:
        for name, candidate in index.snapshot:
            if index.namespace.get(name, missing) is not candidate:
                raise PluginExecutableIdentityError(
                    "module target native module changed while fingerprinting"
                )
    except (KeyError, RuntimeError, TypeError) as error:
        raise PluginExecutableIdentityError(
            "module target native module changed while fingerprinting"
        ) from error


def _verify_native_export_indexes(budget: _TargetIdentityBudget) -> None:
    for index in tuple(budget.native_export_indexes.values()):
        _verify_native_export_index(index)


def _verify_function_dependency_analyses(budget: _TargetIdentityBudget) -> None:
    for analysis in tuple(budget.function_dependency_analyses.values()):
        if analysis.function.__code__ is not analysis.code:
            raise PluginExecutableIdentityError(
                "module target function code changed while fingerprinting"
            )


def _verify_dependency_class_caches(budget: _TargetIdentityBudget) -> None:
    for implementation, _identity, members in tuple(
        budget.dependency_class_cache.values()
    ):
        _verify_class_member_snapshot(
            implementation,
            members,
            label="module target cached dependency class",
        )


def _verify_cached_class_snapshot(
    implementation: type[Any],
    *,
    budget: _TargetIdentityBudget,
    label: str,
) -> None:
    cached = budget.class_snapshots.get(id(implementation))
    if cached is None or cached[0] is not implementation:
        raise PluginExecutableIdentityError(
            "module target class identity cache is inconsistent"
        )
    _verify_class_member_snapshot(implementation, cached[1], label=label)


def _verify_class_identity_caches(budget: _TargetIdentityBudget) -> None:
    """Recheck every retained class after the complete graph traversal."""

    for implementation, members in tuple(budget.class_snapshots.values()):
        _verify_class_member_snapshot(
            implementation,
            members,
            label="module target cached class",
        )


def _verify_object_identity_caches(budget: _TargetIdentityBudget) -> None:
    """Recheck mutable object state after the complete graph traversal."""

    for value in tuple(budget.object_refs.values()):
        _verify_cached_object_snapshot(value, budget=budget)


def _verify_source_path_caches(budget: _TargetIdentityBudget) -> None:
    for module, module_name, registry_name, module_file, source_path in tuple(
        budget.module_source_paths.values()
    ):
        current_source_path = (
            _resolved_source_path((module_file,))
            if isinstance(module_file, str) and module_file
            else None
        )
        if (
            getattr(module, "__name__", None) != module_name
            or getattr(getattr(module, "__spec__", None), "name", None)
            != registry_name
            or getattr(module, "__file__", None) != module_file
            or type(module_name) is not str
            or type(registry_name) is not str
            or sys.modules.get(registry_name) is not module
            or current_source_path != source_path
        ):
            raise PluginExecutableIdentityError(
                "module target module source provenance changed while fingerprinting"
            )
    for value, source, source_path in tuple(budget.object_source_paths.values()):
        try:
            current = inspect.getsourcefile(value)
        except (OSError, TypeError):
            current = None
        current_source_path = (
            _resolved_source_path((current,)) if current else None
        )
        if current != source or current_source_path != source_path:
            raise PluginExecutableIdentityError(
                "module target object source provenance changed while fingerprinting"
            )
    for (module_name, source_path), cached in tuple(
        budget.declared_code_cache.items()
    ):
        try:
            source_bytes, source_stat_identity = _read_regular_source_snapshot(
                source_path
            )
        except PluginExecutableIdentityError as error:
            raise PluginExecutableIdentityError(
                "module target source changed while fingerprinting"
            ) from error
        source_identity = _source_module_identity_from_bytes(
            module_name,
            source_bytes,
        )
        if (
            source_identity != cached.source_identity
            or source_stat_identity != cached.source_stat_identity
        ):
            raise PluginExecutableIdentityError(
                "module target source changed while fingerprinting"
            )
    for (module_name, source_path), cached in tuple(
        budget.declared_ast_cache.items()
    ):
        try:
            source_bytes, source_stat_identity = _read_regular_source_snapshot(
                source_path
            )
        except PluginExecutableIdentityError as error:
            raise PluginExecutableIdentityError(
                "module target AST source changed while fingerprinting"
            ) from error
        if (
            _source_module_identity_from_bytes(module_name, source_bytes)
            != cached.source_identity
            or source_stat_identity != cached.source_stat_identity
        ):
            raise PluginExecutableIdentityError(
                "module target AST source changed while fingerprinting"
            )


def _verify_derived_cache_slots(budget: _TargetIdentityBudget) -> None:
    for module, name, value in tuple(budget.derived_cache_slots):
        if vars(module).get(name) is not value:
            raise PluginExecutableIdentityError(
                "module target derived cache slot changed while fingerprinting"
            )


def _scope_cache_key(module_name: str, source_path: Path) -> str:
    return f"{module_name}\0{source_path}"


def _source_module_identity_from_bytes(module_name: str, source: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(_CALLABLE_SOURCE_SCOPE_FINGERPRINT_SCHEMA)
    _digest_field(digest, module_name.encode("utf-8"))
    _digest_field(digest, source)
    return digest.hexdigest()


def _source_module_identity(module_name: str, source_path: Path) -> str:
    """Bind one same-process dependency to its exact defining source file."""

    source = _read_regular_source_bytes(source_path)
    return _source_module_identity_from_bytes(module_name, source)


def _consume_target_budget(
    budget: _TargetIdentityBudget,
    *,
    depth: int,
    code: bool = False,
) -> None:
    _consume_target_nodes(budget, count=1, depth=depth)
    if code:
        budget.code_objects += 1
        if budget.code_objects > _MAX_TARGET_CODE_OBJECTS:
            raise PluginExecutableIdentityError(
                "module target exceeds the recursive code-object limit"
            )


def _consume_target_nodes(
    budget: _TargetIdentityBudget,
    *,
    count: int,
    depth: int,
) -> None:
    """Reserve reflection work before traversing an adversarial collection."""

    if depth > _MAX_TARGET_VALUE_DEPTH:
        raise PluginExecutableIdentityError(
            "module target exceeds the recursive value-depth limit"
        )
    if count < 0:
        raise PluginExecutableIdentityError(
            "module target has a noncanonical recursive value count"
        )
    budget.value_nodes += count
    if budget.value_nodes > _MAX_TARGET_VALUE_NODES:
        raise PluginExecutableIdentityError(
            "module target exceeds the recursive value limit"
        )


def _consume_target_bytes(budget: _TargetIdentityBudget, size: int) -> None:
    budget.value_bytes += size
    if budget.value_bytes > _MAX_TARGET_VALUE_BYTES:
        raise PluginExecutableIdentityError(
            "module target exceeds the recursive runtime-byte limit"
        )


def _read_regular_source_snapshot(
    path: Path,
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_TARGET_SOURCE_BYTES:
            raise PluginExecutableIdentityError(
                "module target source is not a bounded regular file"
            )
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size > _MAX_TARGET_SOURCE_BYTES
                or not _same_file_object(before, opened)
            ):
                raise PluginExecutableIdentityError(
                    "module target source changed before reading"
                )
            source = stream.read(opened.st_size + 1)
            after_handle = os.fstat(stream.fileno())
        after = path.lstat()
    except PluginExecutableIdentityError:
        raise
    except OSError as error:
        raise PluginExecutableIdentityError(
            "module target source cannot be read safely"
        ) from error
    if (
        len(source) != opened.st_size
        or _stat_identity(opened) != _stat_identity(after_handle)
        or not stat.S_ISREG(after.st_mode)
        or not _same_file_object(opened, after)
    ):
        raise PluginExecutableIdentityError(
            "module target source changed while reading"
        )
    return source, _stat_identity(after_handle)


def _read_regular_source_bytes(path: Path) -> bytes:
    source, _source_stat_identity = _read_regular_source_snapshot(path)
    return source


def _executable_scope_fingerprint(module_name: str, source_path: Path) -> str:
    """Hash one relocation-stable top-level module or complete package scope."""

    scope = _executable_scope(module_name, source_path)
    entries = (
        _package_entries(scope.roots)
        if scope.roots
        else (_PackageEntry(source_path.name, source_path),)
    )
    if not entries:
        raise PluginExecutableIdentityError(
            f"plug-in module {module_name!r} has no fingerprintable package files"
        )
    digest = hashlib.sha256()
    digest.update(_FINGERPRINT_SCHEMA)
    _digest_field(digest, scope.kind.encode("ascii"))
    _digest_field(digest, scope.logical_name.encode("utf-8"))
    _digest_field(digest, len(scope.roots).to_bytes(8, "big", signed=False))
    _digest_field(digest, module_name.encode("utf-8"))
    total_bytes = 0
    for entry in entries:
        relative = entry.relative
        encoded_path = relative.encode("utf-8")
        if len(encoded_path) > MAX_PLUGIN_PACKAGE_PATH_BYTES:
            raise PluginExecutableIdentityError(
                "plug-in package contains an overlong relative path"
            )
        _digest_field(digest, encoded_path)
        if entry.alias_kind is not None:
            _digest_field(digest, entry.alias_kind.encode("ascii"))
            _digest_field(digest, (entry.alias_target or "").encode("utf-8"))
            continue
        if entry.entry_kind == "directory":
            _digest_field(digest, b"directory")
            continue
        path = entry.path
        if path is None:  # pragma: no cover - guarded by _PackageEntry producers
            raise PluginExecutableIdentityError(
                f"plug-in package file {relative!r} has no readable path"
            )
        try:
            before = path.lstat()
        except OSError as error:
            raise PluginExecutableIdentityError(
                f"cannot stat plug-in package file {relative!r}: {error}"
            ) from error
        if not stat.S_ISREG(before.st_mode):
            raise PluginExecutableIdentityError(
                f"plug-in package path {relative!r} is not a regular file"
            )
        _digest_field(digest, b"file")
        try:
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or not _same_file_object(before, opened)
                ):
                    raise PluginExecutableIdentityError(
                        f"plug-in package file {relative!r} changed before reading"
                    )
                if opened.st_size > MAX_PLUGIN_PACKAGE_FILE_BYTES:
                    raise PluginExecutableIdentityError(
                        f"plug-in package file {relative!r} exceeds "
                        f"{MAX_PLUGIN_PACKAGE_FILE_BYTES} bytes"
                    )
                if total_bytes + opened.st_size > MAX_PLUGIN_PACKAGE_BYTES:
                    raise PluginExecutableIdentityError(
                        "plug-in package exceeds the executable identity byte limit "
                        f"of {MAX_PLUGIN_PACKAGE_BYTES}"
                    )
                digest.update(opened.st_size.to_bytes(8, "big", signed=False))
                actual_bytes = 0
                remaining = opened.st_size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    digest.update(chunk)
                    actual_bytes += len(chunk)
                    remaining -= len(chunk)
                sentinel = stream.read(1)
                after_handle = os.fstat(stream.fileno())
            after = path.lstat()
        except OSError as error:
            raise PluginExecutableIdentityError(
                f"cannot read plug-in package file {relative!r}: {error}"
            ) from error
        if (
            actual_bytes != opened.st_size
            or sentinel
            or _stat_identity(opened) != _stat_identity(after_handle)
            or not stat.S_ISREG(after.st_mode)
            or not _same_file_object(opened, after)
        ):
            raise PluginExecutableIdentityError(
                f"plug-in package file {relative!r} changed while fingerprinting"
            )
        total_bytes += actual_bytes
    prefix = "module-sha256" if scope.kind == "module" else "package-sha256"
    return f"{prefix}:{digest.hexdigest()}"


def _plugin_module_name(plugin: Any) -> str | None:
    module_name = getattr(type(plugin), "__module__", None)
    if (
        not isinstance(module_name, str)
        or not module_name
        or module_name == "builtins"
    ):
        return None
    return module_name


def _module_source_path(
    plugin: Any,
    module: ModuleType | None,
) -> Path | None:
    candidates: list[str] = []
    try:
        source = inspect.getsourcefile(type(plugin))
    except (OSError, TypeError):
        source = None
    if source:
        candidates.append(source)
    if module is not None:
        module_file = getattr(module, "__file__", None)
        if isinstance(module_file, str) and module_file:
            candidates.append(module_file)
    return _resolved_source_path(tuple(candidates))


def _resolved_source_path(candidates: tuple[str, ...]) -> Path | None:
    """Resolve the first regular source file without accepting sourceless caches."""

    for candidate in candidates:
        path = Path(candidate)
        if path.suffix.lower() in {".pyc", ".pyo"}:
            source_candidate = path.with_suffix(".py")
            if source_candidate.is_file():
                path = source_candidate
            else:
                # CPython bytecode can embed the source/build filename inside
                # its marshalled code object. Hashing a sourceless cache would
                # therefore make the supposedly relocation-stable identity
                # depend on its build host. Normalizing bytecode is also
                # interpreter-version-specific and would weaken the
                # executable-byte claim, so require a trusted loader-supplied
                # artifact digest instead.
                raise PluginExecutableIdentityError(
                    "sourceless Python bytecode has no relocation-stable "
                    "executable identity"
                )
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file():
            return resolved
    return None


def _executable_scope(module_name: str, source_path: Path) -> _ExecutableScope:
    """Resolve a complete, bounded package scope without using host paths.

    The first import-package ancestor is the boundary.  If it is a PEP 420
    namespace, that namespace remains the conservative boundary even when a
    later component is a regular package; every search location participates
    in import precedence order.  This includes helpers reached by
    parent-relative imports.  A genuine top-level module has no package helpers,
    so it receives a distinct module identity rather than a misleading one-file
    ``package-sha256`` identity.
    """

    parts = module_name.split(".")
    namespace_scopes: list[tuple[str, object]] = []
    for length in range(1, len(parts) + 1):
        logical_name = ".".join(parts[:length])
        module = sys.modules.get(logical_name)
        spec = getattr(module, "__spec__", None) if module is not None else None
        spec_locations = getattr(spec, "submodule_search_locations", None)
        if spec_locations is None:
            continue
        runtime_locations = getattr(module, "__path__", None)
        locations = (
            runtime_locations
            if runtime_locations is not None
            else spec_locations
        )
        module_file = getattr(module, "__file__", None)
        if not isinstance(module_file, str) or not module_file:
            namespace_scopes.append((logical_name, locations))
            continue
        if namespace_scopes:
            namespace_name, namespace_locations = namespace_scopes[0]
            return _ExecutableScope(
                "namespace-package",
                namespace_name,
                _scope_roots(
                    namespace_name,
                    namespace_locations,
                    source_path,
                ),
            )
        roots = _scope_roots(logical_name, locations, source_path)
        return _ExecutableScope("regular-package", logical_name, roots)
    for logical_name, locations in namespace_scopes:
        roots = _scope_roots(logical_name, locations, source_path)
        return _ExecutableScope("namespace-package", logical_name, roots)
    return _ExecutableScope("module", module_name, ())


def _scope_roots(
    logical_name: str,
    locations: Any,
    source_path: Path,
) -> tuple[Path, ...]:
    """Validate and canonicalize every search root for one package scope."""

    raw_locations: list[str] = []
    try:
        if isinstance(locations, (str, bytes)):
            raise TypeError("search locations must be an iterable of paths")
        for item in locations:
            if len(raw_locations) >= MAX_PLUGIN_PACKAGE_PATHS:
                raise PluginExecutableIdentityError(
                    "plug-in package exceeds the executable identity path limit of "
                    f"{MAX_PLUGIN_PACKAGE_PATHS}"
                )
            raw_locations.append(str(item))
    except PluginExecutableIdentityError:
        raise
    except (OSError, RuntimeError, TypeError) as error:
        raise PluginExecutableIdentityError(
            f"plug-in package {logical_name!r} has unreadable search locations"
        ) from error
    if not raw_locations:
        raise PluginExecutableIdentityError(
            f"plug-in package {logical_name!r} has no search locations"
        )
    roots: list[Path] = []
    for raw_location in raw_locations:
        try:
            location = Path(raw_location).resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise PluginExecutableIdentityError(
                f"plug-in package {logical_name!r} has an unavailable search location"
            ) from error
        if not location.is_dir():
            raise PluginExecutableIdentityError(
                f"plug-in package {logical_name!r} has a non-directory search location"
            )
        if location not in roots:
            roots.append(location)
    if not any(source_path.is_relative_to(root) for root in roots):
        raise PluginExecutableIdentityError(
            f"plug-in package {logical_name!r} search locations do not contain "
            "its defining module"
        )
    return tuple(roots)


def _package_entries(roots: tuple[Path, ...]) -> tuple[_PackageEntry, ...]:
    entries: list[_PackageEntry] = []
    pending: list[tuple[int, Path, Path, Path]] = [
        (index, root, root, Path())
        for index, root in reversed(tuple(enumerate(roots)))
    ]
    examined_paths = len(roots)
    try:
        while pending:
            root_index, root, directory, relative_directory = pending.pop()
            with os.scandir(directory) as scan:
                children = []
                for child in scan:
                    examined_paths += 1
                    if examined_paths > MAX_PLUGIN_PACKAGE_PATHS:
                        raise PluginExecutableIdentityError(
                            "plug-in package exceeds the executable identity "
                            f"path limit of {MAX_PLUGIN_PACKAGE_PATHS}"
                        )
                    children.append(child)
                children.sort(key=lambda item: item.name)
            for child in reversed(children):
                local_relative = relative_directory / child.name
                relative = _scoped_relative(
                    root_index,
                    local_relative,
                    root_count=len(roots),
                )
                relative_text = relative.as_posix()
                _validate_entry_relative_path(relative_text)
                path = directory / child.name
                is_symlink = child.is_symlink()
                is_junction = path.is_junction()
                if is_symlink or is_junction:
                    kind = "junction" if is_junction else "symlink"
                    local_target = _contained_alias_target(root, path, local_relative)
                    target = _scoped_relative(
                        root_index,
                        Path(local_target),
                        root_count=len(roots),
                    ).as_posix()
                    _append_package_entry(
                        entries,
                        _PackageEntry(
                            relative_text,
                            None,
                            alias_kind=kind,
                            alias_target=target,
                        ),
                    )
                    continue
                if child.is_dir(follow_symlinks=False):
                    # Metadata/cache names describe ignorable directories,
                    # not an exemption for arbitrary package entries.  A
                    # regular file or alias using one of these names remains
                    # executable package material and must participate in the
                    # identity (or fail closed under the alias policy).
                    if child.name in _IGNORED_DIRECTORY_NAMES:
                        continue
                    _append_package_entry(
                        entries,
                        _PackageEntry(
                            relative_text,
                            None,
                            entry_kind="directory",
                        ),
                    )
                    pending.append(
                        (root_index, root, path, local_relative)
                    )
                    continue
                if not child.is_file(follow_symlinks=False):
                    continue
                _append_package_entry(
                    entries,
                    _PackageEntry(relative_text, path),
                )
    except OSError as error:
        raise PluginExecutableIdentityError(
            "cannot enumerate plug-in package safely"
        ) from error
    return tuple(sorted(entries, key=lambda item: item.relative))


def _append_package_entry(
    entries: list[_PackageEntry],
    entry: _PackageEntry,
) -> None:
    entries.append(entry)
    if len(entries) > MAX_PLUGIN_PACKAGE_FILES:
        raise PluginExecutableIdentityError(
            "plug-in package exceeds the executable identity entry limit of "
            f"{MAX_PLUGIN_PACKAGE_FILES}"
        )


def _validate_entry_relative_path(relative: str) -> None:
    if len(relative.encode("utf-8")) > MAX_PLUGIN_PACKAGE_PATH_BYTES:
        raise PluginExecutableIdentityError(
            "plug-in package contains an overlong relative path"
        )


def _scoped_relative(
    root_index: int,
    relative: Path,
    *,
    root_count: int,
) -> Path:
    if root_count == 1:
        return relative
    return Path(f"namespace-root-{root_index:04d}") / relative


def _contained_alias_target(root: Path, path: Path, relative: Path) -> str:
    try:
        target = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise PluginExecutableIdentityError(
            f"plug-in package alias {relative.as_posix()!r} cannot be resolved"
        ) from error
    if not target.is_relative_to(root):
        raise PluginExecutableIdentityError(
            f"plug-in package alias {relative.as_posix()!r} escapes its package root"
        )
    target_relative = target.relative_to(root)
    current = root
    for part in target_relative.parts:
        current /= part
        if part not in _IGNORED_DIRECTORY_NAMES:
            continue
        try:
            target_metadata = current.lstat()
        except OSError as error:
            raise PluginExecutableIdentityError(
                f"plug-in package alias {relative.as_posix()!r} cannot be resolved"
            ) from error
        if stat.S_ISDIR(target_metadata.st_mode):
            raise PluginExecutableIdentityError(
                f"plug-in package alias {relative.as_posix()!r} "
                "targets ignored content"
            )
    normalized = target_relative.as_posix()
    return normalized if normalized else "."


def _digest_field(digest: Any, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big", signed=False))
    digest.update(value)


def _stat_identity(value: Any) -> tuple[int, int, int, int, int]:
    return (
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_dev,
        value.st_ino,
    )


def _same_file_object(left: Any, right: Any) -> bool:
    """Compare stable object identity across path and handle stat APIs."""

    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


__all__ = [
    "MAX_PLUGIN_PACKAGE_BYTES",
    "MAX_PLUGIN_PACKAGE_FILES",
    "MAX_PLUGIN_PACKAGE_FILE_BYTES",
    "MAX_PLUGIN_PACKAGE_PATHS",
    "MAX_PLUGIN_PACKAGE_PATH_BYTES",
    "PluginExecutableIdentityError",
    "executable_plugin_fingerprint",
]
