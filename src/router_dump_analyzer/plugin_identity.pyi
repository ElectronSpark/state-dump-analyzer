import ast
from dataclasses import dataclass, field
from pathlib import Path
from types import CodeType, FunctionType, ModuleType
from typing import Any

__all__ = ['MAX_PLUGIN_PACKAGE_FILES', 'MAX_PLUGIN_PACKAGE_PATHS', 'MAX_PLUGIN_PACKAGE_BYTES', 'MAX_PLUGIN_PACKAGE_FILE_BYTES', 'MAX_PLUGIN_PACKAGE_PATH_BYTES', 'PluginExecutableIdentityError', 'executable_plugin_fingerprint']

MAX_PLUGIN_PACKAGE_FILES: int
MAX_PLUGIN_PACKAGE_PATHS: int
MAX_PLUGIN_PACKAGE_BYTES: int
MAX_PLUGIN_PACKAGE_FILE_BYTES: int
MAX_PLUGIN_PACKAGE_PATH_BYTES: int

class PluginExecutableIdentityError(ValueError): ...

@dataclass(frozen=True, slots=True)
class _PackageEntry:
    relative: str
    path: Path | None
    entry_kind: str = ...
    alias_kind: str | None = ...
    alias_target: str | None = ...

@dataclass(frozen=True, slots=True)
class _ExecutableScope:
    kind: str
    logical_name: str
    roots: tuple[Path, ...]

@dataclass(slots=True)
class _NativeExportIndex:
    module: ModuleType
    namespace: dict[str, object]
    snapshot: tuple[tuple[object, object], ...]
    exports: dict[int, tuple[object, tuple[str, ...]]]

@dataclass(frozen=True, slots=True)
class _FunctionDependencyAnalysis:
    function: FunctionType
    code: CodeType
    global_names: tuple[str, ...]
    global_attribute_paths: tuple[tuple[str, ...], ...]
    has_runtime_imports: bool

@dataclass(frozen=True, slots=True)
class _DeclaredCodeCacheEntry:
    source_identity: str
    source_stat_identity: tuple[int, int, int, int, int]
    code_objects: tuple[CodeType, ...]

@dataclass(frozen=True, slots=True)
class _DeclaredAstCacheEntry:
    source_identity: str
    source_stat_identity: tuple[int, int, int, int, int]
    functions: tuple[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef], ...]

@dataclass(frozen=True, slots=True)
class _OwnedDescriptorAccessor:
    owner: type[Any]
    name: str
    descriptor: object
    slot: str
    accessor: FunctionType

@dataclass(frozen=True, slots=True)
class _OwnedStaticDescriptor:
    owner: type[Any]
    name: str
    descriptor: object
    accessors: tuple[tuple[str, FunctionType | None], ...]

@dataclass(slots=True)
class _TargetIdentityBudget:
    code_objects: int = ...
    value_nodes: int = ...
    value_bytes: int = ...
    declared_code_cache: dict[tuple[str, Path], _DeclaredCodeCacheEntry] = field(default_factory=dict)
    declared_ast_cache: dict[tuple[str, Path], _DeclaredAstCacheEntry] = field(default_factory=dict)
    batch_declared_code_cache: dict[tuple[str, Path, str], tuple[CodeType, ...]] | None = ...
    class_cache: dict[int, str] = field(default_factory=dict)
    class_snapshots: dict[int, tuple[type[Any], tuple[tuple[str, object], ...]]] = field(default_factory=dict)
    active_classes: set[int] = field(default_factory=set)
    object_cache: dict[int, str] = field(default_factory=dict)
    active_objects: set[int] = field(default_factory=set)
    active_dependency_leaves: set[int] = field(default_factory=set)
    dependency_class_cache: dict[tuple[int, bool], tuple[type[Any], str, tuple[tuple[str, object], ...]]] = field(default_factory=dict)
    object_snapshots: dict[int, tuple[tuple[object, object], ...]] = field(default_factory=dict)
    object_refs: dict[int, object] = field(default_factory=dict)
    native_export_indexes: dict[int, _NativeExportIndex] = field(default_factory=dict)
    function_dependency_analyses: dict[int, _FunctionDependencyAnalysis] = field(default_factory=dict)
    owned_descriptor_accessors: dict[int, list[_OwnedDescriptorAccessor]] = field(default_factory=dict)
    owned_static_descriptors: dict[int, list[_OwnedStaticDescriptor]] = field(default_factory=dict)
    module_source_paths: dict[int, tuple[ModuleType, object, object, object, Path | None]] = field(default_factory=dict)
    object_source_paths: dict[int, tuple[object, str | None, Path | None]] = field(default_factory=dict)
    derived_cache_slots: list[tuple[ModuleType, str, object]] = field(default_factory=list)
    allow_runtime_closures: bool = ...
    allow_unbound_source_objects: bool = ...
    leaf_external_references: bool = ...
    bind_exact_object_tokens: bool = ...
    root_scope_identity: str | None = ...
    external_class_member_runtime_depth: int = ...

@dataclass(frozen=True, slots=True)
class _RuntimeImportBinding:
    module_name: str
    attribute_path: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class _StaticAttributeResolution:
    value: object
    owner: object | None
    name: str | None
    descriptor: object

def executable_plugin_fingerprint(plugin: Any) -> str | None: ...
