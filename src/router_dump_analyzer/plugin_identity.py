"""Deterministic executable identities for locally importable plug-ins."""

from __future__ import annotations

import hashlib
import inspect
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

MAX_PLUGIN_PACKAGE_FILES = 4_096
MAX_PLUGIN_PACKAGE_PATHS = 8_192
MAX_PLUGIN_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_PLUGIN_PACKAGE_FILE_BYTES = 32 * 1024 * 1024
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
