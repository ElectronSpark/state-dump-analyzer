"""Lexical path checks for the standalone generator's local file boundaries."""

from __future__ import annotations

import os
from pathlib import Path


def lexical_absolute(path: Path | str) -> Path:
    """Return an absolute normalized path without resolving symbolic links."""

    expanded = Path(path).expanduser()
    return Path(os.path.abspath(os.fspath(expanded)))


def path_has_link_component(path: Path | str) -> bool:
    """Return whether any existing component is a symlink or junction."""

    candidate = lexical_absolute(path)
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current = current / part
        if current.is_symlink():
            return True
        is_junction = getattr(current, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        if not current.exists():
            continue
    return False


def resolve_regular_file(path: Path | str, *, label: str) -> Path:
    """Resolve one existing regular file after rejecting link traversal."""

    lexical = lexical_absolute(path)
    if path_has_link_component(lexical) or not lexical.is_file():
        raise ValueError(f"{label} must be a regular file without link components")
    return lexical.resolve(strict=True)


def resolve_regular_directory(path: Path | str, *, label: str) -> Path:
    """Resolve one existing directory after rejecting link traversal."""

    lexical = lexical_absolute(path)
    if path_has_link_component(lexical) or not lexical.is_dir():
        raise ValueError(
            f"{label} must be a directory without symbolic-link or junction components"
        )
    return lexical.resolve(strict=True)


def resolve_output_file(path: Path | str, *, label: str) -> Path:
    """Resolve an output target without following a link in its existing path."""

    lexical = lexical_absolute(path)
    if path_has_link_component(lexical):
        raise ValueError(f"{label} cannot contain symbolic-link or junction components")
    if lexical.exists() and not lexical.is_file():
        raise ValueError(f"{label} must be a regular file")
    parent = lexical.parent.resolve(strict=True) if lexical.parent.exists() else lexical.parent
    return parent / lexical.name


__all__ = [
    "lexical_absolute",
    "path_has_link_component",
    "resolve_output_file",
    "resolve_regular_directory",
    "resolve_regular_file",
]
