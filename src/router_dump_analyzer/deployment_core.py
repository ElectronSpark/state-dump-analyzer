"""Dependency-light primitives for trusted deployment descriptors.

Public deployment context types remain distinct so they cannot be substituted
across trust boundaries. Only their path normalization and target grammar are
shared here; importing or invoking a factory remains its adapter's responsibility.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_PLATFORM_PATH_TYPE = type(Path())


@dataclass(frozen=True, slots=True)
class _StateDirectoryContext:
    state_dir: Path

    def __post_init__(self) -> None:
        if type(self.state_dir) not in (str, _PLATFORM_PATH_TYPE):
            raise TypeError("state_dir must be a string or platform Path")
        try:
            resolved = Path(self.state_dir).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as error:
            raise ValueError("state_dir could not be resolved safely") from error
        if not resolved.is_absolute():  # pragma: no cover - resolve guarantees it.
            raise ValueError("state_dir must resolve to an absolute path")
        object.__setattr__(self, "state_dir", resolved)


def _deployment_target(value: object) -> tuple[str, str]:
    if type(value) is not str:
        raise TypeError("deployment target must be a string")
    if not value or value != value.strip() or len(value) > 512:
        raise ValueError("deployment target must use 'package.module:attribute' syntax")
    module_name, separator, attribute = value.partition(":")
    if (
        not separator
        or not module_name
        or not attribute
        or ":" in attribute
        or len(module_name) > 255
        or len(attribute) > 128
        or any(not part.isidentifier() for part in module_name.split("."))
        or not attribute.isidentifier()
    ):
        raise ValueError("deployment target must use 'package.module:attribute' syntax")
    return module_name, attribute
