"""Standalone temporal router state-dump generator.

This package intentionally has no dependency on the dump analyzer, its demo,
or any analyzer plug-in.  Saved authoring projects contain private ground
truth; generated node dumps expose only node-local final state and logs.
"""

from __future__ import annotations

from importlib import import_module as _import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .archive import (
        ASSEMBLY_SCHEMA,
        NODE_DUMP_SCHEMA,
        ArchiveProjectionError,
        build_assembly_bytes,
        build_node_dump_bytes,
        compile_and_build,
        write_assembly,
    )
    from .simulation import compile_scenario, reconstruct_scenario

__version__ = "0.1.0"

# Keep concrete legacy exports without importing their engines for leaf users.
_EXPORT_MODULES = {
    'ASSEMBLY_SCHEMA': '.archive',
    'NODE_DUMP_SCHEMA': '.archive',
    'ArchiveProjectionError': '.archive',
    'build_assembly_bytes': '.archive',
    'build_node_dump_bytes': '.archive',
    'compile_scenario': '.simulation',
    'compile_and_build': '.archive',
    'reconstruct_scenario': '.simulation',
    'write_assembly': '.archive',
}

__all__ = [
    "ASSEMBLY_SCHEMA",
    "NODE_DUMP_SCHEMA",
    "ArchiveProjectionError",
    "build_assembly_bytes",
    "build_node_dump_bytes",
    "compile_scenario",
    "compile_and_build",
    "reconstruct_scenario",
    "write_assembly",
]


def __getattr__(name: str) -> object:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(_import_module(module_name, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
