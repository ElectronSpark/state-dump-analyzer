"""Standalone temporal router state-dump generator.

This package intentionally has no dependency on the dump analyzer, its demo,
or any analyzer plug-in.  Saved authoring projects contain private ground
truth; generated node dumps expose only node-local final state and logs.
"""

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
