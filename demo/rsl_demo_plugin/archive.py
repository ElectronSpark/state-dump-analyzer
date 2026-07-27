"""Archive-member name safety shared with the separate demo generator."""

from __future__ import annotations

from pathlib import PurePosixPath


ASSEMBLY_GENERATOR = "router-dump-analyzer-demo-assembly-v1"
NODE_PACK_GENERATOR = "router-dump-analyzer-packed-scale-v1"
ASSEMBLY_ROOT = "router-state-lab-demo"
NODE_PACK_ROOT = "router-state-lab-100k"
MANIFEST_MEMBER_NAME = "manifest.json"
COVERAGE_MEMBER_NAME = "coverage.json"
NORMALIZED_SCALE_DIRECTORY = "normalized-scale"
HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME = (
    "high-fanout-relationships.jsonl"
)
RELATIONSHIP_MUTATIONS_MEMBER_NAME = "relationship-mutations.jsonl"
CTF_METADATA_MEMBER = "routertrace/metadata"
CTF_STREAM_MEMBER = "routertrace/dummystream"
ASSEMBLY_MANIFEST_MEMBER = (
    f"{ASSEMBLY_ROOT}/{MANIFEST_MEMBER_NAME}"
)
ASSEMBLY_COVERAGE_MEMBER = (
    f"{ASSEMBLY_ROOT}/{COVERAGE_MEMBER_NAME}"
)
NODE_PACK_MANIFEST_MEMBER = (
    f"{NODE_PACK_ROOT}/{MANIFEST_MEMBER_NAME}"
)
NORMALIZED_SCALE_PREFIX = (
    f"{NODE_PACK_ROOT}/{NORMALIZED_SCALE_DIRECTORY}"
)
NORMALIZED_SCALE_MANIFEST_MEMBER = (
    f"{NORMALIZED_SCALE_PREFIX}/{MANIFEST_MEMBER_NAME}"
)


def normalize_archive_member_name(logical_name: str) -> PurePosixPath:
    """Return a safe canonical POSIX archive path or raise :class:`ValueError`."""

    if not logical_name or "\x00" in logical_name or "\\" in logical_name:
        raise ValueError(f"unsafe archive member name: {logical_name!r}")
    if logical_name.startswith("/") or (
        len(logical_name) >= 2
        and logical_name[0].isalpha()
        and logical_name[1] == ":"
    ):
        raise ValueError(f"unsafe archive member name: {logical_name!r}")
    path = PurePosixPath(logical_name)
    if (
        path == PurePosixPath(".")
        or path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != logical_name
    ):
        raise ValueError(f"unsafe archive member name: {logical_name!r}")
    reserved_windows_names = {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
    for part in path.parts:
        base_name = part.split(".", 1)[0].casefold()
        if (
            ":" in part
            or part.endswith((".", " "))
            or base_name in reserved_windows_names
        ):
            raise ValueError(f"unsafe archive member name: {logical_name!r}")
    return path


__all__ = [
    "ASSEMBLY_GENERATOR",
    "ASSEMBLY_COVERAGE_MEMBER",
    "ASSEMBLY_MANIFEST_MEMBER",
    "ASSEMBLY_ROOT",
    "COVERAGE_MEMBER_NAME",
    "CTF_METADATA_MEMBER",
    "CTF_STREAM_MEMBER",
    "HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME",
    "MANIFEST_MEMBER_NAME",
    "NODE_PACK_MANIFEST_MEMBER",
    "NODE_PACK_GENERATOR",
    "NODE_PACK_ROOT",
    "NORMALIZED_SCALE_DIRECTORY",
    "NORMALIZED_SCALE_MANIFEST_MEMBER",
    "NORMALIZED_SCALE_PREFIX",
    "RELATIONSHIP_MUTATIONS_MEMBER_NAME",
    "normalize_archive_member_name",
]
