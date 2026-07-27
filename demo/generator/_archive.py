"""Deterministic archive primitives owned by the demo generator."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from plugin.archive import (
    normalize_archive_member_name as validate_archive_name,
)


DETERMINISTIC_GZIP_LEVEL = 3
"""Fast, byte-stable compression for generated JSON-heavy fixture archives."""


def json_bytes(value: Any) -> bytes:
    """Serialize one deterministic, human-readable JSON document."""

    return (
        json.dumps(value, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class ArchiveWriteResult:
    """Digest and byte count captured while an archive is written."""

    sha256: str
    size: int


class _DigestingWriter:
    """Minimal binary-writer proxy used by :class:`gzip.GzipFile`."""

    def __init__(self, output: Any) -> None:
        self._output = output
        self._digest = hashlib.sha256()
        self.size = 0

    def write(self, content: bytes) -> int:
        written = self._output.write(content)
        if written:
            emitted = content[:written]
            self._digest.update(emitted)
            self.size += written
        return written

    def flush(self) -> None:
        self._output.flush()

    def tell(self) -> int:
        return self._output.tell()

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()


def deterministic_tgz_bytes(files: Mapping[str, bytes]) -> bytes:
    """Return a byte-stable TGZ containing regular files only."""

    tar_buffer = io.BytesIO()
    with tarfile.open(
        fileobj=tar_buffer,
        mode="w",
        format=tarfile.PAX_FORMAT,
    ) as archive:
        for logical_name in sorted(files):
            path = validate_archive_name(logical_name)
            content = files[logical_name]
            info = tarfile.TarInfo(path.as_posix())
            info.size = len(content)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(content))
    output = io.BytesIO()
    with gzip.GzipFile(
        fileobj=output,
        mode="wb",
        compresslevel=DETERMINISTIC_GZIP_LEVEL,
        mtime=0,
        filename="",
    ) as compressor:
        compressor.write(tar_buffer.getvalue())
    return output.getvalue()


def write_deterministic_tgz(
    output: Path,
    members: Mapping[str, Path],
) -> ArchiveWriteResult:
    """Write a deterministic TGZ and capture its digest in the same pass."""

    with output.open("wb") as raw_output:
        digesting_output = _DigestingWriter(raw_output)
        with gzip.GzipFile(
            fileobj=digesting_output,
            mode="wb",
            compresslevel=DETERMINISTIC_GZIP_LEVEL,
            mtime=0,
            filename="",
        ) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w|",
                format=tarfile.PAX_FORMAT,
            ) as archive:
                for logical_name in sorted(members):
                    path = validate_archive_name(logical_name)
                    source = members[logical_name]
                    if source.is_symlink() or not source.is_file():
                        raise RuntimeError(
                            f"expected a regular file: {source}"
                        )
                    info = tarfile.TarInfo(path.as_posix())
                    info.size = source.stat().st_size
                    info.mode = 0o644
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    with source.open("rb") as content:
                        archive.addfile(info, content)
        raw_output.flush()
        return ArchiveWriteResult(
            sha256=digesting_output.sha256,
            size=digesting_output.size,
        )


def directory_members(directory: Path) -> dict[str, Path]:
    """Return regular files below *directory* keyed by safe archive names."""

    members: dict[str, Path] = {}
    for candidate in sorted(
        directory.rglob("*"),
        key=lambda item: item.as_posix(),
    ):
        if candidate.is_dir():
            continue
        if candidate.is_symlink() or not candidate.is_file():
            raise RuntimeError(f"expected a regular file: {candidate}")
        logical_name = candidate.relative_to(directory).as_posix()
        members[validate_archive_name(logical_name).as_posix()] = candidate
    return members


__all__ = [
    "ArchiveWriteResult",
    "DETERMINISTIC_GZIP_LEVEL",
    "deterministic_tgz_bytes",
    "directory_members",
    "json_bytes",
    "validate_archive_name",
    "write_deterministic_tgz",
]
