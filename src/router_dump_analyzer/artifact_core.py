"""Core-owned, quota-enforced inventory and access for dump artifacts.

Plug-ins receive logical artifact identifiers and read-only streams.  They
never receive the original archive path and never choose extraction targets.
The reader accepts a regular file, a directory tree, a tar archive, or a ZIP
archive and applies the same portable member-name policy to every container.
"""

from __future__ import annotations

import mimetypes
import os
import shutil
import stat
import tarfile
import tempfile
import unicodedata
import zipfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from copy import copy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import IO, BinaryIO, Literal, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from .plugin_api import ArtifactInfo, DumpInventory, Value

_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_WINDOWS_INVALID_CHARACTERS = frozenset('<>:"\\|?*')
_MAX_PORTABLE_COMPONENT_BYTES = 255
_MAX_PORTABLE_PATH_BYTES = 4_096
_ZIP_END_RECORD_SIGNATURE = b"PK\x05\x06"
_ZIP_END_RECORD_BYTES = 22
_ZIP_MAX_COMMENT_BYTES = 65_535


class ArtifactBoundaryError(RuntimeError):
    """Raised when an input cannot safely cross the core/plug-in boundary."""


@dataclass(frozen=True, slots=True)
class ArtifactLimits:
    """Resource limits applied before and while artifact bytes are exposed."""

    max_artifacts: int = 10_000
    max_inventory_entries: int = 20_000
    max_path_depth: int = 32
    max_artifact_bytes: int = 512 * 1024 * 1024
    max_total_uncompressed_bytes: int = 2 * 1024 * 1024 * 1024
    max_compression_ratio: int = 1_000

    def __post_init__(self) -> None:
        for name, value in (
            ("max_artifacts", self.max_artifacts),
            ("max_inventory_entries", self.max_inventory_entries),
            ("max_path_depth", self.max_path_depth),
            ("max_artifact_bytes", self.max_artifact_bytes),
            (
                "max_total_uncompressed_bytes",
                self.max_total_uncompressed_bytes,
            ),
            ("max_compression_ratio", self.max_compression_ratio),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")


def _unsafe_artifact_component(component: str) -> bool:
    """Return whether one POSIX component is unsafe on supported hosts."""

    stem = component.partition(".")[0].casefold()
    return (
        not component
        or component in {".", ".."}
        or any(character in _WINDOWS_INVALID_CHARACTERS for character in component)
        or any(unicodedata.category(character) == "Cc" for character in component)
        or component[-1:] in {".", " "}
        or stem in _WINDOWS_RESERVED_NAMES
    )


def normalize_artifact_path(value: str) -> PurePosixPath:
    """Return one canonical, portable logical artifact path.

    This parser is deliberately independent from the demo generator's archive
    validator.  Both implementations are checked against the same normative
    vectors, while the core additionally produces its own boundary error type.
    """

    invalid_prefix = value[:1] == "/" or (
        len(value) > 1 and value[0].isalpha() and value[1] == ":"
    )
    raw_components = value.split("/")
    try:
        path_bytes = len(value.encode("utf-8"))
        component_bytes = tuple(
            len(component.encode("utf-8")) for component in raw_components
        )
    except UnicodeEncodeError as error:
        raise ArtifactBoundaryError(
            f"unsafe artifact path: {value!r}"
        ) from error
    if (
        not value
        or "\\" in value
        or invalid_prefix
        or path_bytes > _MAX_PORTABLE_PATH_BYTES
        or any(
            size > _MAX_PORTABLE_COMPONENT_BYTES for size in component_bytes
        )
        or any(_unsafe_artifact_component(item) for item in raw_components)
    ):
        raise ArtifactBoundaryError(f"unsafe artifact path: {value!r}")
    path = PurePosixPath(*raw_components)
    if path.is_absolute() or path.as_posix() != value:
        raise ArtifactBoundaryError(f"unsafe artifact path: {value!r}")
    return path


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _has_link_component(path: Path) -> bool:
    candidate = _lexical_absolute(path)
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current = current / part
        if current.is_symlink():
            return True
        is_junction = getattr(current, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        if not current.exists():
            break
    return False


def _regular_input(path: Path) -> Path:
    lexical = _lexical_absolute(path)
    if _has_link_component(lexical) or not (
        lexical.is_file() or lexical.is_dir()
    ):
        raise ArtifactBoundaryError(
            "analyzer input must be a regular file or directory without "
            "symbolic-link or junction components"
        )
    return lexical.resolve(strict=True)


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int


def _file_identity(result: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=result.st_dev,
        inode=result.st_ino,
        mode=stat.S_IFMT(result.st_mode),
        size=result.st_size,
        mtime_ns=result.st_mtime_ns,
        ctime_ns=result.st_ctime_ns,
    )


def _path_identity(
    path: Path,
    *,
    follow_symlinks: bool = True,
) -> _FileIdentity:
    return _file_identity(path.stat(follow_symlinks=follow_symlinks))


def _opened_regular_identity(path: Path) -> _FileIdentity:
    with path.open("rb") as stream:
        identity = _file_identity(os.fstat(stream.fileno()))
    if identity.mode != stat.S_IFREG:
        raise ArtifactBoundaryError("inventoried input is not a regular file")
    return identity


def _require_identity(
    actual: _FileIdentity,
    expected: _FileIdentity,
    *,
    description: str,
) -> None:
    if actual != expected:
        raise ArtifactBoundaryError(f"inventoried {description} changed")


def _require_same_object(
    actual: _FileIdentity,
    expected: _FileIdentity,
    *,
    description: str,
) -> None:
    stable_metadata_matches = (
        actual.mode,
        actual.size,
        actual.mtime_ns,
    ) == (
        expected.mode,
        expected.size,
        expected.mtime_ns,
    )
    identity_available = bool(expected.device or expected.inode)
    identity_matches = (
        actual.device,
        actual.inode,
    ) == (
        expected.device,
        expected.inode,
    )
    if not stable_metadata_matches or (
        identity_available and not identity_matches
    ):
        raise ArtifactBoundaryError(f"inventoried {description} changed")


def _portable_component(component: str) -> tuple[str, str]:
    normalized = unicodedata.normalize("NFC", component)
    return normalized, normalized.casefold()


def _portable_path_key(path: PurePosixPath) -> tuple[str, ...]:
    return tuple(_portable_component(part)[1] for part in path.parts)


def _normalize_directory_entry(value: str) -> PurePosixPath:
    candidate = value.removesuffix("/")
    return normalize_artifact_path(candidate)


@dataclass(frozen=True, slots=True)
class _ArtifactSource:
    artifact_id: UUID
    logical_path: PurePosixPath
    source_kind: Literal["file", "directory", "tar", "zip"]
    source_name: str | None
    compressed_size: int | None
    uncompressed_size: int
    media_type: str
    file_identity: _FileIdentity | None = None
    zip_crc: int | None = None
    tar_offset_data: int | None = None
    tar_member: tarfile.TarInfo | None = None


def _media_type(path: PurePosixPath) -> str:
    return (
        mimetypes.guess_type(path.name)[0]
        or "application/octet-stream"
    )


class CoreArtifactReader:
    """Concrete implementation of :class:`plugin_api.ArtifactReader`.

    The object is a context manager because private materializations are
    session-scoped.  Calling an access method after close fails explicitly.
    """

    def __init__(
        self,
        input_path: Path,
        *,
        node_hint: str | None = None,
        metadata: Mapping[str, Value] | None = None,
        limits: ArtifactLimits | None = None,
    ) -> None:
        self._input_path = _regular_input(input_path)
        self._input_identity = (
            _path_identity(self._input_path)
            if self._input_path.is_dir()
            else _opened_regular_identity(self._input_path)
        )
        self.limits = limits or ArtifactLimits()
        self._temporary = tempfile.TemporaryDirectory(
            prefix="router-dump-artifacts-"
        )
        self._materialized: dict[UUID, Path] = {}
        self._tar_container: BinaryIO | None = None
        self._tar_archive: tarfile.TarFile | None = None
        self._tar_sources_by_offset: tuple[_ArtifactSource, ...] = ()
        self._tar_source_positions: dict[UUID, int] = {}
        self._tar_materialized_through = -1
        self._lock = RLock()
        self._closed = False
        try:
            self._kind, sources = self._inventory_sources()
            _require_identity(
                (
                    _path_identity(self._input_path)
                    if self._input_path.is_dir()
                    else _opened_regular_identity(self._input_path)
                ),
                self._input_identity,
                description="input",
            )
        except BaseException:
            self._closed = True
            self._temporary.cleanup()
            raise
        self._sources = {item.artifact_id: item for item in sources}
        self._tar_sources_by_offset = tuple(
            sorted(
                (
                    item
                    for item in sources
                    if item.source_kind == "tar"
                ),
                key=lambda item: (
                    item.tar_offset_data
                    if item.tar_offset_data is not None
                    else -1
                ),
            )
        )
        self._tar_source_positions = {
            item.artifact_id: index
            for index, item in enumerate(self._tar_sources_by_offset)
        }
        inventory_metadata = dict(metadata or {})
        inventory_metadata.setdefault("container_kind", self._kind)
        self.inventory = DumpInventory(
            node_hint=node_hint,
            artifacts=tuple(
                ArtifactInfo(
                    artifact_id=item.artifact_id,
                    logical_path=item.logical_path,
                    parent_artifact_id=None,
                    media_type=item.media_type,
                    compressed_size=item.compressed_size,
                    uncompressed_size=item.uncompressed_size,
                    sha256=None,
                )
                for item in sources
            ),
            metadata=inventory_metadata,
        )

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._close_tar_session()
            finally:
                self._materialized.clear()
                self._temporary.cleanup()

    def _require_open(self) -> None:
        if self._closed:
            raise ArtifactBoundaryError("artifact reader is closed")

    def _artifact_id(self, logical_path: PurePosixPath) -> UUID:
        """Return an inventory-scoped ID without encoding a host path.

        Evidence IDs are interpreted within an immutable revision/inventory.
        Stable logical IDs keep equivalent inputs portable across machines;
        node and revision identity are incorporated separately when the core
        assigns globally visible source-record IDs.
        """

        return uuid5(
            NAMESPACE_URL,
            f"router-dump-artifact:v1:{logical_path.as_posix()}",
        )

    def _check_sources(
        self,
        sources: list[_ArtifactSource],
        *,
        container_bytes: int | None,
        declared_directories: Sequence[PurePosixPath] = (),
    ) -> tuple[_ArtifactSource, ...]:
        if len(sources) > self.limits.max_artifacts:
            raise ArtifactBoundaryError(
                "artifact count exceeds the configured limit"
            )
        total = 0
        namespace: dict[
            tuple[str, ...],
            tuple[Literal["directory", "file"], tuple[str, ...]],
        ] = {}
        explicit_directory_keys: set[tuple[str, ...]] = set()

        def add_namespace_path(
            path: PurePosixPath,
            *,
            kind: Literal["directory", "file"],
            explicit_directory: bool = False,
        ) -> None:
            portable_parts = _portable_path_key(path)
            normalized_parts = tuple(
                _portable_component(part)[0] for part in path.parts
            )
            for index in range(1, len(portable_parts) + 1):
                key = portable_parts[:index]
                normalized = normalized_parts[:index]
                expected_kind: Literal["directory", "file"] = (
                    kind if index == len(portable_parts) else "directory"
                )
                existing = namespace.get(key)
                if existing is None:
                    namespace[key] = (expected_kind, normalized)
                    continue
                existing_kind, existing_normalized = existing
                if existing_normalized != normalized:
                    raise ArtifactBoundaryError(
                        "NFC/casefold-colliding artifact namespace: "
                        f"{path}"
                    )
                if existing_kind == "file" and expected_kind == "directory":
                    raise ArtifactBoundaryError(
                        f"file/ancestor artifact collision: {path}"
                    )
                if (
                    existing_kind == "directory"
                    and expected_kind == "file"
                ):
                    raise ArtifactBoundaryError(
                        f"file/ancestor artifact collision: {path}"
                    )
                if expected_kind == "file":
                    raise ArtifactBoundaryError(
                        f"duplicate artifact: {path}"
                    )
            if explicit_directory:
                key = portable_parts
                if key in explicit_directory_keys:
                    raise ArtifactBoundaryError(
                        f"duplicate directory entry: {path}"
                    )
                explicit_directory_keys.add(key)

        for directory in declared_directories:
            add_namespace_path(
                directory,
                kind="directory",
                explicit_directory=True,
            )
        for source in sources:
            if len(source.logical_path.parts) > self.limits.max_path_depth:
                raise ArtifactBoundaryError(
                    f"artifact path exceeds depth limit: {source.logical_path}"
                )
            logical_name = source.logical_path.as_posix()
            add_namespace_path(source.logical_path, kind="file")
            if source.uncompressed_size > self.limits.max_artifact_bytes:
                raise ArtifactBoundaryError(
                    f"artifact exceeds per-file byte limit: {logical_name}"
                )
            total += source.uncompressed_size
            if total > self.limits.max_total_uncompressed_bytes:
                raise ArtifactBoundaryError(
                    "artifact set exceeds total uncompressed byte limit"
                )
            compressed = source.compressed_size
            if (
                compressed is not None
                and source.uncompressed_size
                > max(1, compressed) * self.limits.max_compression_ratio
            ):
                raise ArtifactBoundaryError(
                    f"artifact exceeds compression-ratio limit: {logical_name}"
                )
        if (
            container_bytes is not None
            and total
            > max(1, container_bytes) * self.limits.max_compression_ratio
        ):
            raise ArtifactBoundaryError(
                "artifact container exceeds total compression-ratio limit"
            )
        return tuple(sorted(sources, key=lambda item: item.logical_path.as_posix()))

    def _inventory_sources(
        self,
    ) -> tuple[str, tuple[_ArtifactSource, ...]]:
        if self._input_path.is_dir():
            return "directory", self._inventory_directory()
        if tarfile.is_tarfile(self._input_path):
            return "tar", self._inventory_tar()
        if zipfile.is_zipfile(self._input_path):
            return "zip", self._inventory_zip()
        size = self._input_identity.size
        logical_path = normalize_artifact_path(self._input_path.name)
        return "file", self._check_sources(
            [
                _ArtifactSource(
                    artifact_id=self._artifact_id(logical_path),
                    logical_path=logical_path,
                    source_kind="file",
                    source_name=None,
                    compressed_size=size,
                    uncompressed_size=size,
                    media_type=_media_type(logical_path),
                    file_identity=self._input_identity,
                )
            ],
            container_bytes=None,
        )

    def _inventory_directory(self) -> tuple[_ArtifactSource, ...]:
        sources: list[_ArtifactSource] = []
        entry_count = 0
        pending: list[tuple[Path, PurePosixPath | None]] = [
            (self._input_path, None)
        ]
        while pending:
            parent, logical_parent = pending.pop()
            try:
                entries = os.scandir(parent)
            except OSError as error:
                raise ArtifactBoundaryError(
                    "cannot enumerate directory input"
                ) from error
            with entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > self.limits.max_inventory_entries:
                        raise ArtifactBoundaryError(
                            "directory entry count exceeds the configured "
                            "inventory limit"
                        )
                    relative_name = (
                        entry.name
                        if logical_parent is None
                        else f"{logical_parent.as_posix()}/{entry.name}"
                    )
                    logical_path = normalize_artifact_path(relative_name)
                    if (
                        len(logical_path.parts)
                        > self.limits.max_path_depth
                    ):
                        raise ArtifactBoundaryError(
                            "directory entry path exceeds depth limit: "
                            f"{logical_path}"
                        )
                    candidate = Path(entry.path)
                    if entry.is_symlink() or _has_link_component(candidate):
                        raise ArtifactBoundaryError(
                            "directory input contains a link: "
                            f"{logical_path}"
                        )
                    is_junction = getattr(candidate, "is_junction", None)
                    if callable(is_junction) and is_junction():
                        raise ArtifactBoundaryError(
                            "directory input contains a junction: "
                            f"{logical_path}"
                        )
                    if entry.is_dir(follow_symlinks=False):
                        pending.append((candidate, logical_path))
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        raise ArtifactBoundaryError(
                            "directory input contains a non-regular entry: "
                            f"{logical_path}"
                        )
                    discovered_identity = _file_identity(
                        entry.stat(follow_symlinks=False)
                    )
                    with candidate.open("rb") as opened:
                        identity = _file_identity(
                            os.fstat(opened.fileno())
                        )
                    _require_same_object(
                        identity,
                        discovered_identity,
                        description=f"artifact {logical_path}",
                    )
                    if identity.mode != stat.S_IFREG:
                        raise ArtifactBoundaryError(
                            "directory input contains a non-regular entry: "
                            f"{logical_path}"
                        )
                    sources.append(
                        _ArtifactSource(
                            artifact_id=self._artifact_id(logical_path),
                            logical_path=logical_path,
                            source_kind="directory",
                            source_name=logical_path.as_posix(),
                            compressed_size=identity.size,
                            uncompressed_size=identity.size,
                            media_type=_media_type(logical_path),
                            file_identity=identity,
                        )
                    )
                    if len(sources) > self.limits.max_artifacts:
                        raise ArtifactBoundaryError(
                            "artifact count exceeds the configured limit"
                        )
        return self._check_sources(sources, container_bytes=None)

    def _inventory_tar(self) -> tuple[_ArtifactSource, ...]:
        sources: list[_ArtifactSource] = []
        directories: list[PurePosixPath] = []
        entry_count = 0
        with self._input_path.open("rb") as container:
            _require_identity(
                _file_identity(os.fstat(container.fileno())),
                self._input_identity,
                description="input",
            )
            with tarfile.open(fileobj=container, mode="r:*") as archive:
                for member in archive:
                    entry_count += 1
                    if entry_count > self.limits.max_inventory_entries:
                        raise ArtifactBoundaryError(
                            "tar member count exceeds the configured "
                            "inventory limit"
                        )
                    if member.isdir():
                        directories.append(
                            _normalize_directory_entry(member.name)
                        )
                        continue
                    logical_path = normalize_artifact_path(member.name)
                    if not member.isfile():
                        raise ArtifactBoundaryError(
                            "tar contains a non-regular member: "
                            f"{member.name}"
                        )
                    sources.append(
                        _ArtifactSource(
                            artifact_id=self._artifact_id(logical_path),
                            logical_path=logical_path,
                            source_kind="tar",
                            source_name=member.name,
                            compressed_size=None,
                            uncompressed_size=member.size,
                            media_type=_media_type(logical_path),
                            tar_offset_data=member.offset_data,
                            tar_member=copy(member),
                        )
                    )
                    if len(sources) > self.limits.max_artifacts:
                        raise ArtifactBoundaryError(
                            "artifact count exceeds the configured limit"
                        )
            _require_identity(
                _file_identity(os.fstat(container.fileno())),
                self._input_identity,
                description="input",
            )
        return self._check_sources(
            sources,
            container_bytes=self._input_identity.size,
            declared_directories=directories,
        )

    def _inventory_zip(self) -> tuple[_ArtifactSource, ...]:
        sources: list[_ArtifactSource] = []
        directories: list[PurePosixPath] = []
        with self._input_path.open("rb") as container:
            _require_identity(
                _file_identity(os.fstat(container.fileno())),
                self._input_identity,
                description="input",
            )
            self._preflight_zip_entry_count(container)
            container.seek(0)
            with zipfile.ZipFile(container, mode="r") as archive:
                members = archive.filelist
                if len(members) > self.limits.max_inventory_entries:
                    raise ArtifactBoundaryError(
                        "zip member count exceeds the configured inventory "
                        "limit"
                    )
                for member in members:
                    if member.is_dir():
                        directories.append(
                            _normalize_directory_entry(member.filename)
                        )
                        continue
                    logical_path = normalize_artifact_path(member.filename)
                    unix_mode = member.external_attr >> 16
                    file_type = stat.S_IFMT(unix_mode)
                    if file_type and not stat.S_ISREG(unix_mode):
                        raise ArtifactBoundaryError(
                            "zip contains a non-regular member: "
                            f"{member.filename}"
                        )
                    sources.append(
                        _ArtifactSource(
                            artifact_id=self._artifact_id(logical_path),
                            logical_path=logical_path,
                            source_kind="zip",
                            source_name=member.filename,
                            compressed_size=member.compress_size,
                            uncompressed_size=member.file_size,
                            media_type=_media_type(logical_path),
                            zip_crc=member.CRC,
                        )
                    )
                    if len(sources) > self.limits.max_artifacts:
                        raise ArtifactBoundaryError(
                            "artifact count exceeds the configured limit"
                        )
            _require_identity(
                _file_identity(os.fstat(container.fileno())),
                self._input_identity,
                description="input",
            )
        return self._check_sources(
            sources,
            container_bytes=self._input_identity.size,
            declared_directories=directories,
        )

    def _preflight_zip_entry_count(self, container: BinaryIO) -> None:
        """Reject oversized ZIP inventories before ``ZipFile`` builds lists."""

        tail_bytes = min(
            self._input_identity.size,
            _ZIP_END_RECORD_BYTES + _ZIP_MAX_COMMENT_BYTES,
        )
        container.seek(-tail_bytes, os.SEEK_END)
        tail = container.read(tail_bytes)
        record_offset = len(tail)
        record = b""
        while record_offset:
            record_offset = tail.rfind(
                _ZIP_END_RECORD_SIGNATURE,
                0,
                record_offset,
            )
            if record_offset < 0:
                break
            candidate = tail[
                record_offset : record_offset + _ZIP_END_RECORD_BYTES
            ]
            if len(candidate) == _ZIP_END_RECORD_BYTES:
                comment_bytes = int.from_bytes(candidate[20:22], "little")
                if (
                    record_offset
                    + _ZIP_END_RECORD_BYTES
                    + comment_bytes
                    == len(tail)
                ):
                    record = candidate
                    break
        if not record:
            raise ArtifactBoundaryError("zip end record is missing or invalid")
        if int.from_bytes(record[4:6], "little") or int.from_bytes(
            record[6:8], "little"
        ):
            raise ArtifactBoundaryError(
                "multi-disk ZIP archives are not supported"
            )
        entry_count = int.from_bytes(record[10:12], "little")
        if entry_count == 0xFFFF:
            raise ArtifactBoundaryError(
                "ZIP64 member enumeration cannot be bounded safely"
            )
        if entry_count > self.limits.max_inventory_entries:
            raise ArtifactBoundaryError(
                "zip member count exceeds the configured inventory limit"
            )

    @staticmethod
    def _copy_bounded(
        source: IO[bytes],
        destination: IO[bytes],
        *,
        expected_bytes: int,
        maximum_bytes: int,
    ) -> None:
        copied = 0
        while chunk := source.read(1024 * 1024):
            copied += len(chunk)
            if copied > maximum_bytes:
                raise ArtifactBoundaryError(
                    "artifact exceeded its declared or configured byte limit"
                )
            destination.write(chunk)
        if copied != expected_bytes:
            raise ArtifactBoundaryError(
                "artifact byte count disagrees with its inventory metadata"
            )

    @staticmethod
    def _tar_info(source: _ArtifactSource) -> tarfile.TarInfo:
        if (
            source.source_name is None
            or source.tar_offset_data is None
            or source.tar_member is None
        ):
            raise ArtifactBoundaryError(
                f"tar member index is incomplete: {source.logical_path}"
            )
        member = copy(source.tar_member)
        if (
            member.name != source.source_name
            or member.size != source.uncompressed_size
            or member.offset_data != source.tar_offset_data
            or not member.isfile()
        ):
            raise ArtifactBoundaryError(
                f"tar member index is inconsistent: {source.logical_path}"
            )
        return member

    def _close_tar_session(self) -> None:
        archive = self._tar_archive
        container = self._tar_container
        self._tar_archive = None
        self._tar_container = None
        try:
            if archive is not None:
                archive.close()
        finally:
            if container is not None:
                container.close()

    def _require_tar_session(
        self,
    ) -> tuple[BinaryIO, tarfile.TarFile]:
        if self._tar_container is not None and self._tar_archive is not None:
            return self._tar_container, self._tar_archive
        container = self._input_path.open("rb")
        try:
            _require_identity(
                _file_identity(os.fstat(container.fileno())),
                self._input_identity,
                description="input",
            )
            # This archive intentionally lives until the owning reader closes.
            archive = tarfile.open(  # noqa: SIM115
                fileobj=container,
                mode="r:*",
            )
        except BaseException:
            container.close()
            raise
        self._tar_container = container
        self._tar_archive = archive
        return container, archive

    def _materialize_tar_through(self, position: int) -> None:
        """Materialize a tar prefix once, in physical member order.

        A compressed tar stream can seek forward cheaply but may replay all
        decompression on a backward seek.  Caching every preceding regular
        member means arbitrary subsequent artifact access never moves the
        shared archive stream backward and each member is decoded at most
        once per reader session.
        """

        if position <= self._tar_materialized_through:
            return
        container, archive = self._require_tar_session()
        first_new_position = self._tar_materialized_through + 1
        try:
            for index in range(
                first_new_position,
                position + 1,
            ):
                source = self._tar_sources_by_offset[index]
                target = (
                    Path(self._temporary.name)
                    / "files"
                    / source.artifact_id.hex
                )
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    member = self._tar_info(source)
                    tar_stream = archive.extractfile(member)
                    if tar_stream is None:
                        raise ArtifactBoundaryError(
                            f"cannot read tar member: {source.logical_path}"
                        )
                    with (
                        tar_stream,
                        target.open("xb") as destination,
                    ):
                        self._copy_bounded(
                            tar_stream,
                            destination,
                            expected_bytes=source.uncompressed_size,
                            maximum_bytes=min(
                                source.uncompressed_size,
                                self.limits.max_artifact_bytes,
                            ),
                        )
                    target.chmod(
                        stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
                    )
                except BaseException:
                    target.unlink(missing_ok=True)
                    raise
                self._materialized[source.artifact_id] = target
                self._tar_materialized_through = index
            _require_identity(
                _file_identity(os.fstat(container.fileno())),
                self._input_identity,
                description="input",
            )
        except BaseException:
            for index in range(
                first_new_position,
                self._tar_materialized_through + 1,
            ):
                artifact_id = self._tar_sources_by_offset[
                    index
                ].artifact_id
                materialized = self._materialized.pop(artifact_id, None)
                if materialized is not None:
                    materialized.unlink(missing_ok=True)
            self._tar_materialized_through = first_new_position - 1
            self._close_tar_session()
            raise

    @contextmanager
    def _source_stream(self, source: _ArtifactSource) -> Iterator[IO[bytes]]:
        if source.source_kind == "file":
            assert source.file_identity is not None
            with self._input_path.open("rb") as file_stream:
                _require_identity(
                    _file_identity(os.fstat(file_stream.fileno())),
                    source.file_identity,
                    description=f"artifact {source.logical_path}",
                )
                try:
                    yield file_stream
                finally:
                    _require_identity(
                        _file_identity(os.fstat(file_stream.fileno())),
                        source.file_identity,
                        description=f"artifact {source.logical_path}",
                    )
            return
        if source.source_kind == "directory":
            assert source.source_name is not None
            assert source.file_identity is not None
            candidate = self._input_path.joinpath(
                *PurePosixPath(source.source_name).parts
            )
            if _has_link_component(candidate) or not candidate.is_file():
                raise ArtifactBoundaryError(
                    f"inventoried artifact is no longer a regular file: "
                    f"{source.logical_path}"
                )
            with candidate.open("rb") as directory_stream:
                _require_identity(
                    _file_identity(os.fstat(directory_stream.fileno())),
                    source.file_identity,
                    description=f"artifact {source.logical_path}",
                )
                try:
                    yield directory_stream
                finally:
                    _require_identity(
                        _file_identity(os.fstat(directory_stream.fileno())),
                        source.file_identity,
                        description=f"artifact {source.logical_path}",
                    )
            return
        if source.source_kind == "tar":
            raise AssertionError(
                "tar sources use the forward-only session materializer"
            )
        assert source.source_kind == "zip"
        assert source.source_name is not None
        with self._input_path.open("rb") as container:
            _require_identity(
                _file_identity(os.fstat(container.fileno())),
                self._input_identity,
                description="input",
            )
            with zipfile.ZipFile(container, mode="r") as archive:
                try:
                    zip_member = archive.getinfo(source.source_name)
                except KeyError as error:
                    raise ArtifactBoundaryError(
                        f"inventoried zip member disappeared: "
                        f"{source.logical_path}"
                    ) from error
                if (
                    zip_member.file_size != source.uncompressed_size
                    or zip_member.compress_size != source.compressed_size
                    or zip_member.CRC != source.zip_crc
                ):
                    raise ArtifactBoundaryError(
                        f"inventoried zip member changed: {source.logical_path}"
                    )
                with archive.open(zip_member, mode="r") as zip_stream:
                    try:
                        yield zip_stream
                    finally:
                        _require_identity(
                            _file_identity(os.fstat(container.fileno())),
                            self._input_identity,
                            description="input",
                        )

    def _materialize(self, artifact_id: UUID) -> Path:
        self._require_open()
        try:
            source = self._sources[artifact_id]
        except KeyError as error:
            raise ArtifactBoundaryError(
                f"unknown artifact identifier: {artifact_id}"
            ) from error
        with self._lock:
            cached = self._materialized.get(artifact_id)
            if cached is not None:
                return cached
            if source.source_kind == "tar":
                try:
                    position = self._tar_source_positions[artifact_id]
                except KeyError as error:
                    raise ArtifactBoundaryError(
                        f"tar member index is missing: "
                        f"{source.logical_path}"
                    ) from error
                self._materialize_tar_through(position)
                return self._materialized[artifact_id]
            target = Path(self._temporary.name) / "files" / artifact_id.hex
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with (
                    target.open("xb") as destination,
                    self._source_stream(source) as stream,
                ):
                    self._copy_bounded(
                        stream,
                        destination,
                        expected_bytes=source.uncompressed_size,
                        maximum_bytes=min(
                            source.uncompressed_size,
                            self.limits.max_artifact_bytes,
                        ),
                    )
                target.chmod(
                    stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
                )
            except BaseException:
                target.unlink(missing_ok=True)
                raise
            self._materialized[artifact_id] = target
            return target

    def open_binary(self, artifact_id: UUID) -> BinaryIO:
        """Open one private materialization as a new read-only binary stream."""

        return self._materialize(artifact_id).open("rb")

    def scoped(
        self,
        artifact_ids: Sequence[UUID],
    ) -> ScopedArtifactReader:
        """Return a non-owning reader restricted to exactly these artifacts.

        The facade deliberately has no ``close`` operation.  Its streams and
        private materializations remain owned by this parent session, and
        every access fails once the parent closes.
        """

        self._require_open()
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ArtifactBoundaryError(
                "artifact scopes cannot repeat artifact identifiers"
            )
        for artifact_id in artifact_ids:
            if artifact_id not in self._sources:
                raise ArtifactBoundaryError(
                    f"unknown artifact identifier: {artifact_id}"
                )
        return ScopedArtifactReader(self, tuple(artifact_ids))

    def materialize_private_path(self, artifact_id: UUID) -> str:
        """Return a session-private path for a single inventoried artifact."""

        return os.fspath(self._materialize(artifact_id))

    def materialize_private_tree(
        self,
        artifact_ids: Sequence[UUID],
        logical_root: PurePosixPath | None = None,
    ) -> str:
        """Copy selected artifacts into one session-private logical tree."""

        self._require_open()
        if not artifact_ids:
            raise ArtifactBoundaryError(
                "private trees require at least one artifact"
            )
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ArtifactBoundaryError(
                "private trees cannot repeat artifact identifiers"
            )
        root = (
            normalize_artifact_path(logical_root.as_posix())
            if logical_root is not None
            else None
        )
        digest = sha256()
        digest.update(b"router-dump-private-tree:v1")
        digest.update((root.as_posix() if root else "").encode("utf-8"))
        for artifact_id in artifact_ids:
            digest.update(artifact_id.bytes)
        tree = Path(self._temporary.name) / "trees" / digest.hexdigest()
        with self._lock:
            if tree.exists():
                return os.fspath(tree)
            tree.mkdir(parents=True, exist_ok=False)
            try:
                used_paths: set[str] = set()
                for artifact_id in artifact_ids:
                    try:
                        source = self._sources[artifact_id]
                    except KeyError as error:
                        raise ArtifactBoundaryError(
                            f"unknown artifact identifier: {artifact_id}"
                        ) from error
                    relative = source.logical_path
                    if root is not None:
                        try:
                            relative = relative.relative_to(root)
                        except ValueError as error:
                            raise ArtifactBoundaryError(
                                f"artifact {source.logical_path} is outside "
                                f"logical root {root}"
                            ) from error
                    if relative == PurePosixPath("."):
                        relative = PurePosixPath(source.logical_path.name)
                    portable = "/".join(_portable_path_key(relative))
                    if portable in used_paths:
                        raise ArtifactBoundaryError(
                            f"private tree path collision: {relative}"
                        )
                    used_paths.add(portable)
                    destination = tree.joinpath(*relative.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(
                        self._materialize(artifact_id),
                        destination,
                    )
                    destination.chmod(
                        stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
                    )
            except BaseException:
                shutil.rmtree(tree, ignore_errors=True)
                raise
        return os.fspath(tree)


class ScopedArtifactReader:
    """Non-owning, read-only view over an explicit artifact capability set."""

    __slots__ = ("_artifact_ids", "_parent", "inventory")

    def __init__(
        self,
        parent: CoreArtifactReader,
        artifact_ids: tuple[UUID, ...],
    ) -> None:
        self._parent = parent
        self._artifact_ids = frozenset(artifact_ids)
        artifacts_by_id = {
            artifact.artifact_id: artifact
            for artifact in parent.inventory.artifacts
        }
        self.inventory = DumpInventory(
            node_hint=parent.inventory.node_hint,
            artifacts=tuple(
                artifacts_by_id[artifact_id]
                for artifact_id in artifact_ids
            ),
            metadata=dict(parent.inventory.metadata),
        )

    def _require_allowed(self, artifact_id: UUID) -> None:
        self._parent._require_open()
        if artifact_id not in self._artifact_ids:
            raise ArtifactBoundaryError(
                f"artifact identifier is outside this reader scope: "
                f"{artifact_id}"
            )

    def open_binary(self, artifact_id: UUID) -> BinaryIO:
        self._require_allowed(artifact_id)
        return self._parent.open_binary(artifact_id)

    def materialize_private_path(self, artifact_id: UUID) -> str:
        self._require_allowed(artifact_id)
        return self._parent.materialize_private_path(artifact_id)

    def materialize_private_tree(
        self,
        artifact_ids: Sequence[UUID],
        logical_root: PurePosixPath | None = None,
    ) -> str:
        if not artifact_ids:
            self._parent._require_open()
        for artifact_id in artifact_ids:
            self._require_allowed(artifact_id)
        return self._parent.materialize_private_tree(
            artifact_ids,
            logical_root,
        )

    def scoped(
        self,
        artifact_ids: Sequence[UUID],
    ) -> ScopedArtifactReader:
        for artifact_id in artifact_ids:
            self._require_allowed(artifact_id)
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ArtifactBoundaryError(
                "artifact scopes cannot repeat artifact identifiers"
            )
        return ScopedArtifactReader(self._parent, tuple(artifact_ids))


__all__ = [
    "ArtifactBoundaryError",
    "ArtifactLimits",
    "CoreArtifactReader",
    "ScopedArtifactReader",
    "normalize_artifact_path",
]
