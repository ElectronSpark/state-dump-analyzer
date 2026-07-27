"""Example plug-in lazy access to the generated multi-node demo assembly.

The assembly is a transport format owned by the example plug-in.  This module
adapts it to the core ``RevisionStore`` contract without eagerly expanding
every 100K-event history.  The small outer archive index is read once, nested
node archives are copied to a private temporary cache in one pass, and full
normalized datasets are materialized only when a node workspace requests one.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import tempfile
from collections import OrderedDict
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from router_dump_analyzer.revision_store import (
    AssemblyDescriptor,
    RevisionDescriptor,
)

from .archive import (
    ASSEMBLY_COVERAGE_MEMBER,
    ASSEMBLY_GENERATOR,
    ASSEMBLY_MANIFEST_MEMBER,
    ASSEMBLY_ROOT,
    MANIFEST_MEMBER_NAME,
    NODE_PACK_ROOT,
    normalize_archive_member_name,
)
from . import (
    GENERATED_ASSEMBLY_FORMAT_VERSION,
    GENERATED_PROJECTION_POLICY,
)
from .scale_data import ScaleRuntime, load_scale_dataset


MAX_ASSEMBLY_METADATA_BYTES = 16 * 1024 * 1024
MAX_NESTED_NODE_ARCHIVE_BYTES = 512 * 1024 * 1024
PLUGIN_PROJECTION_ROOT = GENERATED_PROJECTION_POLICY.projection_root


class DemoAssemblyError(RuntimeError):
    """Raised when the generated demo assembly is unsafe or inconsistent."""


DatasetLoader = Callable[[Path, str], dict[str, Any]]


def _safe_member_name(name: str) -> PurePosixPath:
    try:
        return normalize_archive_member_name(name)
    except ValueError as error:
        raise DemoAssemblyError(
            f"unsafe assembly member name: {name!r}"
        ) from error


def _read_json_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
) -> dict[str, Any]:
    if not member.isfile() or member.size > MAX_ASSEMBLY_METADATA_BYTES:
        raise DemoAssemblyError(
            f"assembly metadata member is not a bounded regular file: {member.name}"
        )
    source = archive.extractfile(member)
    if source is None:
        raise DemoAssemblyError(f"cannot read assembly member: {member.name}")
    try:
        value = json.load(source)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DemoAssemblyError(
            f"assembly member is not valid JSON: {member.name}"
        ) from error
    if not isinstance(value, dict):
        raise DemoAssemblyError(
            f"assembly JSON member must contain an object: {member.name}"
        )
    return value


def _default_dataset_loader(path: Path, revision_id: str) -> dict[str, Any]:
    return load_scale_dataset(
        path,
        revision_id=revision_id,
        gaps=[],
        review_prompts=[],
    )


class DemoAssemblyStore:
    """Implement the core revision store over one generated demo assembly."""

    def __init__(
        self,
        archive_path: Path,
        *,
        cache_size: int = 2,
        dataset_loader: DatasetLoader | None = None,
    ) -> None:
        if cache_size < 1:
            raise ValueError("cache_size must be at least one")
        candidate = archive_path.expanduser().resolve()
        if candidate.is_symlink() or not candidate.is_file():
            raise DemoAssemblyError(
                f"demo assembly is not a regular file: {candidate}"
            )
        self.archive_path = candidate
        self.cache_size = cache_size
        self._dataset_loader = dataset_loader or _default_dataset_loader
        self._temporary_directory = tempfile.TemporaryDirectory(
            prefix="router-dump-plugin-assembly-"
        )
        self._node_archive_paths: dict[str, Path] = {}
        self._revisions_by_id: dict[str, RevisionDescriptor] = {}
        self._revisions_by_node: dict[str, RevisionDescriptor] = {}
        self._datasets: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._projections_by_node: dict[str, dict[str, Any]] = {}
        self.coverage: dict[str, Any] = {}
        self.manifest: dict[str, Any] = {}
        try:
            self._index_and_materialize_node_archives()
        except BaseException:
            self._temporary_directory.cleanup()
            raise

    def _index_and_materialize_node_archives(self) -> None:
        manifest_name = ASSEMBLY_MANIFEST_MEMBER
        coverage_name = ASSEMBLY_COVERAGE_MEMBER
        with tarfile.open(self.archive_path, mode="r:gz") as archive:
            members: dict[str, tarfile.TarInfo] = {}
            for member in archive.getmembers():
                _safe_member_name(member.name)
                if member.name in members:
                    raise DemoAssemblyError(
                        f"duplicate assembly member: {member.name}"
                    )
                if not member.isfile() and not member.isdir():
                    raise DemoAssemblyError(
                        f"assembly contains a non-regular member: {member.name}"
                    )
                members[member.name] = member
            try:
                manifest_member = members[manifest_name]
                coverage_member = members[coverage_name]
            except KeyError as error:
                raise DemoAssemblyError(
                    "assembly must contain manifest.json and coverage.json"
                ) from error
            manifest = _read_json_member(archive, manifest_member)
            coverage = _read_json_member(archive, coverage_member)
            if manifest.get("generator") != ASSEMBLY_GENERATOR:
                raise DemoAssemblyError("unsupported demo assembly generator")
            if (
                manifest.get("format_version")
                != GENERATED_ASSEMBLY_FORMAT_VERSION
            ):
                raise DemoAssemblyError("unsupported demo assembly format version")
            try:
                GENERATED_PROJECTION_POLICY.validate_archive_plugin_descriptor(
                    manifest.get("plugin")
                )
                GENERATED_PROJECTION_POLICY.validate_coverage_registry(
                    coverage
                )
            except ValueError as error:
                raise DemoAssemblyError(str(error)) from error
            raw_nodes = manifest.get("nodes")
            if not isinstance(raw_nodes, list) or not raw_nodes:
                raise DemoAssemblyError("assembly manifest nodes must be non-empty")

            descriptors: list[RevisionDescriptor] = []
            for raw_node in raw_nodes:
                if not isinstance(raw_node, dict):
                    raise DemoAssemblyError(
                        "assembly manifest node entries must be objects"
                    )
                try:
                    node_id = str(raw_node["node_id"])
                    revision_id = str(raw_node["revision_id"])
                    logical_archive = str(raw_node["archive"])
                    expected_sha256 = str(raw_node["sha256"])
                    expected_size = int(raw_node["compressed_size"])
                    event_count = int(raw_node["event_records"])
                    resource_count = int(raw_node["resource_records"])
                except (KeyError, TypeError, ValueError) as error:
                    raise DemoAssemblyError(
                        "assembly node metadata is incomplete or malformed"
                    ) from error
                if (
                    not node_id
                    or not revision_id
                    or not logical_archive
                    or not expected_sha256
                    or expected_size < 0
                    or event_count < 0
                    or resource_count < 0
                ):
                    raise DemoAssemblyError("assembly node metadata is invalid")
                if node_id in self._revisions_by_node:
                    raise DemoAssemblyError(f"duplicate assembly node: {node_id}")
                if revision_id in self._revisions_by_id:
                    raise DemoAssemblyError(
                        f"duplicate assembly revision: {revision_id}"
                    )
                expected_member_name = f"{ASSEMBLY_ROOT}/{logical_archive}"
                member = members.get(expected_member_name)
                if (
                    member is None
                    or not member.isfile()
                    or member.size != expected_size
                    or member.size > MAX_NESTED_NODE_ARCHIVE_BYTES
                ):
                    raise DemoAssemblyError(
                        f"nested node archive size/member mismatch: {node_id}"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise DemoAssemblyError(
                        f"cannot read nested node archive: {node_id}"
                    )
                target = (
                    Path(self._temporary_directory.name)
                    / f"{len(descriptors):03d}-{node_id}.tgz"
                )
                digest = hashlib.sha256()
                with target.open("wb") as output:
                    while chunk := source.read(1024 * 1024):
                        digest.update(chunk)
                        output.write(chunk)
                if digest.hexdigest() != expected_sha256:
                    target.unlink(missing_ok=True)
                    raise DemoAssemblyError(
                        f"nested node archive checksum mismatch: {node_id}"
                    )
                self._projections_by_node[node_id] = (
                    self._read_plugin_projection(target, node_id, revision_id)
                )
                descriptor = RevisionDescriptor(
                    node_id=node_id,
                    revision_id=revision_id,
                    label=str(raw_node.get("label") or node_id),
                    event_count=event_count,
                    resource_count=resource_count,
                    plugin_ids=(
                        str(manifest.get("plugin", {}).get("plugin_id", "")),
                    )
                    if isinstance(manifest.get("plugin"), dict)
                    and manifest["plugin"].get("plugin_id")
                    else (),
                    metadata={
                        key: value
                        for key, value in raw_node.items()
                        if key
                        not in {
                            "node_id",
                            "revision_id",
                            "label",
                            "event_records",
                            "resource_records",
                        }
                    },
                )
                descriptors.append(descriptor)
                self._node_archive_paths[revision_id] = target
                self._revisions_by_id[revision_id] = descriptor
                self._revisions_by_node[node_id] = descriptor

        coverage_cases = coverage.get("cases")
        if not isinstance(coverage_cases, list):
            raise DemoAssemblyError("coverage cases must be an array")
        case_ids: list[str] = []
        for case in coverage_cases:
            assert isinstance(case, Mapping)
            case_ids.append(str(case["case_id"]))

        default_node_id = str(manifest.get("default_node_id", ""))
        if default_node_id not in self._revisions_by_node:
            raise DemoAssemblyError(
                "assembly default_node_id does not identify a member"
            )
        self.default_node_id = default_node_id
        self.default_revision_id = self._revisions_by_node[
            default_node_id
        ].revision_id
        self.manifest = manifest
        self.coverage = coverage
        self.assembly = AssemblyDescriptor(
            assembly_id=str(manifest.get("assembly_id") or "demo-assembly"),
            revisions=tuple(descriptors),
            coverage_case_ids=tuple(case_ids),
            metadata={
                "generator": manifest["generator"],
                "format_version": manifest["format_version"],
                "seed": manifest.get("seed"),
                "scale_policy": manifest.get("scale_policy", {}),
                "plugin_projection": (
                    GENERATED_PROJECTION_POLICY.runtime_load_descriptor()
                ),
            },
        )

    @staticmethod
    def _read_plugin_projection(
        archive_path: Path,
        node_id: str,
        revision_id: str,
    ) -> dict[str, Any]:
        prefix = f"{NODE_PACK_ROOT}/{PLUGIN_PROJECTION_ROOT}/"
        wanted = {f"{prefix}{MANIFEST_MEMBER_NAME}": "manifest"}
        wanted.update(
            {
                f"{prefix}{member.relative_path}": member.member_id
                for member in GENERATED_PROJECTION_POLICY.projection_members
            }
        )
        payloads: dict[str, bytes] = {}
        # Node packs are gzip streams. ``getmembers()`` followed by
        # ``extractfile()`` seeks backwards through that stream for each
        # selected projection member, repeatedly decompressing large event
        # prefixes. Consume the pack once in archive order instead; projection
        # members are immutable and individually bounded.
        with tarfile.open(archive_path, mode="r|gz") as archive:
            seen: set[str] = set()
            for member in archive:
                _safe_member_name(member.name)
                if member.name in seen:
                    raise DemoAssemblyError(
                        f"duplicate node-pack member: {member.name}"
                    )
                seen.add(member.name)
                target = wanted.get(member.name)
                if target is None:
                    continue
                if (
                    not member.isfile()
                    or member.size > MAX_ASSEMBLY_METADATA_BYTES
                ):
                    raise DemoAssemblyError(
                        f"node projection member is not bounded: {member.name}"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise DemoAssemblyError(
                        f"cannot read node projection member: {member.name}"
                    )
                payloads[target] = source.read()
        missing = set(wanted.values()) - payloads.keys()
        if missing:
            raise DemoAssemblyError(
                f"node {node_id} lacks plug-in projection members: "
                + ", ".join(sorted(missing))
            )
        try:
            manifest = json.loads(payloads["manifest"])
            topology = json.loads(payloads["topology"])
            packet_cases = json.loads(payloads["packet_cases"])
            routes = [
                json.loads(line)
                for line in payloads["routes"].splitlines()
                if line.strip()
            ]
            forwarding = [
                json.loads(line)
                for line in payloads["forwarding"].splitlines()
                if line.strip()
            ]
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DemoAssemblyError(
                f"node {node_id} plug-in projection is malformed"
            ) from error
        for value, label in (
            (manifest, "manifest"),
            (topology, "topology"),
            (packet_cases, "packet_cases"),
        ):
            if not isinstance(value, dict):
                raise DemoAssemblyError(
                    f"node {node_id} projection {label} must be an object"
                )
            if (
                str(value.get("node_id", "")) != node_id
                or str(value.get("revision_id", "")) != revision_id
            ):
                raise DemoAssemblyError(
                    f"node {node_id} projection {label} identity mismatch"
                )
        files = manifest.get("files")
        if not isinstance(files, dict):
            raise DemoAssemblyError(
                f"node {node_id} projection manifest lacks files"
            )
        try:
            GENERATED_PROJECTION_POLICY.validate_projection_manifest(
                manifest,
                node_id=node_id,
                revision_id=revision_id,
            )
        except ValueError as error:
            raise DemoAssemblyError(str(error)) from error
        for value, label in (
            (topology, "topology"),
            (packet_cases, "packet_cases"),
        ):
            if (
                value.get("projection_policy_id")
                != GENERATED_PROJECTION_POLICY.policy_id
            ):
                raise DemoAssemblyError(
                    f"node {node_id} projection {label} policy mismatch"
                )
        checks = {
            "topology": (payloads["topology"], len(topology.get("claims", []))),
            "routes": (payloads["routes"], len(routes)),
            "forwarding": (payloads["forwarding"], len(forwarding)),
            "packet_cases": (
                payloads["packet_cases"],
                len(packet_cases.get("cases", [])),
            ),
        }
        for key, (content, count) in checks.items():
            descriptor = files.get(key)
            if (
                not isinstance(descriptor, dict)
                or int(descriptor.get("records", -1)) != count
                or str(descriptor.get("sha256", ""))
                != hashlib.sha256(content).hexdigest()
            ):
                raise DemoAssemblyError(
                    f"node {node_id} projection {key} checksum/count mismatch"
                )
        try:
            for row in forwarding:
                GENERATED_PROJECTION_POLICY.validate_forwarding_row(
                    row,
                    node_id=node_id,
                    revision_id=revision_id,
                )
        except ValueError as error:
            raise DemoAssemblyError(str(error)) from error
        return {
            "manifest": manifest,
            "topology": topology,
            "routes": routes,
            "forwarding": forwarding,
            "packet_cases": packet_cases,
            "runtime_load": (
                GENERATED_PROJECTION_POLICY.runtime_load_descriptor()
            ),
        }

    def revision(self, revision_id: str) -> RevisionDescriptor:
        try:
            return self._revisions_by_id[revision_id]
        except KeyError as error:
            raise KeyError(f"unknown demo revision: {revision_id}") from error

    def revision_for_node(self, node_id: str) -> RevisionDescriptor:
        try:
            return self._revisions_by_node[node_id]
        except KeyError as error:
            raise KeyError(f"unknown demo node: {node_id}") from error

    def dataset_for_node(self, node_id: str) -> Mapping[str, Any]:
        return self.dataset_for_revision(
            self.revision_for_node(node_id).revision_id
        )

    def projection_for_node(self, node_id: str) -> Mapping[str, Any]:
        """Return bounded plug-in topology/route data without loading history."""

        self.revision_for_node(node_id)
        return self._projections_by_node[node_id]

    def dataset_for_revision(self, revision_id: str) -> Mapping[str, Any]:
        descriptor = self.revision(revision_id)
        cached = self._datasets.pop(revision_id, None)
        if cached is not None:
            self._datasets[revision_id] = cached
            return cached
        dataset = self._dataset_loader(
            self._node_archive_paths[revision_id],
            revision_id,
        )
        demo = dataset.get("demo")
        if not isinstance(demo, dict):
            raise DemoAssemblyError(
                f"node dataset lacks demo metadata: {descriptor.node_id}"
            )
        loaded_revision = str(demo.get("revision_id", ""))
        loaded_node = str(demo.get("node", ""))
        loaded_events = int(demo.get("event_count", -1))
        loaded_resources = int(demo.get("resource_count", -1))
        if loaded_revision != revision_id:
            raise DemoAssemblyError(
                f"node dataset revision mismatch: {descriptor.node_id}"
            )
        if loaded_node != descriptor.node_id:
            raise DemoAssemblyError(
                f"node dataset identity mismatch: {descriptor.node_id}"
            )
        if (
            loaded_events != descriptor.event_count
            or loaded_resources != descriptor.resource_count
        ):
            raise DemoAssemblyError(
                f"node dataset inventory mismatch: {descriptor.node_id}"
            )
        demo["fixture_materialization"] = {
            "mode": "generator_synthesized_normalized_fixture",
            **GENERATED_PROJECTION_POLICY.runtime_load_descriptor(),
        }
        self._datasets[revision_id] = dataset
        while len(self._datasets) > self.cache_size:
            _evicted_revision, evicted = self._datasets.popitem(last=False)
            runtime = evicted.get("_scale_runtime")
            if isinstance(runtime, ScaleRuntime):
                runtime.event_search.close()
        return dataset

    def loaded_revision_ids(self) -> tuple[str, ...]:
        return tuple(self._datasets)

    def close(self) -> None:
        while self._datasets:
            _revision_id, dataset = self._datasets.popitem(last=False)
            runtime = dataset.get("_scale_runtime")
            if isinstance(runtime, ScaleRuntime):
                runtime.event_search.close()
        self._temporary_directory.cleanup()

    def __enter__(self) -> "DemoAssemblyStore":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()


__all__ = [
    "ASSEMBLY_GENERATOR",
    "ASSEMBLY_ROOT",
    "DemoAssemblyError",
    "DemoAssemblyStore",
]
