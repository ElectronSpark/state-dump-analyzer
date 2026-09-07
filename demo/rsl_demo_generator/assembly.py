"""Build and validate a deterministic, coherent multi-node demo assembly."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Final, Iterable, Mapping

import rsl_demo_plugin as demo_plugin_package
from rsl_demo_plugin import (
    GENERATED_ASSEMBLY_FORMAT_VERSION,
    GENERATED_COVERAGE_FORMAT_VERSION,
    GENERATED_COVERAGE_REGISTRY_ID,
    GENERATED_PROJECTION_POLICY,
)
from rsl_demo_plugin import (
    plugin as example_router_plugin,
)
from rsl_demo_plugin.archive import (
    ASSEMBLY_COVERAGE_MEMBER,
    ASSEMBLY_GENERATOR,
    ASSEMBLY_MANIFEST_MEMBER,
    ASSEMBLY_ROOT,
    COVERAGE_MEMBER_NAME,
    HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME,
    MANIFEST_MEMBER_NAME,
    NODE_PACK_MANIFEST_MEMBER,
    NODE_PACK_ROOT,
    NORMALIZED_SCALE_DIRECTORY,
    NORMALIZED_SCALE_MANIFEST_MEMBER,
    NORMALIZED_SCALE_PREFIX,
    RELATIONSHIP_MUTATIONS_MEMBER_NAME,
)
from rsl_demo_plugin.cross_node_consistency import evaluate_boundary_findings
from rsl_demo_plugin.scenario_registry import (
    ROUTE_PROTOCOL_BY_TYPE,
    ROUTE_RESOLUTION_LAYERS_BY_TYPE,
    scenario_semantics,
)
from rsl_demo_plugin.vpn_topology import project_vpn_topology_resource

from . import _node_pack as packed_generator
from . import _scale as scale_generator
from ._archive import (
    json_bytes as _json_bytes,
)
from ._archive import (
    validate_archive_name,
    write_deterministic_tgz,
)
from .catalog import (
    COVERAGE_CASES,
    DEFAULT_SCENARIO_SOURCE,
    DEMO_LINKS,
    DEMO_NODES,
    GENERATED_TOPOLOGY_PROFILE,
    GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID,
    CoverageCaseSpec,
    NodeSpec,
    TemporalEvidenceSelector,
    TopologyEvidenceSelector,
    adjacent_nodes,
    links_for_node,
    route_inventory_contexts_for_node,
)
from .scenario_source import (
    DemoScenarioSource,
    ScenarioSourceError,
    load_default_scenario_source,
)

ASSEMBLY_FORMAT_VERSION = GENERATED_ASSEMBLY_FORMAT_VERSION
DEFAULT_ASSEMBLY_NAME = "router-state-lab-demo.tgz"
DEFAULT_ASSEMBLY_ID: Final[str] = DEFAULT_SCENARIO_SOURCE.defaults.assembly_id
DEFAULT_PLUGIN_ID: Final[str] = example_router_plugin.manifest.plugin_id
DEFAULT_PLUGIN_VERSION: Final[str] = example_router_plugin.manifest.plugin_version
DEFAULT_EVENT_COUNT: Final[int] = DEFAULT_SCENARIO_SOURCE.defaults.events_per_node
DEFAULT_RESOURCE_COUNT: Final[int] = (
    DEFAULT_SCENARIO_SOURCE.defaults.resources_per_node
)
DEFAULT_SEED: Final[int] = DEFAULT_SCENARIO_SOURCE.defaults.seed
MIN_EVENT_COUNT = 1_000_000
MIN_STATE_CHANGE_EVENT_COUNT = 1_000_000
MIN_RESOURCE_COUNT = 5_000
MAX_RESOURCE_COUNT = 10_000
MIN_GENERATOR_EVENT_COUNT = 1_025_000
MIN_DEVELOPER_RESOURCE_COUNT = 100
MAX_NODE_BUILD_WORKERS = 4
MAX_FULL_SCALE_NODE_BUILD_WORKERS = 2
SOURCE_MATERIALIZER_ID = "demo.example-router.scenario-materializer"
SOURCE_MATERIALIZER_VERSION = 1
SOURCE_MATERIALIZER_FINGERPRINT_ALGORITHM = (
    "sha256-demo-materializer-source-v1"
)
_MAX_MATERIALIZER_SOURCE_BYTES = 4 * 1024 * 1024
_REWRITE_BATCH_BYTES = 1024 * 1024
PROJECTION_ROOT: Final[str] = GENERATED_PROJECTION_POLICY.projection_root
_NODE_ID_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62})\Z")
_TIMESTAMP_FIELDS = {
    "base_time_ns",
    "capture_time_ns",
    "effective_time_ns",
    "end_ns",
    "observed_at_ns",
    "start_ns",
    "timestamp_ns",
    "valid_from_ns",
    "valid_to_ns",
}
_CANONICAL_RESOURCE_PREFIXES = (
    "control-plane/",
    "data-bridge-layer/",
    "hardware-driver-plane/",
)
_GENERATED_ID_PREFIXES = (
    "fanout-",
    "scale-event-",
    "scale-mutation-",
    "scale-rel-",
)
_GENERATED_JSON_PREFIXES = tuple(
    f'"{prefix}'.encode("utf-8")
    for prefix in (*_CANONICAL_RESOURCE_PREFIXES, *_GENERATED_ID_PREFIXES)
)
_GENERATED_TIMESTAMP_PATTERN = re.compile(
    rb'"(?P<key>'
    + b"|".join(
        sorted(
            (field.encode("ascii") for field in _TIMESTAMP_FIELDS),
            key=len,
            reverse=True,
        )
    )
    + rb')":(?P<quote>"?)(?P<value>-?\d+)(?P=quote)'
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_EVENT_TIMESTAMP_PATTERN = re.compile(
    rb'"timestamp_ns":"?(?P<value>-?\d+)"?'
)
_EVENT_SEQUENCE_PATTERN = re.compile(
    rb'"source_sequence":(?P<value>-?\d+)'
)
_MAX_LAUNCH_METADATA_BYTES = 16 * 1024 * 1024
_MAX_LAUNCH_NODE_ARCHIVE_BYTES = 512 * 1024 * 1024
_CANONICAL_LAUNCH_NODE_MEMBERS = {
    f"{ASSEMBLY_ROOT}/nodes/{node.node_id}.tgz"
    for node in DEMO_NODES
}
_CANONICAL_LAUNCH_MEMBERS = frozenset(
    {
        ASSEMBLY_MANIFEST_MEMBER,
        ASSEMBLY_COVERAGE_MEMBER,
        *_CANONICAL_LAUNCH_NODE_MEMBERS,
    }
)
_MAX_LAUNCH_OUTER_MEMBERS = len(_CANONICAL_LAUNCH_MEMBERS)
_MAX_LAUNCH_UNCOMPRESSED_BYTES = (
    len(DEMO_NODES) * _MAX_LAUNCH_NODE_ARCHIVE_BYTES
    + 2 * _MAX_LAUNCH_METADATA_BYTES
)
_MAX_LAUNCH_ARCHIVE_BYTES = _MAX_LAUNCH_UNCOMPRESSED_BYTES


def _framed_digest_update(
    digest: Any,
    label: str,
    content: bytes,
) -> None:
    encoded_label = label.encode("utf-8")
    digest.update(len(encoded_label).to_bytes(4, "big"))
    digest.update(encoded_label)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)


def _materializer_contract_fingerprint() -> str:
    """Hash every demo-owned code input that can materialize node packs.

    The authoring save has its own digest.  This fingerprint covers the
    generator and example plug-in source trees plus their emitted contract
    descriptors.  Paths are package-relative and line endings are normalized,
    so a source checkout and an installed wheel produce the same identity.
    The calculation intentionally is not cached: launch preflight must notice
    implementation changes made after this module was imported.
    """

    digest = hashlib.sha256()
    contract = {
        "algorithm": SOURCE_MATERIALIZER_FINGERPRINT_ALGORITHM,
        "assembly_format_version": ASSEMBLY_FORMAT_VERSION,
        "materializer_id": SOURCE_MATERIALIZER_ID,
        "materializer_version": SOURCE_MATERIALIZER_VERSION,
        "plugin_archive": (
            GENERATED_PROJECTION_POLICY.archive_plugin_descriptor()
        ),
        "plugin_materialization": (
            GENERATED_PROJECTION_POLICY.generation_materialization_descriptor()
        ),
        "plugin_projection_capability": (
            GENERATED_PROJECTION_POLICY.projection_capability_descriptor()
        ),
        "plugin_schema_contract": (
            GENERATED_PROJECTION_POLICY.generated_schema_contract_descriptor()
        ),
    }
    _framed_digest_update(
        digest,
        "contract.json",
        json.dumps(
            contract,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"),
    )
    roots = (
        ("generator", Path(__file__).resolve().parent),
        (
            "plugin",
            Path(str(demo_plugin_package.__file__)).resolve().parent,
        ),
    )
    for package_name, root in roots:
        if root.is_symlink() or not root.is_dir():
            raise RuntimeError(
                f"materializer source package is unavailable: {package_name}"
            )
        source_paths = sorted(
            (
                path
                for path in root.rglob("*.py")
                if "__pycache__" not in path.parts
            ),
            key=lambda path: path.relative_to(root).as_posix(),
        )
        if not source_paths:
            raise RuntimeError(
                f"materializer source package is empty: {package_name}"
            )
        for path in source_paths:
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(
                    "materializer source must contain regular files: "
                    f"{package_name}/{path.relative_to(root).as_posix()}"
                )
            content = path.read_bytes()
            if len(content) > _MAX_MATERIALIZER_SOURCE_BYTES:
                raise RuntimeError(
                    "materializer source file exceeds its bound: "
                    f"{package_name}/{path.relative_to(root).as_posix()}"
                )
            normalized = content.replace(b"\r\n", b"\n").replace(
                b"\r",
                b"\n",
            )
            _framed_digest_update(
                digest,
                f"{package_name}/{path.relative_to(root).as_posix()}",
                normalized,
            )
    return digest.hexdigest()


_LOADED_MATERIALIZER_FINGERPRINT = (
    _materializer_contract_fingerprint()
)


def _source_scenario_descriptor(
    source: DemoScenarioSource,
    *,
    materializer_fingerprint: str,
) -> dict[str, Any]:
    if not _SHA256_PATTERN.fullmatch(materializer_fingerprint):
        raise RuntimeError("materializer fingerprint is invalid")
    return {
        "scenario_id": source.scenario_id,
        "schema_id": "state-dump-generator-scenario/v1",
        "sha256": source.sha256,
        "materializer": {
            "id": SOURCE_MATERIALIZER_ID,
            "version": SOURCE_MATERIALIZER_VERSION,
            "fingerprint_algorithm": (
                SOURCE_MATERIALIZER_FINGERPRINT_ALGORITHM
            ),
            "fingerprint": materializer_fingerprint,
        },
    }


def _loaded_source_scenario_descriptor() -> dict[str, Any]:
    return _source_scenario_descriptor(
        DEFAULT_SCENARIO_SOURCE,
        materializer_fingerprint=_LOADED_MATERIALIZER_FINGERPRINT,
    )


def _fresh_source_scenario_descriptor() -> dict[str, Any]:
    try:
        source = load_default_scenario_source(fresh=True)
    except ScenarioSourceError as error:
        raise RuntimeError(
            "cannot read the current canonical authoring scenario"
        ) from error
    return _source_scenario_descriptor(
        source,
        materializer_fingerprint=_materializer_contract_fingerprint(),
    )


def _capture_source_scenario_descriptor() -> dict[str, Any]:
    """Capture one build identity and reject stale imported semantics."""

    loaded = _loaded_source_scenario_descriptor()
    current = _fresh_source_scenario_descriptor()
    if loaded != current:
        raise RuntimeError(
            "canonical authoring source or materializer changed after "
            "the generator was loaded; retry in a fresh process"
        )
    return current


def _assert_source_snapshot_current(
    expected: Mapping[str, Any],
) -> None:
    if _fresh_source_scenario_descriptor() != dict(expected):
        raise RuntimeError(
            "canonical authoring source or materializer changed during "
            "demo generation"
        )


def _validate_source_scenario_descriptor(
    value: Any,
    *,
    expected: Mapping[str, Any] | None = None,
) -> None:
    current = (
        dict(expected)
        if expected is not None
        else _fresh_source_scenario_descriptor()
    )
    if not isinstance(value, Mapping) or any(
        value.get(key) != expected_value
        for key, expected_value in current.items()
    ):
        raise RuntimeError(
            "generated assembly does not match the current canonical "
            "authoring scenario"
        )


@dataclass(frozen=True, slots=True)
class _JsonlRewritePlan:
    quoted_prefixes: tuple[bytes, ...]
    timestamp_pattern: re.Pattern[bytes]
    has_clock_domain: bool = False
    has_burst_id: bool = False


def _timestamp_pattern(*fields: str) -> re.Pattern[bytes]:
    return re.compile(
        rb'"(?P<key>'
        + b"|".join(field.encode("ascii") for field in fields)
        + rb')":(?P<quote>"?)(?P<value>-?\d+)(?P=quote)'
    )


_CANONICAL_QUOTED_PREFIXES = tuple(
    f'"{prefix}'.encode("utf-8")
    for prefix in _CANONICAL_RESOURCE_PREFIXES
)
_GENERATED_JSONL_REWRITE_PLANS = {
    "events.jsonl": _JsonlRewritePlan(
        quoted_prefixes=(
            *_CANONICAL_QUOTED_PREFIXES,
            b'"scale-event-',
        ),
        timestamp_pattern=_timestamp_pattern("timestamp_ns"),
        has_clock_domain=True,
        has_burst_id=True,
    ),
    "relationships.jsonl": _JsonlRewritePlan(
        quoted_prefixes=(
            *_CANONICAL_QUOTED_PREFIXES,
            b'"scale-rel-',
        ),
        timestamp_pattern=_timestamp_pattern(
            "valid_from_ns",
            "valid_to_ns",
        ),
    ),
    HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME: _JsonlRewritePlan(
        quoted_prefixes=(
            *_CANONICAL_QUOTED_PREFIXES,
            b'"fanout-',
        ),
        timestamp_pattern=_timestamp_pattern(
            "valid_from_ns",
            "valid_to_ns",
        ),
    ),
    RELATIONSHIP_MUTATIONS_MEMBER_NAME: _JsonlRewritePlan(
        quoted_prefixes=(
            *_CANONICAL_QUOTED_PREFIXES,
            b'"scale-mutation-',
        ),
        timestamp_pattern=_timestamp_pattern("effective_time_ns"),
    ),
}
_DEFAULT_JSONL_REWRITE_PLAN = _JsonlRewritePlan(
    quoted_prefixes=_GENERATED_JSON_PREFIXES,
    timestamp_pattern=_GENERATED_TIMESTAMP_PATTERN,
    has_clock_domain=True,
    has_burst_id=True,
)


@dataclass(frozen=True, slots=True)
class AssemblyConfig:
    """Inputs for a deterministic assembly build.

    ``allow_small`` is deliberately explicit.  Production/default fixtures
    must meet the advertised per-node scale; tests can request a much smaller
    corpus without weakening validation of a full assembly.
    """

    nodes: tuple[NodeSpec, ...] = DEMO_NODES
    events_per_node: int = DEFAULT_EVENT_COUNT
    resources_per_node: int = DEFAULT_RESOURCE_COUNT
    seed: int = DEFAULT_SEED
    allow_small: bool = False
    assembly_id: str = DEFAULT_ASSEMBLY_ID
    default_node_id: str | None = None

    def __post_init__(self) -> None:
        if not self.nodes:
            raise ValueError("the demo assembly must contain at least one node")
        node_ids = [node.node_id for node in self.nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("demo node IDs must be unique")
        for node_id in node_ids:
            if not _NODE_ID_PATTERN.fullmatch(node_id):
                raise ValueError(f"unsafe demo node ID: {node_id!r}")
        if self.events_per_node <= 0:
            raise ValueError("events_per_node must be positive")
        if self.resources_per_node <= 0:
            raise ValueError("resources_per_node must be positive")
        if (
            self.allow_small
            and self.resources_per_node < MIN_DEVELOPER_RESOURCE_COUNT
        ):
            raise ValueError(
                "small demo fixtures still need at least "
                f"{MIN_DEVELOPER_RESOURCE_COUNT} resources per node so every "
                "generated topology/route evidence reference is resolvable"
            )
        if not self.allow_small:
            if self.events_per_node < MIN_GENERATOR_EVENT_COUNT:
                raise ValueError(
                    "full demo generation needs enough records to retain at "
                    f"least {MIN_STATE_CHANGE_EVENT_COUNT:,} state-changing "
                    f"events per node; use at least {MIN_GENERATOR_EVENT_COUNT:,}"
                )
            if not (
                MIN_RESOURCE_COUNT
                <= self.resources_per_node
                <= MAX_RESOURCE_COUNT
            ):
                raise ValueError(
                    "full demo resources_per_node must be between "
                    f"{MIN_RESOURCE_COUNT:,} and {MAX_RESOURCE_COUNT:,}"
                )
        selected_default = self.default_node_id or node_ids[0]
        if selected_default not in node_ids:
            raise ValueError("default_node_id must identify a selected node")
        if not self.assembly_id.strip():
            raise ValueError("assembly_id cannot be empty")
    @property
    def selected_default_node_id(self) -> str:
        return self.default_node_id or self.nodes[0].node_id

    @property
    def full_scale(self) -> bool:
        return not self.allow_small


def _node_build_worker_count(config: AssemblyConfig) -> int:
    """Return the measured-safe node-pack concurrency for this workload.

    Full-scale packs spend most of their build time in GIL-held byte rewriting
    and event-to-CTF materialization. More than two concurrent full histories
    increased contention in representative multi-node 1.25M-event builds.
    Smaller developer fixtures remain cheap enough to benefit from four-way
    overlap of compression and file IO.
    """

    workload_cap = (
        MAX_FULL_SCALE_NODE_BUILD_WORKERS
        if config.full_scale
        else MAX_NODE_BUILD_WORKERS
    )
    return min(
        len(config.nodes),
        workload_cap,
        max(1, os.cpu_count() or 1),
    )


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """Summary returned after an assembly passes validation."""

    assembly_id: str
    node_ids: tuple[str, ...]
    coverage_case_count: int
    full_scale: bool
    deep: bool
    archive_sha256: str
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class LaunchPreflightReport:
    """Bounded outer-integrity summary for a launch-ready assembly.

    This preflight scans bounded outer members, hashes every opaque node pack,
    and parses the two small JSON documents.  It deliberately does not decode
    the nested packs; callers that need their structural audit must use
    :func:`validate_demo_fixture`.
    """

    assembly_id: str
    node_ids: tuple[str, ...]
    coverage_case_count: int
    full_scale: bool


@dataclass(frozen=True, slots=True)
class EnsureLaunchReport:
    """Result of preparing the canonical demo input for a launcher."""

    preferred_path: Path
    output_path: Path
    preflight: LaunchPreflightReport
    generated: bool
    used_recovery_path: bool = False
    preserved_preferred: bool = False
    rejection_reason: str | None = None


def _compact_json_line(value: Any) -> bytes:
    return (
        json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _safe_member_name(name: str) -> str:
    try:
        return validate_archive_name(name).as_posix()
    except ValueError as error:
        raise RuntimeError(
            f"unsafe generated archive member: {name!r}"
        ) from error


def _stable_number(seed: int, *parts: str, modulo: int) -> int:
    digest = hashlib.sha256()
    digest.update(str(seed).encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return int.from_bytes(digest.digest()[:8], "big") % modulo


def _namespaced_resource_id(node_id: str, value: str) -> str:
    if value.startswith(f"{node_id}/"):
        return value
    if value.startswith(_CANONICAL_RESOURCE_PREFIXES):
        return f"{node_id}/{value}"
    return value


def _namespaced_generated_id(node_id: str, value: str) -> str:
    if value.startswith(f"{node_id}/"):
        return value
    if value.startswith(_GENERATED_ID_PREFIXES):
        return f"{node_id}/{value}"
    return _namespaced_resource_id(node_id, value)


def _transform_value(
    value: Any,
    *,
    node: NodeSpec,
    key: str | None = None,
) -> Any:
    if isinstance(value, dict):
        return {
            item_key: _transform_value(item_value, node=node, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_transform_value(item, node=node, key=key) for item in value]
    if isinstance(value, tuple):
        return tuple(_transform_value(item, node=node, key=key) for item in value)
    if key in _TIMESTAMP_FIELDS and value is not None:
        try:
            adjusted = int(value) + node.clock_offset_ns
        except (TypeError, ValueError):
            return value
        return str(adjusted) if isinstance(value, str) else adjusted
    if isinstance(value, str):
        if key == "clock_domain" and not value.startswith(f"{node.node_id}:"):
            return f"{node.node_id}:{value}"
        if key == "burst_id" and not value.startswith(f"{node.node_id}/"):
            return f"{node.node_id}/{value}"
        return _namespaced_generated_id(node.node_id, value)
    return value


def _rewrite_json_file(
    path: Path,
    node: NodeSpec,
    *,
    additions: Mapping[str, Any] | None = None,
    output: Path | None = None,
) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    transformed = _transform_value(value, node=node)
    if not isinstance(transformed, dict):
        raise RuntimeError(f"expected JSON object in {path}")
    if additions:
        transformed.update(additions)
    (output or path).write_bytes(_json_bytes(transformed))
    return transformed


def _transform_generated_json_line(
    raw_line: bytes,
    node: NodeSpec,
    *,
    plan: _JsonlRewritePlan | None = None,
) -> bytes:
    """Namespace one canonical generated JSONL record without rebuilding it.

    ``_scale`` already emits compact, sorted JSON.  The former implementation
    decoded every record, recursively visited every scalar, and serialized the
    same object again.  Generated IDs have a deliberately small, registered
    prefix set, while all time adjustment is keyed by the public timestamp
    field registry.  Applying those exact transformations to the canonical
    bytes preserves the reference transform byte-for-byte and avoids millions
    of short-lived Python objects for a full assembly.
    """

    selected_plan = plan or _DEFAULT_JSONL_REWRITE_PLAN
    node_namespace = node.identity_namespace.encode("utf-8")
    transformed = raw_line
    for quoted_prefix in selected_plan.quoted_prefixes:
        transformed = transformed.replace(
            quoted_prefix,
            b'"' + node_namespace + quoted_prefix[1:],
        )
    if selected_plan.has_clock_domain:
        transformed = transformed.replace(
            b'"clock_domain":"',
            f'"clock_domain":"{node.node_id}:'.encode("utf-8"),
        )
    if selected_plan.has_burst_id:
        transformed = transformed.replace(
            b'"burst_id":"',
            b'"burst_id":"' + node_namespace,
        )
    if node.clock_offset_ns:
        offset = node.clock_offset_ns

        def adjust_timestamp(match: re.Match[bytes]) -> bytes:
            adjusted = int(match.group("value")) + offset
            quote = match.group("quote")
            return (
                b'"'
                + match.group("key")
                + b'":'
                + quote
                + str(adjusted).encode("ascii")
                + quote
            )

        transformed = selected_plan.timestamp_pattern.sub(
            adjust_timestamp,
            transformed,
        )
    return transformed


def _rewrite_jsonl(
    path: Path,
    node: NodeSpec,
    *,
    output: Path | None = None,
) -> tuple[int, str]:
    target = output or path
    in_place = target == path
    stage = (
        path.with_suffix(path.suffix + ".namespaced")
        if in_place
        else target
    )
    try:
        rewrite_plan = _GENERATED_JSONL_REWRITE_PLANS[path.name]
    except KeyError as error:
        raise RuntimeError(
            f"no generated JSONL rewrite plan is registered for {path.name}"
        ) from error
    count = 0
    digest = hashlib.sha256()
    try:
        with (
            path.open("rb") as source,
            stage.open("wb") as output,
        ):
            pending = bytearray()
            pending_line_count = 0

            def flush_pending() -> None:
                nonlocal count, pending_line_count
                if not pending:
                    return
                transformed = _transform_generated_json_line(
                    bytes(pending),
                    node,
                    plan=rewrite_plan,
                )
                output.write(transformed)
                digest.update(transformed)
                count += pending_line_count
                pending.clear()
                pending_line_count = 0

            for raw_line in source:
                if not raw_line.strip():
                    continue
                pending.extend(raw_line)
                pending_line_count += 1
                if len(pending) >= _REWRITE_BATCH_BYTES:
                    flush_pending()
            flush_pending()
        if in_place:
            stage.replace(path)
    finally:
        if in_place:
            stage.unlink(missing_ok=True)
    return count, digest.hexdigest()


def _rewrite_resource_table(
    path: Path,
    node: NodeSpec,
    *,
    output: Path | None = None,
) -> tuple[int, str]:
    target = output or path
    in_place = target == path
    stage = (
        path.with_suffix(path.suffix + ".namespaced")
        if in_place
        else target
    )
    digest = hashlib.sha256()
    records = 0
    try:
        with (
            path.open("r", encoding="utf-8", newline="") as source,
            stage.open("wb") as output,
        ):
            header_line = source.readline().rstrip("\r\n")
            header = header_line.split("|")
            resource_columns = {
                header.index(name)
                for name in ("RESOURCE_ID", "PARENT_ID", "ES_ID", "NEXT_HOP")
                if name in header
            }
            json_columns = {
                header.index(name)
                for name in ("KEY_JSON", "STATE_JSON")
                if name in header
            }
            encoded_header = (header_line + "\n").encode("utf-8")
            output.write(encoded_header)
            digest.update(encoded_header)
            for source_line in source:
                row = source_line.rstrip("\r\n")
                if not row:
                    continue
                values = row.split("|")
                if len(values) != len(header):
                    raise RuntimeError(
                        f"resource table row has {len(values)} columns; "
                        f"expected {len(header)}"
                    )
                for index in resource_columns:
                    if values[index]:
                        values[index] = _namespaced_resource_id(
                            node.node_id,
                            values[index],
                        )
                for index in json_columns:
                    if values[index]:
                        values[index] = json.dumps(
                            _transform_value(
                                json.loads(values[index]),
                                node=node,
                            ),
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                encoded = ("|".join(values) + "\n").encode("utf-8")
                output.write(encoded)
                digest.update(encoded)
                records += 1
        if in_place:
            stage.replace(path)
    finally:
        if in_place:
            stage.unlink(missing_ok=True)
    return records, digest.hexdigest()


def _source_layer(resource_type: str) -> str:
    normalized = resource_type.upper()
    if normalized in {
        "DTE",
        "ETE",
        "ETG",
        "VIRTUAL_INTERFACE",
    }:
        return "data-bridge-layer"
    if normalized in {
        "ADJACENCY",
        "EVPN_ES",
        "IP_ROUTE",
        "IP_ROUTING",
        "NEIGHBOR",
    }:
        return "control-plane"
    return "hardware-driver-plane"


def _source_resource_id(
    node_id: str,
    resource_type: str,
    local_resource_id: str,
) -> str:
    return (
        f"{node_id}/{_source_layer(resource_type)}/"
        f"{resource_type.upper()}/{local_resource_id}"
    )


def _source_boundary_observations(
    node: NodeSpec, scenario_id: str, direction: str,
) -> list[dict[str, Any]]:
    """Project authored local declarations without inventing comparison values."""

    observations = []
    for resource in DEFAULT_SCENARIO_SOURCE.resources_at(node.node_id):
        properties = resource.properties
        if properties.get("scenario_id") != scenario_id or properties.get("direction") != direction:
            continue
        observations.append({
            **properties,
            "node_id": node.node_id,
            "revision_id": node.revision_id,
            "resource_type": resource.resource_type.upper(),
            "resource_id": _source_resource_id(node.node_id, resource.resource_type, resource.resource_id),
            "source_resource_id": resource.resource_id,
            "observed_at_ns": str(resource.updated_at_ns + node.clock_offset_ns),
        })
    return observations


def _source_status_class(status: str | None) -> str:
    normalized = str(status or "unknown").casefold()
    if normalized in {
        "absent",
        "down",
        "error",
        "failed",
        "unreachable",
        "withdrawn",
    }:
        return "error"
    if normalized in {
        "active",
        "installed",
        "programmed",
        "ready",
        "standby",
        "up",
        "reachable",
    }:
        return "healthy"
    return "unknown"


def _source_event_rows(node: NodeSpec) -> list[bytes]:
    """Compile authored observations into plug-in-owned normalized records."""

    result: list[bytes] = []
    for observation in DEFAULT_SCENARIO_SOURCE.observations_by_node[
        node.node_id
    ]:
        properties = observation.to_event().get("properties", {})
        state_changed = observation.update_snapshot
        normalized_outcome = (
            "success"
            if observation.outcome == "success"
            else "failure"
        )
        before_resources = {
            item.resource_id: item
            for item in DEFAULT_SCENARIO_SOURCE.resources_at(
                node.node_id,
                timestamp_ns=max(
                    DEFAULT_SCENARIO_SOURCE.base_time_ns,
                    observation.timestamp_ns - 1,
                ),
            )
        }
        after_resources = {
            item.resource_id: item
            for item in DEFAULT_SCENARIO_SOURCE.resources_at(
                node.node_id,
                timestamp_ns=observation.timestamp_ns,
            )
        }
        before_resource = before_resources.get(observation.resource_id)
        after_resource = after_resources.get(observation.resource_id)
        before = (
            {
                **before_resource.properties,
                "exists": True,
                "status": before_resource.status,
            }
            if before_resource is not None
            else {"exists": False, "status": "absent"}
        )
        after = (
            {
                **after_resource.properties,
                "exists": True,
                "status": after_resource.status,
            }
            if after_resource is not None
            else {"exists": False, "status": "absent"}
        )
        full_resource_id = _source_resource_id(
            node.node_id,
            observation.resource_type,
            observation.resource_id,
        )
        result_status = (
            "Ok"
            if observation.outcome == "success" and state_changed
            else observation.outcome
        )
        record = {
            "absolute_timestamp_ns": str(observation.timestamp_ns),
            "action": observation.operation,
            "burst_id": (
                f"{node.node_id}/authored-history/"
                f"{observation.relative_time_ns // 1_000_000_000:06d}"
            ),
            "clock_domain": f"{node.node_id}:scenario-realtime",
            "effects": [
                {
                    "after": after,
                    "before": before,
                    "condition": observation.status or "unknown",
                    "condition_class": _source_status_class(
                        observation.status
                    ),
                    "effect_type": observation.operation,
                    "kind": observation.resource_type,
                    "resource_id": full_resource_id,
                    "state_changed": state_changed,
                }
            ],
            "event_name": f"scenario_{observation.kind.replace('-', '_')}",
            "event_uid": (
                f"{node.node_id}/scenario/{observation.event_id}"
            ),
            "layer": _source_layer(observation.resource_type),
            "outcome": normalized_outcome,
            "phase": "authored_history",
            "properties": {
                **dict(properties),
                "message": observation.message,
                "source_outcome": observation.outcome,
                "source_event_id": observation.event_id,
                "source_scenario_id": DEFAULT_SCENARIO_SOURCE.scenario_id,
            },
            "relationship_effects": [],
            "resource": observation.resource_id,
            "resource_id": full_resource_id,
            "resource_kind": observation.resource_type,
            "result": {"updateStatus": result_status},
            "source_sequence": 1_000_000_000 + observation.order,
            "state_changed": state_changed,
            "timestamp_ns": str(
                observation.timestamp_ns + node.clock_offset_ns
            ),
        }
        result.append(
            json.dumps(
                record,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    return sorted(result, key=_event_line_key)


def _event_line_key(raw_line: bytes) -> tuple[int, int]:
    timestamp_match = _EVENT_TIMESTAMP_PATTERN.search(raw_line)
    sequence_match = _EVENT_SEQUENCE_PATTERN.search(raw_line)
    if timestamp_match is None or sequence_match is None:
        raise RuntimeError("normalized event lacks its sort key")
    return (
        int(timestamp_match.group("value")),
        int(sequence_match.group("value")),
    )


def _merge_source_events(
    path: Path,
    node: NodeSpec,
) -> tuple[int, str, int]:
    """Merge a bounded authored stream without loading generated history."""

    authored = _source_event_rows(node)
    if not authored:
        return _stream_file_count_and_digest(path)
    stage = path.with_suffix(path.suffix + ".authored")
    digest = hashlib.sha256()
    count = 0
    authored_index = 0

    def emit(output: Any, content: bytes) -> None:
        nonlocal count
        output.write(content)
        digest.update(content)
        count += 1

    try:
        with path.open("rb") as source, stage.open("wb") as output:
            for raw_line in source:
                if not raw_line.strip():
                    continue
                source_key = _event_line_key(raw_line)
                while (
                    authored_index < len(authored)
                    and _event_line_key(authored[authored_index])
                    <= source_key
                ):
                    emit(output, authored[authored_index])
                    authored_index += 1
                emit(output, raw_line)
            while authored_index < len(authored):
                emit(output, authored[authored_index])
                authored_index += 1
        stage.replace(path)
    finally:
        stage.unlink(missing_ok=True)
    state_changes = sum(
        observation.update_snapshot
        for observation in DEFAULT_SCENARIO_SOURCE.observations_by_node[
            node.node_id
        ]
    )
    return count, digest.hexdigest(), state_changes


def _stream_file_count_and_digest(path: Path) -> tuple[int, str, int]:
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as source:
        for raw_line in source:
            if not raw_line.strip():
                continue
            digest.update(raw_line)
            count += 1
    return count, digest.hexdigest(), 0


def _source_resource_rows(node: NodeSpec) -> list[bytes]:
    rows: list[bytes] = []
    for resource in DEFAULT_SCENARIO_SOURCE.resources_at(node.node_id):
        properties = resource.properties
        resource_id = _source_resource_id(
            node.node_id,
            resource.resource_type,
            resource.resource_id,
        )
        state = {
            **properties,
            "status": resource.status,
            "source_resource_id": resource.resource_id,
            "source_scenario_id": DEFAULT_SCENARIO_SOURCE.scenario_id,
            "updated_at_ns": str(
                resource.updated_at_ns + node.clock_offset_ns
            ),
        }
        values = [
            resource.resource_type,
            resource_id,
            _source_layer(resource.resource_type),
            str(properties.get("vrf", "")),
            str(properties.get("service_id", "")),
            "",
            str(properties.get("es_id", "")),
            str(properties.get("esi", "")),
            str(properties.get("home_mode", "")),
            str(properties.get("role", "")),
            str(properties.get("match", "")),
            str(properties.get("packet_action", "")),
            str(properties.get("next_hop", "")),
            str(properties.get("encapsulation", "")),
            str(properties.get("admin_status", "")),
            resource.status,
            str(properties.get("df_state", "")),
            str(properties.get("neighbor", "")),
            json.dumps(
                {"source_resource_id": resource.resource_id},
                separators=(",", ":"),
                sort_keys=True,
            ),
            json.dumps(state, separators=(",", ":"), sort_keys=True),
        ]
        if any("|" in value or "\r" in value or "\n" in value for value in values):
            raise RuntimeError("authored resource contains a table delimiter")
        rows.append(("|".join(values) + "\n").encode("utf-8"))
    return rows


def _append_source_resources(
    path: Path,
    node: NodeSpec,
) -> tuple[int, str, dict[str, int]]:
    rows = _source_resource_rows(node)
    digest = hashlib.sha256()
    records = 0
    with path.open("rb") as source:
        header = source.readline()
        if not header:
            raise RuntimeError("normalized resource table is empty")
        digest.update(header)
        for raw_line in source:
            digest.update(raw_line)
            if raw_line.strip():
                records += 1
    with path.open("ab") as output:
        for raw_line in rows:
            output.write(raw_line)
            digest.update(raw_line)
            records += 1
    by_kind: dict[str, int] = {}
    for resource in DEFAULT_SCENARIO_SOURCE.resources_at(node.node_id):
        by_kind[resource.resource_type] = (
            by_kind.get(resource.resource_type, 0) + 1
        )
    return records, digest.hexdigest(), by_kind


def _namespace_scale_fixture(
    scale_dir: Path,
    node: NodeSpec,
    *,
    assembly_id: str,
    source_descriptor: Mapping[str, Any],
    template_dir: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    source_dir = template_dir or scale_dir
    scale_dir.mkdir(parents=True, exist_ok=True)
    resource_records, resource_sha = _rewrite_resource_table(
        source_dir / "resources.table.txt",
        node,
        output=scale_dir / "resources.table.txt",
    )
    (
        resource_records,
        resource_sha,
        authored_resource_counts,
    ) = _append_source_resources(
        scale_dir / "resources.table.txt",
        node,
    )
    event_records, event_sha = _rewrite_jsonl(
        source_dir / "events.jsonl",
        node,
        output=scale_dir / "events.jsonl",
    )
    (
        event_records,
        event_sha,
        authored_state_changes,
    ) = _merge_source_events(
        scale_dir / "events.jsonl",
        node,
    )
    relationship_records, relationship_sha = _rewrite_jsonl(
        source_dir / "relationships.jsonl",
        node,
        output=scale_dir / "relationships.jsonl",
    )
    high_fanout_records, high_fanout_sha = _rewrite_jsonl(
        source_dir / HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME,
        node,
        output=scale_dir / HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME,
    )
    mutation_records, mutation_sha = _rewrite_jsonl(
        source_dir / RELATIONSHIP_MUTATIONS_MEMBER_NAME,
        node,
        output=scale_dir / RELATIONSHIP_MUTATIONS_MEMBER_NAME,
    )
    identity = {
        "assembly_id": assembly_id,
        "node_id": node.node_id,
        "node_label": node.label,
        "node_role": node.role,
        "site": node.site,
        "revision_id": node.revision_id,
        "identity_namespace": node.identity_namespace,
        "source_scenario_id": DEFAULT_SCENARIO_SOURCE.scenario_id,
        "source_scenario_sha256": DEFAULT_SCENARIO_SOURCE.sha256,
    }
    scenario = _rewrite_json_file(
        source_dir / "scenario.json",
        node,
        additions={"node_identity": identity},
        output=scale_dir / "scenario.json",
    )
    scenario["capture_time_ns"] = str(
        DEFAULT_SCENARIO_SOURCE.capture_time_ns + node.clock_offset_ns
    )
    scenario["scale"]["events"] = event_records
    scenario["scale"]["resources"] = resource_records
    for kind, count in authored_resource_counts.items():
        scenario["resource_counts"][kind] = (
            int(scenario["resource_counts"].get(kind, 0)) + count
        )
    source_observations = (
        DEFAULT_SCENARIO_SOURCE.observations_by_node[node.node_id]
    )
    if "authored_history" not in scenario["phase_order"]:
        scenario["phase_order"].insert(0, "authored_history")
    scenario["phases"].insert(
        0,
        {
            "phase": "authored_history",
            "description": (
                "User-authored local observations compiled from the "
                "canonical standalone scenario save."
            ),
            "start_ns": str(
                DEFAULT_SCENARIO_SOURCE.base_time_ns
                + node.clock_offset_ns
            ),
            "events": len(source_observations),
        },
    )
    scenario["expected_changes"]["state_change_events"] = (
        int(scenario["expected_changes"]["state_change_events"])
        + authored_state_changes
    )
    scenario["expected_changes"]["authored_history_events"] = len(
        source_observations
    )
    scenario["source_scenario"] = {
        **source_descriptor
    }
    (scale_dir / "scenario.json").write_bytes(_json_bytes(scenario))
    _rewrite_json_file(
        source_dir / "walkthrough.json",
        node,
        additions={"node_identity": identity},
        output=scale_dir / "walkthrough.json",
    )
    schema_template = _rewrite_json_file(
        source_dir / "plugin-schema.json",
        node,
        output=scale_dir / "plugin-schema.json",
    )
    plugin_schema = (
        GENERATED_PROJECTION_POLICY.materialize_generated_schema(
            schema_template,
            node_identity=identity,
        )
    )
    (scale_dir / "plugin-schema.json").write_bytes(_json_bytes(plugin_schema))
    readme_path = scale_dir / "README.md"
    readme_path.write_bytes(
        (source_dir / "README.md").read_bytes()
        + (
            "\n## Assembly identity\n\n"
            f"- Node: {node.node_id}\n"
            f"- Revision: {node.revision_id}\n"
            f"- Resource/event namespace: {node.identity_namespace}\n"
            f"- Plug-in projection: {PROJECTION_ROOT}/\n"
            f"- Canonical authoring save: "
            f"{DEFAULT_SCENARIO_SOURCE.scenario_id} "
            f"({DEFAULT_SCENARIO_SOURCE.sha256})\n"
        ).encode("utf-8")
    )

    manifest_path = scale_dir / MANIFEST_MEMBER_NAME
    manifest = json.loads(
        (source_dir / MANIFEST_MEMBER_NAME).read_text(encoding="utf-8")
    )
    manifest["node_identity"] = identity
    manifest["fixture_materialization"] = (
        GENERATED_PROJECTION_POLICY.generation_materialization_descriptor()
    )
    manifest["events"].update(
        {
            "records": event_records,
            "sha256": event_sha,
            "state_change_records": int(
                scenario["expected_changes"]["state_change_events"]
            ),
        }
    )
    manifest["resources"].update(
        {
            "records": resource_records,
            "lines_including_header": resource_records + 1,
            "sha256": resource_sha,
            "by_kind": dict(scenario["resource_counts"]),
        }
    )
    manifest["relationships"].update(
        {"records": relationship_records, "sha256": relationship_sha}
    )
    manifest["high_fanout_relationships"].update(
        {"records": high_fanout_records, "sha256": high_fanout_sha}
    )
    manifest["relationship_mutations"].update(
        {"records": mutation_records, "sha256": mutation_sha}
    )
    manifest["scenario"]["sha256"] = _sha256(scale_dir / "scenario.json")
    manifest["plugin_schema"]["sha256"] = _sha256(
        scale_dir / "plugin-schema.json"
    )
    manifest["walkthrough"]["sha256"] = _sha256(
        scale_dir / "walkthrough.json"
    )
    manifest["readme"]["sha256"] = _sha256(readme_path)
    manifest_path.write_bytes(_json_bytes(manifest))
    return manifest, scenario, plugin_schema


def _coverage_timestamp(case_index: int) -> int:
    # Place coverage probes near the end of the generated capture while keeping
    # stable, distinct absolute times for cross-node lookup.
    return scale_generator.BASE_TIME_NS + 610_000_000_000 + case_index * 1_000_000


@dataclass(frozen=True, slots=True)
class _PathSpec:
    suffix: str
    sequence: tuple[str, ...]
    selected: bool
    primary: bool
    alternative: str
    steering_profile_id: str | None = None
    resolution_modes: tuple[str, ...] = ()
    inferred: bool = False


def _path_spec(
    suffix: str,
    sequence: tuple[str, ...],
    selected: bool = True,
    primary: bool = True,
    alternative: str = "selected_primary",
    *,
    steering_profile_id: str | None = None,
    resolution_modes: tuple[str, ...] = (),
    inferred: bool = False,
) -> _PathSpec:
    return _PathSpec(
        suffix=suffix,
        sequence=sequence,
        selected=selected,
        primary=primary,
        alternative=alternative,
        steering_profile_id=steering_profile_id,
        resolution_modes=resolution_modes,
        inferred=inferred,
    )


_FORWARD_PATHS: dict[str, tuple[_PathSpec, ...]] = {
    "single-active-primary": (
        _path_spec("primary-p1", ("node-a", "transit-p-1", "node-b")),
        _path_spec(
            "standby-p2",
            ("node-a", "transit-p-2", "node-b"),
            False,
            False,
            "eligible_standby",
        ),
    ),
    "all-active-ecmp": (
        _path_spec(
            "ecmp-p1",
            ("node-a", "transit-p-1", "node-b"),
            True,
            False,
            "ecmp_member",
        ),
        _path_spec(
            "ecmp-p2",
            ("node-a", "transit-p-2", "node-b"),
            True,
            False,
            "ecmp_member",
        ),
    ),
    "cross-layer-inconsistent": (
        _path_spec("observed", ("node-a", "transit-p-1", "node-b")),
        _path_spec(
            "control",
            ("node-a", "transit-p-2", "node-b"),
            False,
            False,
            "control_expected_not_observed",
        ),
    ),
    "router-to-router": (
        _path_spec("default", ("node-a", "transit-p-1", "node-b")),
    ),
    "transit-start-endpoint-reachability": (
        _path_spec("transit-start", ("transit-p-1", "node-b")),
    ),
    "site-a-site-c-asymmetric": (
        _path_spec("srv6", ("node-a", "transit-p-2", "node-c")),
    ),
    "site-b-site-c-one-way": (
        _path_spec("forward", ("node-b", "transit-p-2", "node-c")),
    ),
    "evpn-mh-all-active": (
        _path_spec(
            "ecmp-pe-b",
            ("node-a", "transit-p-1", "node-b"),
            True,
            False,
            "ecmp_member",
        ),
        _path_spec(
            "ecmp-pe-e",
            ("node-a", "transit-p-2", "node-e"),
            True,
            False,
            "ecmp_member",
        ),
    ),
    "evpn-es-withdraw-failover": (
        _path_spec(
            "withdrawn-pe-b",
            ("node-a", "transit-p-1", "node-b"),
            False,
            False,
            "withdrawn_dead",
        ),
        _path_spec("failover-pe-e", ("node-a", "transit-p-2", "node-e")),
    ),
    "evpn-stale-fib-after-withdraw": (
        _path_spec("stale-pe-b", ("node-a", "transit-p-1", "node-b")),
        _path_spec(
            "control-pe-e",
            ("node-a", "transit-p-2", "node-e"),
            False,
            False,
            "control_expected_not_observed",
        ),
    ),
    "srv6-all-active": (
        _path_spec(
            "ecmp-p1",
            ("node-a", "transit-p-1", "node-e"),
            True,
            False,
            "ecmp_member",
        ),
        _path_spec(
            "ecmp-p2",
            ("node-a", "transit-p-2", "node-e"),
            True,
            False,
            "ecmp_member",
        ),
    ),
    "recursive-static-to-external": (
        _path_spec("recursive", ("node-a", "transit-p-1", "node-e")),
    ),
    "recursive-resolution-cycle": (
        _path_spec("cycle", ("node-a", "node-a", "node-a")),
    ),
    "cross-node-forwarding-loop": (
        _path_spec(
            "loop",
            ("node-a", "transit-p-1", "node-b", "transit-p-1"),
        ),
    ),
    "evpn-split-horizon-block": (
        _path_spec("blocked", ("node-b", "transit-p-2", "node-e")),
    ),
    "connected-external-subnet": (
        _path_spec("connected", ("node-e",)),
    ),
    "incomplete-intermediate-resolution": (
        _path_spec("incomplete", ("node-d", "transit-p-2", "node-b")),
    ),
}


_REVERSE_PATHS: dict[str, tuple[_PathSpec, ...]] = {
    "single-active-primary": (
        _path_spec("primary-p1", ("node-b", "transit-p-1", "node-a")),
        _path_spec(
            "standby-p2",
            ("node-b", "transit-p-2", "node-a"),
            False,
            False,
            "eligible_standby",
        ),
    ),
    "all-active-ecmp": (
        _path_spec(
            "ecmp-p1",
            ("node-b", "transit-p-1", "node-a"),
            True,
            False,
            "ecmp_member",
        ),
        _path_spec(
            "ecmp-p2",
            ("node-b", "transit-p-2", "node-a"),
            True,
            False,
            "ecmp_member",
        ),
    ),
    "cross-layer-inconsistent": (
        _path_spec("observed", ("node-b", "transit-p-1", "node-a")),
        _path_spec(
            "control",
            ("node-b", "transit-p-2", "node-a"),
            False,
            False,
            "control_expected_not_observed",
        ),
    ),
    "site-a-site-c-asymmetric": (
        _path_spec(
            "mpls",
            ("node-c", "transit-p-2", "transit-p-1", "node-a"),
        ),
        _path_spec(
            "eligible-backup",
            ("node-c", "transit-p-2", "node-a"),
            False,
            False,
            "eligible_standby",
        ),
    ),
    "site-b-site-c-one-way": (
        _path_spec(
            "dropped",
            ("node-c", "transit-p-2"),
            resolution_modes=("strict", "best_effort"),
        ),
        _path_spec(
            "best-effort",
            ("node-c", "transit-p-2", "transit-p-1", "node-b"),
            False,
            False,
            "best_effort_possible",
            resolution_modes=("best_effort",),
            inferred=True,
        ),
    ),
    "evpn-mh-all-active": (
        _path_spec(
            "ecmp-p1",
            ("node-e", "transit-p-1", "node-a"),
            True,
            False,
            "ecmp_member",
        ),
        _path_spec(
            "ecmp-p2",
            ("node-e", "transit-p-2", "node-a"),
            True,
            False,
            "ecmp_member",
        ),
    ),
    "evpn-es-withdraw-failover": (
        _path_spec(
            "withdrawn-p1",
            ("node-e", "transit-p-1", "node-a"),
            False,
            False,
            "withdrawn_dead",
        ),
        _path_spec("failover-p2", ("node-e", "transit-p-2", "node-a")),
    ),
    "evpn-stale-fib-after-withdraw": (
        _path_spec("stale-p1", ("node-e", "transit-p-1", "node-a")),
        _path_spec(
            "control-p2",
            ("node-e", "transit-p-2", "node-a"),
            False,
            False,
            "control_expected_not_observed",
        ),
    ),
    "srv6-all-active": (
        _path_spec(
            "ecmp-p1",
            ("node-e", "transit-p-1", "node-a"),
            True,
            False,
            "ecmp_member",
        ),
        _path_spec(
            "ecmp-p2",
            ("node-e", "transit-p-2", "node-a"),
            True,
            False,
            "ecmp_member",
        ),
    ),
    "recursive-resolution-cycle": (
        _path_spec("cycle", ("node-b", "node-b", "node-b")),
    ),
    "cross-node-forwarding-loop": (
        _path_spec(
            "loop",
            ("node-b", "transit-p-2", "node-a", "transit-p-2"),
        ),
    ),
    "transit-start-endpoint-reachability": (
        _path_spec("endpoint-return", ("node-b", "transit-p-2", "node-a")),
    ),
    "connected-external-subnet": (
        _path_spec("connected", ("node-e",)),
    ),
    "incomplete-intermediate-resolution": (
        _path_spec("incomplete", ("node-b", "transit-p-2", "node-d")),
    ),
}


def _candidate_path_id(
    case_id: str,
    direction: str,
    suffix: str,
) -> str:
    legacy_ids = {
        ("single-active-primary", "forward", "primary-p1"): (
            "route-path:underlay:pe-a-primary"
        ),
        ("single-active-primary", "forward", "standby-p2"): (
            "route-path:underlay:pe-a-alternate"
        ),
    }
    return legacy_ids.get(
        (case_id, direction, suffix),
        f"route-path:generated:{case_id}:{direction}:{suffix}",
    )


def _candidate_traversal_states(
    case: CoverageCaseSpec,
    spec: _PathSpec,
    *,
    route_type: str,
    vrf_id: str,
    destination_node_id: str,
) -> list[dict[str, Any]]:
    """Emit plug-in-canonicalized traversal identity and budget counters."""

    states: list[dict[str, Any]] = []
    recursion_depth = 0
    for visit_index, node_id in enumerate(spec.sequence):
        if visit_index and node_id == spec.sequence[visit_index - 1]:
            recursion_depth += 1
        else:
            recursion_depth = 0
        cycle_key = (
            f"{vrf_id}|{route_type}|{destination_node_id}|{node_id}"
        )
        # The recursive demo intentionally resolves A -> B -> A within one
        # node. The plug-in, not core, distinguishes the intermediate lookup
        # state so exact typed comparison closes only on the third visit.
        if (
            case.case_id == "recursive-resolution-cycle"
            and 0 < visit_index < len(spec.sequence) - 1
        ):
            cycle_key = f"{cycle_key}|recursive-intermediate"
        states.append(
            {
                "visit_index": visit_index,
                "node_id": node_id,
                "occurrence_index": sum(
                    1
                    for previous in spec.sequence[:visit_index]
                    if previous == node_id
                ),
                "repeated": node_id in spec.sequence[:visit_index],
                "cycle_key": cycle_key,
                "hop_index": visit_index,
                "recursion_depth": recursion_depth,
                "identity_complete": True,
                "semantic_owner": "plugin",
            }
        )
    return states


def _candidate_policy_decisions(
    case: CoverageCaseSpec,
    spec: _PathSpec,
    *,
    direction: str,
) -> list[dict[str, Any]]:
    """Return typed example policy input; core evaluates the exact match."""

    if case.case_id != "evpn-split-horizon-block":
        return []
    scope = {
        "contract_id": "demo.evpn.split-horizon.v1",
        "arguments": [
            {"name": "ethernet_segment", "value": "esi-east"},
            {"name": "evi", "value": 320},
            {"name": "direction", "value": direction},
        ],
    }
    terminal_node_id = spec.sequence[-1]
    return [
        {
            "decision_id": (
                f"{case.case_id}:{direction}:{spec.suffix}:split-horizon"
            ),
            "policy_kind": "split_horizon",
            "candidate": {
                "namespace": "demo",
                "node": terminal_node_id,
                "layer": "data-bridge",
                "kind": "EVPN_EGRESS_CANDIDATE",
                "parts": {
                    "ethernet_segment": "esi-east",
                    "evi": 320,
                },
            },
            "constraints": [
                {
                    "constraint_id": (
                        f"{case.case_id}:{direction}:exclude-same-scope"
                    ),
                    "kind": "exclude_exact_scope",
                    "candidate_scope": scope,
                    "traffic_classes": ["ethernet.bum"],
                }
            ],
            "ingress_scopes": [scope],
            "ingress_scopes_complete": True,
            "traffic_class": "ethernet.bum",
            "scope_refs": [
                {
                    "kind": "ethernet_segment",
                    "resource_id": (
                        f"{terminal_node_id}/data-bridge/EVPN_ES/esi-east"
                    ),
                },
                {
                    "kind": "bridge_domain",
                    "resource_id": (
                        f"{terminal_node_id}/data-bridge/BD/320"
                    ),
                },
                {
                    "kind": "virtual_interface",
                    "resource_id": (
                        f"{terminal_node_id}/data-bridge/"
                        "VIRTUAL_INTERFACE/esi-east.320"
                    ),
                },
            ],
            "evidence": [
                {
                    "kind": "ingress_attachment",
                    "resource_id": (
                        f"{terminal_node_id}/data-bridge/"
                        "VIRTUAL_INTERFACE/esi-east.320"
                    ),
                },
                {
                    "kind": "egress_attachment",
                    "resource_id": (
                        f"{terminal_node_id}/data-bridge/"
                        "VIRTUAL_INTERFACE/esi-east.320"
                    ),
                },
                {
                    "kind": "encapsulation",
                    "value": "vxlan:vni-10320",
                },
            ],
            "provided_by": {
                "plugin_id": "demo.evpn.forwarding-policy",
                "semantic_owner": "plugin",
            },
        }
    ]


def _case_candidate_paths(
    case: CoverageCaseSpec,
) -> tuple[dict[str, Any], ...]:
    if "route_resolution" not in case.required_capabilities:
        return ()
    if case.case_id.startswith("packet-"):
        four_hop = case.packet_profile_id in {
            "sr-mpls-php",
            "l3vpn-over-sr-mpls",
            "vpn-over-vpn",
            "forced-steering",
        }
        forward_sequence = (
            ("node-a", "transit-p-1", "transit-p-2", "node-b")
            if four_hop
            else ("node-a", "transit-p-1", "node-b")
        )
        forward_specs = (_path_spec("observed", forward_sequence),)
        reverse_specs = (
            _path_spec("observed", tuple(reversed(forward_sequence))),
        )
        if case.case_id == "packet-forced-steering":
            forward_specs = (
                _path_spec(
                    "observed",
                    forward_sequence,
                    steering_profile_id="observed",
                ),
                _path_spec(
                    "forced-alternate-p2",
                    ("node-a", "transit-p-2", "node-b"),
                    False,
                    False,
                    "counterfactual_forced_alternate",
                    steering_profile_id="force-alternate-p2",
                ),
            )
            reverse_specs = (
                _path_spec(
                    "observed",
                    tuple(reversed(forward_sequence)),
                    steering_profile_id="observed",
                ),
                _path_spec(
                    "forced-alternate-p2",
                    ("node-b", "transit-p-2", "node-a"),
                    False,
                    False,
                    "counterfactual_forced_alternate",
                    steering_profile_id="force-alternate-p2",
                ),
            )
    else:
        forward_specs = _FORWARD_PATHS.get(
            case.case_id,
            (_path_spec("observed", case.involved_nodes),),
        )
        reverse_specs = _REVERSE_PATHS.get(case.case_id)
        if reverse_specs is None:
            selected_forward = next(
                (item for item in forward_specs if item.selected),
                forward_specs[0],
            )
            reverse_specs = (
                _path_spec(
                    "return",
                    tuple(reversed(selected_forward.sequence)),
                ),
            )
    result: list[dict[str, Any]] = []
    for direction, specs in (
        ("forward", forward_specs),
        ("reverse", reverse_specs),
    ):
        for spec in specs:
            declaration = {
                "candidate_id": (
                    f"{case.case_id}:{direction}:{spec.suffix}"
                ),
                "path_id": _candidate_path_id(
                    case.case_id,
                    direction,
                    spec.suffix,
                ),
                "direction": direction,
                "node_sequence": list(spec.sequence),
                "selected_active": spec.selected,
                "primary": spec.primary,
                "alternative_state": spec.alternative,
            }
            if spec.steering_profile_id is not None:
                declaration["steering_profile_id"] = (
                    spec.steering_profile_id
                )
                declaration["counterfactual"] = (
                    spec.steering_profile_id != "observed"
                )
            if spec.resolution_modes:
                declaration["resolution_modes"] = list(
                    spec.resolution_modes
                )
            if spec.inferred:
                declaration["inferred"] = True
            semantics = scenario_semantics(case.case_id)
            directional_context = semantics.get(
                "directional_routing_contexts",
                {},
            ).get(direction, semantics)
            destination_node_id = (
                case.destination_node
                if direction == "forward"
                else case.source_node
            )
            semantic_ordinal = _stable_number(
                0,
                case.case_id,
                direction,
                spec.suffix,
                modulo=1_000,
            )
            route_type = str(directional_context["route_type"])
            label_payload = _route_label_payload(
                route_type,
                semantic_ordinal,
            )
            if semantics.get("cross_node_rule"):
                # These cases compare independent local lookup declarations.
                # A synthetic path-wide label/VNI would imply an unobserved agreement.
                label_payload = {}
            semantic_payload = _route_semantic_payload(
                route_type,
                spec.sequence[-1],
                semantic_ordinal,
            )
            perspective_by_alternative = {
                "control_expected_not_observed": "control_plane",
                "best_effort_possible": "inferred_topology",
                "counterfactual_forced_alternate": "counterfactual",
                "withdrawn_dead": "withdrawn_history",
            }
            declaration.update(
                {
                    "label": (
                        f"{case.title} / "
                        f"{spec.suffix.replace('-', ' ')}"
                    ),
                    "perspective": perspective_by_alternative.get(
                        spec.alternative,
                        "forwarding_observed",
                    ),
                    "forwarding_capable": (
                        spec.alternative
                        not in {
                            "control_expected_not_observed",
                            "withdrawn_dead",
                        }
                    ),
                    "policy_role": spec.alternative,
                    "route_context": dict(directional_context),
                    "protocol": ROUTE_PROTOCOL_BY_TYPE[route_type],
                    "resolution_layers": semantic_payload[
                        "resolution_layers"
                    ],
                    "encapsulation": {
                        "kind": (
                            "srv6"
                            if route_type == "srv6_policy"
                            else "mpls"
                            if route_type
                            in {"mpls_transport", "mpls_l3vpn"}
                            else "vxlan"
                            if route_type.startswith("evpn_")
                            else "ip"
                        ),
                        **(
                            {
                                "remote_vtep": semantic_payload[
                                    "remote_vtep"
                                ]
                            }
                            if "remote_vtep" in semantic_payload
                            else {}
                        ),
                        **(
                            {
                                "segment_list": semantic_payload[
                                    "segment_list"
                                ]
                            }
                            if "segment_list" in semantic_payload
                            else {}
                        ),
                        **(
                            {"label_stack": label_payload["label_stack"]}
                            if "label_stack" in label_payload
                            else {}
                        ),
                    },
                    "traversal_states": _candidate_traversal_states(
                        case,
                        spec,
                        route_type=route_type,
                        vrf_id=str(directional_context["vrf_id"]),
                        destination_node_id=destination_node_id,
                    ),
                    "policy_decisions": _candidate_policy_decisions(
                        case,
                        spec,
                        direction=direction,
                    ),
                }
            )
            (
                terminal_state,
                terminal_disposition,
                terminal_reason_code,
            ) = _directional_decision_semantics(
                case,
                declaration,
                len(spec.sequence) - 1,
            )
            declaration["terminal_semantics"] = {
                "state": terminal_state,
                "disposition": terminal_disposition,
                "reason_code": terminal_reason_code,
            }
            if route_type == "connected":
                egress_resource_id = _attachment_resource_for_segment(
                    destination_node_id,
                    "eta-external",
                )
                declaration["egress_resource_id"] = egress_resource_id
                declaration["terminal_attachment"] = {
                    "node_id": destination_node_id,
                    "resource_id": egress_resource_id,
                    "subnet": "203.0.113.0/24",
                    "classification": "external",
                    "protocol": "connected",
                }
            result.append(declaration)
    return tuple(result)


def _link_for_evidence_selector(
    selector: TopologyEvidenceSelector,
) -> Any:
    matches = [
        link
        for link in DEMO_LINKS
        if link.segment_id == selector.reference_id
    ]
    if len(matches) != 1:
        raise ValueError(
            "topology evidence selector must resolve one generated link: "
            f"{selector.reference_id}"
        )
    return matches[0]


def _topology_evidence_node_ids(
    selector: TopologyEvidenceSelector,
) -> tuple[str, ...]:
    if selector.selector_kind == "link":
        return _link_for_evidence_selector(selector).participants
    return selector.node_ids


def _materialize_topology_evidence(
    case: CoverageCaseSpec,
    *,
    config: AssemblyConfig,
    topology_projections: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    selected_nodes = {node.node_id: node for node in config.nodes}
    evidence: list[dict[str, Any]] = []
    missing: list[str] = []
    for selector in case.topology_evidence:
        for node_id in _topology_evidence_node_ids(selector):
            node = selected_nodes.get(node_id)
            if node is None:
                continue
            projection = (
                topology_projections[node_id]
                if topology_projections is not None
                else _topology_projection(node, config=config)
            )
            claim_id = f"{node_id}/topology/{selector.reference_id}"
            claims = [
                claim
                for claim in projection["claims"]
                if claim["claim_id"] == claim_id
            ]
            if len(claims) != 1:
                missing.append(
                    f"topology:{selector.selector_kind}:"
                    f"{selector.reference_id}:{node_id}"
                )
                continue
            claim = claims[0]
            subnet = claim["subnet"]
            item: dict[str, Any] = {
                "evidence_kind": "topology_claim",
                "node_id": node_id,
                "revision_id": node.revision_id,
                "resource_id": claim["interface_resource_id"],
                "topology_claim_id": claim["claim_id"],
                "selector_kind": selector.selector_kind,
                "reference_id": selector.reference_id,
                "segment_key": claim["segment_key"],
                "matcher_id": claim["matcher_id"],
                "subnet_prefix": subnet["prefix"],
                "classification": subnet["classification"],
                "attachment_kind": claim["attachment_kind"],
                "status": claim["status"],
                "confidence": claim["confidence"],
                "valid_from_ns": claim["valid_from_ns"],
                "valid_to_ns": claim["valid_to_ns"],
                "excluded_from_connectivity": bool(
                    claim.get("excluded_from_connectivity", False)
                ),
                "calculation": claim["calculation"],
            }
            if "topology_presentation" in claim:
                item["topology_presentation"] = claim[
                    "topology_presentation"
                ]
            evidence.append(item)
    return evidence, missing


def _temporal_event_matches(
    event: Mapping[str, Any],
    selector: TemporalEvidenceSelector,
) -> bool:
    return (
        event.get("phase") == selector.phase
        and event.get("event_name") == selector.event_name
        and event.get("resource_kind") == selector.resource_kind
        and (
            selector.outcome is None
            or event.get("outcome") == selector.outcome
        )
        and (
            selector.state_changed is None
            or event.get("state_changed") is selector.state_changed
        )
    )


def _resolve_temporal_evidence_event(
    selector: TemporalEvidenceSelector,
    *,
    config: AssemblyConfig,
) -> dict[str, Any] | None:
    layout = scale_generator._layout(config.resources_per_node)
    phase_counts = scale_generator._phase_event_counts(
        config.events_per_node
    )
    if selector.phase not in phase_counts:
        return None
    sequence = 0
    for phase, _weight, _description in scale_generator.PHASES:
        phase_count = phase_counts[phase]
        if phase != selector.phase:
            sequence += phase_count
            continue
        start_ns = scale_generator._phase_start_ns(phase)
        for local_index in range(phase_count):
            event = scale_generator._event_for_phase(
                phase,
                sequence + local_index,
                local_index,
                start_ns + local_index * scale_generator.EVENT_STEP_NS,
                layout,
            )
            if _temporal_event_matches(event, selector):
                return event
        return None
    return None


def _materialize_temporal_evidence(
    case: CoverageCaseSpec,
    *,
    config: AssemblyConfig,
    event_cache: dict[
        TemporalEvidenceSelector,
        dict[str, Any] | None,
    ]
    | None = None,
) -> tuple[list[dict[str, Any]], list[str], list[int]]:
    selected_nodes = {node.node_id: node for node in config.nodes}
    evidence: list[dict[str, Any]] = []
    missing: list[str] = []
    timestamps: list[int] = []
    for selector in case.temporal_evidence:
        if event_cache is None:
            event = _resolve_temporal_evidence_event(
                selector,
                config=config,
            )
        else:
            try:
                event = event_cache[selector]
            except KeyError:
                event = _resolve_temporal_evidence_event(
                    selector,
                    config=config,
                )
                event_cache[selector] = event
        selector_key = (
            f"temporal:{selector.phase}:{selector.event_name}:"
            f"{selector.resource_kind}:{selector.outcome or '*'}"
        )
        if event is None:
            missing.append(selector_key)
            continue
        timestamps.append(int(event["timestamp_ns"]))
        for node_id in case.involved_nodes:
            node = selected_nodes.get(node_id)
            if node is None:
                continue
            transformed = _transform_value(event, node=node)
            properties = transformed.get("properties", {})
            item: dict[str, Any] = {
                "evidence_kind": "temporal_event",
                "node_id": node_id,
                "revision_id": node.revision_id,
                "resource_id": transformed["resource_id"],
                "event_uid": transformed["event_uid"],
                "event_name": transformed["event_name"],
                "phase": transformed["phase"],
                "timestamp_ns": transformed["timestamp_ns"],
                "resource_kind": transformed["resource_kind"],
                "action": transformed["action"],
                "outcome": transformed["outcome"],
                "state_changed": transformed["state_changed"],
                "relationship_types": sorted(
                    {
                        str(change["type"])
                        for change in transformed.get(
                            "relationship_effects", ()
                        )
                    }
                ),
            }
            if isinstance(properties, Mapping) and properties.get(
                "service_id"
            ):
                item["service_id"] = properties["service_id"]
            evidence.append(item)
    return evidence, missing, timestamps


def _case_materialization(
    case: CoverageCaseSpec,
    *,
    case_index: int,
    config: AssemblyConfig,
    selected_nodes: Mapping[str, NodeSpec] | None = None,
    topology_projections: Mapping[str, Mapping[str, Any]] | None = None,
    temporal_event_cache: dict[
        TemporalEvidenceSelector,
        dict[str, Any] | None,
    ]
    | None = None,
) -> dict[str, Any]:
    node_catalog = selected_nodes or {
        node.node_id: node for node in config.nodes
    }
    selected = set(node_catalog)
    candidate_paths = _case_candidate_paths(case)
    semantics = (
        scenario_semantics(case.case_id)
        if "route_resolution" in case.required_capabilities
        else {}
    )
    consistency_findings = []
    for finding_index, spec in enumerate(
        semantics.get("consistency_finding_specs", ()),
        start=1,
    ):
        alternative_states = set(
            spec.get("candidate_alternative_states", ())
        )
        candidate_directions = set(
            spec.get("candidate_directions", ())
        )
        referenced_candidates = [
            path
            for path in candidate_paths
            if path["alternative_state"] in alternative_states
            and (
                not candidate_directions
                or path["direction"] in candidate_directions
            )
        ]
        consistency_findings.append(
            {
                "finding_id": (
                    f"{case.case_id}:consistency:{finding_index}"
                ),
                **(
                    {"issue_id": str(spec["issue_id"])}
                    if spec.get("issue_id")
                    else {}
                ),
                "category": str(
                    spec.get("category") or "cross_layer"
                ),
                "finding_type": str(spec["finding_type"]),
                "summary": str(spec["summary"]),
                "candidate_ids": [
                    path["candidate_id"]
                    for path in referenced_candidates
                ],
                "path_ids": [
                    path["path_id"]
                    for path in referenced_candidates
                ],
                "affects_consistency": bool(
                    spec.get("affects_consistency", True)
                ),
                "semantic_owner": "plugin",
            }
        )
    cross_node_rule = semantics.get("cross_node_rule")
    if isinstance(cross_node_rule, Mapping):
        consistency_findings.extend(evaluate_boundary_findings(
            case.case_id,
            cross_node_rule,
            candidate_paths,
            [
                observation
                for node in node_catalog.values()
                for direction in ("forward", "reverse")
                for observation in _source_boundary_observations(node, case.case_id, direction)
            ],
            {node.node_id: node.revision_id for node in node_catalog.values()},
        ))
    topology_evidence_node_ids = [
        node_id
        for selector in case.topology_evidence
        for node_id in _topology_evidence_node_ids(selector)
    ]
    involved_nodes = list(
        dict.fromkeys(
            [
                *case.involved_nodes,
                *topology_evidence_node_ids,
                *(
                    node_id
                    for path in candidate_paths
                    for node_id in path["node_sequence"]
                ),
            ]
        )
    )
    missing_nodes = sorted(set(involved_nodes) - selected)
    timestamp_ns = _coverage_timestamp(case_index)
    candidate_node_ids = list(
        dict.fromkeys(
            node_id
            for path in candidate_paths
            for node_id in path["node_sequence"]
        )
    )
    candidate_node_set = set(candidate_node_ids)
    evidence_node_ids = (
        [
            *(
                node_id
                for node_id in involved_nodes
                if node_id in candidate_node_set
            ),
            *(
                node_id
                for node_id in candidate_node_ids
                if node_id not in involved_nodes
            ),
        ]
        if "route_resolution" in case.required_capabilities
        else involved_nodes
    )
    evidence_refs: list[dict[str, Any]] = []
    missing_evidence: list[str] = []
    if "route_resolution" in case.required_capabilities:
        for evidence_index, node_id in enumerate(evidence_node_ids):
            if node_id not in selected:
                continue
            event_index = (
                case_index * 17 + evidence_index
            ) % config.events_per_node
            evidence_refs.append(
                {
                    "evidence_kind": "route_projection",
                    "node_id": node_id,
                    "revision_id": node_catalog[node_id].revision_id,
                    "resource_id": (
                        f"{node_id}/control-plane/IP_ROUTING/blue"
                    ),
                    "event_uid": (
                        f"{node_id}/scale-event-{event_index:08d}"
                    ),
                    "route_id": f"{node_id}/route/{case.case_id}",
                    "forwarding_id": (
                        f"{node_id}/forwarding/{case.case_id}"
                    ),
                }
            )
    elif case.category == "topology":
        evidence_refs, missing_evidence = (
            _materialize_topology_evidence(
                case,
                config=config,
                topology_projections=topology_projections,
            )
        )
    elif case.category == "temporal":
        (
            evidence_refs,
            missing_evidence,
            temporal_timestamps,
        ) = _materialize_temporal_evidence(
            case,
            config=config,
            event_cache=temporal_event_cache,
        )
        if temporal_timestamps:
            timestamp_ns = max(temporal_timestamps)
    else:
        missing_evidence.append(
            f"unsupported-non-route-category:{case.category}"
        )
    generated = not missing_nodes and not missing_evidence
    default_start = semantics.get("default_start")
    return {
        "case_id": case.case_id,
        "category": case.category,
        "title": case.title,
        "timestamp_ns": str(timestamp_ns),
        "source": {
            "node_id": case.source_node,
            "endpoint_id": f"source:{case.source_node}",
        },
        "destination": {
            "node_id": case.destination_node,
            "endpoint_id": f"destination:{case.destination_node}",
        },
        "trace_start_node": (
            str(default_start).split(":", 1)[-1]
            if default_start
            else None
        ),
        "route_type": case.route_type,
        "route_family": case.route_family,
        "address_family": case.address_family,
        "vrf": case.vrf,
        "involved_nodes": involved_nodes,
        "candidate_paths": list(candidate_paths),
        "required_capabilities": list(case.required_capabilities),
        "private_analysis_intents": list(case.private_analysis_intents),
        "packet_profile_id": case.packet_profile_id,
        "expected_outcome": case.expected_outcome,
        "consistency_findings": consistency_findings,
        "generated": generated,
        "missing_nodes": missing_nodes,
        "missing_evidence": missing_evidence,
        "evidence_refs": evidence_refs,
    }


def build_coverage(
    config: AssemblyConfig,
    *,
    _topology_projections: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Materialize the complete public behavior registry for this assembly."""

    selected_nodes = {node.node_id: node for node in config.nodes}
    topology_projections = _topology_projections or {
        node_id: _topology_projection(node, config=config)
        for node_id, node in selected_nodes.items()
    }
    temporal_event_cache: dict[
        TemporalEvidenceSelector,
        dict[str, Any] | None,
    ] = {}
    cases = [
        _case_materialization(
            case,
            case_index=index,
            config=config,
            selected_nodes=selected_nodes,
            topology_projections=topology_projections,
            temporal_event_cache=temporal_event_cache,
        )
        for index, case in enumerate(COVERAGE_CASES)
    ]
    return {
        "format_version": GENERATED_COVERAGE_FORMAT_VERSION,
        "registry_id": GENERATED_COVERAGE_REGISTRY_ID,
        "assembly_id": config.assembly_id,
        "complete": all(case["generated"] for case in cases),
        "cases": cases,
        "case_count": len(cases),
        "categories": sorted({case.category for case in COVERAGE_CASES}),
    }


def _interface_resource_id(
    node_id: str,
    local_resource_id: str,
) -> str:
    return _source_resource_id(
        node_id,
        "VIRTUAL_INTERFACE",
        local_resource_id,
    )


def _adjacency_resource_id(
    node_id: str,
    segment_id: str,
    neighbor_node_id: str,
) -> str:
    return (
        f"{node_id}/control-plane/ADJACENCY/"
        f"{segment_id}/{neighbor_node_id}"
    )


def _source_topology_changes(
    node: NodeSpec,
    local_resource_id: str,
) -> list[dict[str, Any]]:
    """Transport authored local history without interpreting service types."""

    changes: list[dict[str, Any]] = []
    for observation in DEFAULT_SCENARIO_SOURCE.observations_by_node[node.node_id]:
        if observation.resource_id != local_resource_id:
            continue
        operation = observation.operation.casefold().replace("_", "-")
        change: dict[str, Any] = {
            "event_uid": f"{node.node_id}/scenario/{observation.event_id}",
            "operation": observation.operation,
            "outcome": observation.outcome,
            "state": observation.to_event().get("properties", {}),
            "state_changed": observation.update_snapshot,
            "time_ns": str(observation.timestamp_ns),
        }
        if observation.status is not None:
            change["status"] = observation.status
        if operation in {"create", "add", "restore", "recreate"}:
            change["exists"] = True
        elif operation in {"delete", "remove", "withdraw"}:
            change["exists"] = False
        changes.append(change)
    return changes


def _topology_projection(
    node: NodeSpec,
    *,
    config: AssemblyConfig,
) -> dict[str, Any]:
    claims: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    observed_at_ns = (
        DEFAULT_SCENARIO_SOURCE.capture_time_ns
        + node.clock_offset_ns
    )
    for index, link in enumerate(links_for_node(node.node_id)):
        local_interface_id = link.attachment_resource_id(node.node_id)
        interface_id = _interface_resource_id(
            node.node_id,
            local_interface_id,
        )
        host_number = (
            _stable_number(
                config.seed,
                node.node_id,
                link.segment_id,
                modulo=200,
            )
            + 1
        )
        interface_name = local_interface_id.removeprefix("interface:")
        topology_changes = _source_topology_changes(node, local_interface_id)
        resources.append(
            {
                "resource_id": interface_id,
                "kind": "VIRTUAL_INTERFACE",
                "label": interface_name,
                "status": link.attachment_status(node.node_id),
                "valid_from_ns": str(DEFAULT_SCENARIO_SOURCE.base_time_ns),
                "valid_to_ns": None,
                "changes": topology_changes,
                "attachment_kind": link.attachment_kind,
                "vlan_id": link.vlan_id,
                "lag_id": link.lag_id,
            }
        )
        resources.extend(
            {
                "resource_id": _adjacency_resource_id(
                    node.node_id,
                    link.segment_id,
                    neighbor_node_id,
                ),
                "kind": "ADJACENCY",
                "label": f"{interface_name} to {neighbor_node_id}",
                "neighbor_node_id": neighbor_node_id,
                "interface_resource_id": interface_id,
                "segment_key": f"subnet:{link.segment_id}",
            }
            for neighbor_node_id in link.participants
            if neighbor_node_id != node.node_id
        )
        claims.append(
            {
                "claim_id": f"{node.node_id}/topology/{link.segment_id}",
                "node_id": node.node_id,
                "revision_id": node.revision_id,
                "interface_resource_id": interface_id,
                "interface_name": interface_name,
                "attachment_kind": link.attachment_kind,
                "components": {
                    "physical_interfaces": [f"Ethernet{index + 1}/1"],
                    "lag_id": link.lag_id,
                    "vlan_id": link.vlan_id,
                },
                "segment_key": f"subnet:{link.segment_id}",
                "matcher_id": GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID,
                "subnet": {
                    "prefix": link.prefix,
                    "classification": link.classification,
                    "render_hint": (
                        "direct_line"
                        if len(link.participants) == 2
                        else "shared_subnet"
                    ),
                    "local_address_hint": f"host-{host_number}",
                },
                "topology_presentation": {
                    "two_participant_shape": (
                        "compact_edge"
                        if len(link.participants) == 2
                        else "domain_node"
                    ),
                    "reason": (
                        "The demo plug-in infers the presentation from local "
                        "interface, route, and neighbor evidence; no private "
                        "medium ID or participant list is emitted."
                    ),
                },
                "status": "usable",
                "valid_from_ns": str(
                    DEFAULT_SCENARIO_SOURCE.base_time_ns
                ),
                "valid_to_ns": None,
                "confidence": link.confidence,
                "calculation": {
                    "owner": "plugin",
                    "basis": [
                        "interface status",
                        "connected route",
                        "neighbor adjacency",
                    ],
                    "summary": (
                        "The example plug-in normalized interface, route, and "
                        "neighbor evidence to a shared segment key."
                    ),
                },
                "evidence_resource_ids": [interface_id],
            }
        )

    for authored in node.initial_resources:
        projected = project_vpn_topology_resource(
            node_id=node.node_id,
            revision_id=node.revision_id,
            resource={
                "resource_id": _source_resource_id(
                    node.node_id, authored.resource_type, authored.resource_id
                ),
                "kind": authored.resource_type,
                "status": authored.status,
                "properties": authored.properties,
                "changes": _source_topology_changes(node, authored.resource_id),
            },
            valid_from_ns=DEFAULT_SCENARIO_SOURCE.base_time_ns,
        )
        if projected is not None:
            resource, claim = projected
            resources.append(resource)
            claims.append(claim)

    # These one-node scopes prove that plugins can classify evidence which the
    # generic topology core must retain but must not use for inter-node links.
    for suffix, classification, prefix in (
        ("management", "management", "192.0.2.0/24"),
        ("loopback", "loopback", "10.255.0.0/24"),
    ):
        claims.append(
            {
                "claim_id": f"{node.node_id}/topology/{suffix}",
                "node_id": node.node_id,
                "revision_id": node.revision_id,
                "interface_resource_id": (
                    f"{node.node_id}/control-plane/IP_ROUTING/blue"
                ),
                "interface_name": suffix,
                "attachment_kind": "logical",
                "components": {},
                "segment_key": f"{classification}:{node.node_id}",
                "matcher_id": GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID,
                "subnet": {
                    "prefix": prefix,
                    "classification": classification,
                    "render_hint": "local_only",
                },
                "status": "usable",
                "valid_from_ns": str(observed_at_ns),
                "valid_to_ns": None,
                "confidence": "plugin_declared",
                "excluded_from_connectivity": True,
                "calculation": {
                    "owner": "plugin",
                    "basis": ["plugin subnet classification"],
                    "summary": (
                        f"The example plug-in classified this {classification} "
                        "scope as local-only."
                    ),
                },
                "evidence_resource_ids": [
                    f"{node.node_id}/control-plane/IP_ROUTING/blue"
                ],
            }
        )
    return {
        "format_version": 1,
        "projection_policy_id": GENERATED_PROJECTION_POLICY.policy_id,
        "node_id": node.node_id,
        "revision_id": node.revision_id,
        "observed_at_ns": str(observed_at_ns),
        "profile": {
            "profile_id": GENERATED_TOPOLOGY_PROFILE.profile_id,
            "label": GENERATED_TOPOLOGY_PROFILE.label,
            "projection_role": (
                GENERATED_TOPOLOGY_PROFILE.projection_role
            ),
            "presentation_roles": list(
                GENERATED_TOPOLOGY_PROFILE.presentation_roles
            ),
        },
        "resources": resources,
        "claims": claims,
    }


def _route_label_payload(
    route_type: str,
    ordinal: int,
) -> dict[str, Any]:
    if route_type in {"mpls_transport", "mpls_l3vpn"}:
        return {
            "label_stack": [
                16_000 + ordinal,
                *(
                    [24_000 + ordinal]
                    if route_type == "mpls_l3vpn"
                    else []
                ),
            ]
        }
    if route_type == "srv6_policy":
        return {
            "sid_stack": [
                f"2001:db8:ffff:{ordinal + 1:x}::1",
                f"2001:db8:ffff:{ordinal + 2:x}::1",
            ]
        }
    if route_type in {
        "evpn_ip_prefix",
        "evpn_mac_ip",
        "evpn_service",
    }:
        return {
            "encapsulation": {
                "type": "VXLAN",
                "vni": 10_000 + ordinal,
            }
        }
    return {}


def _route_forwarding_actions(
    route_type: str,
    ordinal: int,
    next_hop_id: str | None,
) -> list[dict[str, Any]]:
    if next_hop_id is None:
        return []
    labels = _route_label_payload(route_type, ordinal)
    label_stack = labels.get("label_stack")
    if isinstance(label_stack, list):
        return [
            {
                "action_id": f"{next_hop_id}/mpls-label-stack",
                "kind": "mpls_label_stack",
                "label": "Plug-in label stack",
                "operation": "push",
                "order": "outer_to_inner",
                "applies_to_next_hop_id": next_hop_id,
                "values": [
                    {
                        "value": value,
                        "display": str(value),
                        "kind": (
                            "sr_mpls_sid"
                            if index == 0
                            else "mpls_label"
                        ),
                        "value_type": "integer",
                        "role": (
                            "transport"
                            if index == 0
                            else "vpn"
                            if route_type == "mpls_l3vpn" and index == 1
                            else f"label_{index + 1}"
                        ),
                        "position": index,
                    }
                    for index, value in enumerate(label_stack)
                ],
            }
        ]
    sid_stack = labels.get("sid_stack")
    if isinstance(sid_stack, list):
        return [
            {
                "action_id": f"{next_hop_id}/srv6-sid-list",
                "kind": "srv6_sid_list",
                "label": "Plug-in SID list",
                "operation": "encapsulate",
                "order": "first_segment_to_last",
                "applies_to_next_hop_id": next_hop_id,
                "values": [
                    {
                        "value": value,
                        "display": str(value),
                        "kind": "srv6_sid",
                        "value_type": "ipv6_address",
                        "role": f"segment_{index + 1}",
                        "position": index,
                    }
                    for index, value in enumerate(sid_stack)
                ],
            }
        ]
    encapsulation = labels.get("encapsulation")
    if isinstance(encapsulation, Mapping):
        return [
            {
                "action_id": f"{next_hop_id}/vxlan-encapsulation",
                "kind": "vxlan_encapsulation",
                "label": "Plug-in VXLAN encapsulation",
                "operation": "encapsulate",
                "applies_to_next_hop_id": next_hop_id,
                "values": [
                    {
                        "value": encapsulation["vni"],
                        "display": str(encapsulation["vni"]),
                        "kind": "vni",
                        "value_type": "integer",
                        "role": "overlay",
                        "position": 0,
                    }
                ],
            }
        ]
    return []


def _shortest_demo_node_path(
    source_node_id: str,
    destination_node_id: str,
) -> tuple[str, ...]:
    if source_node_id == destination_node_id:
        return (source_node_id,)
    adjacency = {
        node.node_id: set(adjacent_nodes(node.node_id))
        for node in DEMO_NODES
    }
    pending: deque[tuple[str, ...]] = deque([(source_node_id,)])
    visited = {source_node_id}
    while pending:
        path = pending.popleft()
        for neighbor in sorted(adjacency[path[-1]]):
            if neighbor in visited:
                continue
            candidate = (*path, neighbor)
            if neighbor == destination_node_id:
                return candidate
            visited.add(neighbor)
            pending.append(candidate)
    raise ValueError(
        f"no generated fabric path from {source_node_id} "
        f"to {destination_node_id}"
    )


def _attachment_resource_for_segment(
    node_id: str,
    segment_id: str,
) -> str:
    for link in links_for_node(node_id):
        if link.segment_id == segment_id:
            return _interface_resource_id(
                node_id,
                link.attachment_resource_id(node_id),
            )
    raise ValueError(
        f"node {node_id} has no generated attachment for {segment_id}"
    )


def _typed_connector_endpoint_reference(
    node_id: str,
    resource_id: str,
) -> dict[str, Any]:
    """Declare the demo provider's typed key without core qualification."""

    return {
        "node_id": node_id,
        "resource_id": resource_id,
        "typed_resource_key": {
            "namespace": "demo.generated.topology",
            "node": node_id,
            "layer": "underlay",
            "kind": "demo.topology.endpoint",
            "parts": [
                {
                    "name": "resource_id",
                    "value": {
                        "type": "string",
                        "value": resource_id,
                    },
                }
            ],
        },
    }


def _connectivity_next_hop_declaration(
    *,
    route_type: str,
    declaration_id: str,
    node_id: str,
    next_node_id: str,
) -> dict[str, Any]:
    """Join one plug-in route next hop to exact generated fabric evidence."""

    candidate_links = [
        link
        for link in links_for_node(node_id)
        if next_node_id in link.participants
    ]
    try:
        selected = GENERATED_PROJECTION_POLICY.select_connectivity_domain(
            route_type=route_type,
            candidates=(
                {
                    "segment_id": link.segment_id,
                    "classification": link.classification,
                    "participant_count": len(link.participants),
                    "attachment_kind": link.attachment_kind,
                }
                for link in candidate_links
            ),
        )
    except ValueError as error:
        raise ValueError(
            f"{declaration_id}: no connectivity declaration for "
            f"{node_id} -> {next_node_id}"
        ) from error
    segment_id = str(selected["segment_id"])
    selected_links = [
        link for link in candidate_links if link.segment_id == segment_id
    ]
    if len(selected_links) != 1:
        raise ValueError(
            f"{declaration_id}: selected connectivity domain {segment_id} "
            "does not identify exactly one generated link"
        )
    selected_link = selected_links[0]
    local_resource_id = _attachment_resource_for_segment(
        node_id,
        segment_id,
    )
    remote_resource_id = _attachment_resource_for_segment(
        next_node_id,
        segment_id,
    )
    adjacency_resource_id = _adjacency_resource_id(
        node_id,
        segment_id,
        next_node_id,
    )
    remote_adjacency_resource_id = _adjacency_resource_id(
        next_node_id,
        segment_id,
        node_id,
    )
    next_hop_id = (
        f"{node_id}/next-hop/{segment_id}/{next_node_id}"
    )
    topology_references: list[dict[str, Any]] = [
        {
            "reference_kind": "connectivity_domain",
            "match": {
                "matcher_id": (
                    GENERATED_PROJECTION_POLICY.topology_segment_matcher_id
                ),
                "matcher_contract_version": "1.0",
                "arguments": {
                    "segment_key": {
                        "type": "string",
                        "value": f"subnet:{segment_id}",
                    }
                },
            },
        }
    ]
    if len(selected_link.participants) == 2:
        topology_references.append(
            {
                "reference_kind": "typed_inter_node_link",
                "source_endpoint": _typed_connector_endpoint_reference(
                    node_id,
                    local_resource_id,
                ),
                "target_endpoint": _typed_connector_endpoint_reference(
                    next_node_id,
                    remote_resource_id,
                ),
            }
        )
    return {
        "next_hop_id": next_hop_id,
        "node_id": next_node_id,
        "interface_resource_id": local_resource_id,
        "remote_interface_resource_id": remote_resource_id,
        "adjacency_resource_id": adjacency_resource_id,
        "remote_adjacency_resource_id": remote_adjacency_resource_id,
        "interface_endpoint": {
            "node_id": node_id,
            "resource_id": local_resource_id,
        },
        "adjacency_endpoint": {
            "node_id": node_id,
            "resource_id": adjacency_resource_id,
            "neighbor_node_id": next_node_id,
        },
        "topology_references": topology_references,
        "selection_owner": "plugin",
        "selection_policy_id": GENERATED_PROJECTION_POLICY.policy_id,
    }


def _next_hop_declaration(
    case: CoverageCaseSpec,
    *,
    node_id: str,
    next_node_id: str,
) -> dict[str, Any]:
    return _connectivity_next_hop_declaration(
        route_type=case.route_type,
        declaration_id=case.case_id,
        node_id=node_id,
        next_node_id=next_node_id,
    )


def _directional_decision_semantics(
    case: CoverageCaseSpec,
    path: Mapping[str, Any],
    visit_index: int,
) -> tuple[str, str, str]:
    """Return the plug-in-owned state and action for one path occurrence."""

    sequence = path["node_sequence"]
    next_node_id = (
        sequence[visit_index + 1]
        if visit_index + 1 < len(sequence)
        else None
    )
    alternative = str(path["alternative_state"])
    if not path["selected_active"]:
        inactive_semantics = {
            "eligible_standby": (
                "standby",
                "standby",
                "eligible_standby",
            ),
            "withdrawn_dead": (
                "failed",
                "withdrawn",
                "evpn_es_withdrawn",
            ),
            "control_expected_not_observed": (
                "control_plane_only",
                "control_only",
                "control_plane_only",
            ),
            "best_effort_possible": (
                "inferred_inactive",
                "best_effort_inferred",
                "topology_best_effort_inference",
            ),
            "counterfactual_forced_alternate": (
                "counterfactual",
                "counterfactual",
                "forced_steering_alternate",
            ),
        }
        return inactive_semantics.get(
            alternative,
            ("inactive", "inactive", "inactive_candidate"),
        )

    direction = str(path["direction"])
    if (
        case.case_id == "site-b-site-c-one-way"
        and direction == "reverse"
        and visit_index == len(sequence) - 1
    ):
        return "failed", "drop", "dropped"
    if (
        case.case_id == "evpn-split-horizon-block"
        and visit_index == len(sequence) - 1
    ):
        return "rejected", "split_horizon_block", "split_horizon_same_scope"
    if case.case_id == "incomplete-node-resolution":
        if visit_index == len(sequence) - 1:
            return "incomplete", "unresolved", "missing_node_resolution"
    if case.case_id == "incomplete-intermediate-resolution":
        missing_index = len(sequence) // 2
        if visit_index >= missing_index:
            return (
                "incomplete",
                "unresolved",
                "missing_intermediate_resolution",
            )
    if (
        case.case_id == "recursive-resolution-cycle"
        and visit_index == len(sequence) - 1
    ):
        return "loop", "loop", "recursive_resolution_cycle"
    if (
        case.case_id == "cross-node-forwarding-loop"
        and visit_index == len(sequence) - 1
    ):
        return "loop", "loop", "forwarding_loop"
    if (
        case.case_id == "evpn-stale-fib-after-withdraw"
        and alternative == "selected_primary"
        and visit_index == len(sequence) - 1
    ):
        return "failed", "unusable", "stale_fib_to_withdrawn_es"
    return (
        "active",
        "forward" if next_node_id is not None else "delivered",
        "selected_forwarding"
        if next_node_id is not None
        else "destination_reached",
    )


def _directional_resolution_text(
    case: CoverageCaseSpec,
    *,
    node_id: str,
    candidate_id: str,
    next_node_id: str | None,
    disposition: str,
) -> str:
    if disposition == "forward":
        action = f"forwards toward {next_node_id}"
    elif disposition == "delivered":
        action = "resolves the local destination attachment"
    elif disposition == "drop":
        action = "drops the packet before the declared destination"
    elif disposition == "split_horizon_block":
        action = "rejects egress under the declared split-horizon policy"
    elif disposition == "unresolved":
        action = "cannot prove the next route-resolution step"
    elif disposition == "loop":
        action = "returns to a previously visited forwarding state"
    elif disposition == "withdrawn":
        action = "retains a withdrawn candidate without selecting it"
    elif disposition == "control_only":
        action = "retains the control-plane candidate without programming it"
    elif disposition == "standby":
        action = "retains an eligible standby candidate"
    elif disposition == "best_effort_inferred":
        action = "offers an inactive best-effort continuation"
    elif disposition == "counterfactual":
        action = "offers a user-selectable counterfactual next hop"
    else:
        action = f"reports the {disposition} candidate state"
    return (
        f"The {node_id} example plug-in {action} for "
        f"{case.route_type} candidate {candidate_id}."
    )


def _inventory_destination_value(
    route_type: str,
    destination_node_id: str,
    vrf_id: str,
) -> str:
    ordinal = next(
        index
        for index, node in enumerate(DEMO_NODES, start=1)
        if node.node_id == destination_node_id
    )
    if route_type == "evpn_ip_prefix":
        return f"198.18.{ordinal}.0/24"
    if vrf_id == "red":
        return f"10.30.{ordinal}.0/24"
    if vrf_id == "management":
        return f"192.0.2.{ordinal}/32"
    return f"10.255.{ordinal}.0/32"


def _route_trace_query(
    *,
    scenario_id: str,
    source_node_id: str,
    destination_node_id: str,
    route_type: str,
    route_family: str,
    address_family: str,
    vrf_id: str,
    direction: str = "both",
) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "direction": direction,
        "source": {"node_id": source_node_id},
        "destination": {"node_id": destination_node_id},
        "route_type": route_type,
        "route_family": route_family,
        "address_family": address_family,
        "vrf": vrf_id,
        "vrf_id": vrf_id,
    }


def _apply_scenario_destination_identity(
    trace_query: dict[str, Any],
    semantics: Mapping[str, Any],
    *,
    direction: str,
) -> None:
    """Attach a plug-in-declared endpoint identity to a scenario trace query.

    A route can terminate at a service or external attachment on the same
    router. Node identity alone cannot distinguish that endpoint from the
    router itself, so the generated row carries the role declaration through
    to the core without teaching the core any demo-specific endpoint names.
    """

    if direction != "forward":
        return
    endpoint_ids = [
        str(item)
        for item in semantics.get("destination_endpoint_ids", ())
        if item
    ]
    if not endpoint_ids:
        return
    destination = dict(trace_query["destination"])
    destination_id = next(
        (
            item
            for item in endpoint_ids
            if item.startswith("destination:")
        ),
        endpoint_ids[0],
    )
    endpoint_id = next(
        (
            item
            for item in endpoint_ids
            if item.startswith("endpoint:")
        ),
        None,
    )
    destination["destination_id"] = destination_id
    if endpoint_id is not None:
        destination["endpoint_id"] = endpoint_id
    destination_values = [
        str(item)
        for item in semantics.get("destination_values", ())
        if item
    ]
    if destination_values:
        destination["value"] = destination_values[0]
    trace_query["destination"] = destination


def _route_input_variants(
    *,
    trace_query: Mapping[str, Any],
    first_next_hop: Mapping[str, Any],
    last_next_hop: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    return {
        "nested_node_pair": dict(trace_query),
        "interface_to_adjacency": {
            **dict(trace_query),
            "source": {
                "resource_id": first_next_hop[
                    "interface_resource_id"
                ],
            },
            "destination": {
                "resource_id": last_next_hop[
                    "remote_adjacency_resource_id"
                ],
            },
        },
    }


def _route_semantic_payload(
    route_type: str,
    destination_node_id: str,
    ordinal: int,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "resolution_layers": list(
            ROUTE_RESOLUTION_LAYERS_BY_TYPE[route_type]
        ),
    }
    if route_type.startswith("evpn_"):
        destination_ordinal = next(
            index
            for index, node in enumerate(DEMO_NODES, start=1)
            if node.node_id == destination_node_id
        )
        payload["remote_vtep"] = f"10.254.0.{destination_ordinal}"
    labels = _route_label_payload(route_type, ordinal)
    if "sid_stack" in labels:
        payload["segment_list"] = list(labels["sid_stack"])
    if "label_stack" in labels:
        payload["outgoing_label_stack"] = list(
            labels["label_stack"]
        )
    return payload


def _per_hop_declarations(
    *,
    declaration_id: str,
    path_id: str,
    route_type: str,
    route_family: str,
    address_family: str,
    vrf_id: str,
    protocol: str,
    node_sequence: tuple[str, ...],
    state: str,
    forwarding_capable: bool,
    reason_code: str,
    ordinal: int,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for visit_index, node_id in enumerate(node_sequence):
        next_node_id = (
            node_sequence[visit_index + 1]
            if visit_index + 1 < len(node_sequence)
            else None
        )
        next_hop = (
            _connectivity_next_hop_declaration(
                route_type=route_type,
                declaration_id=declaration_id,
                node_id=node_id,
                next_node_id=next_node_id,
            )
            if next_node_id is not None and next_node_id != node_id
            else None
        )
        if next_node_id is None:
            packet_operation = "deliver"
        elif route_type in {"mpls_transport", "mpls_l3vpn"}:
            packet_operation = (
                "push"
                if visit_index == 0
                else "php"
                if visit_index == len(node_sequence) - 2
                else "swap"
            )
        elif route_type == "srv6_policy":
            packet_operation = (
                "encapsulate"
                if visit_index == 0
                else "advance_sid"
            )
        elif route_type.startswith("evpn_"):
            packet_operation = (
                "vxlan_encapsulate"
                if visit_index == 0
                else "underlay_forward"
            )
        else:
            packet_operation = "ip_forward"
        result.append(
            {
                "continuation_id": (
                    f"{path_id}:visit:{visit_index}"
                ),
                "path_id": path_id,
                "visit_index": visit_index,
                "node_id": node_id,
                "next_node_id": next_node_id,
                "next_hop": next_hop,
                "state": (
                    state
                ),
                "disposition": (
                    "delivered"
                    if next_node_id is None
                    else "forward"
                    if forwarding_capable
                    else "control_only"
                ),
                "reason_code": (
                    "destination_reached"
                    if next_node_id is None
                    else reason_code
                ),
                "traversal_state": {
                    "visit_index": visit_index,
                    "node_id": node_id,
                    "occurrence_index": sum(
                        1
                        for previous in node_sequence[:visit_index]
                        if previous == node_id
                    ),
                    "repeated": (
                        node_id in node_sequence[:visit_index]
                    ),
                    "cycle_key": (
                        f"{vrf_id}|{route_type}|"
                        f"{node_sequence[-1]}|{node_id}"
                    ),
                    "hop_index": visit_index,
                    "recursion_depth": 0,
                    "identity_complete": True,
                    "semantic_owner": "plugin",
                },
                "packet_operation": packet_operation,
                "route_context": {
                    "route_type": route_type,
                    "route_family": route_family,
                    "address_family": address_family,
                    "vrf_id": vrf_id,
                    "protocol": protocol,
                },
                "resolution_layers": list(
                    ROUTE_RESOLUTION_LAYERS_BY_TYPE[route_type]
                ),
                "forwarding_actions": _route_forwarding_actions(
                    route_type,
                    ordinal,
                    (
                        str(next_hop["next_hop_id"])
                        if next_hop is not None
                        else None
                    ),
                ),
                "table_visible": False,
                "traceable": False,
            }
        )
    return result


def _inventory_route_ordinal(
    node_id: str,
    context_id: str,
    destination_node_id: str,
) -> int:
    """Return the stable semantic ordinal for one inventory route plan."""

    for context_index, context in enumerate(
        route_inventory_contexts_for_node(node_id),
        start=1,
    ):
        if str(context["context_id"]) != context_id:
            continue
        destinations = [
            str(item)
            for item in context["eligible_node_ids"]
            if item != node_id
        ]
        try:
            destination_index = destinations.index(destination_node_id) + 1
        except ValueError as error:
            raise ValueError(
                "inventory destination is not eligible for context "
                f"{context_id!r}: {destination_node_id!r}"
            ) from error
        return (
            100
            + context_index * len(DEMO_NODES)
            + destination_index
        )
    raise ValueError(
        f"unknown inventory context for {node_id!r}: {context_id!r}"
    )


def _inventory_projection_rows(
    node: NodeSpec,
    *,
    config: AssemblyConfig,
) -> list[dict[str, Any]]:
    """Materialize non-scenario route inventory from the plug-in registry."""

    rows: list[dict[str, Any]] = []
    evidence_resource_id = (
        f"{node.node_id}/control-plane/IP_ROUTING/blue"
    )
    observed_at_ns = str(
        scale_generator.BASE_TIME_NS
        + 601_000_000_000
        + node.clock_offset_ns
    )
    for context in route_inventory_contexts_for_node(node.node_id):
        route_type = str(context["route_type"])
        route_family = str(context["route_family"])
        address_family = str(context["address_family"])
        vrf_id = str(context["vrf_id"])
        context_id = str(context["context_id"])
        destination_node_ids = [
            str(item)
            for item in context["eligible_node_ids"]
            if item != node.node_id
        ]
        for destination_node_id in destination_node_ids:
            sequence = _shortest_demo_node_path(
                node.node_id,
                destination_node_id,
            )
            first_next_hop = _connectivity_next_hop_declaration(
                route_type=route_type,
                declaration_id=context_id,
                node_id=node.node_id,
                next_node_id=sequence[1],
            )
            last_next_hop = _connectivity_next_hop_declaration(
                route_type=route_type,
                declaration_id=context_id,
                node_id=sequence[-2],
                next_node_id=destination_node_id,
            )
            ordinal = _inventory_route_ordinal(
                node.node_id,
                context_id,
                destination_node_id,
            )
            control_plane_only = (
                node.role == "provider_core"
                and route_type.startswith("evpn_")
            )
            installed = not control_plane_only
            next_hop_id = str(first_next_hop["next_hop_id"])
            path_id = (
                f"route-path:inventory:{context_id}:"
                f"{node.node_id}:{destination_node_id}"
            )
            trace_query = _route_trace_query(
                scenario_id="router-to-router",
                source_node_id=node.node_id,
                destination_node_id=destination_node_id,
                route_type=route_type,
                route_family=route_family,
                address_family=address_family,
                vrf_id=vrf_id,
            )
            trace_query["focus_path_id"] = path_id
            counterpart_trace_query = _route_trace_query(
                scenario_id="router-to-router",
                source_node_id=destination_node_id,
                destination_node_id=node.node_id,
                route_type=route_type,
                route_family=route_family,
                address_family=address_family,
                vrf_id=vrf_id,
            )
            counterpart_trace_query["focus_path_id"] = (
                f"route-path:inventory:{context_id}:"
                f"{destination_node_id}:{node.node_id}"
            )
            route_id = (
                f"{node.node_id}/route/inventory/{context_id}/"
                f"{destination_node_id}"
            )
            rows.append(
                {
                    "route_id": route_id,
                    "node_id": node.node_id,
                    "revision_id": node.revision_id,
                    "scenario_id": None,
                    "trace_scenario_id": "router-to-router",
                    "inventory_context_id": context_id,
                    "coverage_category": "inventory",
                    "observed_at_ns": observed_at_ns,
                    "destination": _inventory_destination_value(
                        route_type,
                        destination_node_id,
                        vrf_id,
                    ),
                    "destination_node_id": destination_node_id,
                    "node_sequence": list(sequence),
                    "path_id": path_id,
                    "vrf": vrf_id,
                    "route_type": route_type,
                    "route_family": route_family,
                    "address_family": address_family,
                    "protocol": str(context["protocol"]),
                    "decision": (
                        "control_plane_only"
                        if control_plane_only
                        else "active"
                    ),
                    "reason_code": (
                        "control_plane_only"
                        if control_plane_only
                        else "selected_forwarding"
                    ),
                    "install_state": (
                        "control_plane_only"
                        if control_plane_only
                        else "installed"
                    ),
                    "selected": installed,
                    "installed": installed,
                    "active": installed,
                    "backup": False,
                    "forwarding_capable": installed,
                    "traceable": True,
                    "table_visible": True,
                    "metric": (
                        10
                        + _stable_number(
                            config.seed,
                            node.node_id,
                            context_id,
                            destination_node_id,
                            modulo=90,
                        )
                    ),
                    "candidate_next_hops": [
                        {
                            **first_next_hop,
                            "via": (
                                f"adjacency:{node.node_id}:"
                                f"{sequence[1]}"
                            ),
                            "active": installed,
                            "weight": 1,
                        }
                    ],
                    "interface_resource_id": first_next_hop[
                        "interface_resource_id"
                    ],
                    "adjacency_resource_id": first_next_hop[
                        "adjacency_resource_id"
                    ],
                    "forwarding_actions": _route_forwarding_actions(
                        route_type,
                        ordinal,
                        next_hop_id,
                    ),
                    "resolution_phases": [
                        "local_lookup",
                        "next_hop",
                        "adjacency_egress",
                    ],
                    "resolution_text": (
                        f"The {node.node_id} example plug-in resolves "
                        f"{_inventory_destination_value(route_type, destination_node_id, vrf_id)} "
                        f"as {route_type} through {sequence[1]}."
                    ),
                    "terminal_resolution_text": (
                        f"The {destination_node_id} example plug-in resolves "
                        f"the local destination attachment for {route_type}."
                    ),
                    "trace_query": trace_query,
                    "counterpart_trace_query": counterpart_trace_query,
                    "trace_inputs": _route_input_variants(
                        trace_query=trace_query,
                        first_next_hop=first_next_hop,
                        last_next_hop=last_next_hop,
                    ),
                    "evidence_resource_ids": [evidence_resource_id],
                    "semantic_owner": "plugin",
                    **_route_semantic_payload(
                        route_type,
                        destination_node_id,
                        ordinal,
                    ),
                    **_route_label_payload(route_type, ordinal),
                }
            )
    return rows


def _inactive_candidate_inventory_rows(
    node: NodeSpec,
    *,
    config: AssemblyConfig,
) -> list[dict[str, Any]]:
    """Expose retained non-selected candidates as individual route rows."""

    rows: list[dict[str, Any]] = []
    evidence_resource_id = (
        f"{node.node_id}/control-plane/IP_ROUTING/blue"
    )
    for case_index, case in enumerate(COVERAGE_CASES):
        if "route_resolution" not in case.required_capabilities:
            continue
        semantics = scenario_semantics(case.case_id)
        directional_contexts = semantics.get(
            "directional_routing_contexts",
            {},
        )
        for candidate_index, candidate in enumerate(
            _case_candidate_paths(case),
        ):
            sequence = candidate["node_sequence"]
            if (
                candidate["selected_active"]
                or len(sequence) < 2
                or sequence[0] != node.node_id
            ):
                continue
            direction = str(candidate["direction"])
            selected_context = directional_contexts.get(
                direction,
                semantics,
            )
            counterpart_direction = (
                "reverse" if direction == "forward" else "forward"
            )
            counterpart_context = directional_contexts.get(
                counterpart_direction,
                semantics,
            )
            destination_node_id = (
                case.destination_node
                if direction == "forward"
                else case.source_node
            )
            route_type = str(selected_context["route_type"])
            route_family = str(selected_context["route_family"])
            address_family = str(selected_context["address_family"])
            vrf_id = str(selected_context["vrf_id"])
            next_hop = _next_hop_declaration(
                case,
                node_id=node.node_id,
                next_node_id=sequence[1],
            )
            state, disposition, reason_code = (
                _directional_decision_semantics(
                    case,
                    candidate,
                    0,
                )
            )
            backup = (
                candidate["alternative_state"] == "eligible_standby"
            )
            route_id = (
                f"{node.node_id}/route/candidate/{case.case_id}/"
                f"{candidate_index}"
            )
            trace_query = _route_trace_query(
                scenario_id=case.case_id,
                source_node_id=case.source_node,
                destination_node_id=case.destination_node,
                route_type=route_type,
                route_family=route_family,
                address_family=address_family,
                vrf_id=vrf_id,
                direction=direction,
            )
            trace_query["focus_path_id"] = candidate["path_id"]
            if candidate.get("steering_profile_id") is not None:
                trace_query["steering_profile_id"] = candidate[
                    "steering_profile_id"
                ]
            counterpart_candidate = next(
                item
                for item in _case_candidate_paths(case)
                if item["direction"] == counterpart_direction
                and item["selected_active"]
            )
            counterpart_trace_query = _route_trace_query(
                scenario_id=case.case_id,
                source_node_id=case.source_node,
                destination_node_id=case.destination_node,
                route_type=str(counterpart_context["route_type"]),
                route_family=str(counterpart_context["route_family"]),
                address_family=str(
                    counterpart_context["address_family"]
                ),
                vrf_id=str(counterpart_context["vrf_id"]),
                direction=counterpart_direction,
            )
            counterpart_trace_query["focus_path_id"] = (
                counterpart_candidate["path_id"]
            )
            if counterpart_candidate.get("steering_profile_id") is not None:
                counterpart_trace_query["steering_profile_id"] = (
                    counterpart_candidate["steering_profile_id"]
                )
            rows.append(
                {
                    "route_id": route_id,
                    "node_id": node.node_id,
                    "revision_id": node.revision_id,
                    "scenario_id": None,
                    "trace_scenario_id": case.case_id,
                    "trace_candidate_id": candidate["candidate_id"],
                    "path_id": candidate["path_id"],
                    "route_direction": direction,
                    "inventory_context_id": (
                        f"retained:{case.case_id}:"
                        f"{candidate['alternative_state']}"
                    ),
                    "coverage_category": "retained_candidate",
                    "observed_at_ns": str(
                        _coverage_timestamp(case_index)
                        + node.clock_offset_ns
                    ),
                    "destination": (
                        f"demo:{destination_node_id}:{case.case_id}"
                    ),
                    "destination_node_id": destination_node_id,
                    "node_sequence": list(sequence),
                    "vrf": vrf_id,
                    "route_type": route_type,
                    "route_family": route_family,
                    "address_family": address_family,
                    "protocol": ROUTE_PROTOCOL_BY_TYPE[route_type],
                    "decision": state,
                    "disposition": disposition,
                    "reason_code": reason_code,
                    "install_state": (
                        "eligible_not_installed"
                        if backup
                        else state
                    ),
                    "selected": False,
                    "installed": False,
                    "active": False,
                    "backup": backup,
                    "forwarding_capable": False,
                    "traceable": True,
                    "table_visible": True,
                    "metric": (
                        20
                        + _stable_number(
                            config.seed,
                            node.node_id,
                            case.case_id,
                            str(candidate_index),
                            modulo=80,
                        )
                    ),
                    "candidate_next_hops": [
                        {
                            **next_hop,
                            "via": (
                                f"adjacency:{node.node_id}:"
                                f"{sequence[1]}"
                            ),
                            "active": False,
                            "weight": 1,
                        }
                    ],
                    "forwarding_actions": _route_forwarding_actions(
                        route_type,
                        case_index,
                        str(next_hop["next_hop_id"]),
                    ),
                    "resolution_phases": [
                        "local_lookup",
                        "candidate_retention",
                    ],
                    "trace_query": trace_query,
                    "counterpart_trace_query": counterpart_trace_query,
                    "evidence_resource_ids": [evidence_resource_id],
                    "semantic_owner": "plugin",
                    **_route_semantic_payload(
                        route_type,
                        destination_node_id,
                        case_index,
                    ),
                    **_route_label_payload(route_type, case_index),
                }
            )
    return rows


def _inventory_continuation_rows(
    node: NodeSpec,
    *,
    config: AssemblyConfig,
) -> list[dict[str, Any]]:
    """Emit non-table per-hop evidence for every generated inventory route."""

    result: list[dict[str, Any]] = []
    for source_node in DEMO_NODES:
        for route in _inventory_projection_rows(
            source_node,
            config=config,
        ):
            ordinal = _inventory_route_ordinal(
                source_node.node_id,
                str(route["inventory_context_id"]),
                str(route["destination_node_id"]),
            )
            continuations = _per_hop_declarations(
                declaration_id=str(route["inventory_context_id"]),
                path_id=str(route["path_id"]),
                route_type=str(route["route_type"]),
                route_family=str(route["route_family"]),
                address_family=str(route["address_family"]),
                vrf_id=str(route["vrf"]),
                protocol=str(route["protocol"]),
                node_sequence=tuple(
                    str(item) for item in route["node_sequence"]
                ),
                state=str(route["decision"]),
                forwarding_capable=bool(route["forwarding_capable"]),
                reason_code=str(route["reason_code"]),
                ordinal=ordinal,
            )
            for continuation in continuations:
                if continuation["node_id"] != node.node_id:
                    continue
                next_hop = continuation["next_hop"]
                result.append(
                    {
                        "forwarding_id": (
                            f"{node.node_id}/forwarding/inventory/"
                            f"{route['inventory_context_id']}/"
                            f"{source_node.node_id}/"
                            f"{route['destination_node_id']}/"
                            f"{continuation['visit_index']}"
                        ),
                        "node_id": node.node_id,
                        "revision_id": node.revision_id,
                        "scenario_id": None,
                        "inventory_context_id": route[
                            "inventory_context_id"
                        ],
                        "coverage_category": "inventory_continuation",
                        "route_id": route["route_id"],
                        "path_id": route["path_id"],
                        "observed_at_ns": route["observed_at_ns"],
                        "action": continuation["disposition"],
                        "disposition": continuation["disposition"],
                        "reason_code": continuation["reason_code"],
                        "next_nodes": (
                            [continuation["next_node_id"]]
                            if continuation["next_node_id"] is not None
                            else []
                        ),
                        "next_hops": (
                            [next_hop]
                            if next_hop is not None
                            else []
                        ),
                        "continuation": continuation,
                        "node_sequence": route["node_sequence"],
                        "route_context": continuation[
                            "route_context"
                        ],
                        "resolution_layers": continuation[
                            "resolution_layers"
                        ],
                        "forwarding_actions": continuation[
                            "forwarding_actions"
                        ],
                        "resolution_text": (
                            f"The {node.node_id} example plug-in "
                            f"{continuation['packet_operation']} operation "
                            f"continues {route['route_type']} path "
                            f"{route['path_id']}."
                        ),
                        "evidence_resource_ids": route[
                            "evidence_resource_ids"
                        ],
                        "traceable": False,
                        "table_visible": False,
                        "semantic_owner": "plugin",
                    }
                )
    return result


def _projection_rows(
    node: NodeSpec,
    *,
    config: AssemblyConfig,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence_resource_id = f"{node.node_id}/control-plane/IP_ROUTING/blue"
    routes: list[dict[str, Any]] = []
    routes.extend(_inventory_projection_rows(node, config=config))
    routes.extend(_inactive_candidate_inventory_rows(node, config=config))
    forwarding: list[dict[str, Any]] = _inventory_continuation_rows(
        node,
        config=config,
    )
    for case_index, case in enumerate(COVERAGE_CASES):
        if "route_resolution" not in case.required_capabilities:
            continue
        cross_node_rule = scenario_semantics(case.case_id).get("cross_node_rule")
        boundary_observations = {
            direction: _source_boundary_observations(node, case.case_id, direction)
            if cross_node_rule else []
            for direction in ("forward", "reverse")
        }
        case_evidence_resource_ids = list(dict.fromkeys([
            evidence_resource_id,
            *(item["resource_id"] for items in boundary_observations.values() for item in items),
        ]))
        candidate_paths = _case_candidate_paths(case)
        node_occurrences = [
            (path, visit_index)
            for path in candidate_paths
            for visit_index, node_id in enumerate(path["node_sequence"])
            if node_id == node.node_id
        ]
        if not node_occurrences:
            continue
        selected_occurrence = next(
            (
                item
                for item in node_occurrences
                if item[0]["direction"] == "forward"
                and item[0]["selected_active"]
                and item[1] == 0
            ),
            next(
                (
                    item
                    for item in node_occurrences
                    if item[0]["selected_active"]
                    and item[1] == 0
                ),
                next(
                    (
                        item
                        for item in node_occurrences
                        if item[0]["direction"] == "forward"
                        and item[0]["selected_active"]
                    ),
                    node_occurrences[0],
                ),
            ),
        )
        selected_path, path_index = selected_occurrence
        directional_decisions: dict[str, list[dict[str, Any]]] = {
            "forward": [],
            "reverse": [],
        }
        for path, visit_index in node_occurrences:
            sequence = path["node_sequence"]
            next_node_id = (
                sequence[visit_index + 1]
                if visit_index + 1 < len(sequence)
                else None
            )
            next_hop = (
                _next_hop_declaration(
                    case,
                    node_id=node.node_id,
                    next_node_id=next_node_id,
                )
                if next_node_id is not None
                and next_node_id != node.node_id
                else None
            )
            (
                decision_state,
                decision_disposition,
                decision_reason_code,
            ) = (
                _directional_decision_semantics(
                    case,
                    path,
                    visit_index,
                )
            )
            directional_decisions[path["direction"]].append(
                {
                    "candidate_id": path["candidate_id"],
                    "path_id": path["path_id"],
                    "visit_index": visit_index,
                    "next_node_id": next_node_id,
                    "next_hop": next_hop,
                    "selected_active": path["selected_active"],
                    "primary": path["primary"],
                    "alternative_state": path["alternative_state"],
                    "perspective": path["perspective"],
                    "forwarding_capable": path[
                        "forwarding_capable"
                    ],
                    "route_context": path["route_context"],
                    "resolution_layers": path[
                        "resolution_layers"
                    ],
                    "encapsulation": path["encapsulation"],
                    "traversal_state": path[
                        "traversal_states"
                    ][visit_index],
                    "state": decision_state,
                    "disposition": decision_disposition,
                    "reason_code": decision_reason_code,
                    "forwarding_actions": _route_forwarding_actions(
                        str(path["route_context"]["route_type"]),
                        case_index,
                        (
                            str(next_hop["next_hop_id"])
                            if next_hop is not None
                            else None
                        ),
                    ),
                    "resolution_text": _directional_resolution_text(
                        case,
                        node_id=node.node_id,
                        candidate_id=str(path["candidate_id"]),
                        next_node_id=next_node_id,
                        disposition=decision_disposition,
                    ),
                }
            )
            if cross_node_rule:
                decision = directional_decisions[path["direction"]][-1]
                observations = boundary_observations[path["direction"]]
                decision["boundary_observations"] = observations
                # Do not synthesize label operations for a diagnostic lookup.
                decision["forwarding_actions"] = []
                decision["resolution_text"] += (
                    " Diagnostic node-local binding observations (not packet transitions): "
                    + "; ".join(
                        f"{item.get('field', 'unknown field')}={item.get('value', 'unknown')} from {item['resource_id']} "
                        f"at {item['observed_at_ns']} ns"
                        for item in observations
                    )
                    if observations else
                    " This node has no participant declaration for this diagnostic handoff."
                )
        selected_decision = next(
            item
            for item in directional_decisions[selected_path["direction"]]
            if item["candidate_id"] == selected_path["candidate_id"]
            and item["visit_index"] == path_index
        )
        state = str(selected_decision["state"])
        disposition = str(selected_decision["disposition"])
        reason_code = str(selected_decision["reason_code"])
        selected_hops_by_node: dict[str, dict[str, Any]] = {}
        active_selected_hops: set[str] = set()
        for decision in directional_decisions[
            selected_path["direction"]
        ]:
            next_hop = decision["next_hop"]
            if next_hop is None:
                continue
            next_node_id = str(next_hop["node_id"])
            previous = selected_hops_by_node.get(next_node_id)
            if previous is not None and previous != next_hop:
                raise ValueError(
                    f"{case.case_id}: conflicting generated bindings for "
                    f"{node.node_id} -> {next_node_id}"
                )
            selected_hops_by_node[next_node_id] = next_hop
            if (
                decision["selected_active"]
                and decision["disposition"] == "forward"
            ):
                active_selected_hops.add(next_node_id)
        next_hops = list(selected_hops_by_node.values())
        next_nodes = list(selected_hops_by_node)
        metric = (
            10
            + _stable_number(
                config.seed,
                node.node_id,
                case.case_id,
                modulo=90,
            )
        )
        semantics = scenario_semantics(case.case_id)
        declared_directional_contexts = semantics.get(
            "directional_routing_contexts",
            {},
        )
        forward_context = declared_directional_contexts.get(
            "forward",
            semantics,
        )
        reverse_context = declared_directional_contexts.get(
            "reverse",
            semantics,
        )
        route_direction = str(selected_path["direction"])
        selected_context = (
            forward_context
            if route_direction == "forward"
            else reverse_context
        )
        route_destination_node_id = (
            case.destination_node
            if route_direction == "forward"
            else case.source_node
        )
        route_type = str(selected_context["route_type"])
        route_family = str(selected_context["route_family"])
        address_family = str(selected_context["address_family"])
        vrf_id = str(selected_context["vrf_id"])
        traceable = bool(
            selected_path["selected_active"] and path_index == 0
        )
        path_id = str(selected_path["path_id"])
        trace_query = (
            _route_trace_query(
                scenario_id=case.case_id,
                source_node_id=case.source_node,
                destination_node_id=case.destination_node,
                route_type=route_type,
                route_family=route_family,
                address_family=address_family,
                vrf_id=vrf_id,
                direction=route_direction,
            )
            if traceable
            else {}
        )
        if traceable:
            trace_query["focus_path_id"] = path_id
            _apply_scenario_destination_identity(
                trace_query,
                semantics,
                direction=route_direction,
            )
        counterpart_direction = (
            "reverse" if route_direction == "forward" else "forward"
        )
        counterpart_context = (
            reverse_context
            if counterpart_direction == "reverse"
            else forward_context
        )
        counterpart_candidate = next(
            path
            for path in candidate_paths
            if path["direction"] == counterpart_direction
            and path["selected_active"]
        )
        counterpart_trace_query = _route_trace_query(
            scenario_id=case.case_id,
            source_node_id=case.source_node,
            destination_node_id=case.destination_node,
            route_type=str(counterpart_context["route_type"]),
            route_family=str(counterpart_context["route_family"]),
            address_family=str(
                counterpart_context["address_family"]
            ),
            vrf_id=str(counterpart_context["vrf_id"]),
            direction=counterpart_direction,
        )
        counterpart_trace_query["focus_path_id"] = (
            counterpart_candidate["path_id"]
        )
        route = {
            "route_id": f"{node.node_id}/route/{case.case_id}",
            "node_id": node.node_id,
            "revision_id": node.revision_id,
            "scenario_id": case.case_id,
            "coverage_category": case.category,
            "observed_at_ns": str(
                _coverage_timestamp(case_index) + node.clock_offset_ns
            ),
            "destination": (
                "203.0.113.0/24"
                if route_type == "connected"
                else (
                    f"demo:{route_destination_node_id}:"
                    f"{case.case_id}"
                )
            ),
            "destination_node_id": route_destination_node_id,
            "vrf": vrf_id,
            "route_type": route_type,
            "route_family": route_family,
            "address_family": address_family,
            "protocol": ROUTE_PROTOCOL_BY_TYPE[route_type],
            "route_direction": route_direction,
            "path_id": path_id,
            "trace_candidate_id": selected_path["candidate_id"],
            "decision": state,
            "reason_code": reason_code,
            "install_state": (
                "installed"
                if state == "active"
                else state
            ),
            "selected": state == "active",
            "installed": state == "active",
            "active": state == "active",
            "backup": False,
            "forwarding_capable": state == "active",
            "traceable": traceable,
            "table_visible": traceable,
            "trace_unavailable_reason": (
                None
                if traceable
                else (
                    "This row is per-node continuation evidence; "
                    "trace from a declared path origin."
                )
            ),
            "metric": metric,
            "candidate_next_hops": [
                {
                    **next_hop,
                    "via": (
                        f"adjacency:{node.node_id}:{next_hop['node_id']}"
                    ),
                    "active": (
                        str(next_hop["node_id"]) in active_selected_hops
                    ),
                }
                for next_hop in next_hops
            ],
            "forwarding_actions": _route_forwarding_actions(
                route_type,
                case_index,
                (
                    str(next_hops[0]["next_hop_id"])
                    if next_hops
                    else None
                ),
            ),
            "resolution_phases": [
                "local_lookup",
                "candidate_selection",
                "adjacency_egress",
            ],
            "node_sequence": list(selected_path["node_sequence"]),
            "trace_query": trace_query,
            "counterpart_trace_query": counterpart_trace_query,
            "directional_route_contexts": {
                "forward": dict(forward_context),
                "reverse": dict(reverse_context),
            },
            "evidence_resource_ids": case_evidence_resource_ids,
            "semantic_owner": "plugin",
            **_route_semantic_payload(
                route_type,
                route_destination_node_id,
                case_index,
            ),
            **_route_label_payload(route_type, case_index),
        }
        if cross_node_rule:
            for field_name in ("label_stack", "outgoing_label_stack", "encapsulation"):
                route.pop(field_name, None)
            route["forwarding_actions"] = []
            route["boundary_observations"] = selected_decision["boundary_observations"]
            route["resolution_text"] = selected_decision["resolution_text"]
        default_start = semantics.get("default_start")
        if default_start and traceable and route_direction == "forward":
            route["trace_query"]["starting_point"] = {
                "node_id": str(default_start).split(":", 1)[-1],
            }
        terminal_attachment = selected_path.get(
            "terminal_attachment"
        )
        if isinstance(terminal_attachment, Mapping):
            route["egress_interface_resource_id"] = (
                terminal_attachment["resource_id"]
            )
            route["connected_attachment"] = dict(
                terminal_attachment
            )
        routes.append(route)
        forwarding.append(
            {
                "forwarding_id": (
                    f"{node.node_id}/forwarding/{case.case_id}"
                ),
                "node_id": node.node_id,
                "revision_id": node.revision_id,
                "scenario_id": case.case_id,
                "coverage_category": case.category,
                "route_id": route["route_id"],
                "path_id": path_id,
                "trace_candidate_id": selected_path["candidate_id"],
                "route_direction": route_direction,
                "observed_at_ns": route["observed_at_ns"],
                "action": disposition,
                "reason_code": reason_code,
                "disposition": (
                    "delivered"
                    if not next_nodes and disposition == "forward"
                    else disposition
                ),
                "next_nodes": next_nodes,
                "next_hops": next_hops,
                "route_context": dict(selected_context),
                "resolution_layers": list(
                    ROUTE_RESOLUTION_LAYERS_BY_TYPE[route_type]
                ),
                "forwarding_actions": route[
                    "forwarding_actions"
                ],
                "traceable": False,
                "table_visible": False,
                "directional_decisions": directional_decisions,
                "directional_route_contexts": {
                    "forward": dict(forward_context),
                    "reverse": dict(reverse_context),
                },
                "resolution_text": route.get("resolution_text") or (
                    f"The {node.node_id} example plug-in resolves "
                    f"{route_type} for {case.case_id} "
                    + (
                        "toward "
                        + ", ".join(next_nodes)
                        if next_nodes
                        else "to the local destination attachment"
                    )
                    + "."
                ),
                "packet_profile_id": case.packet_profile_id,
                "expected_outcome": case.expected_outcome,
                "evidence_resource_ids": case_evidence_resource_ids,
                "forced_rule_allowed": (
                    case.case_id == "packet-forced-steering"
                ),
                "semantic_owner": "plugin",
            }
        )
    return routes, forwarding


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> tuple[int, str]:
    count = 0
    digest = hashlib.sha256()
    with path.open("wb") as output:
        for row in rows:
            line = _compact_json_line(row)
            output.write(line)
            digest.update(line)
            count += 1
    return count, digest.hexdigest()


def _write_plugin_projection(
    projection_dir: Path,
    node: NodeSpec,
    *,
    config: AssemblyConfig,
    topology: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    projection_dir.mkdir(parents=True, exist_ok=True)
    topology_projection = (
        topology
        if topology is not None
        else _topology_projection(node, config=config)
    )
    topology_path = (
        projection_dir
        / GENERATED_PROJECTION_POLICY.projection_member(
            "topology"
        ).relative_path
    )
    topology_content = _json_bytes(topology_projection)
    topology_path.write_bytes(topology_content)
    routes, forwarding = _projection_rows(node, config=config)
    routes_path = (
        projection_dir
        / GENERATED_PROJECTION_POLICY.projection_member(
            "routes"
        ).relative_path
    )
    route_count, route_sha = _write_jsonl(routes_path, routes)
    forwarding_path = (
        projection_dir
        / GENERATED_PROJECTION_POLICY.projection_member(
            "forwarding"
        ).relative_path
    )
    forwarding_count, forwarding_sha = _write_jsonl(
        forwarding_path,
        forwarding,
    )
    packet_cases = {
        "format_version": 1,
        "projection_policy_id": GENERATED_PROJECTION_POLICY.policy_id,
        "node_id": node.node_id,
        "revision_id": node.revision_id,
        "semantic_owner": "plugin",
        "cases": [
            GENERATED_PROJECTION_POLICY.packet_declaration(
                scenario_id=case.case_id,
                profile_id=case.packet_profile_id,
            )
            for case in COVERAGE_CASES
            if case.packet_profile_id
            and node.node_id in case.involved_nodes
        ],
    }
    packet_path = (
        projection_dir
        / GENERATED_PROJECTION_POLICY.projection_member(
            "packet_cases"
        ).relative_path
    )
    packet_content = _json_bytes(packet_cases)
    packet_path.write_bytes(packet_content)
    manifest = {
        **GENERATED_PROJECTION_POLICY.projection_manifest_identity(
            node_id=node.node_id,
            revision_id=node.revision_id,
        ),
        "files": {
            "topology": (
                GENERATED_PROJECTION_POLICY.projection_file_descriptor(
                    "topology",
                    records=len(topology_projection["claims"]),
                    sha256_hex=_sha256_bytes(topology_content),
                )
            ),
            "routes": (
                GENERATED_PROJECTION_POLICY.projection_file_descriptor(
                    "routes",
                    records=route_count,
                    sha256_hex=route_sha,
                )
            ),
            "forwarding": (
                GENERATED_PROJECTION_POLICY.projection_file_descriptor(
                    "forwarding",
                    records=forwarding_count,
                    sha256_hex=forwarding_sha,
                )
            ),
            "packet_cases": (
                GENERATED_PROJECTION_POLICY.projection_file_descriptor(
                    "packet_cases",
                    records=len(packet_cases["cases"]),
                    sha256_hex=_sha256_bytes(packet_content),
                )
            ),
        },
    }
    (projection_dir / MANIFEST_MEMBER_NAME).write_bytes(
        _json_bytes(manifest)
    )
    return manifest


def _enrich_container_manifests(
    raw_stage: Path,
    container_manifests: list[dict[str, Any]],
    node: NodeSpec,
    *,
    config: AssemblyConfig,
) -> None:
    for manifest in container_manifests:
        manifest.update(
            {
                "assembly_id": config.assembly_id,
                "node_id": node.node_id,
                "revision_id": node.revision_id,
                "capture_clock_domain": (
                    f"{node.node_id}:{manifest['capture_clock_domain']}"
                ),
            }
        )
        trace_dir = (
            raw_stage
            / "containers"
            / manifest["container_id"]
            / "trace"
        )
        # The node pack already contains the canonical normalized corpus once.
        # Raw container packs retain only CTF, status, and unmatched source
        # records; they never materialize a second normalized event corpus.
        retained_log_path = trace_dir / "system.log"
        retained_log_path.write_text(
            "\n".join(
                (
                    (
                        f"{scale_generator.BASE_TIME_NS + node.clock_offset_ns} "
                        f"INFO {node.node_id} {manifest['container_id']} "
                        "capture-start"
                    ),
                    (
                        f"{scale_generator.BASE_TIME_NS + 360_000_000_000 + node.clock_offset_ns} "
                        f"WARN {node.node_id} retained-unmatched "
                        "neighbor update could not be normalized"
                    ),
                    (
                        f"{scale_generator.BASE_TIME_NS + 600_000_000_000 + node.clock_offset_ns} "
                        f"INFO {node.node_id} {manifest['container_id']} "
                        "capture-complete"
                    ),
                    "",
                )
            ),
            encoding="utf-8",
            newline="\n",
        )
        manifest["trace"]["retained_non_ctf"] = {
            "path": "trace/system.log",
            "records": 3,
            "purpose": (
                "Exercise plug-in-owned parsing and generic unmatched-log lanes."
            ),
        }
        (
            raw_stage
            / "containers"
            / manifest["container_id"]
            / MANIFEST_MEMBER_NAME
        ).write_bytes(_json_bytes(manifest))


def _build_node_pack(
    output: Path,
    node: NodeSpec,
    *,
    config: AssemblyConfig,
    work_root: Path,
    scale_template_dir: Path,
    topology_projection: Mapping[str, Any],
    source_descriptor: Mapping[str, Any],
) -> dict[str, Any]:
    node_root = work_root / f"build-{node.node_id}"
    scale_dir = node_root / NORMALIZED_SCALE_DIRECTORY
    raw_stage = node_root / "raw"
    projection_dir = node_root / PROJECTION_ROOT
    normalized_manifest, scenario, _plugin_schema = _namespace_scale_fixture(
        scale_dir,
        node,
        assembly_id=config.assembly_id,
        source_descriptor=source_descriptor,
        template_dir=scale_template_dir,
    )
    state_change_records = int(
        normalized_manifest["events"]["state_change_records"]
    )
    if config.full_scale and state_change_records < MIN_STATE_CHANGE_EVENT_COUNT:
        raise RuntimeError(
            f"{node.node_id} has only {state_change_records:,} "
            "state-changing events"
        )

    row_counts, container_resource_counts = (
        packed_generator._write_status_files(
            raw_stage,
            scale_dir,
            scenario,
        )
    )
    event_counts, outcome_counts = packed_generator._write_event_files(
        raw_stage,
        scale_dir,
        scenario,
    )
    container_manifests = packed_generator._write_container_manifests(
        raw_stage,
        scenario,
        row_counts,
        container_resource_counts,
        event_counts,
        outcome_counts,
    )
    _enrich_container_manifests(
        raw_stage,
        container_manifests,
        node,
        config=config,
    )

    nested_paths: dict[str, Path] = {}
    nested_metadata: list[dict[str, Any]] = []
    for container in packed_generator.CONTAINERS:
        container_root = raw_stage / "containers" / container.container_id
        nested_path = node_root / f"{container.container_id}.tgz"
        nested_archive = write_deterministic_tgz(
            nested_path,
            packed_generator._directory_members(container_root),
        )
        nested_paths[container.container_id] = nested_path
        nested_metadata.append(
            {
                "container_id": container.container_id,
                "path": f"containers/{container.container_id}.tgz",
                "sha256": nested_archive.sha256,
                "compressed_size": nested_archive.size,
                "resource_rows": container_resource_counts.get(
                    container.container_id,
                    0,
                ),
                "event_records": event_counts.get(container.container_id, 0),
                "status_layout": container.status_layout,
                "table_count": len(container.tables),
            }
        )

    projection_manifest = _write_plugin_projection(
        projection_dir,
        node,
        config=config,
        topology=topology_projection,
    )
    pack_manifest = {
        "generator": packed_generator.PACK_GENERATOR,
        "format_version": 3,
        "package_id": f"{config.assembly_id}/{node.node_id}",
        "scenario_id": scenario["scenario_id"],
        "description": (
            "A deterministic node dump with raw CTF/status containers, one "
            "canonical normalized history, and example plug-in topology and "
            "forwarding projections derived from the same node model."
        ),
        "assembly_id": config.assembly_id,
        "node_id": node.node_id,
        "revision_id": node.revision_id,
        "identity_namespace": node.identity_namespace,
        "plugin": (
            GENERATED_PROJECTION_POLICY.archive_plugin_descriptor()
        ),
        "clock": {
            "domain": f"{node.node_id}:realtime",
            "offset_ns": node.clock_offset_ns,
            "uncertainty_ns": node.clock_uncertainty_ns,
        },
        "scale": scenario["scale"],
        "state_change_event_records": state_change_records,
        "resource_counts": scenario["resource_counts"],
        "phase_order": scenario["phase_order"],
        "containers": nested_metadata,
        "container_manifests": container_manifests,
        "normalized_scale_root": NORMALIZED_SCALE_DIRECTORY,
        "plugin_projection_root": PROJECTION_ROOT,
        "plugin_projection": projection_manifest,
        "source": {
            "authoring_scenario": {
                **source_descriptor
            },
            "scale_manifest_sha256": _sha256(
                scale_dir / MANIFEST_MEMBER_NAME
            ),
            "scale_generator_version": normalized_manifest[
                "generator_version"
            ],
            "seed": config.seed,
            "materialization": (
                GENERATED_PROJECTION_POLICY
                .generation_materialization_descriptor()
            ),
        },
    }
    pack_manifest_path = node_root / "pack-manifest.json"
    pack_manifest_path.write_bytes(_json_bytes(pack_manifest))

    members: dict[str, Path] = {
        NODE_PACK_MANIFEST_MEMBER: pack_manifest_path,
    }
    for container_id, nested_path in nested_paths.items():
        members[
            f"{NODE_PACK_ROOT}/containers/{container_id}.tgz"
        ] = nested_path
    for name in packed_generator.SCALE_FILES:
        members[
            f"{NORMALIZED_SCALE_PREFIX}/{name}"
        ] = scale_dir / name
    for projection_path in sorted(projection_dir.iterdir()):
        if projection_path.is_file():
            members[
                f"{NODE_PACK_ROOT}/{PROJECTION_ROOT}/{projection_path.name}"
            ] = projection_path
    node_archive = write_deterministic_tgz(output, members)
    metadata = {
        "node_id": node.node_id,
        "revision_id": node.revision_id,
        "label": node.label,
        "role": node.role,
        "site": node.site,
        "archive": f"nodes/{node.node_id}.tgz",
        "sha256": node_archive.sha256,
        "compressed_size": node_archive.size,
        "event_records": int(scenario["scale"]["events"]),
        "state_change_event_records": state_change_records,
        "resource_records": int(scenario["scale"]["resources"]),
        "identity_namespace": node.identity_namespace,
        "clock": {
            "offset_ns": node.clock_offset_ns,
            "uncertainty_ns": node.clock_uncertainty_ns,
        },
        "plugin_projection": {
            "root": PROJECTION_ROOT,
            "routes": projection_manifest["files"]["routes"]["records"],
            "topology_claims": projection_manifest["files"]["topology"][
                "records"
            ],
            "packet_cases": projection_manifest["files"]["packet_cases"][
                "records"
            ],
        },
    }
    resolved_node_root = node_root.resolve()
    resolved_work_root = work_root.resolve()
    if resolved_work_root not in resolved_node_root.parents:
        raise RuntimeError("refusing to clean an unexpected node staging path")
    shutil.rmtree(resolved_node_root)
    return metadata


def _lexical_absolute_path(path: Path) -> Path:
    """Return an absolute path without following its final symlink."""

    return Path(os.path.abspath(path.expanduser()))


def _hash_launch_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
) -> str:
    source = archive.extractfile(member)
    if source is None:
        raise RuntimeError(f"cannot read generated node pack: {member.name}")
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(1024 * 1024):
        size += len(chunk)
        if size > member.size:
            raise RuntimeError(
                f"generated member exceeds its declared size: {member.name}"
            )
        digest.update(chunk)
    if size != member.size:
        raise RuntimeError(
            f"generated member is truncated: {member.name}"
        )
    return digest.hexdigest()


def _read_bounded_launch_json(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
) -> tuple[dict[str, Any], bytes]:
    if (
        not member.isfile()
        or member.size < 1
        or member.size > _MAX_LAUNCH_METADATA_BYTES
    ):
        raise RuntimeError(
            f"launch metadata is not a bounded regular file: {member.name}"
        )
    source = archive.extractfile(member)
    if source is None:
        raise RuntimeError(f"cannot read launch metadata: {member.name}")
    try:
        content = source.read()
        if len(content) != member.size:
            raise RuntimeError(
                f"launch metadata is truncated: {member.name}"
            )
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"launch metadata is not valid JSON: {member.name}"
        ) from error
    if not isinstance(value, dict):
        raise RuntimeError(
            f"launch metadata must contain an object: {member.name}"
        )
    return value, content


def _is_canonical_generator_owned(path: Path) -> bool:
    """Return whether a regular path has a bounded exact owner manifest."""

    if path.is_symlink() or not path.is_file():
        return False
    try:
        if not 0 < path.stat().st_size <= _MAX_LAUNCH_ARCHIVE_BYTES:
            return False
        manifest: dict[str, Any] | None = None
        with tarfile.open(path, mode="r|gz") as archive:
            for index, member in enumerate(archive):
                if index >= 2:
                    return False
                _safe_member_name(member.name)
                if member.name not in {
                    ASSEMBLY_COVERAGE_MEMBER,
                    ASSEMBLY_MANIFEST_MEMBER,
                }:
                    return False
                if (
                    not member.isfile()
                    or member.size < 1
                    or member.size > _MAX_LAUNCH_METADATA_BYTES
                ):
                    return False
                value, _ = _read_bounded_launch_json(archive, member)
                if member.name == ASSEMBLY_MANIFEST_MEMBER:
                    manifest = value
                    break
    except (
        OSError,
        EOFError,
        RuntimeError,
        tarfile.TarError,
    ):
        return False
    if manifest is None:
        return False
    if (
        manifest.get("generator") != ASSEMBLY_GENERATOR
        or manifest.get("format_version") != ASSEMBLY_FORMAT_VERSION
        or manifest.get("assembly_id") != DEFAULT_ASSEMBLY_ID
    ):
        return False
    try:
        GENERATED_PROJECTION_POLICY.validate_archive_plugin_descriptor(
            manifest.get("plugin")
        )
    except ValueError:
        return False
    return True


def probe_demo_fixture_for_launch(path: Path) -> LaunchPreflightReport:
    """Verify that *path* has the cheap outer shape of the full demo corpus.

    A successful result means the launcher can confidently select the
    canonical full-scale, multi-node corpus rather than a one-node,
    developer, or outer-corrupt fixture.  It is intentionally cheaper than
    :func:`validate_demo_fixture`: nested node packs are hashed as opaque
    bytes, but their internal archives are not decoded.
    """

    candidate = _lexical_absolute_path(path)
    try:
        invalid_candidate = candidate.is_symlink() or not candidate.is_file()
        archive_size = candidate.stat().st_size if not invalid_candidate else 0
    except OSError as error:
        raise RuntimeError(
            f"cannot inspect generated assembly archive: {candidate}"
        ) from error
    if invalid_candidate:
        raise RuntimeError(
            f"expected a regular generated assembly archive: {candidate}"
        )
    if (
        archive_size < 1
        or archive_size > _MAX_LAUNCH_ARCHIVE_BYTES
    ):
        raise RuntimeError("generated assembly archive size is invalid")
    manifest: dict[str, Any] | None = None
    coverage: dict[str, Any] | None = None
    coverage_content: bytes | None = None
    member_sizes: dict[str, int] = {}
    member_sha256: dict[str, str] = {}
    cumulative_size = 0
    try:
        with tarfile.open(candidate, mode="r|gz") as archive:
            for member in archive:
                _safe_member_name(member.name)
                if member.name not in _CANONICAL_LAUNCH_MEMBERS:
                    raise RuntimeError(
                        f"unexpected assembly member: {member.name}"
                    )
                if member.name in member_sizes:
                    raise RuntimeError(
                        f"duplicate assembly member: {member.name}"
                    )
                if len(member_sizes) >= _MAX_LAUNCH_OUTER_MEMBERS:
                    raise RuntimeError(
                        "generated assembly has too many outer members"
                    )
                if not member.isfile():
                    raise RuntimeError(
                        f"assembly contains a non-file member: {member.name}"
                    )
                member_limit = (
                    _MAX_LAUNCH_METADATA_BYTES
                    if member.name
                    in {
                        ASSEMBLY_MANIFEST_MEMBER,
                        ASSEMBLY_COVERAGE_MEMBER,
                    }
                    else _MAX_LAUNCH_NODE_ARCHIVE_BYTES
                )
                if member.size < 1 or member.size > member_limit:
                    raise RuntimeError(
                        f"generated assembly member size is invalid: "
                        f"{member.name}"
                    )
                if (
                    cumulative_size
                    > _MAX_LAUNCH_UNCOMPRESSED_BYTES - member.size
                ):
                    raise RuntimeError(
                        "generated assembly exceeds its uncompressed limit"
                    )
                cumulative_size += member.size
                member_sizes[member.name] = member.size
                if member.name == ASSEMBLY_MANIFEST_MEMBER:
                    manifest, _ = _read_bounded_launch_json(archive, member)
                elif member.name == ASSEMBLY_COVERAGE_MEMBER:
                    coverage, coverage_content = _read_bounded_launch_json(
                        archive,
                        member,
                    )
                else:
                    member_sha256[member.name] = _hash_launch_member(
                        archive,
                        member,
                    )
    except (
        OSError,
        EOFError,
        tarfile.TarError,
    ) as error:
        raise RuntimeError(
            f"cannot read generated assembly archive: {candidate}"
        ) from error

    if manifest is None or coverage is None:
        raise RuntimeError(
            "generated assembly is missing manifest.json or coverage.json"
        )
    if manifest.get("generator") != ASSEMBLY_GENERATOR:
        raise RuntimeError("unsupported demo assembly generator")
    if manifest.get("format_version") != ASSEMBLY_FORMAT_VERSION:
        raise RuntimeError("unsupported demo assembly format version")
    if manifest.get("assembly_id") != DEFAULT_ASSEMBLY_ID:
        raise RuntimeError("launcher requires the canonical demo assembly")
    _validate_source_scenario_descriptor(manifest.get("source_scenario"))
    try:
        GENERATED_PROJECTION_POLICY.validate_archive_plugin_descriptor(
            manifest.get("plugin")
        )
    except ValueError as error:
        raise RuntimeError(str(error)) from error

    raw_nodes = manifest.get("nodes")
    if not isinstance(raw_nodes, list):
        raise RuntimeError("assembly manifest nodes must be an array")
    canonical_node_ids = tuple(node.node_id for node in DEMO_NODES)
    try:
        node_ids = tuple(str(item["node_id"]) for item in raw_nodes)
    except (KeyError, TypeError) as error:
        raise RuntimeError("assembly node metadata is malformed") from error
    if node_ids != canonical_node_ids:
        raise RuntimeError(
            "launcher requires every canonical generated node dump"
        )
    if len(node_ids) < 2:
        raise RuntimeError("launcher requires a multi-node generated assembly")
    if manifest.get("node_count") != len(node_ids):
        raise RuntimeError("assembly node_count is incorrect")
    if manifest.get("default_node_id") != canonical_node_ids[0]:
        raise RuntimeError("assembly default_node_id is not canonical")
    scale_policy = manifest.get("scale_policy")
    if (
        not isinstance(scale_policy, Mapping)
        or scale_policy.get("full_scale") is not True
    ):
        raise RuntimeError("launcher requires a full-scale generated assembly")

    expected_members = {
        ASSEMBLY_MANIFEST_MEMBER,
        ASSEMBLY_COVERAGE_MEMBER,
    }
    revision_ids: set[str] = set()
    for raw_node, expected_node in zip(raw_nodes, DEMO_NODES):
        expected_node_id = expected_node.node_id
        if not isinstance(raw_node, Mapping):
            raise RuntimeError("assembly node metadata must contain objects")
        try:
            revision_id = str(raw_node["revision_id"])
            logical_archive = str(raw_node["archive"])
            expected_size = int(raw_node["compressed_size"])
            expected_sha256 = str(raw_node["sha256"])
            event_count = int(raw_node["event_records"])
            state_change_count = int(
                raw_node["state_change_event_records"]
            )
            resource_count = int(raw_node["resource_records"])
        except (KeyError, TypeError, ValueError) as error:
            raise RuntimeError(
                f"incomplete generated node metadata: {expected_node_id}"
            ) from error
        if revision_id != expected_node.revision_id:
            raise RuntimeError(
                f"generated node revision is not canonical: "
                f"{expected_node_id}"
            )
        if revision_id in revision_ids:
            raise RuntimeError("assembly node revisions must be unique")
        revision_ids.add(revision_id)
        if logical_archive != f"nodes/{expected_node_id}.tgz":
            raise RuntimeError(
                f"generated node archive path is inconsistent: "
                f"{expected_node_id}"
            )
        if raw_node.get("identity_namespace") != f"{expected_node_id}/":
            raise RuntimeError(
                f"generated identity namespace is inconsistent: "
                f"{expected_node_id}"
            )
        if (
            expected_size < 1
            or expected_size > _MAX_LAUNCH_NODE_ARCHIVE_BYTES
        ):
            raise RuntimeError(
                f"generated node archive size is invalid: {expected_node_id}"
            )
        if not _SHA256_PATTERN.fullmatch(expected_sha256):
            raise RuntimeError(
                f"generated node digest is invalid: {expected_node_id}"
            )
        if event_count < MIN_EVENT_COUNT:
            raise RuntimeError(
                f"generated node event count is below demo scale: "
                f"{expected_node_id}"
            )
        if state_change_count < MIN_STATE_CHANGE_EVENT_COUNT:
            raise RuntimeError(
                f"generated state-change count is below demo scale: "
                f"{expected_node_id}"
            )
        if not MIN_RESOURCE_COUNT <= resource_count <= MAX_RESOURCE_COUNT:
            raise RuntimeError(
                f"generated node resource count is outside demo scale: "
                f"{expected_node_id}"
            )
        member_name = f"{ASSEMBLY_ROOT}/{logical_archive}"
        expected_members.add(member_name)
        member_size = member_sizes.get(member_name)
        if (
            member_size is None
            or member_size != expected_size
        ):
            raise RuntimeError(
                f"generated node pack is missing or has the wrong size: "
                f"{expected_node_id}"
            )
        if member_sha256.get(member_name) != expected_sha256:
            raise RuntimeError(
                f"generated node pack checksum mismatch: {expected_node_id}"
            )

    if set(member_sizes) != expected_members:
        raise RuntimeError("generated assembly member set is inconsistent")

    try:
        GENERATED_PROJECTION_POLICY.validate_coverage_registry(coverage)
    except ValueError as error:
        raise RuntimeError(str(error)) from error
    if coverage.get("assembly_id") != DEFAULT_ASSEMBLY_ID:
        raise RuntimeError("coverage registry assembly identity mismatch")
    cases = coverage.get("cases")
    if not isinstance(cases, list):
        raise RuntimeError("coverage cases must be an array")
    expected_case_ids = {case.case_id for case in COVERAGE_CASES}
    actual_case_ids = {str(case.get("case_id")) for case in cases}
    if (
        len(cases) != len(actual_case_ids)
        or actual_case_ids != expected_case_ids
        or coverage.get("case_count") != len(cases)
        or coverage.get("complete") is not True
    ):
        raise RuntimeError(
            "launcher requires complete canonical coverage metadata"
        )
    coverage_descriptor = manifest.get("coverage")
    if not isinstance(coverage_descriptor, Mapping):
        raise RuntimeError("assembly coverage descriptor is missing")
    coverage_sha256 = str(coverage_descriptor.get("sha256", ""))
    if (
        coverage_descriptor.get("path") != COVERAGE_MEMBER_NAME
        or coverage_descriptor.get("cases") != len(cases)
        or coverage_descriptor.get("complete") is not True
        or coverage_content is None
        or not _SHA256_PATTERN.fullmatch(coverage_sha256)
        or _sha256_bytes(coverage_content) != coverage_sha256
    ):
        raise RuntimeError("assembly coverage descriptor is inconsistent")

    return LaunchPreflightReport(
        assembly_id=DEFAULT_ASSEMBLY_ID,
        node_ids=node_ids,
        coverage_case_count=len(cases),
        full_scale=True,
    )


def _assert_replaceable_output(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"refusing symbolic-link output: {path}")
    if not path.exists():
        return
    if not path.is_file():
        raise RuntimeError(f"assembly output is not a regular file: {path}")
    if not _is_canonical_generator_owned(path):
        raise RuntimeError(f"refusing to replace an unowned assembly: {path}")


def _publish_archive_atomically(
    source: Path,
    output: Path,
    *,
    expected_sha256: str,
    before_replace: Callable[[], None] | None = None,
) -> None:
    """Copy a validated archive beside its destination, then rename it."""

    descriptor, raw_name = tempfile.mkstemp(
        prefix=f".{output.name}.publish-",
        suffix=".tmp",
        dir=output.parent,
    )
    publish_path = Path(raw_name)
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "wb") as destination:
            with source.open("rb") as content:
                for chunk in iter(lambda: content.read(1024 * 1024), b""):
                    destination.write(chunk)
                    digest.update(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        if digest.hexdigest() != expected_sha256:
            raise RuntimeError("validated assembly changed before publication")
        _assert_replaceable_output(output)
        if before_replace is not None:
            before_replace()
        publish_path.replace(output)
    finally:
        publish_path.unlink(missing_ok=True)


def _build_demo_fixture_with_report(
    output: Path,
    *,
    config: AssemblyConfig | None = None,
    deep_validate: bool = False,
) -> tuple[Path, ValidationReport]:
    """Generate one outer TGZ while retaining only one node in memory at a time."""

    selected_config = config or AssemblyConfig()
    source_snapshot = _capture_source_scenario_descriptor()
    output = _lexical_absolute_path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    _assert_replaceable_output(output)
    lock = output.parent / f".{output.name}.router-dump-analyzer.lock"
    lock_fd: int | None = None
    stage: Path | None = None
    stage_parent = Path(tempfile.gettempdir()).resolve()
    try:
        try:
            lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as error:
            raise RuntimeError(
                f"another generator is using output: {output}"
            ) from error
        stage = Path(
            tempfile.mkdtemp(
                prefix=".rda-demo-assembly-",
            )
        ).resolve()
        if stage.parent != stage_parent:
            raise RuntimeError("assembly stage is outside the system temp root")
        work_root = stage / "work"
        node_pack_root = stage / "node-packs"
        work_root.mkdir()
        node_pack_root.mkdir()
        scale_template_dir = stage / "scale-template"
        scale_generator.generate_scale_tree(
            scale_template_dir,
            selected_config.events_per_node,
            selected_config.resources_per_node,
        )
        topology_projections = {
            node.node_id: _topology_projection(
                node,
                config=selected_config,
            )
            for node in selected_config.nodes
        }
        coverage = build_coverage(
            selected_config,
            _topology_projections=topology_projections,
        )
        coverage_path = stage / COVERAGE_MEMBER_NAME
        coverage_path.write_bytes(_json_bytes(coverage))

        def build_node(node: NodeSpec) -> dict[str, Any]:
            node_pack = node_pack_root / f"{node.node_id}.tgz"
            return _build_node_pack(
                node_pack,
                node,
                config=selected_config,
                work_root=work_root,
                scale_template_dir=scale_template_dir,
                topology_projection=topology_projections[node.node_id],
                source_descriptor=source_snapshot,
            )

        worker_count = _node_build_worker_count(selected_config)
        if worker_count == 1:
            nodes = [build_node(node) for node in selected_config.nodes]
        else:
            # Pydantic parsing, zlib, and bulk file IO dominate this stage and
            # release the GIL. Threads avoid Windows process-spawn recursion,
            # while ``map`` retains catalog order for deterministic manifests.
            with ThreadPoolExecutor(
                max_workers=worker_count,
                thread_name_prefix="rda-node-pack",
            ) as executor:
                nodes = list(executor.map(build_node, selected_config.nodes))
        manifest = {
            "generator": ASSEMBLY_GENERATOR,
            "format_version": ASSEMBLY_FORMAT_VERSION,
            "assembly_id": selected_config.assembly_id,
            "seed": selected_config.seed,
            "source_scenario": {
                **source_snapshot
            },
            "plugin": (
                GENERATED_PROJECTION_POLICY.archive_plugin_descriptor()
            ),
            "default_node_id": selected_config.selected_default_node_id,
            "scale_policy": {
                "minimum_events_per_node": MIN_EVENT_COUNT,
                "minimum_state_change_events_per_node": (
                    MIN_STATE_CHANGE_EVENT_COUNT
                ),
                "minimum_resources_per_node": MIN_RESOURCE_COUNT,
                "maximum_resources_per_node": MAX_RESOURCE_COUNT,
                "full_scale": selected_config.full_scale,
            },
            "nodes": nodes,
            "node_count": len(nodes),
            "coverage": {
                "path": "coverage.json",
                "sha256": _sha256(coverage_path),
                "cases": len(coverage["cases"]),
                "complete": coverage["complete"],
            },
        }
        manifest_path = stage / MANIFEST_MEMBER_NAME
        manifest_path.write_bytes(_json_bytes(manifest))
        staged_archive = stage / DEFAULT_ASSEMBLY_NAME
        outer_members = {
            ASSEMBLY_MANIFEST_MEMBER: manifest_path,
            ASSEMBLY_COVERAGE_MEMBER: coverage_path,
            **{
                f"{ASSEMBLY_ROOT}/nodes/{node['node_id']}.tgz": (
                    node_pack_root / f"{node['node_id']}.tgz"
                )
                for node in nodes
            },
        }
        write_deterministic_tgz(
            staged_archive,
            outer_members,
        )
        report = validate_demo_fixture(
            staged_archive,
            require_full_scale=selected_config.full_scale,
            deep=deep_validate,
        )
        _publish_archive_atomically(
            staged_archive,
            output,
            expected_sha256=report.archive_sha256,
            before_replace=lambda: _assert_source_snapshot_current(
                source_snapshot
            ),
        )
        return output, report
    finally:
        if stage is not None and stage.exists():
            resolved_stage = stage.resolve()
            if resolved_stage.parent != stage_parent:
                raise RuntimeError("refusing to clean an unexpected assembly stage")
            shutil.rmtree(resolved_stage)
        if lock_fd is not None:
            os.close(lock_fd)
            lock.unlink(missing_ok=True)


def build_demo_fixture(
    output: Path,
    *,
    config: AssemblyConfig | None = None,
) -> Path:
    """Generate and internally validate one deterministic demo assembly."""

    built_output, _ = _build_demo_fixture_with_report(
        output,
        config=config,
        deep_validate=False,
    )
    return built_output


def _path_lexically_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _generated_recovery_path(path: Path) -> Path:
    suffix = "".join(path.suffixes)
    base_name = (
        path.name[: -len(suffix)]
        if suffix
        else path.name
    )
    return path.with_name(
        f"{base_name}.generated{suffix}"
    )


def _output_ownership_state(path: Path) -> str:
    if not _path_lexically_exists(path):
        return "absent"
    if path.is_symlink() or not path.is_file():
        return "preserve"
    return (
        "owned-generated"
        if _is_canonical_generator_owned(path)
        else "preserve"
    )


def ensure_demo_fixture_for_launch(
    output: Path,
    *,
    force_rebuild: bool = False,
) -> EnsureLaunchReport:
    """Return a canonical launch input without mutating unknown paths.

    Missing or generator-owned inputs can be generated in place.  An unowned,
    malformed, symlink, or non-regular preferred path is preserved byte-for-
    byte and a fixed ``*.generated.tgz`` sibling is used instead.  The recovery
    path itself is replaced only when it has the exact bounded generator owner
    manifest; otherwise preparation fails closed.
    """

    output = _lexical_absolute_path(output)
    rejection_reason: str | None = None
    try:
        existing = probe_demo_fixture_for_launch(output)
    except RuntimeError as error:
        rejection_reason = str(error)
    else:
        if not force_rebuild:
            return EnsureLaunchReport(
                preferred_path=output,
                output_path=output,
                preflight=existing,
                generated=False,
            )

    preferred_state = _output_ownership_state(output)
    preserve_preferred = preferred_state == "preserve"
    selected_output = (
        _generated_recovery_path(output)
        if preserve_preferred
        else output
    )

    if preserve_preferred:
        try:
            recovery_preflight = probe_demo_fixture_for_launch(
                selected_output
            )
        except RuntimeError:
            recovery_preflight = None
        if recovery_preflight is not None and not force_rebuild:
            return EnsureLaunchReport(
                preferred_path=output,
                output_path=selected_output,
                preflight=recovery_preflight,
                generated=False,
                used_recovery_path=True,
                preserved_preferred=True,
                rejection_reason=rejection_reason,
            )

    selected_state = _output_ownership_state(selected_output)
    if selected_state == "preserve":
        raise RuntimeError(
            "refusing to replace unsafe recovery fixture path: "
            f"{selected_output}"
        )

    _build_demo_fixture_with_report(
        selected_output,
        config=AssemblyConfig(),
        deep_validate=False,
    )
    preflight = probe_demo_fixture_for_launch(selected_output)

    return EnsureLaunchReport(
        preferred_path=output,
        output_path=selected_output,
        preflight=preflight,
        generated=True,
        used_recovery_path=preserve_preferred,
        preserved_preferred=preserve_preferred,
        rejection_reason=rejection_reason,
    )


def _copy_member_to_temp(
    source: Any,
    *,
    directory: Path,
    suffix: str,
) -> tuple[Path, str, int]:
    descriptor, raw_name = tempfile.mkstemp(
        prefix=".rda-validate-",
        suffix=suffix,
        dir=directory,
    )
    os.close(descriptor)
    path = Path(raw_name)
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("wb") as output:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path, digest.hexdigest(), size


@dataclass(frozen=True, slots=True)
class _JsonlScan:
    records: int
    sha256: str
    state_change_records: int


@dataclass(frozen=True, slots=True)
class _ResourceTableScan:
    records: int
    sha256: str


def _scan_namespaced_jsonl(
    source: Any,
    *,
    node_id: str,
    id_field: str,
) -> _JsonlScan:
    # Keep the generator package importable for manifest/catalog inspection
    # without importing optional runtime dependencies. Deep validation is the
    # only path that needs the accelerated strict JSON decoder.
    from pydantic_core import from_json as strict_json_loads

    digest = hashlib.sha256()
    count = 0
    state_change_count = 0
    identifiers: set[str] = set()
    prefix = f"{node_id}/"
    for line in source:
        digest.update(line)
        if not line.strip():
            continue
        record = strict_json_loads(line)
        if not isinstance(record, Mapping):
            raise RuntimeError(
                f"{node_id} {id_field} record must be an object"
            )
        identifier = str(record.get(id_field, ""))
        if not identifier.startswith(prefix):
            raise RuntimeError(
                f"{node_id} {id_field} is not namespaced: {identifier!r}"
            )
        if identifier in identifiers:
            raise RuntimeError(
                f"{node_id} has duplicate {id_field}: {identifier!r}"
            )
        identifiers.add(identifier)
        state_change_count += bool(record.get("state_changed", False))
        count += 1
    return _JsonlScan(
        records=count,
        sha256=digest.hexdigest(),
        state_change_records=state_change_count,
    )


def _assert_jsonl_scan(
    scan: _JsonlScan,
    *,
    node_id: str,
    id_field: str,
    expected_records: int,
    expected_sha256: str,
    expected_state_change_records: int | None = None,
) -> None:
    count = scan.records
    if count != expected_records:
        raise RuntimeError(
            f"{node_id} {id_field} count mismatch: "
            f"{count} != {expected_records}"
        )
    if scan.sha256 != expected_sha256:
        raise RuntimeError(f"{node_id} {id_field} checksum mismatch")
    if (
        expected_state_change_records is not None
        and scan.state_change_records != expected_state_change_records
    ):
        raise RuntimeError(
            f"{node_id} state-changing event count mismatch: "
            f"{scan.state_change_records} != {expected_state_change_records}"
        )


def _scan_namespaced_resource_table(
    source: Any,
    *,
    node_id: str,
) -> _ResourceTableScan:
    digest = hashlib.sha256()
    prefix = f"{node_id}/"
    header_line = source.readline()
    digest.update(header_line)
    header = header_line.decode("utf-8").rstrip("\r\n").split("|")
    try:
        resource_index = header.index("RESOURCE_ID")
    except ValueError as error:
        raise RuntimeError("normalized resource table lacks RESOURCE_ID") from error
    count = 0
    resource_ids: set[str] = set()
    for line in source:
        digest.update(line)
        if not line.strip():
            continue
        values = line.decode("utf-8").rstrip("\r\n").split("|")
        if len(values) != len(header):
            raise RuntimeError(
                f"{node_id} normalized resource table has a malformed row"
            )
        if not values[resource_index].startswith(prefix):
            raise RuntimeError(
                f"{node_id} resource ID is not namespaced: "
                f"{values[resource_index]!r}"
            )
        if values[resource_index] in resource_ids:
            raise RuntimeError(
                f"{node_id} has duplicate resource ID: "
                f"{values[resource_index]!r}"
            )
        resource_ids.add(values[resource_index])
        count += 1
    return _ResourceTableScan(
        records=count,
        sha256=digest.hexdigest(),
    )


def _assert_resource_table_scan(
    scan: _ResourceTableScan,
    *,
    node_id: str,
    expected_records: int,
    expected_sha256: str,
) -> None:
    count = scan.records
    if count != expected_records:
        raise RuntimeError(
            f"{node_id} resource count mismatch: {count} != {expected_records}"
        )
    if scan.sha256 != expected_sha256:
        raise RuntimeError(f"{node_id} resource table checksum mismatch")


def _validate_projection_member(
    source: Any,
    *,
    node_id: str,
    revision_id: str,
    descriptor: Mapping[str, Any],
    projection_name: str,
) -> None:
    content = source.read()
    if _sha256_bytes(content) != descriptor["sha256"]:
        raise RuntimeError(
            f"{node_id} {projection_name} projection checksum mismatch"
        )
    if projection_name in {"routes", "forwarding"}:
        rows = [
            json.loads(line)
            for line in content.splitlines()
            if line.strip()
        ]
        if len(rows) != int(descriptor["records"]):
            raise RuntimeError(
                f"{node_id} {projection_name} projection count mismatch"
            )
        identifier_key = (
            "route_id" if projection_name == "routes" else "forwarding_id"
        )
        for row in rows:
            if not isinstance(row, Mapping):
                raise RuntimeError(
                    f"{node_id} {projection_name} row must be an object"
                )
            if row.get("node_id") != node_id:
                raise RuntimeError(
                    f"{node_id} {projection_name} row has wrong node identity"
                )
            if row.get("revision_id") != revision_id:
                raise RuntimeError(
                    f"{node_id} {projection_name} row has wrong revision"
                )
            if not str(row.get(identifier_key, "")).startswith(f"{node_id}/"):
                raise RuntimeError(
                    f"{node_id} {projection_name} row ID is not namespaced"
                )
            if projection_name == "forwarding":
                try:
                    GENERATED_PROJECTION_POLICY.validate_forwarding_row(
                        row,
                        node_id=node_id,
                        revision_id=revision_id,
                    )
                except ValueError as error:
                    raise RuntimeError(str(error)) from error
        return
    value = json.loads(content)
    if value.get("node_id") != node_id:
        raise RuntimeError(
            f"{node_id} {projection_name} projection has wrong node identity"
        )
    if value.get("revision_id") != revision_id:
        raise RuntimeError(
            f"{node_id} {projection_name} projection has wrong revision"
        )
    records = (
        value.get("claims", [])
        if projection_name == "topology"
        else value.get("cases", [])
    )
    if len(records) != int(descriptor["records"]):
        raise RuntimeError(
            f"{node_id} {projection_name} projection count mismatch"
        )


def _stream_digest_and_size(source: Any) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _read_json_object(source: Any, *, member_name: str) -> tuple[dict[str, Any], bytes]:
    content = source.read()
    value = json.loads(content)
    if not isinstance(value, dict):
        raise RuntimeError(f"node member is not a JSON object: {member_name}")
    return value, content


def _drain_member(source: Any) -> None:
    for _ in iter(lambda: source.read(1024 * 1024), b""):
        pass


def _validate_node_pack(
    path: Path,
    metadata: Mapping[str, Any],
    *,
    require_full_scale: bool,
    deep: bool,
) -> None:
    node_id = str(metadata["node_id"])
    expected_pack_manifest_name = NODE_PACK_MANIFEST_MEMBER
    expected_normalized_manifest_name = NORMALIZED_SCALE_MANIFEST_MEMBER
    expected_generated_schema_name = (
        f"{NORMALIZED_SCALE_PREFIX}/plugin-schema.json"
    )
    expected_projection_manifest_name = (
        f"{NODE_PACK_ROOT}/{PROJECTION_ROOT}/manifest.json"
    )
    normalized_root = NORMALIZED_SCALE_PREFIX
    projection_root = f"{NODE_PACK_ROOT}/{PROJECTION_ROOT}"
    resource_member_name = f"{normalized_root}/resources.table.txt"
    deep_targets = {
        f"{normalized_root}/events.jsonl": (
            "event_uid",
            "events",
            True,
        ),
        f"{normalized_root}/relationships.jsonl": (
            "relationship_id",
            "relationships",
            False,
        ),
        f"{normalized_root}/{HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME}": (
            "relationship_id",
            "high_fanout_relationships",
            False,
        ),
        f"{normalized_root}/{RELATIONSHIP_MUTATIONS_MEMBER_NAME}": (
            "mutation_id",
            "relationship_mutations",
            False,
        ),
    }
    seen: set[str] = set()
    container_scans: dict[str, tuple[str, int]] = {}
    jsonl_scans: dict[str, _JsonlScan] = {}
    resource_scan: _ResourceTableScan | None = None
    validated_projection_members: set[str] = set()
    projection_descriptors: dict[
        str,
        tuple[str, Mapping[str, Any]],
    ] = {}
    pack_manifest: dict[str, Any] | None = None
    normalized_manifest: dict[str, Any] | None = None
    projection_manifest: dict[str, Any] | None = None
    generated_schema: dict[str, Any] | None = None
    normalized_manifest_content: bytes | None = None
    with tarfile.open(path, mode="r|gz") as archive:
        for member in archive:
            _safe_member_name(member.name)
            if member.name in seen:
                raise RuntimeError(
                    f"duplicate node archive member: {member.name}"
                )
            seen.add(member.name)
            if not member.isfile():
                raise RuntimeError(
                    f"node archive has a non-file member: {member.name}"
                )
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"cannot read node member: {member.name}")

            if member.name == expected_pack_manifest_name:
                pack_manifest, _ = _read_json_object(
                    source,
                    member_name=member.name,
                )
                embedded_projection = pack_manifest.get("plugin_projection")
                if not isinstance(embedded_projection, Mapping):
                    raise RuntimeError(
                        f"{node_id} pack lacks an embedded projection manifest"
                    )
                files = embedded_projection.get("files")
                if not isinstance(files, Mapping):
                    raise RuntimeError(
                        f"{node_id} projection file registry is invalid"
                    )
                for projection_name, descriptor in files.items():
                    if not isinstance(descriptor, Mapping):
                        raise RuntimeError(
                            f"{node_id} projection descriptor is invalid"
                        )
                    member_name = (
                        f"{projection_root}/{descriptor['path']}"
                    )
                    projection_descriptors[member_name] = (
                        str(projection_name),
                        descriptor,
                    )
                continue

            if member.name == expected_normalized_manifest_name:
                (
                    normalized_manifest,
                    normalized_manifest_content,
                ) = _read_json_object(
                    source,
                    member_name=member.name,
                )
                continue

            if member.name == expected_projection_manifest_name:
                projection_manifest, _ = _read_json_object(
                    source,
                    member_name=member.name,
                )
                continue

            if member.name == expected_generated_schema_name:
                generated_schema, _ = _read_json_object(
                    source,
                    member_name=member.name,
                )
                continue

            if member.name.startswith(f"{NODE_PACK_ROOT}/containers/"):
                container_scans[member.name] = _stream_digest_and_size(source)
                continue

            if deep and member.name in deep_targets:
                id_field, _, _ = deep_targets[member.name]
                jsonl_scans[member.name] = _scan_namespaced_jsonl(
                    source,
                    node_id=node_id,
                    id_field=id_field,
                )
                continue

            if deep and member.name == resource_member_name:
                resource_scan = _scan_namespaced_resource_table(
                    source,
                    node_id=node_id,
                )
                continue

            projection_descriptor = projection_descriptors.get(member.name)
            if projection_descriptor is not None:
                projection_name, descriptor = projection_descriptor
                _validate_projection_member(
                    source,
                    node_id=node_id,
                    revision_id=str(metadata["revision_id"]),
                    descriptor=descriptor,
                    projection_name=projection_name,
                )
                validated_projection_members.add(member.name)
                continue

            if (
                member.name.startswith(f"{projection_root}/")
                and pack_manifest is None
            ):
                raise RuntimeError(
                    f"{node_id} projection data precedes its pack manifest"
                )
            _drain_member(source)

    member_names = seen
    for required_name, value in (
        (expected_pack_manifest_name, pack_manifest),
        (expected_normalized_manifest_name, normalized_manifest),
        (expected_projection_manifest_name, projection_manifest),
        (expected_generated_schema_name, generated_schema),
    ):
        if value is None:
            raise RuntimeError(f"{node_id} node pack lacks {required_name}")
    assert pack_manifest is not None
    assert normalized_manifest is not None
    assert projection_manifest is not None
    assert generated_schema is not None
    assert normalized_manifest_content is not None

    if (
        _sha256_bytes(normalized_manifest_content)
        != pack_manifest["source"]["scale_manifest_sha256"]
    ):
        raise RuntimeError(f"{node_id} normalized manifest checksum mismatch")
    _validate_source_scenario_descriptor(
        pack_manifest.get("source", {}).get("authoring_scenario")
    )
    if pack_manifest.get("plugin_projection") != projection_manifest:
        raise RuntimeError(f"{node_id} pack/projection manifests disagree")

    expected_projection_members = {
        f"{projection_root}/{descriptor['path']}"
        for descriptor in projection_manifest.get("files", {}).values()
    }
    expected_container_members = {
        f"{NODE_PACK_ROOT}/{container['path']}"
        for container in pack_manifest.get("containers", [])
    }
    expected_members = {
        expected_pack_manifest_name,
        *{
            f"{normalized_root}/{name}"
            for name in packed_generator.SCALE_FILES
        },
        *expected_container_members,
        *expected_projection_members,
        expected_projection_manifest_name,
    }
    if member_names != expected_members:
        missing = sorted(expected_members - member_names)
        extra = sorted(member_names - expected_members)
        raise RuntimeError(
            f"{node_id} node member registry mismatch; "
            f"missing={missing}, extra={extra}"
        )

    for container in pack_manifest.get("containers", []):
        member_name = f"{NODE_PACK_ROOT}/{container['path']}"
        digest, size = container_scans[member_name]
        if digest != container["sha256"]:
            raise RuntimeError(
                f"{node_id} raw container checksum mismatch: {member_name}"
            )
        if size != int(container["compressed_size"]):
            raise RuntimeError(
                f"{node_id} raw container size mismatch: {member_name}"
            )
    if validated_projection_members != expected_projection_members:
        missing = sorted(
            expected_projection_members - validated_projection_members
        )
        raise RuntimeError(
            f"{node_id} projection members were not validated: {missing}"
        )

    if deep:
        for member_name, (
            id_field,
            manifest_key,
            checks_state_changes,
        ) in deep_targets.items():
            descriptor = normalized_manifest[manifest_key]
            _assert_jsonl_scan(
                jsonl_scans[member_name],
                node_id=node_id,
                id_field=id_field,
                expected_records=int(descriptor["records"]),
                expected_sha256=str(descriptor["sha256"]),
                expected_state_change_records=(
                    int(pack_manifest["state_change_event_records"])
                    if checks_state_changes
                    else None
                ),
            )
        if resource_scan is None:
            raise RuntimeError(
                f"cannot read normalized member: {resource_member_name}"
            )
        _assert_resource_table_scan(
            resource_scan,
            node_id=node_id,
            expected_records=int(
                normalized_manifest["resources"]["records"]
            ),
            expected_sha256=str(
                normalized_manifest["resources"]["sha256"]
            ),
        )

    if pack_manifest.get("generator") != packed_generator.PACK_GENERATOR:
        raise RuntimeError(f"{node_id} node pack has an unsupported generator")
    for identity in (pack_manifest, projection_manifest):
        if identity.get("node_id") != node_id:
            raise RuntimeError(f"{node_id} node pack identity mismatch")
        if identity.get("revision_id") != metadata["revision_id"]:
            raise RuntimeError(f"{node_id} revision identity mismatch")
    try:
        GENERATED_PROJECTION_POLICY.validate_archive_plugin_descriptor(
            pack_manifest.get("plugin")
        )
        GENERATED_PROJECTION_POLICY.validate_projection_manifest(
            projection_manifest,
            node_id=node_id,
            revision_id=str(metadata["revision_id"]),
        )
        GENERATED_PROJECTION_POLICY.validate_materialized_generated_schema(
            generated_schema,
            node_id=node_id,
            revision_id=str(metadata["revision_id"]),
        )
    except ValueError as error:
        raise RuntimeError(str(error)) from error
    event_records = int(pack_manifest["scale"]["events"])
    resource_records = int(pack_manifest["scale"]["resources"])
    state_change_records = int(pack_manifest["state_change_event_records"])
    if event_records != int(metadata["event_records"]):
        raise RuntimeError(f"{node_id} event metadata mismatch")
    if resource_records != int(metadata["resource_records"]):
        raise RuntimeError(f"{node_id} resource metadata mismatch")
    if state_change_records != int(metadata["state_change_event_records"]):
        raise RuntimeError(f"{node_id} state-change metadata mismatch")
    if require_full_scale:
        if event_records < MIN_EVENT_COUNT:
            raise RuntimeError(f"{node_id} has fewer than 1M events")
        if state_change_records < MIN_STATE_CHANGE_EVENT_COUNT:
            raise RuntimeError(
                f"{node_id} has fewer than 1M state-changing events"
            )
        if not MIN_RESOURCE_COUNT <= resource_records <= MAX_RESOURCE_COUNT:
            raise RuntimeError(f"{node_id} resource count is outside 5K-10K")
    required_projection_files = {
        member.member_id
        for member in GENERATED_PROJECTION_POLICY.projection_members
    }
    if set(projection_manifest.get("files", {})) != required_projection_files:
        raise RuntimeError(
            f"{node_id} plug-in projection file registry is incomplete"
        )


def validate_demo_fixture(
    path: Path,
    *,
    require_full_scale: bool | None = None,
    deep: bool = False,
) -> ValidationReport:
    """Validate assembly ownership, integrity, scale, and coverage.

    The normal build performs a bounded manifest validation.  ``deep=True``
    additionally streams every event/relationship ID and checksum in each node
    pack; it is intended for release validation and small fixture tests.
    """

    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"expected a regular assembly archive: {path}")
    archive_sha = _sha256(path)
    temp_parent = Path(tempfile.gettempdir()).resolve()
    temp_root = Path(
        tempfile.mkdtemp(prefix=".rda-assembly-validation-")
    ).resolve()
    if temp_root.parent != temp_parent:
        raise RuntimeError("validation stage is outside the system temp root")
    assembly_manifest: dict[str, Any] | None = None
    coverage: dict[str, Any] | None = None
    coverage_content: bytes | None = None
    manifest_nodes: dict[str, Mapping[str, Any]] | None = None
    selected_full_scale: bool | None = None
    pending_node_paths: dict[str, tuple[Path, str, int]] = {}
    validated_node_ids: set[str] = set()
    seen: set[str] = set()

    def validate_copied_node(
        node_id: str,
        node_path: Path,
        digest: str,
        size: int,
    ) -> None:
        if manifest_nodes is None or selected_full_scale is None:
            raise RuntimeError(
                "assembly node data precedes the assembly manifest"
            )
        metadata = manifest_nodes.get(node_id)
        if metadata is None:
            raise RuntimeError(
                f"assembly contains an unregistered node pack: {node_id}"
            )
        try:
            if digest != metadata["sha256"]:
                raise RuntimeError(
                    f"{node_id} node archive checksum mismatch"
                )
            if size != int(metadata["compressed_size"]):
                raise RuntimeError(
                    f"{node_id} node archive size mismatch"
                )
            _validate_node_pack(
                node_path,
                metadata,
                require_full_scale=selected_full_scale,
                deep=deep,
            )
            validated_node_ids.add(node_id)
        finally:
            node_path.unlink(missing_ok=True)

    try:
        with tarfile.open(path, mode="r|gz") as archive:
            for member in archive:
                _safe_member_name(member.name)
                if member.name in seen:
                    raise RuntimeError(
                        f"duplicate assembly member: {member.name}"
                    )
                seen.add(member.name)
                if not member.isfile():
                    raise RuntimeError(
                        f"assembly contains a non-file member: {member.name}"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeError(
                        f"cannot read assembly member: {member.name}"
                    )
                if member.name == ASSEMBLY_MANIFEST_MEMBER:
                    assembly_manifest = json.load(source)
                    if not isinstance(assembly_manifest, dict):
                        raise RuntimeError(
                            "assembly manifest must be an object"
                        )
                    if (
                        assembly_manifest.get("generator")
                        != ASSEMBLY_GENERATOR
                    ):
                        raise RuntimeError(
                            "unsupported demo assembly generator"
                        )
                    if (
                        assembly_manifest.get("format_version")
                        != ASSEMBLY_FORMAT_VERSION
                    ):
                        raise RuntimeError(
                            "unsupported demo assembly format version"
                        )
                    _validate_source_scenario_descriptor(
                        assembly_manifest.get("source_scenario")
                    )
                    try:
                        GENERATED_PROJECTION_POLICY.validate_archive_plugin_descriptor(
                            assembly_manifest.get("plugin")
                        )
                    except ValueError as error:
                        raise RuntimeError(str(error)) from error
                    manifest_items = assembly_manifest.get("nodes", [])
                    manifest_node_ids = [
                        str(item["node_id"]) for item in manifest_items
                    ]
                    if len(manifest_node_ids) != len(set(manifest_node_ids)):
                        raise RuntimeError(
                            "assembly manifest has duplicate node IDs"
                        )
                    manifest_nodes = {
                        str(item["node_id"]): item
                        for item in manifest_items
                    }
                    selected_full_scale = (
                        bool(
                            assembly_manifest["scale_policy"]["full_scale"]
                        )
                        if require_full_scale is None
                        else require_full_scale
                    )
                elif member.name == f"{ASSEMBLY_ROOT}/coverage.json":
                    coverage_content = source.read()
                    coverage = json.loads(coverage_content)
                    try:
                        GENERATED_PROJECTION_POLICY.validate_coverage_registry(
                            coverage
                        )
                    except ValueError as error:
                        raise RuntimeError(str(error)) from error
                elif member.name.startswith(f"{ASSEMBLY_ROOT}/nodes/"):
                    node_id = PurePosixPath(member.name).stem
                    if (
                        member.name
                        != f"{ASSEMBLY_ROOT}/nodes/{node_id}.tgz"
                    ):
                        raise RuntimeError(
                            f"unexpected assembly node member: {member.name}"
                        )
                    if (
                        node_id in pending_node_paths
                        or node_id in validated_node_ids
                    ):
                        raise RuntimeError(
                            f"duplicate assembly node pack: {node_id}"
                        )
                    node_path, digest, size = _copy_member_to_temp(
                        source,
                        directory=temp_root,
                        suffix=f"-{node_id}.tgz",
                    )
                    if manifest_nodes is None:
                        pending_node_paths[node_id] = (
                            node_path,
                            digest,
                            size,
                        )
                    else:
                        validate_copied_node(
                            node_id,
                            node_path,
                            digest,
                            size,
                        )
                else:
                    raise RuntimeError(
                        f"unexpected assembly member: {member.name}"
                    )
        if assembly_manifest is None or coverage is None:
            raise RuntimeError("assembly manifest or coverage registry is missing")
        for node_id, (
            node_path,
            digest,
            size,
        ) in pending_node_paths.items():
            validate_copied_node(
                node_id,
                node_path,
                digest,
                size,
            )
        pending_node_paths.clear()
        manifest_node_ids = [
            str(item["node_id"]) for item in assembly_manifest.get("nodes", [])
        ]
        if len(manifest_node_ids) != len(set(manifest_node_ids)):
            raise RuntimeError("assembly manifest has duplicate node IDs")
        if set(manifest_node_ids) != validated_node_ids:
            raise RuntimeError("assembly node pack set does not match manifest")
        if assembly_manifest.get("node_count") != len(manifest_node_ids):
            raise RuntimeError("assembly node_count is incorrect")
        if assembly_manifest.get("default_node_id") not in manifest_node_ids:
            raise RuntimeError("assembly default_node_id is not present")
        if coverage.get("assembly_id") != assembly_manifest.get("assembly_id"):
            raise RuntimeError("coverage registry assembly identity mismatch")
        if (
            coverage_content is None
            or _sha256_bytes(coverage_content)
            != assembly_manifest["coverage"]["sha256"]
        ):
            raise RuntimeError("coverage registry checksum mismatch")
        expected_case_ids = {case.case_id for case in COVERAGE_CASES}
        cases = coverage.get("cases", [])
        assert isinstance(cases, list)
        actual_case_ids = {str(case.get("case_id")) for case in cases}
        if len(cases) != len(actual_case_ids):
            raise RuntimeError("coverage registry has duplicate case IDs")
        if actual_case_ids != expected_case_ids:
            missing = sorted(expected_case_ids - actual_case_ids)
            extra = sorted(actual_case_ids - expected_case_ids)
            raise RuntimeError(
                f"coverage registry mismatch; missing={missing}, extra={extra}"
            )
        if coverage.get("case_count") != len(cases):
            raise RuntimeError("coverage case_count is incorrect")
        if assembly_manifest["coverage"]["cases"] != len(cases):
            raise RuntimeError("assembly coverage case count is incorrect")
        if (
            bool(assembly_manifest["coverage"]["complete"])
            != bool(coverage.get("complete"))
        ):
            raise RuntimeError("assembly coverage completeness is inconsistent")
        assert manifest_nodes is not None
        revisions = [str(item["revision_id"]) for item in manifest_nodes.values()]
        if len(revisions) != len(set(revisions)):
            raise RuntimeError("assembly node revisions must be unique")
        for node_id, metadata in manifest_nodes.items():
            if metadata.get("archive") != f"nodes/{node_id}.tgz":
                raise RuntimeError(f"{node_id} archive path is inconsistent")
            if metadata.get("identity_namespace") != f"{node_id}/":
                raise RuntimeError(
                    f"{node_id} identity namespace is inconsistent"
                )
        assert selected_full_scale is not None
        if selected_full_scale and not coverage.get("complete"):
            raise RuntimeError("full-scale coverage registry is incomplete")
        for case in cases:
            missing_nodes = set(case.get("missing_nodes", []))
            missing_evidence = case.get("missing_evidence", [])
            if not isinstance(missing_evidence, list) or any(
                not isinstance(item, str) or not item
                for item in missing_evidence
            ):
                raise RuntimeError(
                    f"coverage case {case['case_id']} has invalid "
                    "missing_evidence"
                )
            involved_nodes = set(case.get("involved_nodes", []))
            unknown_present = (involved_nodes - missing_nodes) - set(
                manifest_node_ids
            )
            if unknown_present:
                raise RuntimeError(
                    f"coverage case {case['case_id']} references unknown "
                    f"generated nodes: {sorted(unknown_present)}"
                )
            evidence_refs = case.get("evidence_refs", [])
            if not isinstance(evidence_refs, list):
                raise RuntimeError(
                    f"coverage case {case['case_id']} has invalid evidence"
                )
            if case.get("generated") and (
                missing_evidence or not evidence_refs
            ):
                raise RuntimeError(
                    f"generated coverage case {case['case_id']} lacks exact "
                    "evidence"
                )
            for evidence in evidence_refs:
                if not isinstance(evidence, Mapping):
                    raise RuntimeError(
                        f"coverage case {case['case_id']} has non-object "
                        "evidence"
                    )
                evidence_node = str(evidence["node_id"])
                if evidence_node not in manifest_nodes:
                    raise RuntimeError(
                        f"coverage evidence references missing node {evidence_node}"
                    )
                if evidence.get("revision_id") != manifest_nodes[
                    evidence_node
                ].get("revision_id"):
                    raise RuntimeError(
                        f"coverage evidence revision disagrees for "
                        f"{evidence_node}"
                    )
                prefix = f"{evidence_node}/"
                try:
                    required_namespaced_fields = (
                        GENERATED_PROJECTION_POLICY
                        .coverage_evidence_namespaced_fields(
                            evidence,
                            case_id=str(case["case_id"]),
                        )
                    )
                except ValueError as error:
                    raise RuntimeError(str(error)) from error
                for key in required_namespaced_fields:
                    if not str(evidence[key]).startswith(prefix):
                        raise RuntimeError(
                            f"coverage {key} is not namespaced for {evidence_node}"
                        )
        return ValidationReport(
            assembly_id=str(assembly_manifest["assembly_id"]),
            node_ids=tuple(manifest_node_ids),
            coverage_case_count=len(cases),
            full_scale=selected_full_scale,
            deep=deep,
            archive_sha256=archive_sha,
        )
    finally:
        for node_path, _, _ in pending_node_paths.values():
            node_path.unlink(missing_ok=True)
        resolved_temp_root = temp_root.resolve()
        if resolved_temp_root.parent != temp_parent:
            raise RuntimeError("refusing to clean an unexpected validation stage")
        shutil.rmtree(resolved_temp_root)


def parse_node_selection(node_ids: Iterable[str]) -> tuple[NodeSpec, ...]:
    """Resolve CLI node IDs against the canonical demo catalog."""

    requested = tuple(node_ids)
    if not requested:
        return DEMO_NODES
    catalog = {node.node_id: node for node in DEMO_NODES}
    unknown = sorted(set(requested) - set(catalog))
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown demo node ID(s): {', '.join(unknown)}"
        )
    if len(requested) != len(set(requested)):
        raise argparse.ArgumentTypeError("demo node selection contains duplicates")
    return tuple(catalog[node_id] for node_id in requested)


__all__ = [
    "ASSEMBLY_FORMAT_VERSION",
    "ASSEMBLY_GENERATOR",
    "ASSEMBLY_ROOT",
    "DEFAULT_ASSEMBLY_ID",
    "DEFAULT_ASSEMBLY_NAME",
    "DEFAULT_EVENT_COUNT",
    "DEFAULT_PLUGIN_ID",
    "DEFAULT_PLUGIN_VERSION",
    "DEFAULT_RESOURCE_COUNT",
    "DEFAULT_SEED",
    "EnsureLaunchReport",
    "LaunchPreflightReport",
    "PROJECTION_ROOT",
    "AssemblyConfig",
    "ValidationReport",
    "build_coverage",
    "build_demo_fixture",
    "ensure_demo_fixture_for_launch",
    "parse_node_selection",
    "probe_demo_fixture_for_launch",
    "validate_demo_fixture",
]
