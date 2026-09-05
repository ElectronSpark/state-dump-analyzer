"""Deterministic, topology-free state-dump archive projection.

The authoring project deliberately has more information than a router can
observe.  This module is the hard boundary between that private authoring
state and generated node dumps.  It accepts only per-node plans produced by
``simulation.compile_scenario`` and rejects authoring/oracle fields before
serializing a byte.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from ._json_values import plain_value as _project_json_value
from ._json_values import stable_json_key as _stable_sort_key
from .boundary import forbidden_authoring_paths
from .path_safety import resolve_output_file

ASSEMBLY_SCHEMA = "state-dump-assembly/v1"
NODE_DUMP_SCHEMA = "router-state-dump/v1"
GENERATOR_NAME = "state-dump-generator"
GZIP_LEVEL = 6

_SAFE_SLUG = re.compile(r"[^A-Za-z0-9_.-]+")
_WINDOWS_RESERVED_MEMBER_NAMES = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


class ArchiveProjectionError(ValueError):
    """A compiled plan cannot safely be represented as a node dump."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON with a trailing newline."""

    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("utf-8")


def canonical_jsonl_bytes(records: Iterable[Mapping[str, Any]]) -> bytes:
    """Return compact deterministic JSON Lines."""

    output = io.StringIO()
    for record in records:
        output.write(
            json.dumps(
                record,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        output.write("\n")
    return output.getvalue().encode("utf-8")


def validate_member_name(value: str) -> str:
    """Validate and normalize a regular-file archive member name."""

    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "\x00" in value
    ):
        raise ArchiveProjectionError("archive member name must be non-empty text")
    if "\\" in value or re.match(r"^[A-Za-z]:", value):
        raise ArchiveProjectionError(f"unsafe archive member name: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveProjectionError(f"unsafe archive member name: {value!r}")
    normalized = path.as_posix()
    if normalized != value:
        raise ArchiveProjectionError(f"non-canonical archive member name: {value!r}")
    for part in path.parts:
        base_name = part.split(".", 1)[0].casefold()
        if (
            ":" in part
            or part.endswith((".", " "))
            or base_name in _WINDOWS_RESERVED_MEMBER_NAMES
        ):
            raise ArchiveProjectionError(f"unsafe archive member name: {value!r}")
    return normalized


def deterministic_tgz_bytes(files: Mapping[str, bytes]) -> bytes:
    """Build a byte-stable TGZ containing regular files only."""

    tar_buffer = io.BytesIO()
    with tarfile.open(
        fileobj=tar_buffer,
        mode="w",
        format=tarfile.PAX_FORMAT,
    ) as archive:
        for member_name in sorted(files):
            name = validate_member_name(member_name)
            content = files[member_name]
            if not isinstance(content, bytes):
                raise TypeError(f"archive member {name!r} must contain bytes")
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(content))

    output = io.BytesIO()
    with gzip.GzipFile(
        fileobj=output,
        mode="wb",
        compresslevel=GZIP_LEVEL,
        mtime=0,
        filename="",
    ) as compressor:
        compressor.write(tar_buffer.getvalue())
    return output.getvalue()


def sha256_hex(content: bytes) -> str:
    """Return the lower-case SHA-256 digest of *content*."""

    return hashlib.sha256(content).hexdigest()


def _plain_value(value: Any) -> Any:
    return _project_json_value(
        value,
        set_sort_key=_stable_sort_key,
        path_strings=True,
        error_type=ArchiveProjectionError,
        unsupported_message="compiled plan contains a non-serializable {kind}",
    )


def _assert_node_local(value: Any, *, location: str) -> None:
    """Reject authoring truth recursively.

    Compilers should emit explicit node-local observations rather than asking
    the archive writer to guess which parts of a topology are safe.
    """

    first = next(
        forbidden_authoring_paths(value, location=location),
        None,
    )
    if first is not None:
        path, raw_key = first
        raise ArchiveProjectionError(
            f"{path} contains forbidden authoring field {raw_key!r}"
        )


def _mapping(value: Any, *, location: str) -> dict[str, Any]:
    plain = _plain_value(value)
    if not isinstance(plain, dict):
        raise ArchiveProjectionError(f"{location} must be an object")
    return plain


def _field(
    plan: Mapping[str, Any],
    names: Sequence[str],
    *,
    default: Any = None,
) -> Any:
    for name in names:
        if name in plan:
            return plan[name]
    return default


def _record_sequence(value: Any, *, location: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        # A map keyed by resource/event ID is convenient in the simulation
        # layer.  Preserve the key when the value does not already carry one.
        records: list[dict[str, Any]] = []
        for key, item in value.items():
            record = _mapping(item, location=f"{location}.{key}")
            if not any(
                candidate in record
                for candidate in ("id", "event_id", "resource_id", "key")
            ):
                record = {"id": str(key), **record}
            records.append(record)
        return records
    if isinstance(value, str | bytes) or not isinstance(value, Iterable):
        raise ArchiveProjectionError(f"{location} must be an array or object")
    return [
        _mapping(item, location=f"{location}[{index}]")
        for index, item in enumerate(value)
    ]


def _timestamp(record: Mapping[str, Any]) -> int:
    for name in (
        "timestamp_ns",
        "observed_at_ns",
        "time_ns",
        "at_ns",
        "timestamp",
    ):
        value = record.get(name)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
    return 0


def _source_sequence(record: Mapping[str, Any]) -> int:
    """Return the producer-declared order within one timestamp."""

    value = record.get("source_sequence", record.get("order", 0))
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _record_identity(record: Mapping[str, Any]) -> str:
    for name in ("event_id", "resource_id", "id", "key"):
        value = record.get(name)
        if value is not None:
            return str(value)
    return _stable_sort_key(record)


def _normalize_plan(plan_value: Any, node_id_hint: str | None) -> dict[str, Any]:
    plan = _mapping(plan_value, location="node plan")
    node_id_value = _field(plan, ("node_id", "id"), default=node_id_hint)
    if node_id_value is None or not str(node_id_value).strip():
        raise ArchiveProjectionError("compiled node plan is missing node_id")
    node_id = str(node_id_value)
    if node_id_hint is not None and node_id != node_id_hint:
        raise ArchiveProjectionError(
            f"compiled node key {node_id_hint!r} disagrees with node_id {node_id!r}"
        )

    final_records = _record_sequence(
        _field(
            plan,
            (
                "final_state",
                "final_resources",
                "resources",
                "status_records",
                "status",
            ),
            default=[],
        ),
        location=f"node[{node_id}].final_state",
    )
    log_records = _record_sequence(
        _field(
            plan,
            ("past_logs", "logs", "history", "events", "log_records"),
            default=[],
        ),
        location=f"node[{node_id}].logs",
    )
    for index, record in enumerate(final_records):
        _assert_node_local(
            record,
            location=f"node[{node_id}].final_state[{index}]",
        )
    for index, record in enumerate(log_records):
        _assert_node_local(record, location=f"node[{node_id}].logs[{index}]")

    final_records.sort(
        key=lambda item: (_record_identity(item), _stable_sort_key(item))
    )
    log_records.sort(
        key=lambda item: (
            _timestamp(item),
            _source_sequence(item),
            _record_identity(item),
            _stable_sort_key(item),
        )
    )
    captured_at = _field(
        plan,
        (
            "captured_at_ns",
            "final_timestamp_ns",
            "snapshot_at_ns",
            "capture_time_ns",
        ),
        default=max((_timestamp(item) for item in log_records), default=0),
    )
    try:
        captured_at_ns = int(captured_at)
    except (TypeError, ValueError) as error:
        raise ArchiveProjectionError(
            f"node[{node_id}].captured_at_ns must be an integer"
        ) from error
    if captured_at_ns < 0:
        raise ArchiveProjectionError(
            f"node[{node_id}].captured_at_ns cannot be negative"
        )
    return {
        "node_id": node_id,
        "captured_at_ns": captured_at_ns,
        "final_state": final_records,
        "logs": log_records,
    }


def normalize_compiled_plans(compiled: Any) -> list[dict[str, Any]]:
    """Normalize common ``compile_scenario`` result shapes.

    The standalone simulation model is free to use dataclasses internally.
    This small adapter accepts a mapping keyed by node ID, an object with a
    ``node_plans``/``nodes`` attribute, or a sequence of node plans.
    """

    value = _plain_value(compiled)
    if isinstance(value, Mapping):
        if "node_plans" in value:
            value = value["node_plans"]
        elif "nodes" in value and isinstance(value["nodes"], (Mapping, list, tuple)):
            value = value["nodes"]
    plans: list[dict[str, Any]]
    if isinstance(value, Mapping):
        plans = [_normalize_plan(plan, str(node_id)) for node_id, plan in value.items()]
    elif isinstance(value, list | tuple):
        plans = [_normalize_plan(plan, None) for plan in value]
    else:
        raise ArchiveProjectionError("compile_scenario must return per-node plans")
    plans.sort(key=lambda item: item["node_id"])
    node_ids = [item["node_id"] for item in plans]
    if not plans:
        raise ArchiveProjectionError("compiled scenario contains no node plans")
    if len(node_ids) != len(set(node_ids)):
        raise ArchiveProjectionError("compiled scenario contains duplicate node IDs")
    return plans


def _status_text(node_id: str, records: Sequence[Mapping[str, Any]]) -> bytes:
    lines = [
        "# node-local final router state",
        f"# node_id={node_id}",
        "RESOURCE|TYPE|STATUS|PROPERTIES",
    ]
    for record in records:
        resource = _record_identity(record)
        resource_type = str(
            record.get("resource_type", record.get("type", record.get("kind", "")))
        )
        status = str(record.get("status", record.get("state", "")))
        reserved = {
            "id",
            "key",
            "kind",
            "resource_id",
            "resource_type",
            "state",
            "status",
            "type",
        }
        properties = {
            key: value for key, value in record.items() if key not in reserved
        }
        escaped = [
            str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n")
            for value in (resource, resource_type, status)
        ]
        escaped.append(
            json.dumps(
                properties,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).replace("|", "\\|")
        )
        lines.append("|".join(escaped))
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_node_dump_bytes(plan_value: Any, *, node_id_hint: str | None = None) -> bytes:
    """Build one deterministic node-local dump TGZ."""

    plan = _normalize_plan(plan_value, node_id_hint)
    node_id = plan["node_id"]
    final_state = plan["final_state"]
    logs = plan["logs"]
    manifest = {
        "schema": NODE_DUMP_SCHEMA,
        "generator": GENERATOR_NAME,
        "node_id": node_id,
        "captured_at_ns": plan["captured_at_ns"],
        "final_state": {
            "jsonl": "status/final-state.jsonl",
            "text": "status/final-state.txt",
            "records": len(final_state),
        },
        "history": {
            "jsonl": "logs/history.jsonl",
            "records": len(logs),
        },
    }
    return deterministic_tgz_bytes(
        {
            "logs/history.jsonl": canonical_jsonl_bytes(logs),
            "manifest.json": canonical_json_bytes(manifest),
            "status/final-state.jsonl": canonical_jsonl_bytes(final_state),
            "status/final-state.txt": _status_text(node_id, final_state),
        }
    )


def _node_member_name(node_id: str, used: set[str]) -> str:
    slug = _SAFE_SLUG.sub("-", node_id.strip()).strip(".-") or "node"
    if slug.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_MEMBER_NAMES:
        slug = f"node-{slug}"
    candidate = f"nodes/{slug}.tgz"
    counter = 2
    while candidate in used:
        candidate = f"nodes/{slug}-{counter}.tgz"
        counter += 1
    used.add(candidate)
    return candidate


def build_assembly_bytes(compiled: Any) -> bytes:
    """Build an outer archive containing one nested dump per compiled node."""

    plans = normalize_compiled_plans(compiled)
    members: dict[str, bytes] = {}
    used_names: set[str] = set()
    nodes: list[dict[str, Any]] = []
    for plan in plans:
        node_dump = build_node_dump_bytes(plan)
        member_name = _node_member_name(plan["node_id"], used_names)
        members[member_name] = node_dump
        nodes.append(
            {
                "node_id": plan["node_id"],
                "file": member_name,
                "sha256": sha256_hex(node_dump),
                "bytes": len(node_dump),
                "final_state_records": len(plan["final_state"]),
                "history_records": len(plan["logs"]),
            }
        )
    members["manifest.json"] = canonical_json_bytes(
        {
            "schema": ASSEMBLY_SCHEMA,
            "generator": GENERATOR_NAME,
            "node_count": len(nodes),
            "nodes": nodes,
        }
    )
    return deterministic_tgz_bytes(members)


def compile_and_build(document: Any) -> bytes:
    """Compile a scenario document and return its topology-free assembly."""

    from .simulation import compile_scenario

    return build_assembly_bytes(compile_scenario(document))


def write_assembly(document: Any, output: Path | str) -> Path:
    """Compile *document* and atomically write an assembly TGZ."""

    try:
        destination = resolve_output_file(output, label="assembly output")
    except ValueError as error:
        raise ArchiveProjectionError(str(error)) from error
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = compile_and_build(document)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


__all__ = [
    "ASSEMBLY_SCHEMA",
    "GENERATOR_NAME",
    "NODE_DUMP_SCHEMA",
    "ArchiveProjectionError",
    "build_assembly_bytes",
    "build_node_dump_bytes",
    "canonical_json_bytes",
    "canonical_jsonl_bytes",
    "compile_and_build",
    "deterministic_tgz_bytes",
    "normalize_compiled_plans",
    "sha256_hex",
    "validate_member_name",
    "write_assembly",
]
