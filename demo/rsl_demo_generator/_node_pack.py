"""Node-pack builder private to the standalone demo generator."""

from __future__ import annotations

import io
import json
import re
import shutil
import struct
import tarfile
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from rsl_demo_plugin.archive import (
    CTF_METADATA_MEMBER,
    CTF_STREAM_MEMBER,
    HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME,
    MANIFEST_MEMBER_NAME,
    NODE_PACK_GENERATOR,
    NODE_PACK_ROOT,
    RELATIONSHIP_MUTATIONS_MEMBER_NAME,
)
from ._archive import (
    directory_members as _directory_members,
    json_bytes as _json_bytes,
    write_deterministic_tgz,
)
from ._synthetic_ctf import (
    synthetic_router_ctf2_archive as _synthetic_router_ctf2_archive,
)


PACK_GENERATOR = NODE_PACK_GENERATOR
PACK_ROOT = NODE_PACK_ROOT
EVENT_ID_PATTERN = re.compile(r"(?:etg|dte)-(\d{6})")
_CTF_WRITE_BATCH_BYTES = 1024 * 1024

SCALE_FILES: Final[tuple[str, ...]] = (
    "README.md",
    "events.jsonl",
    HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME,
    MANIFEST_MEMBER_NAME,
    "plugin-schema.json",
    RELATIONSHIP_MUTATIONS_MEMBER_NAME,
    "relationships.jsonl",
    "resources.table.txt",
    "scenario.json",
    "walkthrough.json",
)

@dataclass(frozen=True)
class ContainerDefinition:
    container_id: str
    label: str
    status_layout: str
    tables: tuple[str, ...]


CONTAINERS: Final[tuple[ContainerDefinition, ...]] = (
    ContainerDefinition(
        "evpn-control",
        "EVPN and routing control",
        "multi-table",
        ("ETHERNET_SEGMENTS", "IP_ROUTING"),
    ),
    ContainerDefinition(
        "forwarding-multihome",
        "Multi-home forwarding programmer",
        "multi-table",
        ("ETG", "ETE_PRIMARY", "ETE_BACKUP", "DTE"),
    ),
    ContainerDefinition(
        "forwarding-single-home",
        "Single-home forwarding programmer",
        "single-table",
        ("FORWARDING_RESOURCES",),
    ),
    ContainerDefinition(
        "underlay-agent",
        "Underlay and hardware agent",
        "multi-table",
        ("VIRTUAL_INTERFACES", "NEIGHBORS"),
    ),
)


def _ctf_template() -> tuple[bytes, bytes]:
    with tarfile.open(
        fileobj=io.BytesIO(_synthetic_router_ctf2_archive()),
        mode="r:gz",
    ) as archive:
        metadata_member = archive.extractfile(CTF_METADATA_MEMBER)
        stream_member = archive.extractfile(CTF_STREAM_MEMBER)
        if metadata_member is None or stream_member is None:
            raise RuntimeError("synthetic CTF template is incomplete")
        metadata = metadata_member.read()
        stream_header = stream_member.read(20)
    if len(stream_header) != 20:
        raise RuntimeError("synthetic CTF stream header is incomplete")
    return metadata, stream_header


def _service_index(value: str) -> int | None:
    if value.startswith("svc-") and value[4:].isdigit():
        return int(value[4:])
    match = EVENT_ID_PATTERN.search(value)
    return int(match.group(1)) if match else None


def _resource_table_destination(
    kind: str,
    service_id: str,
    role: str,
    multi_home_services: int,
) -> tuple[str, str]:
    if kind == "EVPN_ES":
        return "evpn-control", "ETHERNET_SEGMENTS"
    if kind in {"IP_ROUTE", "IP_ROUTING"}:
        return "evpn-control", "IP_ROUTING"
    if kind == "VIRTUAL_INTERFACE":
        return "underlay-agent", "VIRTUAL_INTERFACES"
    if kind in {"ADJACENCY", "NEIGHBOR"}:
        return "underlay-agent", "NEIGHBORS"
    if kind in {"ETG", "DTE", "ETE"}:
        index = _service_index(service_id)
        if index is None:
            raise RuntimeError(f"forwarding resource lacks a service index: {service_id}")
        table = (
            "ETE_BACKUP"
            if kind == "ETE" and role == "backup"
            else "ETE_PRIMARY"
            if kind == "ETE"
            else kind
        )
        if table == "ETE_BACKUP" or index < multi_home_services:
            return "forwarding-multihome", table
        return "forwarding-single-home", "FORWARDING_RESOURCES"
    raise RuntimeError(f"unassigned scale resource kind: {kind}")


def _event_container(event: dict[str, Any], multi_home_services: int) -> str:
    layer = str(event.get("layer", ""))
    if layer == "control-plane":
        return "evpn-control"
    if layer == "hardware-driver-plane":
        return "underlay-agent"
    if layer == "data-bridge-layer":
        properties = event.get("properties", {})
        service_value = str(properties.get("service_id", ""))
        index = _service_index(service_value)
        if index is None:
            index = _service_index(str(event.get("resource_id", "")))
        if index is not None and index >= multi_home_services:
            return "forwarding-single-home"
        return "forwarding-multihome"
    return "evpn-control"


def _ctf_string(value: Any) -> bytes:
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return value.replace("\x00", "\\u0000").encode("utf-8") + b"\x00"


def _append_ctf_event(
    buffer: bytearray,
    event: dict[str, Any],
    properties_json: bytes,
) -> None:
    timestamp_ns = int(event["timestamp_ns"])
    result = event.get("result", {})
    if isinstance(result, dict) and result:
        result_key = sorted(result)[0]
        result_value = result[result_key]
    else:
        result_key = "updateStatus"
        result_value = "Unknown"
    buffer.extend(struct.pack("<Q", timestamp_ns))
    for value in (
        event.get("resource_id", event.get("resource", "")),
        event.get("action", "update"),
    ):
        buffer.extend(_ctf_string(value))
    buffer.extend(properties_json)
    buffer.append(0)
    for value in (result_key, result_value):
        buffer.extend(_ctf_string(value))


def _write_status_files(
    stage: Path,
    scale_dir: Path,
    scenario: dict[str, Any],
) -> tuple[dict[tuple[str, str], int], dict[str, int]]:
    rows_root = stage / "status-rows"
    rows_root.mkdir(parents=True)
    row_counts: Counter[tuple[str, str]] = Counter()
    container_counts: Counter[str] = Counter()
    row_paths: dict[tuple[str, str], Path] = {}
    for container in CONTAINERS:
        for table in container.tables:
            path = rows_root / f"{container.container_id}--{table}.rows"
            row_paths[(container.container_id, table)] = path

    resources_path = scale_dir / "resources.table.txt"
    with resources_path.open(encoding="utf-8") as source:
        header = source.readline().rstrip("\r\n")
        columns = header.split("|")
        kind_column = columns.index("KIND")
        service_column = columns.index("SERVICE_ID")
        role_column = columns.index("ROLE")
        with ExitStack() as stack:
            writers = {
                key: stack.enter_context(
                    path.open("w", encoding="utf-8", newline="\n")
                )
                for key, path in row_paths.items()
            }
            for line in source:
                row = line.rstrip("\r\n")
                values = row.split("|")
                destination = _resource_table_destination(
                    values[kind_column],
                    values[service_column],
                    values[role_column],
                    int(scenario["multi_home_services"]),
                )
                writers[destination].write(row + "\n")
                row_counts[destination] += 1
                container_counts[destination[0]] += 1

    if sum(container_counts.values()) != int(scenario["scale"]["resources"]):
        raise RuntimeError("not every scale resource was assigned to a container")

    for container in CONTAINERS:
        container_root = stage / "containers" / container.container_id
        status_dir = container_root / "status"
        status_dir.mkdir(parents=True, exist_ok=True)
        status_path = status_dir / "resource-status.txt"
        with status_path.open("w", encoding="utf-8", newline="\n") as output:
            output.write(
                f"# {container.label}\n"
                f"# layout={container.status_layout}\n"
                f"# scenario={scenario['scenario_id']}\n"
            )
            for table in container.tables:
                output.write(f"\n=== TABLE: {table} ===\n")
                output.write(header + "\n")
                with row_paths[(container.container_id, table)].open(
                    encoding="utf-8"
                ) as rows:
                    shutil.copyfileobj(rows, output)
        table_index = {
            "layout": container.status_layout,
            "table_count": len(container.tables),
            "resource_rows": container_counts[container.container_id],
            "tables": [
                {
                    "name": table,
                    "rows": row_counts[(container.container_id, table)],
                }
                for table in container.tables
            ],
        }
        (status_dir / "table-index.json").write_bytes(_json_bytes(table_index))

    return dict(row_counts), dict(container_counts)


def _write_event_files(
    stage: Path,
    scale_dir: Path,
    scenario: dict[str, Any],
) -> tuple[dict[str, int], dict[str, Counter[str]]]:
    # Only CTF materialization needs the accelerated decoder. Keeping this
    # import local leaves catalog/import-only generator use stdlib-only.
    from pydantic_core import (
        from_json as strict_json_loads,
        to_json as strict_json_dumps,
    )

    metadata, stream_header = _ctf_template()
    event_counts: Counter[str] = Counter()
    outcome_counts: dict[str, Counter[str]] = {
        container.container_id: Counter() for container in CONTAINERS
    }

    with ExitStack() as stack:
        ctf_writers: dict[str, Any] = {}
        ctf_buffers: dict[str, bytearray] = {}
        for container in CONTAINERS:
            trace_dir = stage / "containers" / container.container_id / "trace"
            ctf_dir = trace_dir / "ctf"
            ctf_dir.mkdir(parents=True, exist_ok=True)
            (ctf_dir / "metadata").write_bytes(metadata)
            ctf_writers[container.container_id] = stack.enter_context(
                (ctf_dir / "dummystream").open("wb")
            )
            ctf_writers[container.container_id].write(stream_header)
            ctf_buffers[container.container_id] = bytearray()

        with (scale_dir / "events.jsonl").open("rb") as source:
            for line in source:
                event = strict_json_loads(line)
                if not isinstance(event, dict):
                    raise RuntimeError("normalized event must be an object")
                container_id = _event_container(
                    event,
                    int(scenario["multi_home_services"]),
                )
                buffer = ctf_buffers[container_id]
                # The scale generator emits canonical, recursively sorted
                # objects. ``from_json`` preserves that insertion order, so
                # pydantic-core can re-encode the property object byte-for-byte
                # without invoking Python's much slower generic JSON encoder.
                properties_json = strict_json_dumps(
                    event.get("properties", {}),
                    ensure_ascii=True,
                )
                _append_ctf_event(buffer, event, properties_json)
                if len(buffer) >= _CTF_WRITE_BATCH_BYTES:
                    ctf_writers[container_id].write(buffer)
                    buffer.clear()
                event_counts[container_id] += 1
                outcome_counts[container_id][str(event.get("outcome", "unknown"))] += 1
        for container_id, buffer in ctf_buffers.items():
            if buffer:
                ctf_writers[container_id].write(buffer)

    if sum(event_counts.values()) != int(scenario["scale"]["events"]):
        raise RuntimeError("not every scale event was assigned to a container")
    return dict(event_counts), outcome_counts


def _write_container_manifests(
    stage: Path,
    scenario: dict[str, Any],
    row_counts: dict[tuple[str, str], int],
    container_resource_counts: dict[str, int],
    event_counts: dict[str, int],
    outcome_counts: dict[str, Counter[str]],
) -> list[dict[str, Any]]:
    manifests: list[dict[str, Any]] = []
    for container in CONTAINERS:
        container_id = container.container_id
        manifest = {
            "container_id": container_id,
            "label": container.label,
            "scenario_id": scenario["scenario_id"],
            "capture_clock_domain": f"{container_id}-realtime",
            "resource_status": {
                "path": "status/resource-status.txt",
                "layout": container.status_layout,
                "table_count": len(container.tables),
                "resource_rows": container_resource_counts.get(container_id, 0),
                "tables": [
                    {
                        "name": table,
                        "rows": row_counts.get((container_id, table), 0),
                    }
                    for table in container.tables
                ],
            },
            "trace": {
                "format": "CTF 2 synthetic router-resource-update",
                "metadata": "trace/ctf/metadata",
                "stream": "trace/ctf/dummystream",
                "event_records": event_counts.get(container_id, 0),
                "outcomes": dict(sorted(outcome_counts[container_id].items())),
            },
        }
        container_root = stage / "containers" / container_id
        (container_root / MANIFEST_MEMBER_NAME).write_bytes(
            _json_bytes(manifest)
        )
        manifests.append(manifest)
    return manifests


__all__ = [
    "CONTAINERS",
    "PACK_GENERATOR",
    "PACK_ROOT",
    "SCALE_FILES",
    "_directory_members",
    "_write_container_manifests",
    "_write_event_files",
    "_write_status_files",
]
