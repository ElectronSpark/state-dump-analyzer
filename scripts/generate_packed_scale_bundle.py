"""Pack the 100K+-event EVPN fixture into one deterministic router dump."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import struct
import tarfile
import tempfile
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

try:
    from .generate_sample_bundle import (
        _synthetic_router_ctf2_archive,
        _validate_archive_name,
    )
except ImportError:  # Direct script execution.
    from generate_sample_bundle import (
        _synthetic_router_ctf2_archive,
        _validate_archive_name,
    )


PACK_GENERATOR = "router-dump-analyzer-packed-scale-v1"
PACK_ROOT = "router-state-lab-100k"
PACK_NAME = "router-state-lab-100k.tgz"
EVENT_ID_PATTERN = re.compile(r"(?:etg|dte)-(\d{6})")

SCALE_FILES = (
    "README.md",
    "events.jsonl",
    "high-fanout-relationships.jsonl",
    "manifest.json",
    "plugin-schema.json",
    "relationship-mutations.jsonl",
    "relationships.jsonl",
    "resources.table.txt",
    "scenario.json",
    "walkthrough.json",
)

SCALE_MANIFEST_FILES = {
    "events": "events.jsonl",
    "high_fanout_relationships": "high-fanout-relationships.jsonl",
    "plugin_schema": "plugin-schema.json",
    "readme": "README.md",
    "relationship_mutations": "relationship-mutations.jsonl",
    "relationships": "relationships.jsonl",
    "resources": "resources.table.txt",
    "scenario": "scenario.json",
    "walkthrough": "walkthrough.json",
}


@dataclass(frozen=True)
class ContainerDefinition:
    container_id: str
    label: str
    status_layout: str
    tables: tuple[str, ...]


CONTAINERS = (
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


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_regular_file(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"expected a regular file: {path}")
    return path


def _write_deterministic_tgz(
    output: Path,
    members: Mapping[str, Path],
) -> None:
    with output.open("wb") as raw_output:
        with gzip.GzipFile(
            fileobj=raw_output,
            mode="wb",
            mtime=0,
            filename="",
        ) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w|",
                format=tarfile.PAX_FORMAT,
            ) as archive:
                for logical_name in sorted(members):
                    source = _safe_regular_file(members[logical_name])
                    canonical = _validate_archive_name(logical_name).as_posix()
                    info = tarfile.TarInfo(canonical)
                    info.size = source.stat().st_size
                    info.mode = 0o644
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    with source.open("rb") as content:
                        archive.addfile(info, content)


def _directory_members(directory: Path) -> dict[str, Path]:
    members: dict[str, Path] = {}
    for candidate in sorted(directory.rglob("*"), key=lambda item: item.as_posix()):
        if candidate.is_dir():
            continue
        relative = candidate.relative_to(directory).as_posix()
        members[relative] = _safe_regular_file(candidate)
    return members


def _validate_scale_fixture(
    scale_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest_path = _safe_regular_file(scale_dir / "manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    scenario = json.loads(
        _safe_regular_file(scale_dir / "scenario.json").read_text(encoding="utf-8")
    )
    if manifest.get("scenario_id") != "evpn-multihome-mass-failover-v2":
        raise RuntimeError("the scale fixture is not the detailed EVPN scenario")
    if scenario.get("scale", {}).get("events", 0) <= 0:
        raise RuntimeError("the scale scenario does not contain events")
    for key, name in SCALE_MANIFEST_FILES.items():
        source = _safe_regular_file(scale_dir / name)
        expected = manifest.get(key, {}).get("sha256")
        actual = _sha256(source)
        if actual != expected:
            raise RuntimeError(
                f"scale fixture checksum mismatch for {name}: {actual} != {expected}"
            )
    return manifest, scenario


def _ctf_template() -> tuple[bytes, bytes]:
    with tarfile.open(
        fileobj=io.BytesIO(_synthetic_router_ctf2_archive()),
        mode="r:gz",
    ) as archive:
        metadata_member = archive.extractfile("routertrace/metadata")
        stream_member = archive.extractfile("routertrace/dummystream")
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
    if kind == "IP_ROUTING":
        return "evpn-control", "IP_ROUTING"
    if kind == "VIRTUAL_INTERFACE":
        return "underlay-agent", "VIRTUAL_INTERFACES"
    if kind == "NEIGHBOR":
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


def _write_ctf_event(stream: Any, event: dict[str, Any]) -> None:
    timestamp_ns = int(event["timestamp_ns"])
    properties = json.dumps(
        event.get("properties", {}),
        sort_keys=True,
        separators=(",", ":"),
    )
    result = event.get("result", {})
    if isinstance(result, dict) and result:
        result_key = sorted(result)[0]
        result_value = result[result_key]
    else:
        result_key = "updateStatus"
        result_value = "Unknown"
    stream.write(struct.pack("<Q", timestamp_ns))
    for value in (
        event.get("resource_id", event.get("resource", "")),
        event.get("action", "update"),
        properties,
        result_key,
        result_value,
    ):
        stream.write(_ctf_string(value))


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
    metadata, stream_header = _ctf_template()
    event_counts: Counter[str] = Counter()
    outcome_counts: dict[str, Counter[str]] = {
        container.container_id: Counter() for container in CONTAINERS
    }

    with ExitStack() as stack:
        normalized_writers: dict[str, Any] = {}
        ctf_writers: dict[str, Any] = {}
        for container in CONTAINERS:
            trace_dir = stage / "containers" / container.container_id / "trace"
            ctf_dir = trace_dir / "ctf"
            ctf_dir.mkdir(parents=True, exist_ok=True)
            (ctf_dir / "metadata").write_bytes(metadata)
            normalized_writers[container.container_id] = stack.enter_context(
                (trace_dir / "normalized-events.jsonl").open("wb")
            )
            ctf_writers[container.container_id] = stack.enter_context(
                (ctf_dir / "dummystream").open("wb")
            )
            ctf_writers[container.container_id].write(stream_header)

        with (scale_dir / "events.jsonl").open("rb") as source:
            for line in source:
                event = json.loads(line)
                container_id = _event_container(
                    event,
                    int(scenario["multi_home_services"]),
                )
                normalized_writers[container_id].write(line)
                _write_ctf_event(ctf_writers[container_id], event)
                event_counts[container_id] += 1
                outcome_counts[container_id][str(event.get("outcome", "unknown"))] += 1

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
                "normalized_export": "trace/normalized-events.jsonl",
                "event_records": event_counts.get(container_id, 0),
                "outcomes": dict(sorted(outcome_counts[container_id].items())),
            },
        }
        container_root = stage / "containers" / container_id
        (container_root / "manifest.json").write_bytes(_json_bytes(manifest))
        manifests.append(manifest)
    return manifests


def _pack_manifest_from_archive(path: Path) -> dict[str, Any] | None:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            member = archive.extractfile(f"{PACK_ROOT}/manifest.json")
            return json.loads(member.read()) if member is not None else None
    except (OSError, tarfile.TarError, json.JSONDecodeError):
        return None


def _assert_replaceable_output(output: Path) -> None:
    if output.is_symlink():
        raise RuntimeError(f"refusing symbolic-link output: {output}")
    if not output.exists():
        return
    if not output.is_file():
        raise RuntimeError(f"packed output is not a regular file: {output}")
    manifest = _pack_manifest_from_archive(output)
    if manifest is None or manifest.get("generator") != PACK_GENERATOR:
        raise RuntimeError(f"refusing to replace an unowned packed fixture: {output}")


def build_packed_bundle(
    output: Path,
    scale_dir: Path,
    review_dir: Path,
    review_manifest: Path,
) -> Path:
    """Build one outer TGZ with four nested container TGZs and review data."""

    output = output.resolve()
    scale_dir = scale_dir.resolve()
    review_dir = review_dir.resolve()
    review_manifest = review_manifest.resolve()
    _assert_replaceable_output(output)
    scale_manifest, scenario = _validate_scale_fixture(scale_dir)
    _safe_regular_file(review_manifest)
    review_files = [
        candidate
        for candidate in sorted(review_dir.rglob("*"), key=lambda item: item.as_posix())
        if not candidate.is_dir()
    ]
    if not review_files:
        raise RuntimeError(f"review projection is empty: {review_dir}")
    for candidate in review_files:
        _safe_regular_file(candidate)

    output.parent.mkdir(parents=True, exist_ok=True)
    lock = output.parent / f".{output.name}.router-dump-analyzer.lock"
    lock_fd: int | None = None
    stage: Path | None = None
    try:
        try:
            lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as error:
            raise RuntimeError(f"another generator is using output: {output}") from error

        stage = Path(
            tempfile.mkdtemp(prefix=".rda-packed-stage-", dir=output.parent)
        )
        row_counts, container_resource_counts = _write_status_files(
            stage,
            scale_dir,
            scenario,
        )
        event_counts, outcome_counts = _write_event_files(
            stage,
            scale_dir,
            scenario,
        )
        container_manifests = _write_container_manifests(
            stage,
            scenario,
            row_counts,
            container_resource_counts,
            event_counts,
            outcome_counts,
        )

        nested_paths: dict[str, Path] = {}
        nested_metadata: list[dict[str, Any]] = []
        for container in CONTAINERS:
            container_root = stage / "containers" / container.container_id
            nested_path = stage / f"{container.container_id}.tgz"
            _write_deterministic_tgz(
                nested_path,
                _directory_members(container_root),
            )
            nested_paths[container.container_id] = nested_path
            nested_metadata.append(
                {
                    "container_id": container.container_id,
                    "path": f"containers/{container.container_id}.tgz",
                    "sha256": _sha256(nested_path),
                    "compressed_size": nested_path.stat().st_size,
                    "resource_rows": container_resource_counts.get(
                        container.container_id,
                        0,
                    ),
                    "event_records": event_counts.get(container.container_id, 0),
                    "status_layout": container.status_layout,
                    "table_count": len(container.tables),
                }
            )

        pack_manifest = {
            "generator": PACK_GENERATOR,
            "format_version": 2,
            "package_id": "router-state-lab-evpn-multihome-100k",
            "scenario_id": scenario["scenario_id"],
            "description": (
                "One deterministic outer dump containing four nested container "
                "packs, per-container CTF logs and heterogeneous status tables, "
                f"the complete {int(scenario['scale']['events']):,}-event / "
                f"{int(scenario['scale']['resources']):,}-resource normalized "
                "scale corpus, and a browser-sized review projection."
            ),
            "scale": scenario["scale"],
            "resource_counts": scenario["resource_counts"],
            "phase_order": scenario["phase_order"],
            "containers": nested_metadata,
            "container_manifests": container_manifests,
            "normalized_scale_root": "normalized-scale",
            "review_projection_root": "review-projection",
            "review_projection": {
                "purpose": "Browser-sized temporal projection loaded by the demo",
                "files": len(review_files) + 1,
            },
            "source": {
                "scale_manifest_sha256": _sha256(scale_dir / "manifest.json"),
                "review_manifest_sha256": _sha256(review_manifest),
                "scale_generator_version": scale_manifest["generator_version"],
            },
        }
        pack_manifest_path = stage / "pack-manifest.json"
        pack_manifest_path.write_bytes(_json_bytes(pack_manifest))

        outer_members: dict[str, Path] = {
            f"{PACK_ROOT}/manifest.json": pack_manifest_path,
            f"{PACK_ROOT}/review-projection/manifest.json": review_manifest,
        }
        for container_id, path in nested_paths.items():
            outer_members[
                f"{PACK_ROOT}/containers/{container_id}.tgz"
            ] = path
        for name in SCALE_FILES:
            outer_members[
                f"{PACK_ROOT}/normalized-scale/{name}"
            ] = _safe_regular_file(scale_dir / name)
        for candidate in review_files:
            relative = candidate.relative_to(review_dir).as_posix()
            if relative == "manifest.json":
                raise RuntimeError(
                    "review directory must not shadow review-projection/manifest.json"
                )
            outer_members[
                f"{PACK_ROOT}/review-projection/{relative}"
            ] = candidate

        staged_archive = stage / PACK_NAME
        _write_deterministic_tgz(staged_archive, outer_members)
        _assert_replaceable_output(output)
        staged_archive.replace(output)
        return output
    finally:
        if stage is not None and stage.exists():
            shutil.rmtree(stage)
        if lock_fd is not None:
            os.close(lock_fd)
            lock.unlink(missing_ok=True)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build the one-file 100K+-event Router State Lab fixture"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "samples" / "generated-scale" / PACK_NAME,
    )
    parser.add_argument(
        "--scale-dir",
        type=Path,
        default=root / "samples" / "generated-scale",
    )
    parser.add_argument(
        "--review-dir",
        type=Path,
        default=root / "samples" / "generated" / "illustrative",
    )
    parser.add_argument(
        "--review-manifest",
        type=Path,
        default=(
            root
            / "samples"
            / "generated"
            / "unpacked"
            / "node-a"
            / "manifest.json"
        ),
    )
    args = parser.parse_args()
    output = build_packed_bundle(
        args.output,
        args.scale_dir,
        args.review_dir,
        args.review_manifest,
    )
    console_path = str(output).encode(
        "ascii",
        errors="backslashreplace",
    ).decode("ascii")
    print(f"Generated packed 100K+-event fixture: {console_path}")


if __name__ == "__main__":
    main()
