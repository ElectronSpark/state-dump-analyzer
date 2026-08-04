"""Headless, deterministic entry point for durable ingestion.

This command is intentionally separate from the interactive web launcher.
It is suitable for CI jobs and documentation examples: inputs are admitted to
one explicit tenant/project/workspace, all results are emitted as a bounded
JSON document, and exit status distinguishes failed imports from imports that
require a human plug-in choice.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, TextIO

from .canonical import canonical_json
from .cli import _add_repeatable_plugin_allowlist_arguments
from .control_plane import ControlPlane
from .ingestion_pipeline import (
    ImportDescriptor,
    ImportState,
    IngestionStateRootPathError,
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
)
from .plugin_loading import (
    LoadedPlugin,
    load_plugin_entry_point,
    load_plugin_module,
    loaded_entry_point,
    loaded_module,
)

DEFAULT_TIMEOUT_SECONDS = 900.0
MAX_TIMEOUT_SECONDS = 7 * 24 * 60 * 60


def _positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be a number") from error
    if not 0 < parsed <= MAX_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError(
            f"timeout must be greater than zero and at most {MAX_TIMEOUT_SECONDS}"
        )
    return parsed


def _metadata_object(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as error:
        raise argparse.ArgumentTypeError(
            "--metadata-json must contain a JSON object"
        ) from error
    if not isinstance(decoded, dict):
        raise argparse.ArgumentTypeError("--metadata-json must contain a JSON object")
    return decoded


@dataclass(frozen=True, slots=True)
class HeadlessIngestionConfiguration:
    state_dir: Path
    tenant_id: str
    project_id: str
    workspace_id: str
    project_label: str
    workspace_label: str
    plugin_names: tuple[str, ...]
    plugin_modules: tuple[str, ...]
    input_paths: tuple[Path, ...]
    timeout_seconds: float
    auto_select: bool
    preferred_plugin_id: str | None
    content_type: str | None
    node_hint: str | None
    metadata: dict[str, Any]
    output_path: Path | None
    pretty: bool
    retention_policy_path: Path | None = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="router-dump-ingest",
        description=(
            "Upload one or more dump artifacts into the durable analyzer "
            "control plane and wait for deterministic queue outcomes."
        ),
    )
    _add_repeatable_plugin_allowlist_arguments(parser)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--tenant", required=True, dest="tenant_id")
    parser.add_argument("--project", required=True, dest="project_id")
    parser.add_argument("--workspace", required=True, dest="workspace_id")
    parser.add_argument("--project-label", default="CI project")
    parser.add_argument("--workspace-label", default="CI workspace")
    parser.add_argument(
        "--input",
        required=True,
        action="append",
        type=Path,
        dest="input_paths",
        help="artifact to upload; repeat for a multi-fixture run",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_timeout,
        default=DEFAULT_TIMEOUT_SECONDS,
        dest="timeout_seconds",
        help="maximum seconds to wait for each import",
    )
    parser.add_argument(
        "--no-auto-select",
        action="store_false",
        dest="auto_select",
        help="stop after probing even when exactly one plug-in matches",
    )
    parser.set_defaults(auto_select=True)
    parser.add_argument(
        "--preferred-plugin",
        dest="preferred_plugin_id",
        help="require and select this plug-in ID after probing",
    )
    parser.add_argument(
        "--content-type",
        help="override MIME type for every input",
    )
    parser.add_argument(
        "--node-hint",
        help="optional node identity hint supplied to probe and ingestion",
    )
    parser.add_argument(
        "--metadata-json",
        type=_metadata_object,
        default={},
        metavar="OBJECT",
        help="bounded JSON object supplied to the selected plug-in",
    )
    parser.add_argument(
        "--output",
        type=Path,
        dest="output_path",
        help="write the complete JSON result document to this path",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="pretty-print JSON instead of canonical compact JSON",
    )
    parser.add_argument(
        "--retention-policy",
        type=Path,
        dest="retention_policy_path",
        help=(
            "optional router_dump_analyzer.retention_policy.v1 JSON used "
            "to enforce ingestion quotas"
        ),
    )
    return parser


def parse_args(
    argv: Sequence[str] | None = None,
) -> HeadlessIngestionConfiguration:
    namespace = build_parser().parse_args(argv)
    return HeadlessIngestionConfiguration(
        state_dir=namespace.state_dir,
        tenant_id=namespace.tenant_id,
        project_id=namespace.project_id,
        workspace_id=namespace.workspace_id,
        project_label=namespace.project_label,
        workspace_label=namespace.workspace_label,
        plugin_names=tuple(namespace.plugin),
        plugin_modules=tuple(namespace.plugin_module),
        input_paths=tuple(namespace.input_paths),
        timeout_seconds=namespace.timeout_seconds,
        auto_select=namespace.auto_select,
        preferred_plugin_id=namespace.preferred_plugin_id,
        content_type=namespace.content_type,
        node_hint=namespace.node_hint,
        metadata=dict(namespace.metadata_json),
        output_path=namespace.output_path,
        pretty=namespace.pretty,
        retention_policy_path=namespace.retention_policy_path,
    )


def _load_plugins(
    configuration: HeadlessIngestionConfiguration,
    *,
    entry_point_loader: Callable[[str], Any],
    module_loader: Callable[[str], Any],
) -> tuple[LoadedPlugin, ...]:
    values = [
        loaded_entry_point(name, loader=entry_point_loader)
        for name in configuration.plugin_names
    ]
    values.extend(
        loaded_module(target, loader=module_loader)
        for target in configuration.plugin_modules
    )
    return tuple(values)


def _ensure_scope(
    control_plane: ControlPlane,
    configuration: HeadlessIngestionConfiguration,
) -> None:
    try:
        control_plane.sessions.get_project(
            configuration.tenant_id,
            configuration.project_id,
        )
    except KeyError:
        control_plane.sessions.create_project(
            configuration.tenant_id,
            configuration.project_label,
            project_id=configuration.project_id,
            idempotency_key=(
                f"headless:project:{configuration.tenant_id}:{configuration.project_id}"
            ),
        )
    try:
        workspace = control_plane.sessions.get_workspace(
            configuration.tenant_id,
            configuration.workspace_id,
        )
    except KeyError:
        control_plane.sessions.create_workspace(
            configuration.tenant_id,
            configuration.project_id,
            configuration.workspace_label,
            workspace_id=configuration.workspace_id,
            idempotency_key=(
                "headless:workspace:"
                f"{configuration.tenant_id}:{configuration.project_id}:"
                f"{configuration.workspace_id}"
            ),
        )
    else:
        if workspace.project_id != configuration.project_id:
            raise ValueError("the requested workspace belongs to a different project")


def _file_digest(path: Path, chunk_bytes: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(chunk_bytes):
            digest.update(block)
    return digest.hexdigest()


def _file_chunks(path: Path, chunk_bytes: int) -> Any:
    with path.open("rb") as stream:
        while block := stream.read(chunk_bytes):
            yield block


def _effective_content_type(
    configuration: HeadlessIngestionConfiguration,
    path: Path,
) -> str:
    return (
        configuration.content_type
        or mimetypes.guess_type(path.name)[0]
        or "application/octet-stream"
    )


def _idempotency_key(
    configuration: HeadlessIngestionConfiguration,
    path: Path,
    content_sha256: str,
    *,
    effective_content_type: str,
    registry_fingerprint: str,
) -> str:
    material = {
        "schema_version": "router_dump_analyzer.headless_import.v2",
        "tenant_id": configuration.tenant_id,
        "project_id": configuration.project_id,
        "workspace_id": configuration.workspace_id,
        "original_name": path.name,
        "content_sha256": content_sha256,
        "auto_select": configuration.auto_select,
        "preferred_plugin_id": configuration.preferred_plugin_id,
        "content_type": effective_content_type,
        "node_hint": configuration.node_hint,
        "metadata": configuration.metadata,
        "plugin_registry_fingerprint": registry_fingerprint,
    }
    return (
        "headless:"
        + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
    )


def _result_record(
    descriptor: ImportDescriptor,
    *,
    input_path: Path,
    candidates: Sequence[Any] = (),
    timed_out: bool = False,
) -> dict[str, Any]:
    result = descriptor.as_dict()
    result["input_path"] = str(input_path)
    result["timed_out"] = timed_out
    if candidates:
        result["plugin_candidates"] = [candidate.as_dict() for candidate in candidates]
    return result


def _encode_document(document: dict[str, Any], *, pretty: bool) -> str:
    # Keep stdout strictly ASCII so the command remains scriptable on Windows
    # consoles and redirected streams configured with legacy code pages.
    # JSON escapes preserve the exact Unicode value for every consumer.
    return json.dumps(
        document,
        ensure_ascii=True,
        indent=2 if pretty else None,
        sort_keys=True,
        separators=None if pretty else (",", ":"),
        allow_nan=False,
    )


def run(
    configuration: HeadlessIngestionConfiguration,
    *,
    entry_point_loader: Callable[[str], Any] = load_plugin_entry_point,
    module_loader: Callable[[str], Any] = load_plugin_module,
    stdout: TextIO = sys.stdout,
    pipeline_limits: PipelineLimits | None = None,
) -> int:
    inputs = tuple(path.expanduser().resolve() for path in configuration.input_paths)
    for path in inputs:
        if not path.is_file():
            raise FileNotFoundError(f"ingestion input is not a file: {path}")
    loaded_plugins = _load_plugins(
        configuration,
        entry_point_loader=entry_point_loader,
        module_loader=module_loader,
    )
    registry = PluginRegistry(require_executable_identity=True)
    for loaded_plugin in loaded_plugins:
        loaded_plugin.register(registry)
    registry_fingerprint = registry.fingerprint()
    effective_pipeline_limits = pipeline_limits or PipelineLimits()
    effective_pipeline_limits = replace(
        effective_pipeline_limits,
        plugin_execution_mode=PluginExecutionMode.PROCESS,
        plugin_execution_timeout_seconds=max(
            0.05,
            min(
                effective_pipeline_limits.plugin_execution_timeout_seconds,
                configuration.timeout_seconds,
            ),
        ),
        publisher_execution_timeout_seconds=max(
            0.05,
            min(
                effective_pipeline_limits.effective_publisher_execution_timeout_seconds,
                configuration.timeout_seconds,
            ),
        ),
    )
    state_dir = configuration.state_dir.expanduser().resolve()
    retention_policy = None
    if configuration.retention_policy_path is not None:
        from .maintenance_cli import load_policy

        retention_policy = load_policy(configuration.retention_policy_path).ingestion
    records: list[dict[str, Any]] = []
    exit_code = 0
    with ControlPlane(
        state_dir,
        registry=registry,
        pipeline_limits=effective_pipeline_limits,
        retention_policy=retention_policy,
    ) as control_plane:
        _ensure_scope(control_plane, configuration)
        scope = control_plane.import_scope(
            configuration.tenant_id,
            configuration.project_id,
            configuration.workspace_id,
        )
        for path in inputs:
            effective_content_type = _effective_content_type(
                configuration,
                path,
            )
            content_sha256 = _file_digest(
                path,
                control_plane.ingestion.limits.upload_chunk_bytes,
            )
            admitted = control_plane.ingestion.submit_chunks(
                scope,
                _file_chunks(
                    path,
                    control_plane.ingestion.limits.upload_chunk_bytes,
                ),
                original_name=path.name,
                content_type=effective_content_type,
                idempotency_key=_idempotency_key(
                    configuration,
                    path,
                    content_sha256,
                    effective_content_type=effective_content_type,
                    registry_fingerprint=registry_fingerprint,
                ),
                auto_select=configuration.auto_select,
                preferred_plugin_id=configuration.preferred_plugin_id,
                node_hint=configuration.node_hint,
                metadata=configuration.metadata,
            )
            try:
                completed = control_plane.ingestion.wait(
                    scope,
                    admitted.import_id,
                    timeout=configuration.timeout_seconds,
                )
            except TimeoutError:
                completed = control_plane.ingestion.get_import(
                    scope,
                    admitted.import_id,
                )
                records.append(
                    _result_record(
                        completed,
                        input_path=path,
                        timed_out=True,
                    )
                )
                exit_code = 1
                continue
            candidates = (
                control_plane.ingestion.candidates(
                    scope,
                    completed.import_id,
                )
                if completed.state is ImportState.AWAITING_SELECTION
                else ()
            )
            records.append(
                _result_record(
                    completed,
                    input_path=path,
                    candidates=candidates,
                )
            )
            if completed.state is ImportState.AWAITING_SELECTION:
                if exit_code == 0:
                    exit_code = 2
            elif completed.state is not ImportState.COMPLETED:
                exit_code = 1

    document = {
        "schema_version": "router_dump_analyzer.headless_result.v1",
        "scope": {
            "tenant_id": configuration.tenant_id,
            "project_id": configuration.project_id,
            "workspace_id": configuration.workspace_id,
        },
        "summary": {
            "input_count": len(records),
            "completed_count": sum(
                item["state"] == ImportState.COMPLETED.value for item in records
            ),
            "awaiting_selection_count": sum(
                item["state"] == ImportState.AWAITING_SELECTION.value
                for item in records
            ),
            "failed_count": sum(
                item["state"]
                in {
                    ImportState.FAILED.value,
                    ImportState.CANCELLED.value,
                }
                or item["timed_out"]
                for item in records
            ),
            "exit_code": exit_code,
        },
        "imports": records,
    }
    encoded = _encode_document(document, pretty=configuration.pretty)
    stdout.write(encoded)
    stdout.write("\n")
    if configuration.output_path is not None:
        output = configuration.output_path.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded + "\n", encoding="utf-8")
    return exit_code


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    try:
        configuration = parse_args(argv)
        exit_code = run(configuration)
    except (LookupError, OSError, RuntimeError, TypeError, ValueError) as error:
        parser.exit(1, f"router-dump-ingest: error: {_public_cli_error(error)}\n")
    if exit_code:
        raise SystemExit(exit_code)


def _public_cli_error(error: Exception) -> str:
    """Map pre-import command failures onto a closed, non-diagnostic vocabulary."""

    if isinstance(error, IngestionStateRootPathError):
        # This exception is constructed from counts and fixed core budgets; it
        # deliberately contains no state-root value or host path.
        return str(error)
    if isinstance(error, LookupError):
        return "the requested plug-in could not be loaded"
    if isinstance(error, OSError):
        return "required input or durable state could not be accessed"
    if isinstance(error, (TypeError, ValueError)):
        return "the ingestion command was rejected"
    return "the ingestion command failed"


if __name__ == "__main__":
    main()


__all__ = [
    "HeadlessIngestionConfiguration",
    "build_parser",
    "main",
    "parse_args",
    "run",
]
