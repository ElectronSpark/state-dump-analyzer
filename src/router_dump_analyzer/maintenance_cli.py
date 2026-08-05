"""Headless, fail-closed retention maintenance for durable control-plane state.

The command opens an existing single-host control plane without starting its
ingestion workers.  A versioned JSON policy supplies the three store-specific
retention policies.  Inventory is the default; destructive work requires both
``--execute`` and the relevant policy's explicit ``enabled`` flag.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from enum import Enum
from pathlib import Path
from typing import Any, TextIO

from .annotation_store import (
    ReviewRetentionInventory,
    ReviewRetentionPolicy,
    ReviewRetentionResult,
)
from .control_plane import ControlPlane, ControlPlaneRetentionResult
from .ingestion_pipeline import PluginRegistry, RetentionPolicy
from .session_store import (
    CatalogRetentionInventory,
    CatalogRetentionPolicy,
    CatalogRetentionResult,
)
from .value_core import parse_canonical_decimal_integer

POLICY_SCHEMA_VERSION = "router_dump_analyzer.retention_policy.v1"
RESULT_SCHEMA_VERSION = "router_dump_analyzer.retention_maintenance.v1"
MAX_POLICY_BYTES = 1024 * 1024
MAX_ACTOR_CHARACTERS = 256
MAX_OPERATION_ID_CHARACTERS = 240
MAX_SQLITE_INTEGER = (1 << 63) - 1
_POLICY_DECIMAL_FIELDS = frozenset(
    {
        "fixture_before_ns",
        "idempotency_before_ns",
        "revision_before_ns",
        "snapshot_before_ns",
        "tombstone_before_ns",
    }
)


class RetentionMaintenanceInputError(ValueError):
    """A policy or command option is not a valid maintenance request."""


class RetentionMaintenanceScopeError(LookupError):
    """The requested pre-existing catalog scope could not be resolved."""


@dataclass(frozen=True, slots=True)
class RetentionMaintenanceConfiguration:
    state_dir: Path
    tenant_id: str
    project_id: str
    workspace_id: str
    policy_path: Path
    execute: bool
    actor: str | None
    operation_id: str | None
    now_ns: int | None
    output_path: Path | None
    pretty: bool


@dataclass(frozen=True, slots=True)
class RetentionMaintenancePolicies:
    ingestion: RetentionPolicy
    catalog: CatalogRetentionPolicy
    review: ReviewRetentionPolicy


def _non_negative_integer(value: str) -> int:
    try:
        return parse_canonical_decimal_integer(
            value,
            "value",
            minimum=0,
            maximum=MAX_SQLITE_INTEGER,
        )
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "value must be a non-negative decimal integer"
        ) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="router-dump-maintain",
        description=(
            "Inventory or execute bounded retention for one existing durable "
            "tenant/project/workspace scope. Non-destructive inventory is "
            "the default."
        ),
    )
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--tenant", required=True, dest="tenant_id")
    parser.add_argument("--project", required=True, dest="project_id")
    parser.add_argument("--workspace", required=True, dest="workspace_id")
    parser.add_argument(
        "--policy",
        required=True,
        type=Path,
        dest="policy_path",
        help=f"{POLICY_SCHEMA_VERSION} JSON policy file",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help=(
            "permit destructive work for policy sections whose enabled flag "
            "is true; omit for a non-destructive inventory"
        ),
    )
    parser.add_argument(
        "--actor",
        help="bounded audit actor; required with --execute",
    )
    parser.add_argument(
        "--operation-id",
        help="stable audit operation ID; required with --execute",
    )
    parser.add_argument(
        "--now-ns",
        type=_non_negative_integer,
        help="fixed non-negative wall-clock timestamp for reproducible runs",
    )
    parser.add_argument(
        "--output",
        type=Path,
        dest="output_path",
        help="also write the complete result document to this file",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="pretty-print JSON instead of canonical compact JSON",
    )
    return parser


def parse_args(
    argv: Sequence[str] | None = None,
) -> RetentionMaintenanceConfiguration:
    parser = build_parser()
    namespace = parser.parse_args(argv)
    if namespace.execute and not namespace.actor:
        parser.error("--actor is required with --execute")
    if namespace.execute and not namespace.operation_id:
        parser.error("--operation-id is required with --execute")
    return RetentionMaintenanceConfiguration(
        state_dir=namespace.state_dir,
        tenant_id=namespace.tenant_id,
        project_id=namespace.project_id,
        workspace_id=namespace.workspace_id,
        policy_path=namespace.policy_path,
        execute=namespace.execute,
        actor=namespace.actor,
        operation_id=namespace.operation_id,
        now_ns=namespace.now_ns,
        output_path=namespace.output_path,
        pretty=namespace.pretty,
    )


def _reject_json_constant(value: str) -> None:
    raise RetentionMaintenanceInputError(
        f"the policy must not contain the JSON constant {value}"
    )


def _object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RetentionMaintenanceInputError(
                "the policy must not contain duplicate object keys"
            )
        value[key] = item
    return value


def _policy_section(
    value: object,
    *,
    label: str,
    policy_type: type[Any],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RetentionMaintenanceInputError(
            f"the {label} policy section must be a JSON object"
        )
    allowed = {field.name for field in fields(policy_type)}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise RetentionMaintenanceInputError(
            f"the {label} policy section contains unsupported fields"
        )
    result = dict(value)
    for field_name, item in tuple(result.items()):
        if field_name not in _POLICY_DECIMAL_FIELDS or not isinstance(item, str):
            continue
        try:
            parsed = parse_canonical_decimal_integer(
                item,
                f"{label} {field_name}",
            )
        except ValueError as error:
            raise RetentionMaintenanceInputError(
                f"the {label} {field_name} must be a canonical decimal integer"
            ) from error
        result[field_name] = parsed
    return result


def load_policy(path: Path) -> RetentionMaintenancePolicies:
    resolved = path.expanduser().resolve()
    if resolved.stat().st_size > MAX_POLICY_BYTES:
        raise RetentionMaintenanceInputError(
            f"the policy must contain 1 to {MAX_POLICY_BYTES} bytes"
        )
    with resolved.open("rb") as stream:
        raw = stream.read(MAX_POLICY_BYTES + 1)
    if not raw or len(raw) > MAX_POLICY_BYTES:
        raise RetentionMaintenanceInputError(
            f"the policy must contain 1 to {MAX_POLICY_BYTES} bytes"
        )
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RetentionMaintenanceInputError(
            "the policy must be valid UTF-8"
        ) from error
    try:
        document = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise RetentionMaintenanceInputError("the policy must be valid JSON") from error
    if not isinstance(document, dict):
        raise RetentionMaintenanceInputError("the policy must be a JSON object")
    allowed_top_level = {"schema_version", "ingestion", "catalog", "review"}
    if set(document) - allowed_top_level:
        raise RetentionMaintenanceInputError(
            "the policy contains unsupported top-level fields"
        )
    if document.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise RetentionMaintenanceInputError(
            f"the policy schema_version must be {POLICY_SCHEMA_VERSION}"
        )
    ingestion = _policy_section(
        document.get("ingestion", {}),
        label="ingestion",
        policy_type=RetentionPolicy,
    )
    catalog = _policy_section(
        document.get("catalog", {}),
        label="catalog",
        policy_type=CatalogRetentionPolicy,
    )
    review = _policy_section(
        document.get("review", {}),
        label="review",
        policy_type=ReviewRetentionPolicy,
    )
    try:
        return RetentionMaintenancePolicies(
            ingestion=RetentionPolicy(**ingestion),
            catalog=CatalogRetentionPolicy(**catalog),
            review=ReviewRetentionPolicy(**review),
        )
    except (TypeError, ValueError) as error:
        raise RetentionMaintenanceInputError(
            "the policy contains invalid retention values"
        ) from error


def _policy_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_policy_value(item) for item in value]
    return value


def _policy_document(policy: Any) -> dict[str, Any]:
    return {
        field.name: _policy_value(getattr(policy, field.name))
        for field in fields(policy)
    }


def _candidate_document(candidate: Any) -> dict[str, Any]:
    document = {
        "blockers": list(candidate.blockers),
        "category": candidate.category,
        "identifier": candidate.identifier,
        "retention_value": candidate.retention_value,
    }
    qualifier = getattr(candidate, "qualifier", None)
    if qualifier is not None:
        document["qualifier"] = qualifier
    return document


def _sorted_candidates(values: Sequence[Any]) -> list[dict[str, Any]]:
    return [
        _candidate_document(candidate)
        for candidate in sorted(
            values,
            key=lambda item: (
                item.category,
                item.retention_value,
                item.identifier,
                tuple(item.blockers),
                getattr(item, "qualifier", "") or "",
            ),
        )
    ]


def _catalog_document(
    value: CatalogRetentionInventory | CatalogRetentionResult,
) -> dict[str, Any]:
    if isinstance(value, CatalogRetentionResult):
        inventory = value.inventory
        purged = _sorted_candidates(value.purged)
        releases = [
            {
                "artifact_kind": release.artifact_kind,
                "artifact_ref": release.artifact_ref,
                "owner_operation_id": release.owner_operation_id,
                "catalog_category": release.catalog_category,
                "catalog_identifier": release.catalog_identifier,
            }
            for release in sorted(
                value.artifact_releases,
                key=lambda item: (
                    item.artifact_kind,
                    item.artifact_ref,
                    item.owner_operation_id,
                    item.catalog_category,
                    item.catalog_identifier,
                ),
            )
        ]
        executed = True
    else:
        inventory = value
        purged = []
        releases = []
        executed = False
    return {
        "executed": executed,
        "policy": _policy_document(inventory.policy),
        "total_candidate_count": inventory.total_candidate_count,
        "candidates": _sorted_candidates(inventory.candidates),
        "truncated": inventory.truncated,
        "purged": purged,
        "artifact_releases": releases,
    }


def _review_document(
    value: ReviewRetentionInventory | ReviewRetentionResult,
) -> dict[str, Any]:
    if isinstance(value, ReviewRetentionResult):
        inventory = value.inventory
        purged = _sorted_candidates(value.purged)
        executed = True
    else:
        inventory = value
        purged = []
        executed = False
    return {
        "executed": executed,
        "policy": _policy_document(inventory.policy),
        "total_candidate_count": inventory.total_candidate_count,
        "candidates": _sorted_candidates(inventory.candidates),
        "truncated": inventory.truncated,
        "purged": purged,
    }


def result_document(
    result: ControlPlaneRetentionResult,
    *,
    requested_mode: str,
) -> dict[str, Any]:
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "mode": requested_mode,
        "scope": {
            "tenant_id": result.scope.tenant_id,
            "project_id": result.scope.project_id,
            "workspace_id": result.scope.workspace_id,
        },
        "executed": result.executed,
        "observation_mode": result.observation_mode.value,
        "replayed_release_actions": result.replayed_release_actions,
        "replayed_artifact_releases": result.replayed_artifact_releases,
        "ingestion": result.ingestion.as_dict(),
        "catalog": _catalog_document(result.catalog),
        "review": _review_document(result.review),
    }


def _encode_document(document: Mapping[str, Any], *, pretty: bool) -> str:
    return json.dumps(
        document,
        ensure_ascii=True,
        indent=2 if pretty else None,
        sort_keys=True,
        separators=None if pretty else (",", ":"),
        allow_nan=False,
    )


def _bounded_command_identity(
    value: str | None,
    *,
    label: str,
    maximum: int,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise RetentionMaintenanceInputError(
            f"{label} must be a bounded, non-control string"
        )
    return value


def run(
    configuration: RetentionMaintenanceConfiguration,
    *,
    stdout: TextIO = sys.stdout,
) -> int:
    policies = load_policy(configuration.policy_path)
    actor: str | None = None
    operation_id: str | None = None
    if configuration.execute:
        actor = _bounded_command_identity(
            configuration.actor,
            label="actor",
            maximum=MAX_ACTOR_CHARACTERS,
        )
        operation_id = _bounded_command_identity(
            configuration.operation_id,
            label="operation_id",
            maximum=MAX_OPERATION_ID_CHARACTERS,
        )
    state_dir = configuration.state_dir.expanduser().resolve()
    required_state = (
        state_dir / "sessions.sqlite3",
        state_dir / "annotations.sqlite3",
        state_dir / "control-plane.sqlite3",
        state_dir / "private-analysis-runs.sqlite3",
    )
    if not state_dir.is_dir() or any(not path.is_file() for path in required_state):
        raise RetentionMaintenanceScopeError(
            "the requested maintenance scope does not exist"
        )
    control_plane = ControlPlane(
        state_dir,
        registry=PluginRegistry((), require_executable_identity=True),
        retention_policy=policies.ingestion,
    )
    try:
        try:
            scope = control_plane.scope(
                configuration.tenant_id,
                configuration.project_id,
                configuration.workspace_id,
            )
        except KeyError as error:
            raise RetentionMaintenanceScopeError(
                "the requested maintenance scope does not exist"
            ) from error
        if configuration.execute:
            assert actor is not None
            assert operation_id is not None
            result = control_plane.run_retention(
                scope,
                catalog_policy=policies.catalog,
                review_policy=policies.review,
                actor=actor,
                operation_id=operation_id,
                now_ns=configuration.now_ns,
            )
            requested_mode = "execute"
        else:
            result = control_plane.retention_inventory(
                scope,
                catalog_policy=policies.catalog,
                review_policy=policies.review,
                now_ns=configuration.now_ns,
            )
            requested_mode = "dry_run"
    finally:
        control_plane.close()
    encoded = _encode_document(
        result_document(result, requested_mode=requested_mode),
        pretty=configuration.pretty,
    )
    stdout.write(encoded)
    stdout.write("\n")
    if configuration.output_path is not None:
        output = configuration.output_path.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=output.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(encoded)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(output)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    return 0


def _public_cli_error(error: Exception) -> str:
    if isinstance(error, RetentionMaintenanceScopeError):
        return "the requested maintenance scope does not exist"
    if isinstance(error, OSError):
        return "the policy or durable state could not be accessed"
    if isinstance(error, (RetentionMaintenanceInputError, TypeError, ValueError)):
        return "the maintenance request was rejected"
    return "the maintenance operation failed"


def main(argv: Sequence[str] | None = None) -> None:
    try:
        exit_code = run(parse_args(argv))
    except (LookupError, OSError, RuntimeError, TypeError, ValueError) as error:
        build_parser().exit(
            1,
            f"router-dump-maintain: error: {_public_cli_error(error)}\n",
        )
    if exit_code == 0:
        return
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()


__all__ = [
    "POLICY_SCHEMA_VERSION",
    "RESULT_SCHEMA_VERSION",
    "RetentionMaintenanceConfiguration",
    "RetentionMaintenanceInputError",
    "RetentionMaintenancePolicies",
    "RetentionMaintenanceScopeError",
    "build_parser",
    "load_policy",
    "main",
    "parse_args",
    "result_document",
    "run",
]
