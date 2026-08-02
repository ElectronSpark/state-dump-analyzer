"""Read-only, scriptable durable queue health probe."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from .canonical import canonical_json
from .ingestion_pipeline import QueueHealthSnapshot, inspect_durable_queue
from .value_core import parse_canonical_decimal_integer

HEALTH_SCHEMA_VERSION = "router_dump_analyzer.queue_health.v1"
EXIT_HEALTHY = 0
EXIT_ERROR = 1
EXIT_DEGRADED = 2


def _stall_seconds(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("value must be a number") from error
    if not math.isfinite(parsed) or not 5 <= parsed <= 7 * 24 * 60 * 60:
        raise argparse.ArgumentTypeError(
            "value must be finite and between 5 and 604800"
        )
    return parsed


def _timestamp(value: str) -> int:
    try:
        return parse_canonical_decimal_integer(
            value,
            "now_ns",
            minimum=0,
            maximum=2**63 - 1,
        )
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="router-dump-health",
        description=(
            "Inspect durable ingestion queue depth and age without opening "
            "an analysis session or loading a plug-in."
        ),
    )
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument(
        "--stalled-after",
        type=_stall_seconds,
        default=900.0,
        dest="stalled_after_seconds",
        help="seconds without queue progress before an import is stalled",
    )
    parser.add_argument(
        "--now-ns",
        type=_timestamp,
        help="fixed wall-clock timestamp for deterministic CI checks",
    )
    parser.add_argument("--pretty", action="store_true")
    return parser


def _document(snapshot: QueueHealthSnapshot) -> dict[str, object]:
    healthy = (
        snapshot.stalled_imports == 0
        and snapshot.catalog_attention_imports == 0
        and snapshot.observation_error is None
    )
    return {
        "schema": HEALTH_SCHEMA_VERSION,
        "status": "ok" if healthy else "degraded",
        "healthy": healthy,
        "evaluated_at_ns": str(snapshot.evaluated_at_ns),
        "stall_after_seconds": snapshot.stall_after_seconds,
        "pending_imports": snapshot.pending_imports,
        "awaiting_selection_imports": snapshot.awaiting_selection_imports,
        "stalled_imports": snapshot.stalled_imports,
        "oldest_pending_updated_at_ns": (
            None
            if snapshot.oldest_pending_updated_at_ns is None
            else str(snapshot.oldest_pending_updated_at_ns)
        ),
        "state_counts": dict(snapshot.state_counts),
        "observation_error": snapshot.observation_error,
        "catalog_attention_imports": snapshot.catalog_attention_imports,
    }


def run(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    namespace = build_parser().parse_args(argv)
    database_path = namespace.state_dir.expanduser().resolve() / "control-plane.sqlite3"
    try:
        snapshot = inspect_durable_queue(
            database_path,
            stall_after_seconds=namespace.stalled_after_seconds,
            now_ns=namespace.now_ns,
        )
    except Exception as error:  # noqa: BLE001 - CLI emits a bounded failure.
        print(
            canonical_json(
                {
                    "schema": HEALTH_SCHEMA_VERSION,
                    "status": "error",
                    "error": type(error).__name__,
                }
            ),
            file=stderr,
        )
        return EXIT_ERROR
    document = _document(snapshot)
    encoded = (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True)
        if namespace.pretty
        else canonical_json(document)
    )
    print(encoded, file=stdout)
    return EXIT_HEALTHY if document["healthy"] else EXIT_DEGRADED


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":  # pragma: no cover - console entry point.
    raise SystemExit(main())


__all__ = [
    "EXIT_DEGRADED",
    "EXIT_ERROR",
    "EXIT_HEALTHY",
    "HEALTH_SCHEMA_VERSION",
    "build_parser",
    "main",
    "run",
]
