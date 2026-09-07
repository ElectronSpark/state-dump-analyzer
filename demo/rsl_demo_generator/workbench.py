"""Generate compact raw inputs for the same demo's durable-workflow exercises.

This stdlib-only writer neither imports the analyzer nor publishes revisions.
It leaves the canonical million-event archive entirely alone. Existing files
are accepted only when byte-identical; user-edited inputs are never overwritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def workflow_inputs() -> dict[str, bytes]:
    """Return deterministic raw status files and their expected outcomes."""
    base = 1_759_680_000_000_000_000
    result: dict[str, bytes] = {}
    for name, delay, statuses in (
        ("before", 0, ("down", "down", "up")),
        ("after", 60_000_000_000, ("up", "up", "up")),
        ("peer", 15_000_000_000, ("up", "up", "unknown")),
    ):
        rows = []
        for index, (ifindex, label, status) in enumerate(
            zip((7, 107, 8), ("uplink", "uplink", "peer-link"), statuses)
        ):
            rows.append(
                {
                    "kind": "interface",
                    "captured_at_ns": base + delay,
                    "source_sequence": (index + 1) * 10,
                    "lifecycle": "create",
                    "ifindex": ifindex,
                    "name": label,
                    "admin_status": "up",
                    "oper_status": status,
                    "description": f"Synthetic workbench {name}; independent view {ifindex}",
                }
            )
        result[f"{name}/minimal-status.jsonl"] = (
            "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n"
        ).encode("utf-8")
    manifest = {
        "format": "router-state-lab-workbench-v1",
        "synthetic": True,
        "scale_archive_modified": False,
        "inputs": [
            {
                "file": name,
                "node_hint": "workbench-peer"
                if name.startswith("peer/")
                else "workbench-router",
                "sha256": hashlib.sha256(data).hexdigest(),
                "expected_resources": 3,
                "expected_corresponds_to": 1,
                "expected_finding": "pass" if name.startswith("after/") else "fail",
            }
            for name, data in result.items()
        ],
    }
    result["manifest.json"] = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    return result


def write_workflow_inputs(directory: Path) -> tuple[Path, ...]:
    """Create only missing outputs, checking all conflicts before writing any."""
    directory = Path(directory)
    outputs = workflow_inputs()
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise ValueError("output directory must be a regular directory")
    for name, content in outputs.items():
        target = directory / name
        if (
            (target.parent.exists() and not target.parent.is_dir())
            or target.parent.is_symlink()
            or target.is_symlink()
            or (
                target.exists()
                and (
                    not target.is_file()
                    or target.stat().st_size != len(content)
                    or target.read_bytes() != content
                )
            )
        ):
            raise ValueError(
                "output directory contains a conflicting workflow input; choose a new directory"
            )
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(content)
    return tuple(directory / name for name in outputs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        paths = write_workflow_inputs(args.output_dir)
    except (OSError, ValueError):
        parser.exit(
            2,
            "Cannot write workbench inputs; use a writable new directory or identical generated inputs.\n",
        )
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
