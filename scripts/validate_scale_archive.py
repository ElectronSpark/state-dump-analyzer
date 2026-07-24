"""Validate that a packed scale archive matches the launcher's target."""

from __future__ import annotations

import argparse
import json
import tarfile
from pathlib import Path
from typing import Any


PACK_MANIFEST = "router-state-lab-100k/manifest.json"
SCENARIO_ID = "evpn-multihome-mass-failover-v2"


def read_pack_manifest(archive_path: Path) -> dict[str, Any] | None:
    try:
        with tarfile.open(archive_path, mode="r|gz") as archive:
            for member in archive:
                if member.name != PACK_MANIFEST:
                    continue
                source = archive.extractfile(member)
                if source is None:
                    return None
                value = json.load(source)
                return value if isinstance(value, dict) else None
    except (OSError, tarfile.TarError, json.JSONDecodeError, ValueError):
        return None
    return None


def archive_matches(
    archive_path: Path,
    *,
    minimum_events: int,
    resource_count: int,
    minimum_generator_version: int,
) -> bool:
    manifest = read_pack_manifest(archive_path)
    if manifest is None:
        return False
    scale = manifest.get("scale") or {}
    source = manifest.get("source") or {}
    try:
        return (
            int(manifest.get("format_version", 0)) >= 2
            and manifest.get("scenario_id") == SCENARIO_ID
            and int(source.get("scale_generator_version", 0))
            >= minimum_generator_version
            and int(scale.get("events", 0)) >= minimum_events
            and int(scale.get("resources", 0)) == resource_count
        )
    except (TypeError, ValueError):
        return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("minimum_events", type=int)
    parser.add_argument("resource_count", type=int)
    parser.add_argument("minimum_generator_version", type=int)
    args = parser.parse_args()
    raise SystemExit(
        0
        if archive_matches(
            args.archive,
            minimum_events=args.minimum_events,
            resource_count=args.resource_count,
            minimum_generator_version=args.minimum_generator_version,
        )
        else 1
    )


if __name__ == "__main__":
    main()
