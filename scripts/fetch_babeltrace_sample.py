"""Fetch a tiny, valid, CC0 CTF 2 trace from the Babeltrace test corpus.

The source revision and SHA-256 digests are pinned so the fixture is
reproducible and a changed upstream file cannot be accepted silently.
"""

from __future__ import annotations

import argparse
import os
import tempfile
import urllib.request
from pathlib import Path

try:
    from .ctf_fixture import BASE_URL, COMMIT, FILES, validate_blob
except ImportError:  # Direct ``python scripts/fetch_babeltrace_sample.py`` use.
    from ctf_fixture import BASE_URL, COMMIT, FILES, validate_blob


def fetch(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        target = destination / name
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise RuntimeError(f"refusing non-file CTF fixture target: {target}")
    downloaded: dict[str, bytes] = {}
    for name, (expected_size, _expected_sha256) in FILES.items():
        with urllib.request.urlopen(f"{BASE_URL}/{name}", timeout=30) as response:
            content = response.read(expected_size + 1)
        validate_blob(name, content)
        downloaded[name] = content

    staged: dict[str, Path] = {}
    backups: dict[str, Path] = {}
    published: list[str] = []
    lock = destination / ".ctf-fixture-fetch.lock"
    lock_fd: int | None = None
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        for name in downloaded:
            target = destination / name
            if target.is_symlink() or (target.exists() and not target.is_file()):
                raise RuntimeError(f"refusing non-file CTF fixture target: {target}")
        for name, content in downloaded.items():
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{name}.",
                suffix=".tmp",
                dir=destination,
                delete=False,
            ) as temporary:
                temporary.write(content)
                staged[name] = Path(temporary.name)
        for name, temporary in staged.items():
            target = destination / name
            if target.exists():
                with tempfile.NamedTemporaryFile(
                    prefix=f".{name}.",
                    suffix=".bak",
                    dir=destination,
                    delete=False,
                ) as backup_file:
                    backup = Path(backup_file.name)
                backup.unlink()
                target.replace(backup)
                backups[name] = backup
            temporary.replace(target)
            published.append(name)
    except BaseException:
        for name in reversed(published):
            (destination / name).unlink(missing_ok=True)
        for name, backup in backups.items():
            if backup.exists():
                backup.replace(destination / name)
        raise
    finally:
        try:
            for temporary in staged.values():
                temporary.unlink(missing_ok=True)
            for backup in backups.values():
                backup.unlink(missing_ok=True)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
                lock.unlink(missing_ok=True)


def main() -> None:
    default_destination = (
        Path(__file__).resolve().parents[1] / "samples" / "external" / "ctf2-smalltrace"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=default_destination)
    args = parser.parse_args()
    fetch(args.output.resolve())
    print("Fetched and verified the CTF 2 sample.")


if __name__ == "__main__":
    main()
