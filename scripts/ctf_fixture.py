"""Pinned metadata for the public Babeltrace CTF 2 smoke-test trace."""

from __future__ import annotations

import hashlib


COMMIT = "e4109f9c87f9e93c73abf32c1ffb43e5eaacc4a5"
BASE_URL = (
    "https://raw.githubusercontent.com/efficios/babeltrace/"
    f"{COMMIT}/tests/data/ctf-traces/2/succeed/smalltrace"
)
FILES = {
    "metadata": (
        1195,
        "476e8f7afb93e2cbe1f908733291f54e181a03b255ee1077823e8a3c8ffb0130",
    ),
    "dummystream": (
        69,
        "a5329aa463617c9d780578bf6ef97994e6d702213834f10f7002ffbfbd571e3c",
    ),
}


def validate_blob(name: str, content: bytes) -> None:
    try:
        expected_size, expected_sha256 = FILES[name]
    except KeyError as error:
        raise ValueError(f"unknown pinned CTF fixture member: {name!r}") from error
    if len(content) != expected_size:
        raise RuntimeError(
            f"size mismatch for {name}: {len(content)} != {expected_size}"
        )
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if actual_sha256 != expected_sha256:
        raise RuntimeError(
            f"checksum mismatch for {name}: {actual_sha256} != {expected_sha256}"
        )
