"""Generate the deterministic CTF trace embedded in every node pack."""

from __future__ import annotations

import json
import struct

from rsl_demo_plugin.archive import (
    CTF_METADATA_MEMBER,
    CTF_STREAM_MEMBER,
)
from ._archive import deterministic_tgz_bytes


def synthetic_router_ctf2_archive() -> bytes:
    """Build a small product-shaped CTF 2 trace."""

    metadata_uuid = bytes.fromhex("00112233445566778899aabbccddeeff")
    metadata_documents = [
        {
            "type": "preamble",
            "uuid": list(metadata_uuid),
            "version": 2,
        },
        {
            "type": "trace-class",
            "uid": "00112233-4455-6677-8899-aabbccddeeff",
            "packet-header-field-class": {
                "type": "structure",
                "member-classes": [
                    {
                        "name": "magic",
                        "field-class": {
                            "type": "fixed-length-unsigned-integer",
                            "length": 32,
                            "alignment": 32,
                            "byte-order": "little-endian",
                            "preferred-display-base": 16,
                            "roles": ["packet-magic-number"],
                        },
                    },
                    {
                        "name": "uuid",
                        "field-class": {
                            "type": "static-length-blob",
                            "length": 16,
                            "roles": ["metadata-stream-uuid"],
                        },
                    },
                ],
            },
        },
        {"type": "data-stream-class"},
        {
            "type": "event-record-class",
            "name": "router-resource-update",
            "payload-field-class": {
                "type": "structure",
                "member-classes": [
                    {
                        "name": "timestamp_ns",
                        "field-class": {
                            "type": "fixed-length-unsigned-integer",
                            "length": 64,
                            "alignment": 8,
                            "byte-order": "little-endian",
                            "preferred-display-base": 10,
                        },
                    },
                    *(
                        {
                            "name": name,
                            "field-class": {
                                "type": "null-terminated-string",
                            },
                        }
                        for name in (
                            "resource",
                            "action",
                            "properties_json",
                            "result_key",
                            "result_value",
                        )
                    ),
                ],
            },
        },
    ]
    metadata = b"".join(
        b"\x1e"
        + json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
        for document in metadata_documents
    )

    records = (
        (
            1_759_680_000_100_000_000,
            "route:blue:203.0.113.0/24",
            "create",
            '{"etg":"etg-100","next_hop":"192.0.2.0"}',
            "routeStatus",
            "Ok",
        ),
        (
            1_759_680_003_015_000_000,
            "ete:etg-100:ete-b",
            "update",
            '{"error":"neighbor-unresolved","program_state":"error"}',
            "bridgeStatus",
            "DependencyError",
        ),
    )
    stream = bytearray(b"\xc1\x1f\xfc\xc1" + metadata_uuid)
    for timestamp_ns, *strings in records:
        stream.extend(struct.pack("<Q", timestamp_ns))
        for value in strings:
            stream.extend(value.encode("utf-8") + b"\x00")
    return deterministic_tgz_bytes(
        {
            CTF_METADATA_MEMBER: metadata,
            CTF_STREAM_MEMBER: bytes(stream),
        }
    )


__all__ = ["synthetic_router_ctf2_archive"]
