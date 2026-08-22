"""Generate the compact ingestion/temporal corpus used before runtime v2.

The large multi-node assembly remains a runtime-v1 fixture.  This tiny archive
instead keeps raw, heterogeneous artifacts beside a JSON-safe expectation
vector so a future core ingestion coordinator can exercise inventory, parser
dispatch, ordering, identity, and diagnostic behavior without a 100K history.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any, Final

from rsl_demo_plugin import (
    PLUGIN_ID,
    STATUS_FILENAME,
    render_conformance_status_fixture,
)
from rsl_demo_plugin.archive import (
    CTF_METADATA_MEMBER,
    CTF_STREAM_MEMBER,
)

from ._archive import deterministic_tgz_bytes, json_bytes
from ._synthetic_ctf import synthetic_router_ctf2_archive

CONFORMANCE_CORPUS_FORMAT_VERSION = 1
CONFORMANCE_CORPUS_ROOT = "router-dump-ingestion-conformance-v1"
CONFORMANCE_CORPUS_NAME = "runtime-v2-ingestion-conformance.tgz"

STATUS_MEMBER: Final[str] = (
    f"{CONFORMANCE_CORPUS_ROOT}/status/{STATUS_FILENAME}"
)
LOG_MEMBER: Final[str] = f"{CONFORMANCE_CORPUS_ROOT}/logs/router.log"
CTF_MEMBER: Final[str] = f"{CONFORMANCE_CORPUS_ROOT}/ctf/routertrace.tgz"
MALFORMED_STATUS_MEMBER: Final[str] = (
    f"{CONFORMANCE_CORPUS_ROOT}/malformed/truncated-status.jsonl"
)
MALFORMED_CTF_MEMBER: Final[str] = (
    f"{CONFORMANCE_CORPUS_ROOT}/malformed/truncated-ctf.tgz"
)
UNSUPPORTED_MEMBER: Final[str] = (
    f"{CONFORMANCE_CORPUS_ROOT}/unsupported/capture.pcap"
)
EXPECTATIONS_MEMBER: Final[str] = (
    f"{CONFORMANCE_CORPUS_ROOT}/expected/semantics.json"
)
MANIFEST_MEMBER: Final[str] = f"{CONFORMANCE_CORPUS_ROOT}/manifest.json"

_GROUP_UUID = "123e4567-e89b-12d3-a456-426614174000"
_OPAQUE_UUID_BYTES = "00112233445566778899aabbccddeeff"
_BASE_TIMESTAMP_NS = 1_759_680_000_000_000_000


_SEMANTIC_VECTOR: dict[str, Any] = {
    "schema_id": "router-dump-ingestion-temporal-conformance",
    "schema_version": 1,
    "cases": [
        {
            "case_id": "status.exact-integer-and-source-order",
            "execution_stage": "current_example_parser",
            "artifact": STATUS_MEMBER,
            "records": [
                {
                    "line": 1,
                    "timestamp_ns": _BASE_TIMESTAMP_NS,
                    "source_sequence": 10,
                    "lifecycle": "create",
                },
                {
                    "line": 2,
                    "timestamp_ns": _BASE_TIMESTAMP_NS,
                    "source_sequence": 20,
                    "lifecycle": "modify",
                },
            ],
            "expected_order": [10, 20],
            "timestamp_representation": "json_integer",
        },
        {
            "case_id": "status.create-modify-lifecycle",
            "execution_stage": "current_example_parser",
            "artifact": STATUS_MEMBER,
            "resource_key": {
                "namespace": PLUGIN_ID,
                "node": "router-1",
                "layer": "interface",
                "kind": "INTERFACE",
                "parts": [{"name": "ifindex", "type": "integer", "value": 7}],
            },
            "first_lifecycle": "create",
            "following_lifecycle": "modify",
        },
        {
            "case_id": "temporal.insert-is-creation",
            "execution_stage": "shared_temporal_core",
            "operation": "insert",
            "operation_class": "creation",
            "expected_exists_after": True,
        },
        {
            "case_id": "status.validity-window-only-uncertainty",
            "execution_stage": "current_example_parser",
            "artifact": STATUS_MEMBER,
            "line": 4,
            "timestamp_ns": None,
            "observed_at_min_ns": _BASE_TIMESTAMP_NS + 2_000_000,
            "observed_at_max_ns": _BASE_TIMESTAMP_NS + 2_500_000,
            "quality": "best_effort",
        },
        {
            "case_id": "identity.native-key-types",
            "execution_stage": "requires_core_ingestion",
            "keys": {
                "numeric": {
                    "kind": "INTERFACE",
                    "parts": [{"name": "ifindex", "type": "integer", "value": 7}],
                },
                "uuid": {
                    "kind": "TUNNEL_GROUP",
                    "parts": [
                        {
                            "name": "group_uuid",
                            "type": "uuid",
                            "value": _GROUP_UUID,
                        }
                    ],
                },
                "bytes16": {
                    "kind": "HARDWARE_OBJECT",
                    "parts": [
                        {
                            "name": "opaque_id",
                            "type": "bytes",
                            "encoding": "hex",
                            "value": _OPAQUE_UUID_BYTES,
                        }
                    ],
                },
                "compound": {
                    "kind": "TUNNEL_PATH",
                    "parts": [
                        {
                            "name": "group_uuid",
                            "type": "uuid",
                            "value": _GROUP_UUID,
                        },
                        {"name": "path_id", "type": "integer", "value": 3},
                    ],
                },
            },
        },
        {
            "case_id": "relationship.exact-compound-key",
            "execution_stage": "requires_core_ingestion",
            "relation_type": "member_of",
            "source_key": {
                "kind": "TUNNEL_PATH",
                "parts": [
                    {
                        "name": "group_uuid",
                        "type": "uuid",
                        "value": _GROUP_UUID,
                    },
                    {"name": "path_id", "type": "integer", "value": 3},
                ],
            },
            "target_key": {
                "kind": "TUNNEL_GROUP",
                "parts": [
                    {
                        "name": "group_uuid",
                        "type": "uuid",
                        "value": _GROUP_UUID,
                    }
                ],
            },
        },
        {
            "case_id": "relationship.rule-resolved-target",
            "execution_stage": "requires_plugin_projection",
            "relation_type": "resolves_via",
            "match": {
                "matcher_id": "demo.ip-prefix-lpm.v1",
                "arguments": {
                    "vrf": {"type": "string", "value": "blue"},
                    "address": {
                        "type": "ipv6",
                        "value": "2001:db8:100::9",
                    },
                },
            },
            "missing_match_is": "unresolved",
        },
        {
            "case_id": "records.status-log-ctf",
            "execution_stage": "mixed",
            "records": [
                {
                    "source_type": "status-json",
                    "artifact": STATUS_MEMBER,
                    "support": "current_example_parser",
                },
                {
                    "source_type": "syslog",
                    "artifact": LOG_MEMBER,
                    "support": "requires_text_trace_dispatch",
                },
                {
                    "source_type": "ctf",
                    "artifact": CTF_MEMBER,
                    "support": "requires_core_ctf_decoder",
                    "expected_event_count": 2,
                },
            ],
        },
        {
            "case_id": "artifact.malformed-and-unsupported",
            "execution_stage": "requires_core_ingestion",
            "artifacts": [
                {
                    "artifact": MALFORMED_STATUS_MEMBER,
                    "expected": "recoverable_parser_diagnostic",
                },
                {
                    "artifact": MALFORMED_CTF_MEMBER,
                    "expected": "decoder_diagnostic",
                },
                {
                    "artifact": UNSUPPORTED_MEMBER,
                    "expected": "unselected_unsupported_artifact",
                },
            ],
        },
    ],
}


def ingestion_temporal_semantic_vector() -> dict[str, Any]:
    """Return a detached JSON-safe copy of the normative expectation vector."""

    return deepcopy(_SEMANTIC_VECTOR)


def render_ingestion_temporal_semantic_vector() -> bytes:
    """Serialize the expectation vector deterministically."""

    return json_bytes(_SEMANTIC_VECTOR)


def _log_fixture() -> bytes:
    rows = (
        {
            "timestamp_ns": _BASE_TIMESTAMP_NS,
            "source_sequence": 50,
            "facility": "routing",
            "message": "route installed through tunnel path 3",
        },
        {
            "timestamp_ns": _BASE_TIMESTAMP_NS,
            "source_sequence": 60,
            "facility": "forwarding",
            "message": "hardware programming completed",
        },
    )
    return b"".join(
        (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for row in rows
    )


def ingestion_conformance_members() -> dict[str, bytes]:
    """Return every raw/expected member before deterministic packaging."""

    malformed_ctf = deterministic_tgz_bytes(
        {
            CTF_METADATA_MEMBER: b'\x1e{"type":"preamble"',
            CTF_STREAM_MEMBER: b"\xc1\x1f",
        }
    )
    members = {
        STATUS_MEMBER: render_conformance_status_fixture(),
        LOG_MEMBER: _log_fixture(),
        CTF_MEMBER: synthetic_router_ctf2_archive(),
        MALFORMED_STATUS_MEMBER: (b'{"kind":"interface","captured_at_ns":'),
        MALFORMED_CTF_MEMBER: malformed_ctf,
        UNSUPPORTED_MEMBER: b"\xd4\xc3\xb2\xa1unsupported-pcap-vector",
        EXPECTATIONS_MEMBER: render_ingestion_temporal_semantic_vector(),
    }
    manifest = {
        "generator": "rsl-demo-runtime-v2-conformance-v1",
        "format_version": CONFORMANCE_CORPUS_FORMAT_VERSION,
        "root": CONFORMANCE_CORPUS_ROOT,
        "large_demo_runtime": "v1-unchanged",
        "artifacts": [
            {
                "path": name,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for name, content in sorted(members.items())
        ],
    }
    return {MANIFEST_MEMBER: json_bytes(manifest), **members}


def build_ingestion_conformance_corpus() -> bytes:
    """Return a deterministic TGZ containing the compact raw corpus."""

    return deterministic_tgz_bytes(ingestion_conformance_members())


__all__ = [
    "CONFORMANCE_CORPUS_FORMAT_VERSION",
    "CONFORMANCE_CORPUS_NAME",
    "CONFORMANCE_CORPUS_ROOT",
    "CTF_MEMBER",
    "EXPECTATIONS_MEMBER",
    "LOG_MEMBER",
    "MALFORMED_CTF_MEMBER",
    "MALFORMED_STATUS_MEMBER",
    "MANIFEST_MEMBER",
    "STATUS_MEMBER",
    "UNSUPPORTED_MEMBER",
    "build_ingestion_conformance_corpus",
    "ingestion_conformance_members",
    "ingestion_temporal_semantic_vector",
    "render_ingestion_temporal_semantic_vector",
]
