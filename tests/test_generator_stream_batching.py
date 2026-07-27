from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rsl_demo_generator import _node_pack
from rsl_demo_generator import assembly
from rsl_demo_generator.catalog import DEMO_NODES


class GeneratorStreamBatchingTests(unittest.TestCase):
    def test_jsonl_batching_preserves_reference_bytes_and_final_line_count(
        self,
    ) -> None:
        node = DEMO_NODES[0]
        source_lines = (
            b'{"clock_domain":"capture","event_id":"scale-event-0001",'
            b'"resource_id":"data-bridge-layer/ETG/blue/etg-000001",'
            b'"timestamp_ns":100}\n',
            b" \n",
            b'{"burst_id":"burst-1","event_id":"scale-event-0002",'
            b'"resource_id":"control-plane/EVPN_ES/es-000001",'
            b'"timestamp_ns":"200"}',
        )
        plan = assembly._GENERATED_JSONL_REWRITE_PLANS["events.jsonl"]
        expected = b"".join(
            assembly._transform_generated_json_line(line, node, plan=plan)
            for line in source_lines
            if line.strip()
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "events.jsonl"
            output = root / "rewritten.jsonl"
            source.write_bytes(b"".join(source_lines))
            with patch.object(assembly, "_REWRITE_BATCH_BYTES", 32):
                count, digest = assembly._rewrite_jsonl(
                    source,
                    node,
                    output=output,
                )
            actual = output.read_bytes()

        self.assertEqual(count, 2)
        self.assertEqual(actual, expected)
        self.assertEqual(digest, hashlib.sha256(expected).hexdigest())
        self.assertFalse(actual.endswith(b"\n"))

    def test_ctf_batching_matches_the_per_event_reference_encoder(self) -> None:
        events = [
            {
                "action": "create",
                "layer": "control-plane",
                "outcome": "success",
                "properties": {
                    "description": "caf\u00e9",
                    "nested": {"z": 2, "a": 1},
                },
                "resource_id": "control-plane/EVPN_ES/es-000001",
                "result": {"updateStatus": "Ok"},
                "timestamp_ns": 100,
            },
            {
                "action": "modify",
                "layer": "data-bridge-layer",
                "outcome": "failed",
                "properties": {"service_id": "svc-000003", "status": "down"},
                "resource_id": "data-bridge-layer/ETG/blue/etg-000003",
                "result": {"updateStatus": "Rejected"},
                "timestamp_ns": 200,
            },
            {
                "action": "modify",
                "layer": "hardware-driver-plane",
                "outcome": "success",
                "properties": {"interface": "ae-00001"},
                "resource_id": "hardware-driver-plane/NEIGHBOR/peer-000001",
                "result": {},
                "timestamp_ns": 300,
            },
        ]
        scenario = {
            "multi_home_services": 2,
            "scale": {"events": len(events)},
        }

        metadata, stream_header = _node_pack._ctf_template()
        expected_streams = {
            container.container_id: bytearray(stream_header)
            for container in _node_pack.CONTAINERS
        }
        expected_counts: dict[str, int] = {}
        expected_outcomes: dict[str, dict[str, int]] = {}
        for event in events:
            container_id = _node_pack._event_container(event, 2)
            expected_counts[container_id] = expected_counts.get(container_id, 0) + 1
            outcomes = expected_outcomes.setdefault(container_id, {})
            outcome = str(event["outcome"])
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
            properties = json.dumps(
                event["properties"],
                sort_keys=True,
                separators=(",", ":"),
            )
            result = event["result"]
            if result:
                result_key = sorted(result)[0]
                result_value = result[result_key]
            else:
                result_key = "updateStatus"
                result_value = "Unknown"
            expected = expected_streams[container_id]
            expected.extend(struct.pack("<Q", int(event["timestamp_ns"])))
            for value in (
                event["resource_id"],
                event["action"],
                properties,
                result_key,
                result_value,
            ):
                expected.extend(_node_pack._ctf_string(value))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scale_dir = root / "scale"
            stage = root / "stage"
            scale_dir.mkdir()
            stage.mkdir()
            (scale_dir / "events.jsonl").write_bytes(
                b"".join(
                    (
                        json.dumps(
                            event,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    ).encode("utf-8")
                    for event in events
                )
            )
            with patch.object(_node_pack, "_CTF_WRITE_BATCH_BYTES", 16):
                counts, outcomes = _node_pack._write_event_files(
                    stage,
                    scale_dir,
                    scenario,
                )
            actual_streams = {
                container.container_id: (
                    stage
                    / "containers"
                    / container.container_id
                    / "trace"
                    / "ctf"
                    / "dummystream"
                ).read_bytes()
                for container in _node_pack.CONTAINERS
            }
            actual_metadata = (
                stage
                / "containers"
                / _node_pack.CONTAINERS[0].container_id
                / "trace"
                / "ctf"
                / "metadata"
            ).read_bytes()

        self.assertEqual(actual_metadata, metadata)
        self.assertEqual(
            actual_streams,
            {
                container_id: bytes(content)
                for container_id, content in expected_streams.items()
            },
        )
        self.assertEqual(counts, expected_counts)
        for container in _node_pack.CONTAINERS:
            self.assertEqual(
                dict(outcomes[container.container_id]),
                expected_outcomes.get(container.container_id, {}),
            )


if __name__ == "__main__":
    unittest.main()
