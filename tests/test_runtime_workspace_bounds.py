"""Runtime-v2 publishes observation bounds even without semantic events."""

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from fastapi.testclient import TestClient
from rsl_demo_plugin import parser_plugin

from router_dump_analyzer.plugin_api import TimelineTimeBasis
from router_dump_analyzer.runtime import (
    RuntimeApplicationRequest,
    create_runtime_application,
    require_plugin_runtime,
)
from tests.test_ingestion import ParseOnlyPlugin


class DeclaredStatusClockPlugin(ParseOnlyPlugin):
    def __init__(self, basis, domain):
        self.manifest = replace(
            ParseOnlyPlugin.manifest,
            plugin_id=f"tests.workspace-{basis.value}",
            timeline_time_basis=basis,
            timeline_clock_domain=domain,
        )


class RuntimeWorkspaceBoundsTests(unittest.TestCase):
    def test_status_only_workspace_publishes_bounds_for_initial_capture(self):
        fixture = (
            Path(__file__).resolve().parents[1] / "demo/fixtures/minimal-status.jsonl"
        )
        application = create_runtime_application(
            RuntimeApplicationRequest(
                runtime=require_plugin_runtime(parser_plugin),
                input_path=fixture,
                serve_frontend=False,
            )
        )
        with TestClient(application) as client:
            response = client.get("/v1/workspace")
            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            workspace = payload["workspace"]
            self.assertEqual(payload["events"], [])
            self.assertEqual(len(payload["state_intervals"]), 4)
            self.assertEqual(len(payload["source_records"]), 4)
            self.assertEqual(workspace["timeline_start_ns"], "1759680000000000000")
            self.assertEqual(workspace["timeline_end_ns"], "1759680000002500000")
            self.assertEqual(workspace["capture_ns"], "1759680000002500000")
            self.assertEqual(workspace["timeline_time_basis"], "absolute_unix_ns")
            self.assertIsNone(workspace["timeline_clock_domain"])
            revision = workspace["revision_id"]
            response = client.post(
                f"/v1/revisions/{revision}/resources/query",
                json={
                    "time_ns": workspace["capture_ns"],
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
            rows = response.json()["items"]
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(row["exists"] for row in rows))
            self.assertEqual(
                {row["state"]["name"]: row["state"]["oper_status"] for row in rows},
                {
                    "xe-0/0/0": "down",
                    "xe-0/0/1": "down",
                    "xe-0/0/2": "unknown",
                },
            )
            timeline = client.post(f"/v1/revisions/{revision}/timeline/query", json={})
            self.assertEqual(timeline.status_code, 200, timeline.text)
            self.assertEqual(
                timeline.json()["start_ns"], workspace["timeline_start_ns"]
            )
            self.assertEqual(timeline.json()["end_ns"], workspace["timeline_end_ns"])

    def test_declared_relative_and_source_clock_bounds_are_not_rebased_or_padded(self):
        cases = (
            (
                TimelineTimeBasis.ABSOLUTE_UNIX_NS,
                None,
                (1759680000000000000, 1759680000000000001),
            ),
            (TimelineTimeBasis.REVISION_START_RELATIVE_NS, None, (-9, -1)),
            (TimelineTimeBasis.SOURCE_CLOCK_NS, "device.clock", (-20, 20)),
            (TimelineTimeBasis.REVISION_START_RELATIVE_NS, None, (-7,)),
        )
        for basis, domain, times in cases:
            with (
                self.subTest(basis=basis, times=times),
                tempfile.TemporaryDirectory() as directory,
            ):
                fixture = Path(directory) / "status.jsonl"
                fixture.write_text(
                    "\n".join(
                        json.dumps(
                            {
                                "captured_at_ns": stamp,
                                "ifindex": 7,
                                "name": "opaque",
                                "oper_status": "up",
                            }
                        )
                        for stamp in times
                    )
                    + "\n",
                    encoding="utf-8",
                )
                application = create_runtime_application(
                    RuntimeApplicationRequest(
                        runtime=require_plugin_runtime(
                            DeclaredStatusClockPlugin(basis, domain)
                        ),
                        input_path=fixture,
                        serve_frontend=False,
                    )
                )
                with TestClient(application) as client:
                    response = client.get("/v1/workspace")
                    self.assertEqual(response.status_code, 200, response.text)
                    payload = response.json()
                    self.assertEqual(payload["events"], [])
                    workspace = payload["workspace"]
                    self.assertEqual(workspace["timeline_start_ns"], str(min(times)))
                    self.assertEqual(workspace["timeline_end_ns"], str(max(times)))
                    self.assertEqual(workspace["capture_ns"], str(max(times)))
                    self.assertEqual(workspace["timeline_time_basis"], basis.value)
                    self.assertEqual(workspace["timeline_clock_domain"], domain)
                    result = client.post(
                        f"/v1/revisions/{workspace['revision_id']}/resources/query",
                        json={"time_ns": workspace["capture_ns"]},
                    )
                    self.assertEqual(result.status_code, 200, result.text)
                    self.assertTrue(result.json()["items"][0]["exists"])


if __name__ == "__main__":
    unittest.main()
