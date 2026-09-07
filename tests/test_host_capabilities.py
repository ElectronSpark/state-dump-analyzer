import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from rsl_demo_plugin.data import DEMO_GAPS

from router_dump_analyzer.web import runtime_api


class HostCapabilitiesTests(unittest.TestCase):
    def test_host_configuration_is_independent_of_producer_metadata(self):
        application = FastAPI()
        application.include_router(runtime_api.api_router)
        application.dependency_overrides[runtime_api._bind_request_revision_scope] = lambda: None
        dataset = {
            "gaps": [{"id": "synthetic", "detail": "Synthetic records."}],
            "host_services": {"control_plane_configured": True},
        }
        session = SimpleNamespace(
            temporal_provider=None, topology_provider=None, route_provider=None,
        )
        with ExitStack() as stack:
            for name, value in (
                ("_require_revision", None),
                ("load_dataset", dataset),
                ("current_runtime_session", session),
                ("route_resolution_capability", {}),
                ("_analysis_metadata", {}),
            ):
                stack.enter_context(patch.object(runtime_api, name, return_value=value))
            client = stack.enter_context(TestClient(application))
            path = "/v1/revisions/revision-a/capabilities"
            absent = client.get(path)
            self.assertEqual(absent.status_code, 200, absent.text)
            self.assertFalse(absent.json()["host_services"]["control_plane_configured"])
            self.assertNotIn("durable_review", absent.json()["implemented"])
            application.state.control_plane = object()
            application.state.control_plane_identity_resolver = lambda _request: None
            present = client.get(path)
            self.assertEqual(present.status_code, 200, present.text)
            self.assertEqual(present.json()["host_services"], {
                "control_plane_configured": True,
                "request_identity_configured": True,
            })
            self.assertIn("durable_review", present.json()["implemented"])
            self.assertEqual(present.json()["limitations"], dataset["gaps"])
            application.state.control_plane = None
            self.assertFalse(client.get(path).json()["host_services"]["control_plane_configured"])

    def test_demo_limitations_describe_only_producer_evidence(self):
        self.assertEqual(
            {gap["id"] for gap in DEMO_GAPS},
            {"synthetic-input", "reconstruction", "routing"},
        )
        for gap in DEMO_GAPS:
            self.assertIn(gap["status"], {"fixture-only", "demo-only"})


if __name__ == "__main__":
    unittest.main()
