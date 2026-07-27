from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer.web import runtime_api


class RuntimeCapabilityAdvertisingTests(unittest.TestCase):
    def _capabilities(
        self,
        *,
        route_available: bool,
        temporal_provider=None,
        topology_provider=None,
        route_provider=None,
    ) -> set[str]:
        session = SimpleNamespace(
            temporal_provider=temporal_provider,
            topology_provider=topology_provider,
            route_provider=route_provider,
        )
        with (
            patch.object(runtime_api, "_require_revision"),
            patch.object(
                runtime_api,
                "load_dataset",
                return_value={"gaps": []},
            ),
            patch.object(
                runtime_api,
                "route_resolution_capability",
                return_value={"available": route_available},
            ),
            patch.object(
                runtime_api,
                "_analysis_metadata",
                return_value={},
            ),
            patch.object(
                runtime_api,
                "current_runtime_session",
                return_value=session,
            ),
        ):
            payload = runtime_api.capabilities("revision")
        return set(payload["implemented"])

    def test_optional_services_are_not_advertised_when_absent(self) -> None:
        implemented = self._capabilities(route_available=False)

        self.assertNotIn("precomputed_route_explanation", implemented)
        self.assertNotIn("temporal_topology_projection", implemented)
        self.assertNotIn(
            "heterogeneous_multi_node_topology_reconstruction",
            implemented,
        )
        self.assertNotIn("multi_node_route_tracing", implemented)

    def test_loaded_service_surfaces_are_advertised(self) -> None:
        marker = object()
        implemented = self._capabilities(
            route_available=True,
            temporal_provider=marker,
            topology_provider=marker,
            route_provider=marker,
        )

        self.assertIn("precomputed_route_explanation", implemented)
        self.assertIn("temporal_topology_projection", implemented)
        self.assertIn(
            "heterogeneous_multi_node_topology_reconstruction",
            implemented,
        )
        self.assertIn("multi_node_route_tracing", implemented)


if __name__ == "__main__":
    unittest.main()
