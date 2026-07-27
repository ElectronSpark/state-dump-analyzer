from __future__ import annotations

import unittest
from pathlib import Path

from fastapi import APIRouter
from fastapi.testclient import TestClient

from router_dump_analyzer.web.app import create_web_app
from router_dump_analyzer.web.frontend_host import FrontendHost


class CoreWebAppTests(unittest.TestCase):
    def test_core_shell_hosts_frontend_and_injected_api_without_demo_imports(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1] / "frontend"
        host = FrontendHost(root)
        router = APIRouter()

        @router.get("/v1/runtime")
        def runtime() -> dict[str, str]:
            return {"owner": "injected"}

        application = create_web_app(api_router=router, host=host)
        client = TestClient(application)
        self.assertEqual(client.get("/v1/runtime").json(), {"owner": "injected"})
        self.assertEqual(client.get("/").status_code, 200)
        self.assertEqual(
            client.get("/assets/styles.css").headers["cache-control"],
            "no-store, no-cache, must-revalidate, max-age=0",
        )


if __name__ == "__main__":
    unittest.main()
