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
        api_response = client.get("/v1/runtime")
        page_response = client.get("/")
        self.assertEqual(api_response.json(), {"owner": "injected"})
        self.assertEqual(page_response.status_code, 200)
        self.assertEqual(client.get("/openapi.json").status_code, 404)
        self.assertEqual(client.get("/docs").status_code, 404)
        self.assertEqual(client.get("/redoc").status_code, 404)
        self.assertEqual(
            client.get("/assets/styles.css").headers["cache-control"],
            "no-store, no-cache, must-revalidate, max-age=0",
        )
        for response in (api_response, page_response):
            self.assertEqual(
                response.headers["x-content-type-options"],
                "nosniff",
            )
            self.assertEqual(response.headers["x-frame-options"], "DENY")
            self.assertEqual(
                response.headers["referrer-policy"],
                "no-referrer",
            )
        policy = page_response.headers["content-security-policy"]
        self.assertIn("script-src 'self'", policy)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", policy)
        self.assertIn("object-src 'none'", policy)
        self.assertIn("frame-ancestors 'none'", policy)

        documented = create_web_app(
            api_router=router,
            host=host,
            expose_api_docs=True,
        )
        documented_client = TestClient(documented)
        self.assertEqual(documented_client.get("/openapi.json").status_code, 200)
        self.assertEqual(documented_client.get("/docs").status_code, 200)
        self.assertEqual(documented_client.get("/redoc").status_code, 200)


if __name__ == "__main__":
    unittest.main()
