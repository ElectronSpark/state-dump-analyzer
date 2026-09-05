from __future__ import annotations

import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from state_dump_generator.server import create_server, require_loopback_bind


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.web_root = Path(self.temporary.name)
        (self.web_root / "index.html").write_text(
            "<!doctype html><title>editor</title>",
            encoding="utf-8",
        )
        (self.web_root / "app.js").write_text(
            "document.body.dataset.ready = 'true';",
            encoding="utf-8",
        )
        self.server = create_server("127.0.0.1", 0, web_root=self.web_root)
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def _post(self, path: str, payload: object) -> tuple[int, bytes, object]:
        request = Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=3) as response:
            return response.status, response.read(), response.headers

    def test_serves_index_and_assets_without_directory_escape(self) -> None:
        with urlopen(self.base_url + "/", timeout=3) as response:
            self.assertEqual(response.status, 200)
            self.assertIn(b"<title>editor</title>", response.read())
            self.assertIn(
                "default-src 'self'",
                response.headers["Content-Security-Policy"],
            )
        with urlopen(self.base_url + "/assets/app.js", timeout=3) as response:
            self.assertEqual(response.status, 200)
        with self.assertRaises(HTTPError) as caught:
            urlopen(self.base_url + "/%2e%2e/pyproject.toml", timeout=3)
        self.assertEqual(caught.exception.code, 404)

    def test_static_asset_symlinks_are_not_followed(self) -> None:
        outside = self.web_root.parent / "outside.js"
        outside.write_text("secret", encoding="utf-8")
        linked = self.web_root / "linked.js"
        try:
            linked.symlink_to(outside)
        except OSError as error:
            self.skipTest(f"symbolic links are unavailable: {error}")
        with self.assertRaises(HTTPError) as caught:
            urlopen(self.base_url + "/linked.js", timeout=3)
        self.assertEqual(caught.exception.code, 404)

    def test_new_validate_preview_and_generate_contract(self) -> None:
        with patch(
            "state_dump_generator.server.new_document",
            return_value={"schema_version": 1, "nodes": []},
        ):
            with urlopen(self.base_url + "/api/scenario/new", timeout=3) as response:
                payload = json.load(response)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["scenario"]["nodes"], [])

        document = object()
        with (
            patch(
                "state_dump_generator.server._document_from_mapping",
                return_value=document,
            ),
            patch(
                "state_dump_generator.server.validate_document",
                return_value={"ok": True, "errors": [], "warnings": []},
            ),
        ):
            status, content, _ = self._post(
                "/api/scenario/validate",
                {"scenario": {"nodes": []}},
            )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(content)["ok"])

        with (
            patch(
                "state_dump_generator.server._document_from_mapping",
                return_value=document,
            ),
            patch(
                "state_dump_generator.server.validate_document",
                return_value={"ok": True, "errors": [], "warnings": []},
            ),
            patch(
                "state_dump_generator.server.preview_document",
                return_value={
                    "ok": True,
                    "node_count": 2,
                    "nodes": [],
                    "totals": {},
                },
            ) as preview,
        ):
            status, content, _ = self._post(
                "/api/scenario/preview",
                {"nodes": [], "at_time_ns": 123},
            )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(content)["node_count"], 2)
        preview.assert_called_once_with(document, at_time_ns=123)

        with (
            patch(
                "state_dump_generator.server._document_from_mapping",
                return_value=document,
            ),
            patch(
                "state_dump_generator.server.validate_document",
                return_value={"ok": True, "errors": [], "warnings": []},
            ),
            patch(
                "state_dump_generator.server.compile_and_build",
                return_value=b"tgz-bytes",
            ),
        ):
            status, content, headers = self._post(
                "/api/scenario/generate",
                {"scenario": {"nodes": []}, "filename": "lab export"},
            )
        self.assertEqual(status, 200)
        self.assertEqual(content, b"tgz-bytes")
        self.assertEqual(headers.get_content_type(), "application/gzip")
        self.assertEqual(
            headers["Content-Disposition"],
            'attachment; filename="lab-export.tgz"',
        )

    def test_propagation_endpoint_uses_compiler_observations(self) -> None:
        scenario = {
            "name": "Preview failed propagation",
            "capture_time_ns": 1_000_000_000,
            "nodes": [{"node_id": "a"}, {"node_id": "b"}],
            "events": [
                {
                    "event_id": "source",
                    "timestamp_ns": 0,
                    "node_id": "a",
                    "kind": "status",
                    "resource_id": "resource:test",
                    "status": "up",
                    "propagation": {
                        "mode": "failed",
                        "target_mode": "all-nodes",
                        "delay_ns": 101,
                    },
                }
            ],
        }
        status, content, _ = self._post(
            "/api/scenario/propagation",
            {"scenario": scenario, "event_id": "source"},
        )
        self.assertEqual(status, 200)
        event = json.loads(content)["events"][0]
        self.assertEqual(event["node_id"], "b")
        self.assertEqual(event["timestamp_ns"], "101")
        self.assertEqual(event["outcome"], "failed")
        self.assertFalse(event["update_snapshot"])
        with self.assertRaises(HTTPError) as caught:
            self._post(
                "/api/scenario/propagation",
                {"scenario": scenario, "event_id": "missing"},
            )
        self.assertEqual(caught.exception.code, 400)

    def test_preview_reconstructs_at_requested_time_with_private_truth_summary(
        self,
    ) -> None:
        scenario = {
            "schema_version": 1,
            "scenario_id": "preview-history",
            "name": "Preview history",
            "capture_time_ns": 5_000_000_000,
            "nodes": [{"node_id": "r1", "kind": "router"}],
            "media": [
                {
                    "medium_id": "private-wire",
                    "state": "up",
                    "attachments": [
                        {
                            "node_id": "r1",
                            "port_id": "xe0",
                            "resource_id": "port-resource:r1-xe0",
                        }
                    ],
                }
            ],
            "events": [
                {
                    "event_id": "create",
                    "timestamp_ns": 1_000_000_000,
                    "kind": "resource-upsert",
                    "node_id": "r1",
                    "resource_id": "route:preview",
                    "resource_type": "route",
                    "status": "installed",
                },
                {
                    "event_id": "truth-down",
                    "timestamp_ns": 2_000_000_000,
                    "kind": "link-state",
                    "target_id": "private-wire",
                    "status": "down",
                    "propagation": {"mode": "manual"},
                },
            ],
        }
        status, content, _ = self._post(
            "/api/scenario/preview",
            {
                "scenario": scenario,
                "at_time_ns": 1_000_000_000,
            },
        )
        self.assertEqual(status, 200)
        payload = json.loads(content)
        self.assertEqual(payload["at_time_ns"], 1_000_000_000)
        self.assertFalse(payload["is_final"])
        self.assertEqual(payload["nodes"][0]["history_records"], 1)
        self.assertEqual(payload["nodes"][0]["state_change_records"], 1)
        self.assertEqual(
            payload["nodes"][0]["resource_type_counts"],
            {"interface": 1, "route": 1},
        )
        self.assertEqual(
            payload["private_truth"]["media"][0]["state"],
            "up",
        )
        self.assertFalse(payload["private_truth"]["exported_to_node_dumps"])

        status, content, _ = self._post(
            "/api/scenario/preview",
            {"scenario": scenario},
        )
        self.assertEqual(status, 200)
        final_payload = json.loads(content)
        self.assertTrue(final_payload["is_final"])
        self.assertEqual(
            final_payload["at_time_ns"],
            scenario["capture_time_ns"],
        )
        self.assertEqual(
            final_payload["private_truth"]["media"][0]["state"],
            "down",
        )

    def test_validation_errors_use_422(self) -> None:
        with (
            patch(
                "state_dump_generator.server._document_from_mapping",
                return_value=object(),
            ),
            patch(
                "state_dump_generator.server.validate_document",
                return_value={
                    "ok": False,
                    "errors": ["add at least one node"],
                    "warnings": [],
                },
            ),
        ):
            request = Request(
                self.base_url + "/api/scenario/validate",
                data=b'{"nodes":[]}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(HTTPError) as caught:
                urlopen(request, timeout=3)
        self.assertEqual(caught.exception.code, 422)
        self.assertFalse(json.load(caught.exception)["ok"])

    def test_rejected_post_closes_before_unread_body_can_desynchronize(self) -> None:
        host, port = self.server.server_address
        with socket.create_connection((host, port), timeout=3) as client:
            client.settimeout(3)
            client.sendall(
                (
                    "POST /api/not-a-route HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: 4\r\n"
                    "\r\n"
                    "JUNK"
                    "GET /api/health HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    "\r\n"
                ).encode("ascii")
            )
            chunks: list[bytes] = []
            while True:
                block = client.recv(4096)
                if not block:
                    break
                chunks.append(block)
        response = b"".join(chunks)
        self.assertEqual(response.count(b"HTTP/1.1"), 1)
        self.assertIn(b"404 Not Found", response)
        self.assertNotIn(b'"service":"state-dump-generator"', response)

    def test_non_loopback_bind_is_rejected(self) -> None:
        for host in ("0.0.0.0", "::", "192.0.2.1"):
            with (
                self.subTest(host=host),
                self.assertRaisesRegex(ValueError, "local-only"),
            ):
                require_loopback_bind(host)

    def test_ipv6_loopback_uses_an_ipv6_server_when_available(self) -> None:
        if not socket.has_ipv6:
            self.skipTest("IPv6 is unavailable")
        try:
            server = create_server("::1", 0, web_root=self.web_root)
        except OSError as error:
            self.skipTest(f"IPv6 loopback is unavailable: {error}")
        try:
            self.assertEqual(server.address_family, socket.AF_INET6)
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
