from __future__ import annotations

import json
import os
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer_demo.frontend_host import (
    FRONTEND_DIR_ENV,
    FrontendBundleError,
    FrontendHost,
    load_frontend_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
FRONTEND_ROOT = ROOT / "demo" / "frontend"
PYTHON_PACKAGE = ROOT / "demo" / "src" / "router_dump_analyzer_demo"


class _PageContractParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.asset_references: list[str] = []
        self.inline_scripts = 0
        self.inline_styles = 0
        self.inline_handlers: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = dict(attrs)
        if identifier := values.get("id"):
            self.ids.append(identifier)
        self.inline_handlers.extend(
            name for name, _value in attrs if name.lower().startswith("on")
        )
        if tag == "script":
            source = values.get("src")
            if source is None:
                self.inline_scripts += 1
            else:
                self.asset_references.append(source)
        if tag == "style":
            self.inline_styles += 1
        if tag == "link" and values.get("rel") == "stylesheet":
            if href := values.get("href"):
                self.asset_references.append(href)


class FrontendBoundaryTests(unittest.TestCase):
    def test_manifest_owns_page_files_and_asset_mount(self) -> None:
        bundle = load_frontend_bundle(FRONTEND_ROOT)

        self.assertEqual(
            set(bundle.page_routes),
            {"/", "/topology", "/node"},
        )
        self.assertEqual(bundle.assets_url_prefix, "/assets")
        self.assertEqual(bundle.assets_directory, FRONTEND_ROOT / "assets")
        self.assertEqual(
            bundle.page_for_route("/").name,
            "topology.html",
        )
        self.assertEqual(
            bundle.page_for_route("/node").name,
            "node.html",
        )

    def test_pages_reference_only_declared_local_assets(self) -> None:
        bundle = load_frontend_bundle(FRONTEND_ROOT)
        for route, page_path in bundle.pages_by_route.items():
            parser = _PageContractParser()
            parser.feed(page_path.read_text(encoding="utf-8"))
            self.assertEqual(
                len(parser.ids),
                len(set(parser.ids)),
                f"{route} contains duplicate element IDs",
            )
            self.assertEqual(parser.inline_scripts, 0, route)
            self.assertEqual(parser.inline_styles, 0, route)
            self.assertEqual(parser.inline_handlers, [], route)
            self.assertTrue(parser.asset_references, route)
            for reference in parser.asset_references:
                self.assertTrue(
                    reference.startswith("/assets/"),
                    f"{route} references a non-manifest asset: {reference}",
                )
                asset_name = reference.removeprefix("/assets/").split("?", 1)[0]
                asset_path = (bundle.assets_directory / asset_name).resolve()
                self.assertIn(bundle.assets_directory, asset_path.parents)
                self.assertTrue(asset_path.is_file(), reference)

    def test_python_package_contains_no_frontend_source_files(self) -> None:
        leftovers = [
            path
            for suffix in ("*.html", "*.css", "*.js")
            for path in PYTHON_PACKAGE.rglob(suffix)
        ]
        self.assertEqual(leftovers, [])

    def test_environment_override_resolves_complete_distribution(self) -> None:
        with patch.dict(
            os.environ,
            {FRONTEND_DIR_ENV: str(FRONTEND_ROOT)},
            clear=False,
        ):
            self.assertEqual(load_frontend_bundle().root, FRONTEND_ROOT)

    def test_manifest_rejects_page_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "assets").mkdir()
            (root / "page.html").write_text("<!doctype html>", encoding="utf-8")
            manifest = {
                "schema_version": 1,
                "assets": {
                    "url_prefix": "/assets",
                    "directory": "assets",
                },
                "pages": {
                    "/": "../outside.html",
                    "/topology": "page.html",
                    "/node": "page.html",
                },
            }
            (root / "frontend-manifest.json").write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                FrontendBundleError,
                "must remain inside",
            ):
                load_frontend_bundle(root)

    def test_manifest_rejects_routes_reserved_for_the_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "assets").mkdir()
            (root / "page.html").write_text("<!doctype html>", encoding="utf-8")
            manifest = {
                "schema_version": 1,
                "assets": {
                    "url_prefix": "/assets",
                    "directory": "assets",
                },
                "pages": {
                    "/": "page.html",
                    "/topology": "page.html",
                    "/node": "page.html",
                    "/health": "page.html",
                },
            }
            (root / "frontend-manifest.json").write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                FrontendBundleError,
                "unexpected /health",
            ):
                load_frontend_bundle(root)

    def test_api_only_host_is_lazy_and_keeps_a_stable_route_contract(self) -> None:
        host = FrontendHost(
            Path("this-path-does-not-exist"),
            enabled=True,
        )

        self.assertTrue(host.enabled)
        self.assertIsNone(host.bundle)
        self.assertEqual(set(host.page_routes), {"/", "/topology", "/node"})
        host.configure(enabled=False)
        self.assertFalse(host.enabled)
        self.assertIsNone(host.bundle)
        self.assertEqual(set(host.page_routes), {"/", "/topology", "/node"})
        self.assertFalse(host.owns_request_path("/"))
