from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer.web.frontend_host import (
    FRONTEND_DIR_ENV,
    FrontendBundleError,
    FrontendHost,
    load_frontend_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
FRONTEND_ROOT = ROOT / "frontend"
DEMO_ROOT = ROOT / "demo"
DEMO_PYTHON_ROOTS = (
    DEMO_ROOT / "rsl_demo_plugin",
    DEMO_ROOT / "rsl_demo_generator",
)
MODULE_REFERENCE = re.compile(
    r'(?:^|\n)\s*(?:import|export)\s+'
    r'(?:[^"\';`]*?\s+from\s+)?["\']([^"\']+)["\']',
)


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
    def test_repository_has_one_frontend_source_distribution(self) -> None:
        source_roots = (
            FRONTEND_ROOT,
            ROOT / "src",
            ROOT / "demo",
            ROOT / "scripts",
        )
        source_files = tuple(
            path
            for source_root in source_roots
            for path in source_root.rglob("*")
            if path.is_file()
        )
        manifests = sorted(
            path.resolve()
            for path in source_files
            if path.name == "frontend-manifest.json"
        )
        self.assertEqual(
            manifests,
            [(FRONTEND_ROOT / "frontend-manifest.json").resolve()],
        )

        duplicate_browser_sources = sorted(
            path.relative_to(ROOT).as_posix()
            for path in source_files
            if path.suffix.lower() in {".html", ".css", ".js"}
            and FRONTEND_ROOT.resolve() not in path.resolve().parents
        )
        self.assertEqual(
            duplicate_browser_sources,
            [],
            "browser assets/templates remain outside the core-owned frontend: "
            + ", ".join(duplicate_browser_sources),
        )

    def test_manifest_owns_page_files_and_asset_mount(self) -> None:
        bundle = load_frontend_bundle(FRONTEND_ROOT)

        self.assertEqual(
            set(bundle.page_routes),
            {"/", "/topology", "/node", "/analysis"},
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
        self.assertEqual(
            bundle.page_for_route("/analysis").name,
            "private-analysis.html",
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

    def test_manifest_reaches_every_browser_file_without_exact_copies(
        self,
    ) -> None:
        bundle = load_frontend_bundle(FRONTEND_ROOT)
        declared_pages = {
            path.resolve()
            for path in bundle.pages_by_route.values()
        }
        browser_pages = {
            path.resolve()
            for path in FRONTEND_ROOT.rglob("*.html")
            if path.is_file()
        }
        self.assertEqual(browser_pages, declared_pages)

        reachable_assets: set[Path] = set()
        script_queue: list[Path] = []
        for page_path in declared_pages:
            parser = _PageContractParser()
            parser.feed(page_path.read_text(encoding="utf-8"))
            for reference in parser.asset_references:
                if not reference.startswith("/assets/"):
                    continue
                asset_name = reference.removeprefix("/assets/").split("?", 1)[0]
                asset_path = (bundle.assets_directory / asset_name).resolve()
                reachable_assets.add(asset_path)
                if asset_path.suffix == ".js":
                    script_queue.append(asset_path)

        checked_scripts: set[Path] = set()
        while script_queue:
            script_path = script_queue.pop()
            if script_path in checked_scripts:
                continue
            checked_scripts.add(script_path)
            source = script_path.read_text(encoding="utf-8")
            for reference in MODULE_REFERENCE.findall(source):
                self.assertTrue(
                    reference.startswith("."),
                    f"{script_path} uses an unbundled module: {reference}",
                )
                dependency = (script_path.parent / reference).resolve()
                self.assertIn(bundle.assets_directory, dependency.parents)
                self.assertTrue(dependency.is_file(), reference)
                reachable_assets.add(dependency)
                script_queue.append(dependency)

        browser_assets = {
            path.resolve()
            for suffix in ("*.css", "*.js")
            for path in bundle.assets_directory.rglob(suffix)
            if path.is_file()
        }
        self.assertEqual(browser_assets, reachable_assets)

        content_owners: dict[tuple[str, str], Path] = {}
        duplicates: list[str] = []
        for path in sorted(browser_pages | browser_assets):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            key = (path.suffix.lower(), digest)
            if owner := content_owners.get(key):
                duplicates.append(
                    f"{owner.relative_to(ROOT)} == {path.relative_to(ROOT)}"
                )
            else:
                content_owners[key] = path
        self.assertEqual(
            duplicates,
            [],
            "exact duplicate executable frontend files remain: "
            + ", ".join(duplicates),
        )

    def test_demo_contains_no_executable_frontend_copy(self) -> None:
        self.assertFalse(
            (DEMO_ROOT / "frontend").exists(),
            "the generic browser distribution must be owned only by core frontend/",
        )
        self.assertEqual(
            list(DEMO_ROOT.rglob("frontend-manifest.json")),
            [],
            "the demo must not ship another executable frontend distribution",
        )
        leftovers = [
            path
            for suffix in ("*.html", "*.css", "*.js")
            for package_root in DEMO_PYTHON_ROOTS
            for path in package_root.rglob(suffix)
        ]
        self.assertEqual(leftovers, [])

    def test_large_dataset_behavior_uses_explicit_workspace_capabilities(self) -> None:
        source = (FRONTEND_ROOT / "assets" / "app.js").read_text(encoding="utf-8")
        start = source.index("function isScaleMode()")
        end = source.index("\n}\n", start) + 3
        helper = source[start:end]

        self.assertIn("workspace.scale_mode", helper)
        self.assertIn("workspace.large_dataset", helper)
        self.assertNotIn("workspace.mode", helper)
        self.assertNotIn("full-scale", helper)

        executable_sources = "\n".join(
            path.read_text(encoding="utf-8")
            for suffix in ("*.html", "*.css", "*.js", "*.mjs")
            for path in FRONTEND_ROOT.rglob(suffix)
        )
        for demo_convention in (
            "router-state-lab-generated-demo",
            "synthetic-packed-tgz",
            "full-scale-100k",
            "full-scale-1m",
        ):
            with self.subTest(demo_convention=demo_convention):
                self.assertNotIn(demo_convention, executable_sources)

    def test_topology_frontend_has_no_demo_semantics_or_legacy_adapter(self) -> None:
        source = (FRONTEND_ROOT / "assets" / "topology.js").read_text(
            encoding="utf-8"
        )

        for demo_semantic in (
            "evpn_split_horizon",
            "demo.example-router",
            "router-state-lab-generated-demo",
        ):
            with self.subTest(demo_semantic=demo_semantic):
                self.assertNotIn(demo_semantic, source)
        self.assertNotIn(
            "revision-compatibility",
            source,
            "the multi-node page must use the multi-node contract, not adapt "
            "the unrelated single-revision topology contract",
        )

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
                    "/analysis": "page.html",
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
                    "/analysis": "page.html",
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
        self.assertEqual(
            set(host.page_routes),
            {"/", "/topology", "/node", "/analysis"},
        )
        host.configure(enabled=False)
        self.assertFalse(host.enabled)
        self.assertIsNone(host.bundle)
        self.assertEqual(
            set(host.page_routes),
            {"/", "/topology", "/node", "/analysis"},
        )
        self.assertFalse(host.owns_request_path("/"))
