from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from router_dump_analyzer.cli import (
    LaunchConfiguration,
    parse_args,
    run,
)
from router_dump_analyzer.runtime import (
    PLUGIN_RUNTIME_CAPABILITY_ID,
    PluginRuntimeCapabilityError,
    PluginRuntimeSession,
    RuntimeApplicationRequest,
    create_runtime_application,
    require_plugin_runtime,
)
from tests.support.normalized_data import StaticDataPolicy, StaticDatasetSource


class _Session:
    revision_store = object()
    data_source = StaticDatasetSource({})
    data_policy = StaticDataPolicy()
    temporal_provider = object()
    topology_provider = object()
    route_provider = object()


class _Runtime:
    capability_id = PLUGIN_RUNTIME_CAPABILITY_ID

    def open(self, input_path: Path):
        raise AssertionError(
            f"the CLI must leave {input_path} opening to the app lifetime"
        )


class _Plugin:
    runtime = _Runtime()


class CoreCliTests(unittest.TestCase):
    def test_parser_requires_exactly_one_plugin_selector(self) -> None:
        with self.assertRaises(SystemExit) as missing:
            parse_args(["--input", "fixture.tgz"])
        self.assertEqual(missing.exception.code, 2)

        with self.assertRaises(SystemExit) as duplicate:
            parse_args(
                [
                    "--plugin",
                    "installed",
                    "--plugin-module",
                    "package.plugin",
                    "--input",
                    "fixture.tgz",
                ]
            )
        self.assertEqual(duplicate.exception.code, 2)

    def test_parser_accepts_direct_module_and_server_options(self) -> None:
        parsed = parse_args(
            [
                "--plugin-module",
                "package.plugin:example",
                "--input",
                "fixture.tgz",
                "--host",
                "0.0.0.0",
                "--port",
                "8876",
                "--no-browser",
            ]
        )

        self.assertIsNone(parsed.plugin_name)
        self.assertEqual(parsed.plugin_module, "package.plugin:example")
        self.assertEqual(parsed.input_path, Path("fixture.tgz"))
        self.assertEqual(parsed.host, "0.0.0.0")
        self.assertEqual(parsed.port, 8876)
        self.assertTrue(parsed.no_browser)

    def test_run_loads_module_requires_runtime_and_calls_core_factory(self) -> None:
        plugin = _Plugin()
        calls: list[tuple[str, Any]] = []

        def module_loader(target: str) -> Any:
            calls.append(("module", target))
            return plugin

        def entry_point_loader(name: str) -> Any:
            raise AssertionError(name)

        application = object()

        def application_factory(
            request: RuntimeApplicationRequest,
        ) -> Any:
            calls.append(("factory", request))
            return application

        def server_runner(app: Any, *, host: str, port: int) -> None:
            calls.append(("server", (app, host, port)))

        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory) / "fixture.tgz"
            fixture.touch()
            frontend = Path(temporary_directory) / "frontend"
            frontend.mkdir()
            run(
                LaunchConfiguration(
                    plugin_name=None,
                    plugin_module="package.plugin",
                    input_path=fixture,
                    host="127.0.0.1",
                    port=8876,
                    no_browser=True,
                    frontend_dir=frontend,
                    api_only=True,
                ),
                entry_point_loader=entry_point_loader,
                module_loader=module_loader,
                application_factory=application_factory,
                server_runner=server_runner,
            )

        self.assertEqual(calls[0], ("module", "package.plugin"))
        request = calls[1][1]
        self.assertIsInstance(request, RuntimeApplicationRequest)
        self.assertIs(request.runtime, plugin.runtime)
        self.assertEqual(request.input_path, fixture.resolve())
        self.assertEqual(request.frontend_root, frontend.resolve())
        self.assertFalse(request.serve_frontend)
        self.assertEqual(
            calls[2],
            ("server", (application, "127.0.0.1", 8876)),
        )

    def test_run_uses_installed_selector_and_can_schedule_browser(self) -> None:
        plugin = _Plugin()
        opened: list[str] = []

        def immediate_browser(url: str, _opener) -> None:
            opened.append(url)

        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory) / "fixture.tgz"
            fixture.touch()
            from unittest.mock import patch

            with patch(
                "router_dump_analyzer.cli._schedule_browser",
                immediate_browser,
            ):
                run(
                    LaunchConfiguration(
                        plugin_name="demo_router",
                        plugin_module=None,
                        input_path=fixture,
                        host="0.0.0.0",
                        port=8765,
                        no_browser=False,
                    ),
                    entry_point_loader=lambda name: (
                        plugin
                        if name == "demo_router"
                        else self.fail(name)
                    ),
                    module_loader=lambda target: self.fail(target),
                    application_factory=lambda request: object(),
                    server_runner=lambda app, **kwargs: None,
                )

        self.assertEqual(opened, ["http://127.0.0.1:8765"])

    def test_runtime_capability_and_core_application_factory(self) -> None:
        self.assertIsInstance(_Session(), PluginRuntimeSession)

        with self.assertRaisesRegex(
            PluginRuntimeCapabilityError,
            "does not expose",
        ):
            require_plugin_runtime(object())

        request = RuntimeApplicationRequest(
            runtime=_Runtime(),
            input_path=Path("fixture.tgz"),
        )
        try:
            import fastapi  # noqa: F401
        except ImportError:
            with self.assertRaisesRegex(RuntimeError, "core\\[web\\]"):
                create_runtime_application(request)
        else:
            application = create_runtime_application(request)
            self.assertEqual(application.title, "Router Dump Analyzer API")

            def route_paths(routes) -> set[str]:
                paths: set[str] = set()
                for route in routes:
                    path = getattr(route, "path", None)
                    if isinstance(path, str):
                        paths.add(path)
                    nested = getattr(route, "routes", None)
                    if nested is not None:
                        paths.update(route_paths(nested))
                    original_router = getattr(route, "original_router", None)
                    if original_router is not None:
                        paths.update(route_paths(original_router.routes))
                return paths

            paths = route_paths(application.routes)
            self.assertIn("/health", paths)
            self.assertIn("/v1/workspace", paths)

            api_only_application = create_runtime_application(
                RuntimeApplicationRequest(
                    runtime=_Runtime(),
                    input_path=Path("fixture.tgz"),
                    serve_frontend=False,
                )
            )
            hosted_frontends = [
                route.app
                for route in application.routes
                if getattr(route, "path", None) == "/assets"
            ]
            api_only_frontends = [
                route.app
                for route in api_only_application.routes
                if getattr(route, "path", None) == "/assets"
            ]
            self.assertEqual(len(hosted_frontends), 1)
            self.assertEqual(len(api_only_frontends), 1)
            self.assertIsNot(hosted_frontends[0], api_only_frontends[0])
            self.assertTrue(hosted_frontends[0].enabled)
            self.assertFalse(api_only_frontends[0].enabled)

        class LegacyRuntime:
            capability_id = PLUGIN_RUNTIME_CAPABILITY_ID

            def open_revision_store(self, input_path: Path):
                raise AssertionError(input_path)

        class LegacyPlugin:
            runtime = LegacyRuntime()

        with self.assertRaisesRegex(
            PluginRuntimeCapabilityError,
            "open\\(input_path\\)",
        ):
            require_plugin_runtime(LegacyPlugin())


if __name__ == "__main__":
    unittest.main()
