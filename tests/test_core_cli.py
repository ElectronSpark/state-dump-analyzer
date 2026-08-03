from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any
from unittest.mock import patch

from router_dump_analyzer.cli import (
    LaunchConfiguration,
    build_parser,
    main,
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
from router_dump_analyzer.web.control_plane_api import (
    ControlPlaneAccessDenialReporter,
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


class _ClosableControlPlane:
    def __init__(self) -> None:
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


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
                "--control-plane-dir",
                "durable-state",
                "--trust-control-plane-headers",
                "--control-plane-retention-policy",
                "retention.json",
            ]
        )

        self.assertIsNone(parsed.plugin_name)
        self.assertEqual(parsed.plugin_module, "package.plugin:example")
        self.assertEqual(parsed.input_path, Path("fixture.tgz"))
        self.assertEqual(parsed.host, "0.0.0.0")
        self.assertEqual(parsed.port, 8876)
        self.assertTrue(parsed.no_browser)
        self.assertEqual(parsed.control_plane_dir, Path("durable-state"))
        self.assertTrue(parsed.trust_control_plane_headers)
        self.assertFalse(parsed.grant_instance_operator)
        self.assertFalse(parsed.expose_api_docs)
        self.assertEqual(
            parsed.control_plane_retention_policy,
            Path("retention.json"),
        )

        with self.assertRaises(SystemExit) as missing_control_plane:
            parse_args(
                [
                    "--plugin-module",
                    "package.plugin:example",
                    "--input",
                    "fixture.tgz",
                    "--control-plane-retention-policy",
                    "retention.json",
                ]
            )
        self.assertEqual(missing_control_plane.exception.code, 2)

        with self.assertRaises(SystemExit) as unsafe_docs:
            parse_args(
                [
                    "--plugin-module",
                    "package.plugin:example",
                    "--input",
                    "fixture.tgz",
                    "--host",
                    "0.0.0.0",
                    "--expose-api-docs",
                ]
            )
        self.assertEqual(unsafe_docs.exception.code, 2)

        loopback_docs = parse_args(
            [
                "--plugin-module",
                "package.plugin:example",
                "--input",
                "fixture.tgz",
                "--expose-api-docs",
            ]
        )
        self.assertTrue(loopback_docs.expose_api_docs)

    def test_instance_operator_role_flag_requires_loopback_control_plane(self) -> None:
        parsed = parse_args(
            [
                "--plugin",
                "router",
                "--input",
                "fixture.tgz",
                "--control-plane-dir",
                "state",
                "--grant-instance-operator",
            ]
        )
        self.assertTrue(parsed.grant_instance_operator)

        with self.assertRaises(SystemExit) as missing_control_plane:
            parse_args(
                [
                    "--plugin",
                    "router",
                    "--input",
                    "fixture.tgz",
                    "--grant-instance-operator",
                ]
            )
        self.assertEqual(missing_control_plane.exception.code, 2)

        with self.assertRaises(SystemExit) as non_loopback:
            parse_args(
                [
                    "--plugin",
                    "router",
                    "--input",
                    "fixture.tgz",
                    "--control-plane-dir",
                    "state",
                    "--trust-control-plane-headers",
                    "--host",
                    "0.0.0.0",
                    "--grant-instance-operator",
                ]
            )
        self.assertEqual(non_loopback.exception.code, 2)

        grant_help = next(
            action.help
            for action in build_parser()._actions
            if action.dest == "grant_instance_operator"
        )
        self.assertIn("grant the control-plane instance-operator role", grant_help)
        self.assertNotIn("grant access to", grant_help)

    def test_run_passes_instance_operator_role_grant_to_trusted_resolver(
        self,
    ) -> None:
        plugin = _Plugin()
        resolver = lambda _request: object()
        control_plane = _ClosableControlPlane()
        resolver_options: dict[str, Any] = {}
        requests: list[RuntimeApplicationRequest] = []

        def resolver_factory(**options: Any) -> Any:
            resolver_options.update(options)
            return resolver

        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory) / "fixture.tgz"
            fixture.touch()
            with (
                patch(
                    "router_dump_analyzer.control_plane.ControlPlane",
                    return_value=control_plane,
                ),
                patch(
                    "router_dump_analyzer.ingestion_pipeline.PluginRegistry",
                    return_value=object(),
                ),
                patch(
                    "router_dump_analyzer.web.control_plane_api."
                    "TrustedHeaderIdentityResolver",
                    side_effect=resolver_factory,
                ),
            ):
                run(
                    LaunchConfiguration(
                        plugin_name="router",
                        plugin_module=None,
                        input_path=fixture,
                        host="127.0.0.1",
                        port=8765,
                        no_browser=True,
                        control_plane_dir=Path(temporary_directory) / "state",
                        grant_instance_operator=True,
                    ),
                    entry_point_loader=lambda _name: plugin,
                    application_factory=lambda request: (
                        requests.append(request) or object()
                    ),
                    server_runner=lambda _app, **_values: None,
                )

        self.assertIs(requests[0].control_plane_identity_resolver, resolver)
        self.assertTrue(resolver_options["grant_instance_operator"])
        self.assertEqual(control_plane.close_count, 1)

    def test_programmatic_instance_operator_grant_rejects_invalid_composition(
        self,
    ) -> None:
        base = {
            "plugin_name": "router",
            "plugin_module": None,
            "input_path": Path("fixture.tgz"),
            "port": 8765,
            "no_browser": True,
            "grant_instance_operator": True,
        }
        with self.assertRaisesRegex(ValueError, "trusted-header control plane"):
            run(
                LaunchConfiguration(host="127.0.0.1", **base),
                entry_point_loader=lambda _name: self.fail(),
                application_factory=lambda _request: self.fail(),
                server_runner=lambda _app, **_values: self.fail(),
            )

        with self.assertRaisesRegex(ValueError, "only on a loopback host"):
            run(
                LaunchConfiguration(
                    host="0.0.0.0",
                    control_plane_dir=Path("state"),
                    trust_control_plane_headers=True,
                    **base,
                ),
                entry_point_loader=lambda _name: self.fail(),
                application_factory=lambda _request: self.fail(),
                server_runner=lambda _app, **_values: self.fail(),
            )

    def test_control_plane_refuses_implicit_header_trust_off_loopback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory) / "fixture.tgz"
            fixture.touch()
            with self.assertRaisesRegex(
                RuntimeError,
                "trusted-header control plane may bind only to loopback",
            ):
                run(
                    LaunchConfiguration(
                        plugin_name=None,
                        plugin_module="package.plugin",
                        input_path=fixture,
                        host="0.0.0.0",
                        port=8876,
                        no_browser=True,
                        control_plane_dir=Path(temporary_directory) / "state",
                    ),
                    module_loader=lambda _target: _Plugin(),
                    entry_point_loader=lambda name: self.fail(name),
                    application_factory=lambda request: self.fail(request),
                    server_runner=lambda app, **kwargs: self.fail((app, kwargs)),
                )

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
                    expose_api_docs=True,
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
        self.assertTrue(request.expose_api_docs)
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
                        plugin if name == "demo_router" else self.fail(name)
                    ),
                    module_loader=lambda target: self.fail(target),
                    application_factory=lambda request: object(),
                    server_runner=lambda app, **kwargs: None,
                )

        self.assertEqual(opened, ["http://127.0.0.1:8765"])

    def test_api_only_browser_targets_live_endpoint_for_docs_policy(
        self,
    ) -> None:
        plugin = _Plugin()
        opened: list[str] = []

        def immediate_browser(url: str, _opener) -> None:
            opened.append(url)

        with tempfile.TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory) / "fixture.tgz"
            fixture.touch()
            with patch(
                "router_dump_analyzer.cli._schedule_browser",
                immediate_browser,
            ):
                run(
                    LaunchConfiguration(
                        plugin_name="demo_router",
                        plugin_module=None,
                        input_path=fixture,
                        host="127.0.0.1",
                        port=8765,
                        no_browser=False,
                        api_only=True,
                    ),
                    entry_point_loader=lambda _name: plugin,
                    application_factory=lambda _request: object(),
                    server_runner=lambda _app, **_kwargs: None,
                )
                run(
                    LaunchConfiguration(
                        plugin_name="demo_router",
                        plugin_module=None,
                        input_path=fixture,
                        host="127.0.0.1",
                        port=8765,
                        no_browser=False,
                        api_only=True,
                        expose_api_docs=True,
                    ),
                    entry_point_loader=lambda _name: plugin,
                    application_factory=lambda _request: object(),
                    server_runner=lambda _app, **_kwargs: None,
                )

        self.assertEqual(
            opened,
            [
                "http://127.0.0.1:8765/health",
                "http://127.0.0.1:8765/docs",
            ],
        )

    def test_programmatic_api_docs_opt_in_fails_off_loopback(self) -> None:
        with self.assertRaisesRegex(ValueError, "only on a loopback host"):
            run(
                LaunchConfiguration(
                    plugin_name="demo_router",
                    plugin_module=None,
                    input_path=Path("fixture.tgz"),
                    host="0.0.0.0",
                    port=8765,
                    no_browser=True,
                    expose_api_docs=True,
                ),
                entry_point_loader=lambda name: self.fail(name),
                application_factory=lambda request: self.fail(request),
                server_runner=lambda app, **kwargs: self.fail((app, kwargs)),
            )

    def test_main_redacts_missing_input_absolute_host_path(self) -> None:
        stderr = io.StringIO()
        private_path = Path(r"C:\private\tenant\missing-dump.tgz")
        with (
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as stopped,
        ):
            main(
                [
                    "--plugin",
                    "demo_router",
                    "--input",
                    str(private_path),
                    "--no-browser",
                ]
            )

        self.assertEqual(stopped.exception.code, 1)
        rendered = stderr.getvalue()
        self.assertIn("analyzer configuration or startup failed", rendered)
        self.assertNotIn("private", rendered)
        self.assertNotIn("missing-dump.tgz", rendered)

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
            self.assertIsInstance(
                application.state.control_plane_access_denial_reporter,
                ControlPlaneAccessDenialReporter,
            )

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
            self.assertNotIn("/openapi.json", paths)
            self.assertNotIn("/docs", paths)
            self.assertNotIn("/redoc", paths)

            documented_application = create_runtime_application(
                RuntimeApplicationRequest(
                    runtime=_Runtime(),
                    input_path=Path("fixture.tgz"),
                    expose_api_docs=True,
                )
            )
            documented_paths = route_paths(documented_application.routes)
            self.assertIn("/openapi.json", documented_paths)
            self.assertIn("/docs", documented_paths)
            self.assertIn("/redoc", documented_paths)

            with self.assertRaisesRegex(TypeError, "expose_api_docs"):
                RuntimeApplicationRequest(
                    runtime=_Runtime(),
                    input_path=Path("fixture.tgz"),
                    expose_api_docs=1,  # type: ignore[arg-type]
                )

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
