from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any
from unittest.mock import patch

from router_dump_analyzer.control_plane_server import (
    ControlPlaneApplicationRequest,
)
from router_dump_analyzer.server_cli import (
    ServerConfiguration,
    main,
    parse_args,
    run,
)


class _ControlPlane:
    def __init__(self, root: Path, **values: Any) -> None:
        self.root = root
        self.values = values
        self.close_count = 0

    def start(self) -> None:
        raise AssertionError("the CLI must leave startup to ASGI lifespan")

    def close(self) -> None:
        self.close_count += 1


class ServerCliTests(unittest.TestCase):
    def test_parser_accepts_repeated_plugin_allowlist_and_production_resolver(
        self,
    ) -> None:
        parsed = parse_args(
            [
                "--plugin-module",
                "vendor.alpha:plugin",
                "--plugin-module",
                "vendor.beta:plugin",
                "--state-dir",
                "durable-state",
                "--identity-resolver-module",
                "deployment.identity:resolver",
                "--host",
                "0.0.0.0",
                "--port",
                "8876",
                "--retention-policy",
                "retention.json",
            ]
        )

        self.assertEqual(
            parsed.plugin_modules,
            ("vendor.alpha:plugin", "vendor.beta:plugin"),
        )
        self.assertEqual(parsed.plugin_names, ())
        self.assertEqual(parsed.state_dir, Path("durable-state"))
        self.assertEqual(parsed.host, "0.0.0.0")
        self.assertEqual(parsed.port, 8876)
        self.assertEqual(
            parsed.identity_resolver_module,
            "deployment.identity:resolver",
        )
        self.assertFalse(parsed.trust_control_plane_headers)
        self.assertEqual(parsed.retention_policy_path, Path("retention.json"))
        self.assertFalse(parsed.expose_api_docs)

    def test_parser_requires_plugin_identity_and_safe_identity_mode(self) -> None:
        with self.assertRaises(SystemExit) as missing_plugin:
            parse_args(
                [
                    "--state-dir",
                    "state",
                    "--identity-resolver-module",
                    "deployment.identity:resolver",
                ]
            )
        self.assertEqual(missing_plugin.exception.code, 2)

        with self.assertRaises(SystemExit) as missing_identity:
            parse_args(
                [
                    "--plugin",
                    "router",
                    "--state-dir",
                    "state",
                ]
            )
        self.assertEqual(missing_identity.exception.code, 2)

        with self.assertRaises(SystemExit) as mixed_plugins:
            parse_args(
                [
                    "--plugin",
                    "router",
                    "--plugin-module",
                    "vendor.router:plugin",
                    "--state-dir",
                    "state",
                    "--trust-control-plane-headers",
                ]
            )
        self.assertEqual(mixed_plugins.exception.code, 2)

        with self.assertRaises(SystemExit) as unsafe_headers:
            parse_args(
                [
                    "--plugin",
                    "router",
                    "--state-dir",
                    "state",
                    "--host",
                    "0.0.0.0",
                    "--trust-control-plane-headers",
                ]
            )
        self.assertEqual(unsafe_headers.exception.code, 2)

        with self.assertRaises(SystemExit) as unsafe_docs:
            parse_args(
                [
                    "--plugin",
                    "router",
                    "--state-dir",
                    "state",
                    "--host",
                    "0.0.0.0",
                    "--identity-resolver-module",
                    "deployment.identity:resolver",
                    "--expose-api-docs",
                ]
            )
        self.assertEqual(unsafe_docs.exception.code, 2)

    def test_parser_allows_explicit_api_docs_only_on_loopback(self) -> None:
        parsed = parse_args(
            [
                "--plugin",
                "router",
                "--state-dir",
                "state",
                "--identity-resolver-module",
                "deployment.identity:resolver",
                "--expose-api-docs",
            ]
        )
        self.assertTrue(parsed.expose_api_docs)

    def test_run_builds_multi_plugin_registry_without_input_or_browser(self) -> None:
        calls: list[tuple[str, Any]] = []
        plugins = {"vendor.alpha:plugin": object(), "vendor.beta:plugin": object()}
        resolver = lambda _request: object()
        registry = object()
        control_planes: list[_ControlPlane] = []

        def registry_factory(values: tuple[Any, ...], **options: Any) -> Any:
            calls.append(("registry", (values, options)))
            return registry

        def control_plane_factory(root: Path, **values: Any) -> _ControlPlane:
            control_plane = _ControlPlane(root, **values)
            control_planes.append(control_plane)
            calls.append(("control-plane", control_plane))
            return control_plane

        application = object()

        def application_factory(request: ControlPlaneApplicationRequest) -> Any:
            calls.append(("application", request))
            return application

        def server_runner(app: Any, *, host: str, port: int) -> None:
            calls.append(("server", (app, host, port)))

        with tempfile.TemporaryDirectory() as directory:
            configuration = ServerConfiguration(
                state_dir=Path(directory) / "state",
                plugin_names=(),
                plugin_modules=tuple(plugins),
                host="0.0.0.0",
                port=8876,
                identity_resolver_module="deployment.identity:resolver",
                trust_control_plane_headers=False,
            )
            run(
                configuration,
                entry_point_loader=lambda name: self.fail(name),
                module_loader=lambda target: plugins[target],
                identity_resolver_loader=lambda target: (
                    resolver
                    if target == "deployment.identity:resolver"
                    else self.fail(target)
                ),
                application_factory=application_factory,
                server_runner=server_runner,
                registry_factory=registry_factory,
                control_plane_factory=control_plane_factory,
            )

            expected_root = (Path(directory) / "state").resolve()

        registry_values, registry_options = calls[0][1]
        self.assertEqual(registry_values, tuple(plugins.values()))
        self.assertEqual(
            registry_options,
            {"require_executable_identity": True},
        )
        self.assertEqual(control_planes[0].root, expected_root)
        self.assertIs(control_planes[0].values["registry"], registry)
        self.assertIsNone(control_planes[0].values["retention_policy"])
        request = calls[2][1]
        self.assertIsInstance(request, ControlPlaneApplicationRequest)
        self.assertIs(request.control_plane, control_planes[0])
        self.assertIs(request.identity_resolver, resolver)
        self.assertFalse(request.expose_api_docs)
        self.assertEqual(calls[3], ("server", (application, "0.0.0.0", 8876)))
        self.assertEqual(control_planes[0].close_count, 0)
        self.assertFalse(hasattr(configuration, "input_path"))
        self.assertFalse(hasattr(configuration, "no_browser"))

    def test_run_closes_constructed_control_plane_if_server_never_starts(
        self,
    ) -> None:
        control_planes: list[_ControlPlane] = []

        def control_plane_factory(root: Path, **values: Any) -> _ControlPlane:
            control_plane = _ControlPlane(root, **values)
            control_planes.append(control_plane)
            return control_plane

        with tempfile.TemporaryDirectory() as directory:
            configuration = ServerConfiguration(
                state_dir=Path(directory) / "state",
                plugin_names=("router",),
                plugin_modules=(),
                host="127.0.0.1",
                port=8765,
                identity_resolver_module="deployment.identity:resolver",
                trust_control_plane_headers=False,
            )
            with self.assertRaisesRegex(RuntimeError, "bind failed"):
                run(
                    configuration,
                    entry_point_loader=lambda _name: object(),
                    identity_resolver_loader=lambda _target: lambda _request: object(),
                    application_factory=lambda _request: object(),
                    server_runner=lambda _app, **_values: (_ for _ in ()).throw(
                        RuntimeError("bind failed")
                    ),
                    registry_factory=lambda _plugins, **_values: object(),
                    control_plane_factory=control_plane_factory,
                )

        self.assertEqual(control_planes[0].close_count, 1)

    def test_programmatic_trusted_headers_still_fail_off_loopback(self) -> None:
        configuration = ServerConfiguration(
            state_dir=Path("state"),
            plugin_names=("router",),
            plugin_modules=(),
            host="0.0.0.0",
            port=8765,
            identity_resolver_module=None,
            trust_control_plane_headers=True,
        )
        with self.assertRaisesRegex(RuntimeError, "only on a loopback host"):
            run(
                configuration,
                entry_point_loader=lambda _name: object(),
                registry_factory=lambda _plugins, **_values: object(),
                control_plane_factory=lambda *_args, **_values: self.fail(),
                application_factory=lambda _request: self.fail(),
                server_runner=lambda _app, **_values: self.fail(),
            )

    def test_programmatic_api_docs_still_fail_off_loopback(self) -> None:
        configuration = ServerConfiguration(
            state_dir=Path("state"),
            plugin_names=("router",),
            plugin_modules=(),
            host="0.0.0.0",
            port=8765,
            identity_resolver_module="deployment.identity:resolver",
            trust_control_plane_headers=False,
            expose_api_docs=True,
        )
        with self.assertRaisesRegex(ValueError, "only on a loopback host"):
            run(
                configuration,
                entry_point_loader=lambda _name: self.fail(),
                identity_resolver_loader=lambda _target: self.fail(),
                registry_factory=lambda _plugins, **_values: self.fail(),
                control_plane_factory=lambda *_args, **_values: self.fail(),
                application_factory=lambda _request: self.fail(),
                server_runner=lambda _app, **_values: self.fail(),
            )

    def test_main_redacts_host_paths_from_startup_failures(self) -> None:
        stderr = io.StringIO()
        argv = [
            "--plugin",
            "router",
            "--state-dir",
            "state",
            "--identity-resolver-module",
            "deployment.identity:resolver",
        ]
        private = r"failed to open C:\private\tenant\catalog.sqlite3"
        with (
            patch(
                "router_dump_analyzer.server_cli.run",
                side_effect=RuntimeError(private),
            ),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as stopped,
        ):
            main(argv)

        self.assertEqual(stopped.exception.code, 1)
        rendered = stderr.getvalue()
        self.assertIn("server configuration or startup failed", rendered)
        self.assertNotIn("private", rendered)
        self.assertNotIn("catalog.sqlite3", rendered)


if __name__ == "__main__":
    unittest.main()
