"""Core-owned command line entry point for one analyzer plug-in and input."""

from __future__ import annotations

import argparse
import ipaddress
import threading
import webbrowser
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .plugin_loading import load_plugin_entry_point, load_plugin_module
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .public_text import bounded_public_error_detail
from .runtime import (
    RuntimeApplicationFactory,
    RuntimeApplicationRequest,
    create_runtime_application,
    require_plugin_runtime,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
_CLI_ERROR_FALLBACK = "analyzer configuration or startup failed"


def _cli_error_detail(error: BaseException) -> str:
    """Render one expected startup error behind the final hostile-text fence."""

    try:
        return bounded_public_error_detail(
            str(error),
            fallback=_CLI_ERROR_FALLBACK,
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - hostile exception rendering is data.
        return _CLI_ERROR_FALLBACK


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "port must be an integer from 1 through 65535"
        ) from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be an integer from 1 through 65535")
    return port


def _add_repeatable_plugin_allowlist_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    """Add the shared installed-or-module plug-in allowlist selector."""

    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--plugin",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "allowlisted installed router_dump_analyzer.plugins entry point; "
            "repeat to allow multiple candidates"
        ),
    )
    selection.add_argument(
        "--plugin-module",
        action="append",
        default=[],
        metavar="PACKAGE[:ATTRIBUTE]",
        help=(
            "allowlisted direct plug-in module; ATTRIBUTE defaults to plugin; "
            "repeat to allow multiple candidates"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="router-dump-analyzer",
        description=(
            "Run the core analyzer UI with exactly one installed or "
            "directly named plug-in."
        ),
    )
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--plugin",
        metavar="NAME",
        help="installed router_dump_analyzer.plugins entry-point name",
    )
    selection.add_argument(
        "--plugin-module",
        metavar="PACKAGE[:ATTRIBUTE]",
        help="direct plug-in module target; ATTRIBUTE defaults to plugin",
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        metavar="PATH",
        help="dump, fixture, or assembly path interpreted by the plug-in",
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", default=DEFAULT_PORT, type=_port)
    parser.add_argument(
        "--frontend-dir",
        type=Path,
        help="core frontend distribution; normally discovered automatically",
    )
    parser.add_argument(
        "--api-only",
        action="store_true",
        help="disable core page and asset serving",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="do not open the analyzer URL in the default browser",
    )
    parser.add_argument(
        "--control-plane-dir",
        type=Path,
        help=(
            "enable durable project/workspace/session, review, and upload "
            "APIs using this state directory"
        ),
    )
    parser.add_argument(
        "--trust-control-plane-headers",
        action="store_true",
        help=(
            "development only: trust caller-supplied tenant/principal headers; "
            "required when exposing the built-in control plane off loopback"
        ),
    )
    parser.add_argument(
        "--grant-instance-operator",
        action="store_true",
        help=(
            "development only: grant the control-plane instance-operator role "
            "through the built-in trusted-header resolver on a loopback listener"
        ),
    )
    parser.add_argument(
        "--control-plane-retention-policy",
        type=Path,
        help=(
            "versioned retention-policy JSON used for ingestion quotas and "
            "maintenance; requires --control-plane-dir"
        ),
    )
    parser.add_argument(
        "--expose-api-docs",
        action="store_true",
        help=(
            "explicitly expose /docs, /redoc, and /openapi.json; allowed "
            "only on a loopback listener"
        ),
    )
    return parser


@dataclass(frozen=True, slots=True)
class LaunchConfiguration:
    plugin_name: str | None
    plugin_module: str | None
    input_path: Path
    host: str
    port: int
    no_browser: bool
    frontend_dir: Path | None = None
    api_only: bool = False
    control_plane_dir: Path | None = None
    trust_control_plane_headers: bool = False
    grant_instance_operator: bool = False
    control_plane_retention_policy: Path | None = None
    expose_api_docs: bool = False


def parse_args(argv: Sequence[str] | None = None) -> LaunchConfiguration:
    namespace = build_parser().parse_args(argv)
    host = str(namespace.host).strip()
    if not host:
        build_parser().error("--host must be non-empty")
    if namespace.expose_api_docs and not _is_loopback_host(host):
        build_parser().error("--expose-api-docs is allowed only on a loopback host")
    if namespace.grant_instance_operator and namespace.control_plane_dir is None:
        build_parser().error("--grant-instance-operator requires --control-plane-dir")
    if namespace.grant_instance_operator and not _is_loopback_host(host):
        build_parser().error(
            "--grant-instance-operator is allowed only on a loopback host"
        )
    if (
        namespace.control_plane_retention_policy is not None
        and namespace.control_plane_dir is None
    ):
        build_parser().error(
            "--control-plane-retention-policy requires --control-plane-dir"
        )
    return LaunchConfiguration(
        plugin_name=namespace.plugin,
        plugin_module=namespace.plugin_module,
        input_path=namespace.input,
        host=host,
        port=namespace.port,
        no_browser=namespace.no_browser,
        frontend_dir=namespace.frontend_dir,
        api_only=namespace.api_only,
        control_plane_dir=namespace.control_plane_dir,
        trust_control_plane_headers=namespace.trust_control_plane_headers,
        grant_instance_operator=namespace.grant_instance_operator,
        control_plane_retention_policy=(namespace.control_plane_retention_policy),
        expose_api_docs=namespace.expose_api_docs,
    )


def _is_loopback_host(value: str) -> bool:
    normalized = value.strip().removeprefix("[").removesuffix("]")
    if normalized.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _load_selected_plugin(
    configuration: LaunchConfiguration,
    *,
    entry_point_loader: Callable[[str], Any],
    module_loader: Callable[[str], Any],
) -> Any:
    if configuration.plugin_name is not None:
        return entry_point_loader(configuration.plugin_name)
    assert configuration.plugin_module is not None
    return module_loader(configuration.plugin_module)


def _browser_url(host: str, port: int) -> str:
    browser_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    if ":" in browser_host and not browser_host.startswith("["):
        browser_host = f"[{browser_host}]"
    return f"http://{browser_host}:{port}"


def _listener_authority(host: str, port: int) -> str:
    normalized = host.strip().removeprefix("[").removesuffix("]")
    if ":" in normalized:
        normalized = f"[{normalized}]"
    return f"{normalized}:{port}"


def _schedule_browser(
    url: str,
    opener: Callable[[str], Any],
) -> None:
    timer = threading.Timer(0.8, opener, args=(url,))
    timer.daemon = True
    timer.start()


def _run_uvicorn(application: Any, *, host: str, port: int) -> None:
    import asyncio

    try:
        import uvicorn
    except ImportError as error:
        raise RuntimeError(
            "web serving requires the 'router-dump-analyzer-core[web]' extra"
        ) from error

    # Drive the core-owned lifespan before Uvicorn starts.  Starlette reports
    # lifespan failures through Uvicorn's logger and then converts them into a
    # generic startup exit, which would bypass the CLI's bounded public-error
    # projection.  The same lifespan still surrounds the complete server run;
    # Uvicorn is told not to enter it a second time.
    configuration = uvicorn.Config(
        application,
        host=host,
        port=port,
        lifespan="off",
    )
    server = uvicorn.Server(configuration)

    async def serve_with_core_lifespan() -> None:
        async with application.router.lifespan_context(application):
            await server.serve()

    asyncio.run(
        serve_with_core_lifespan(),
        loop_factory=configuration.get_loop_factory(),
    )
    if not server.started:
        from uvicorn.config import STARTUP_FAILURE

        raise SystemExit(STARTUP_FAILURE)


def run(
    configuration: LaunchConfiguration,
    *,
    entry_point_loader: Callable[[str], Any] = load_plugin_entry_point,
    module_loader: Callable[[str], Any] = load_plugin_module,
    application_factory: RuntimeApplicationFactory | None = None,
    server_runner: Callable[..., None] = _run_uvicorn,
    browser_opener: Callable[[str], Any] = webbrowser.open,
) -> None:
    if configuration.expose_api_docs and not _is_loopback_host(configuration.host):
        raise ValueError("API documentation may be exposed only on a loopback host")
    if (
        configuration.grant_instance_operator
        and configuration.control_plane_dir is None
    ):
        raise ValueError(
            "the instance-operator role may be granted only by the built-in "
            "trusted-header control plane"
        )
    if configuration.grant_instance_operator and not _is_loopback_host(
        configuration.host
    ):
        raise ValueError(
            "the instance-operator role may be granted only on a loopback host"
        )
    input_path = configuration.input_path.expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"analyzer input does not exist: {input_path}")
    plugin = _load_selected_plugin(
        configuration,
        entry_point_loader=entry_point_loader,
        module_loader=module_loader,
    )
    runtime = require_plugin_runtime(plugin)
    factory = application_factory or create_runtime_application
    control_plane = None
    identity_resolver = None
    if configuration.control_plane_dir is not None:
        from .control_plane import ControlPlane
        from .ingestion_pipeline import PluginRegistry
        from .maintenance_cli import load_policy
        from .web.control_plane_api import TrustedHeaderIdentityResolver

        if (
            not _is_loopback_host(configuration.host)
            and not configuration.trust_control_plane_headers
        ):
            raise RuntimeError(
                "the built-in trusted-header control plane may bind only to "
                "loopback; use an authenticated ASGI deployment, or pass "
                "--trust-control-plane-headers explicitly for a controlled "
                "development network"
            )

        retention_policy = (
            load_policy(configuration.control_plane_retention_policy).ingestion
            if configuration.control_plane_retention_policy is not None
            else None
        )
        control_plane = ControlPlane(
            configuration.control_plane_dir.expanduser().resolve(),
            registry=PluginRegistry(
                (plugin,),
                require_executable_identity=True,
            ),
            retention_policy=retention_policy,
        )
        authority = _listener_authority(
            configuration.host,
            configuration.port,
        )
        authorities = (
            (authority, authority.rsplit(":", 1)[0])
            if configuration.port == 80
            else (authority,)
        )
        identity_resolver = TrustedHeaderIdentityResolver(
            allowed_hosts=authorities,
            allowed_origins=tuple(
                f"http://{allowed_authority}" for allowed_authority in authorities
            ),
            grant_instance_operator=configuration.grant_instance_operator,
        )
    try:
        application = factory(
            RuntimeApplicationRequest(
                runtime=runtime,
                input_path=input_path,
                frontend_root=(
                    configuration.frontend_dir.expanduser().resolve()
                    if configuration.frontend_dir is not None
                    else None
                ),
                serve_frontend=not configuration.api_only,
                control_plane=control_plane,
                control_plane_identity_resolver=identity_resolver,
                manage_control_plane_lifecycle=control_plane is not None,
                expose_api_docs=configuration.expose_api_docs,
            )
        )
        if not configuration.no_browser:
            _schedule_browser(
                (
                    f"{_browser_url(configuration.host, configuration.port)}/docs"
                    if configuration.api_only and configuration.expose_api_docs
                    else (
                        f"{_browser_url(configuration.host, configuration.port)}/health"
                        if configuration.api_only
                        else _browser_url(configuration.host, configuration.port)
                    )
                ),
                browser_opener,
            )
        server_runner(
            application,
            host=configuration.host,
            port=configuration.port,
        )
    finally:
        if control_plane is not None:
            control_plane.close()


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    namespace = parser.parse_args(argv)
    host = str(namespace.host).strip()
    if not host:
        parser.error("--host must be non-empty")
    if namespace.expose_api_docs and not _is_loopback_host(host):
        parser.error("--expose-api-docs is allowed only on a loopback host")
    if namespace.grant_instance_operator and namespace.control_plane_dir is None:
        parser.error("--grant-instance-operator requires --control-plane-dir")
    if namespace.grant_instance_operator and not _is_loopback_host(host):
        parser.error("--grant-instance-operator is allowed only on a loopback host")
    if (
        namespace.control_plane_retention_policy is not None
        and namespace.control_plane_dir is None
    ):
        parser.error("--control-plane-retention-policy requires --control-plane-dir")
    configuration = LaunchConfiguration(
        plugin_name=namespace.plugin,
        plugin_module=namespace.plugin_module,
        input_path=namespace.input,
        host=host,
        port=namespace.port,
        no_browser=namespace.no_browser,
        frontend_dir=namespace.frontend_dir,
        api_only=namespace.api_only,
        control_plane_dir=namespace.control_plane_dir,
        trust_control_plane_headers=namespace.trust_control_plane_headers,
        grant_instance_operator=namespace.grant_instance_operator,
        control_plane_retention_policy=(namespace.control_plane_retention_policy),
        expose_api_docs=namespace.expose_api_docs,
    )
    try:
        run(configuration)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except (LookupError, OSError, RuntimeError, TypeError, ValueError) as error:
        detail = _cli_error_detail(error)
        parser.exit(1, f"router-dump-analyzer: error: {detail}\n")
    except BaseException:  # noqa: BLE001 - final process-facing fault fence.
        parser.exit(1, f"router-dump-analyzer: error: {_CLI_ERROR_FALLBACK}\n")


if __name__ == "__main__":
    main()
