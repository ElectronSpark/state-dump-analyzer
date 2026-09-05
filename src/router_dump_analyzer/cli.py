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

from .plugin_composition_deployment import (
    _control_plane_composition_options,
    PluginCompositionDeploymentContext,
    load_plugin_composition_deployment,
)
from .plugin_loading import (
    LoadedPlugin,
    load_plugin_entry_point,
    load_plugin_module,
    loaded_entry_point,
    loaded_module,
)
from .private_analysis_deployment import (
    PrivateAnalysisDeploymentContext,
    load_private_analysis_deployment,
)
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
_UVICORN_STARTUP_FAILURE = 3


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
    selection.add_argument(
        "--plugin-deployment-module",
        metavar="PACKAGE:ATTRIBUTE",
        help=(
            "process-trusted plug-in composition descriptor or factory; "
            "selects exact primary and auxiliary configured instances"
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
        "--private-analysis-deployment-module",
        metavar="PACKAGE:ATTRIBUTE",
        help=(
            "process-trusted local private-analysis deployment descriptor or "
            "factory; requires --control-plane-dir"
        ),
    )
    parser.add_argument(
        "--plugin-composition-deployment-module",
        metavar="PACKAGE:ATTRIBUTE",
        help=(
            "process-trusted plug-in composition descriptor or factory for "
            "the embedded durable control plane; requires --control-plane-dir"
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
    private_analysis_deployment_module: str | None = None
    plugin_composition_deployment_module: str | None = None


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
    if (
        namespace.private_analysis_deployment_module is not None
        and namespace.control_plane_dir is None
    ):
        build_parser().error(
            "--private-analysis-deployment-module requires --control-plane-dir"
        )
    if (
        namespace.plugin_composition_deployment_module is not None
        and namespace.control_plane_dir is None
    ):
        build_parser().error(
            "--plugin-composition-deployment-module requires --control-plane-dir"
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
        private_analysis_deployment_module=(
            namespace.private_analysis_deployment_module
        ),
        plugin_composition_deployment_module=(
            namespace.plugin_composition_deployment_module
        ),
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
) -> LoadedPlugin:
    if configuration.plugin_name is not None:
        return loaded_entry_point(
            configuration.plugin_name,
            loader=entry_point_loader,
        )
    assert configuration.plugin_module is not None
    return loaded_module(
        configuration.plugin_module,
        loader=module_loader,
    )


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

    # Uvicorn 0.30 through 0.35 configures its event-loop policy through
    # setup_event_loop(); 0.36 and later return a loop factory instead.  Keep
    # both declared dependency generations functional and retain Uvicorn's
    # uvloop/asyncio and Windows policy selection.  Entering Runner initializes
    # the selected loop before the lifespan coroutine is constructed, so a
    # broken loop configuration cannot also leak an un-awaited coroutine.
    get_loop_factory = getattr(configuration, "get_loop_factory", None)
    if callable(get_loop_factory):
        loop_factory = get_loop_factory()
    else:
        setup_event_loop = getattr(configuration, "setup_event_loop", None)
        if not callable(setup_event_loop):
            raise RuntimeError(  # noqa: TRY004 - dependency capability is absent.
                "installed Uvicorn does not expose a supported event-loop "
                "configuration API"
            )
        setup_event_loop()
        loop_factory = None

    with asyncio.Runner(loop_factory=loop_factory) as runner:
        runner.run(serve_with_core_lifespan())
    if not server.started:
        # Uvicorn's CLI has used exit status 3 for a server that returns before
        # startup throughout the declared >=0.30,<1 range.  Owning that small
        # process contract avoids depending on its version-specific module.
        raise SystemExit(_UVICORN_STARTUP_FAILURE)


def run(
    configuration: LaunchConfiguration,
    *,
    entry_point_loader: Callable[[str], Any] = load_plugin_entry_point,
    module_loader: Callable[[str], Any] = load_plugin_module,
    application_factory: RuntimeApplicationFactory | None = None,
    server_runner: Callable[..., None] = _run_uvicorn,
    browser_opener: Callable[[str], Any] = webbrowser.open,
    private_analysis_deployment_loader: Callable[..., Any] = (
        load_private_analysis_deployment
    ),
    plugin_composition_deployment_loader: Callable[..., Any] = (
        load_plugin_composition_deployment
    ),
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
    if (
        configuration.private_analysis_deployment_module is not None
        and configuration.control_plane_dir is None
    ):
        raise ValueError(
            "private-analysis deployment requires the durable control plane"
        )
    if (
        configuration.plugin_composition_deployment_module is not None
        and configuration.control_plane_dir is None
    ):
        raise ValueError(
            "plug-in composition deployment requires the durable control plane"
        )
    input_path = configuration.input_path.expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"analyzer input does not exist: {input_path}")
    loaded_plugin = _load_selected_plugin(
        configuration,
        entry_point_loader=entry_point_loader,
        module_loader=module_loader,
    )
    plugin = loaded_plugin.plugin
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
        state_root = configuration.control_plane_dir.expanduser().resolve()
        composition_options: dict[str, Any] = {}
        if configuration.plugin_composition_deployment_module is not None:
            composition = plugin_composition_deployment_loader(
                configuration.plugin_composition_deployment_module,
                context=PluginCompositionDeploymentContext(state_dir=state_root),
            )
            registry = composition.primary_registry
            composition_options = _control_plane_composition_options(composition)
        else:
            registry = PluginRegistry(require_executable_identity=True)
            register = getattr(registry, "register", None)
            if callable(register):
                loaded_plugin.register(registry)
            else:
                # Preserve lightweight dependency-injected registry doubles that
                # predate coordinate-aware composition.
                registry = PluginRegistry(
                    (plugin,),
                    require_executable_identity=True,
                )
        private_analysis_options: dict[str, Any] = {}
        if configuration.private_analysis_deployment_module is not None:
            deployment = private_analysis_deployment_loader(
                configuration.private_analysis_deployment_module,
                context=PrivateAnalysisDeploymentContext(state_dir=state_root),
            )
            private_analysis_options = {
                "private_analysis_runners": deployment.registrations,
                "private_analysis_execution_limits": deployment.execution_limits,
                "private_analysis_ceilings": deployment.ceilings,
            }
        control_plane = ControlPlane(
            state_root,
            registry=registry,
            retention_policy=retention_policy,
            **composition_options,
            **private_analysis_options,
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
    if (
        namespace.private_analysis_deployment_module is not None
        and namespace.control_plane_dir is None
    ):
        parser.error(
            "--private-analysis-deployment-module requires --control-plane-dir"
        )
    if (
        namespace.plugin_composition_deployment_module is not None
        and namespace.control_plane_dir is None
    ):
        parser.error(
            "--plugin-composition-deployment-module requires --control-plane-dir"
        )
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
        private_analysis_deployment_module=(
            namespace.private_analysis_deployment_module
        ),
        plugin_composition_deployment_module=(
            namespace.plugin_composition_deployment_module
        ),
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
