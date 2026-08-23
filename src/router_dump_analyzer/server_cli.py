"""Headless HTTP entry point for the durable analyzer control plane."""

from __future__ import annotations

import argparse
import importlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cli import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    _add_repeatable_plugin_allowlist_arguments,
    _is_loopback_host,
    _listener_authority,
    _port,
    _run_uvicorn,
)
from .control_plane import ControlPlane
from .control_plane_server import (
    ControlPlaneApplicationFactory,
    ControlPlaneApplicationRequest,
    create_control_plane_application,
)
from .ingestion_pipeline import PluginRegistry
from .plugin_composition_deployment import (
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

_SERVER_ERROR_FALLBACK = "server configuration or startup failed"


@dataclass(frozen=True, slots=True)
class ServerConfiguration:
    """Validated configuration for one headless control-plane server."""

    state_dir: Path
    plugin_names: tuple[str, ...]
    plugin_modules: tuple[str, ...]
    host: str
    port: int
    identity_resolver_module: str | None
    trust_control_plane_headers: bool
    grant_instance_operator: bool = False
    retention_policy_path: Path | None = None
    expose_api_docs: bool = False
    private_analysis_deployment_module: str | None = None
    plugin_deployment_module: str | None = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="router-dump-server",
        description=(
            "Serve the durable analyzer control plane without opening an "
            "analysis input or browser."
        ),
    )
    _add_repeatable_plugin_allowlist_arguments(parser)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", default=DEFAULT_PORT, type=_port)
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument(
        "--identity-resolver-module",
        metavar="PACKAGE:ATTRIBUTE",
        help=(
            "module-level callable that verifies credentials and returns a "
            "ControlPlaneIdentity"
        ),
    )
    identity.add_argument(
        "--trust-control-plane-headers",
        action="store_true",
        help=(
            "development only: trust tenant/principal headers on a loopback listener"
        ),
    )
    parser.add_argument(
        "--grant-instance-operator",
        action="store_true",
        help=(
            "development only: grant the control-plane instance-operator role "
            "through the trusted-header resolver on a loopback listener"
        ),
    )
    parser.add_argument(
        "--retention-policy",
        type=Path,
        dest="retention_policy_path",
        help="optional router_dump_analyzer.retention_policy.v1 JSON",
    )
    parser.add_argument(
        "--private-analysis-deployment-module",
        metavar="PACKAGE:ATTRIBUTE",
        help=(
            "process-trusted local private-analysis deployment descriptor or "
            "factory; no runner is configured when omitted"
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


def parse_args(argv: Sequence[str] | None = None) -> ServerConfiguration:
    parser = build_parser()
    namespace = parser.parse_args(argv)
    host = str(namespace.host).strip()
    if not host:
        parser.error("--host must be non-empty")
    if namespace.trust_control_plane_headers and not _is_loopback_host(host):
        parser.error("--trust-control-plane-headers is allowed only on a loopback host")
    if namespace.grant_instance_operator and not namespace.trust_control_plane_headers:
        parser.error("--grant-instance-operator requires --trust-control-plane-headers")
    if namespace.grant_instance_operator and not _is_loopback_host(host):
        parser.error("--grant-instance-operator is allowed only on a loopback host")
    if namespace.expose_api_docs and not _is_loopback_host(host):
        parser.error("--expose-api-docs is allowed only on a loopback host")
    return ServerConfiguration(
        state_dir=namespace.state_dir,
        plugin_names=tuple(namespace.plugin),
        plugin_modules=tuple(namespace.plugin_module),
        host=host,
        port=namespace.port,
        identity_resolver_module=namespace.identity_resolver_module,
        trust_control_plane_headers=namespace.trust_control_plane_headers,
        grant_instance_operator=namespace.grant_instance_operator,
        retention_policy_path=namespace.retention_policy_path,
        expose_api_docs=namespace.expose_api_docs,
        private_analysis_deployment_module=(
            namespace.private_analysis_deployment_module
        ),
        plugin_deployment_module=namespace.plugin_deployment_module,
    )


def _load_identity_resolver(target: str) -> Callable[[Any], Any]:
    module_name, separator, attribute = target.partition(":")
    module_name = module_name.strip()
    attribute = attribute.strip()
    if not separator or not module_name or not attribute or ":" in attribute:
        raise ValueError(
            "identity resolver module must use 'package.module:attribute' syntax"
        )
    try:
        module = importlib.import_module(module_name)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception as error:
        raise RuntimeError("identity resolver module could not be imported") from error
    except BaseException:  # noqa: BLE001 - deployment extensions are hostile code.
        raise RuntimeError("identity resolver module could not be imported") from None
    try:
        resolver = getattr(module, attribute)
    except AttributeError as error:
        raise LookupError("identity resolver target is not available") from error
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception:
        raise
    except BaseException:  # noqa: BLE001 - module attributes may be descriptors.
        raise RuntimeError("identity resolver target could not be resolved") from None
    if not callable(resolver):
        raise TypeError("identity resolver target must be callable")
    return resolver


def _plugins(
    configuration: ServerConfiguration,
    *,
    entry_point_loader: Callable[[str], Any],
    module_loader: Callable[[str], Any],
) -> tuple[LoadedPlugin, ...]:
    if bool(configuration.plugin_names) == bool(configuration.plugin_modules):
        raise ValueError("configure exactly one of plugin_names or plugin_modules")
    if configuration.plugin_names:
        return tuple(
            loaded_entry_point(name, loader=entry_point_loader)
            for name in configuration.plugin_names
        )
    return tuple(
        loaded_module(target, loader=module_loader)
        for target in configuration.plugin_modules
    )


def _trusted_header_resolver(configuration: ServerConfiguration) -> Any:
    from .web.control_plane_api import TrustedHeaderIdentityResolver

    if not _is_loopback_host(configuration.host):
        raise RuntimeError(
            "trusted control-plane headers may be used only on a loopback host"
        )
    authority = _listener_authority(configuration.host, configuration.port)
    authorities = (
        (authority, authority.rsplit(":", 1)[0])
        if configuration.port == 80
        else (authority,)
    )
    return TrustedHeaderIdentityResolver(
        allowed_hosts=authorities,
        allowed_origins=tuple(
            f"http://{allowed_authority}" for allowed_authority in authorities
        ),
        grant_instance_operator=configuration.grant_instance_operator,
    )


def run(
    configuration: ServerConfiguration,
    *,
    entry_point_loader: Callable[[str], Any] = load_plugin_entry_point,
    module_loader: Callable[[str], Any] = load_plugin_module,
    identity_resolver_loader: Callable[
        [str], Callable[[Any], Any]
    ] = _load_identity_resolver,
    private_analysis_deployment_loader: Callable[..., Any] = (
        load_private_analysis_deployment
    ),
    plugin_deployment_loader: Callable[..., Any] = (
        load_plugin_composition_deployment
    ),
    application_factory: ControlPlaneApplicationFactory = (
        create_control_plane_application
    ),
    server_runner: Callable[..., None] = _run_uvicorn,
    registry_factory: Callable[..., Any] = PluginRegistry,
    control_plane_factory: Callable[..., Any] = ControlPlane,
) -> None:
    """Build and serve one API-only durable control plane."""

    host = configuration.host.strip()
    if not host:
        raise ValueError("host must be non-empty")
    if configuration.expose_api_docs and not _is_loopback_host(host):
        raise ValueError("API documentation may be exposed only on a loopback host")
    if (
        configuration.grant_instance_operator
        and not configuration.trust_control_plane_headers
    ):
        raise ValueError(
            "the instance-operator role may be granted only through the "
            "trusted-header resolver"
        )
    if configuration.grant_instance_operator and not _is_loopback_host(host):
        raise ValueError(
            "the instance-operator role may be granted only on a loopback host"
        )
    if configuration.trust_control_plane_headers:
        if configuration.identity_resolver_module is not None:
            raise ValueError("configure either an identity resolver or trusted headers")
        identity_resolver = _trusted_header_resolver(configuration)
    else:
        target = configuration.identity_resolver_module
        if target is None:
            raise ValueError("an identity resolver is required")
        identity_resolver = identity_resolver_loader(target)
        if not callable(identity_resolver):
            raise TypeError("identity resolver target must be callable")

    selector_count = sum(
        (
            bool(configuration.plugin_names),
            bool(configuration.plugin_modules),
            configuration.plugin_deployment_module is not None,
        )
    )
    if selector_count != 1:
        raise ValueError(
            "configure exactly one plug-in allowlist or composition deployment"
        )
    state_root = configuration.state_dir.expanduser().resolve()
    composition_options: dict[str, Any] = {}
    if configuration.plugin_deployment_module is not None:
        composition = plugin_deployment_loader(
            configuration.plugin_deployment_module,
            context=PluginCompositionDeploymentContext(state_dir=state_root),
        )
        registry = composition.primary_registry
        composition_options = {
            "plugin_composition_policy": composition.policy,
            "capability_providers": composition.capability_providers,
            "allow_inline_only": composition.allow_inline_only,
        }
    else:
        loaded_plugins = _plugins(
            configuration,
            entry_point_loader=entry_point_loader,
            module_loader=module_loader,
        )
        if registry_factory is PluginRegistry:
            registry = registry_factory(require_executable_identity=True)
            for loaded_plugin in loaded_plugins:
                loaded_plugin.register(registry)
        else:
            # Keep custom composition factories source-compatible. Production uses
            # the core registry branch above, which records loader coordinates.
            registry = registry_factory(
                tuple(loaded.plugin for loaded in loaded_plugins),
                require_executable_identity=True,
            )
    retention_policy = None
    if configuration.retention_policy_path is not None:
        from .maintenance_cli import load_policy

        retention_policy = load_policy(
            configuration.retention_policy_path.expanduser().resolve()
        ).ingestion
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
    control_plane = control_plane_factory(
        state_root,
        registry=registry,
        retention_policy=retention_policy,
        **composition_options,
        **private_analysis_options,
    )
    try:
        application = application_factory(
            ControlPlaneApplicationRequest(
                control_plane=control_plane,
                identity_resolver=identity_resolver,
                expose_api_docs=configuration.expose_api_docs,
            )
        )
        server_runner(
            application,
            host=host,
            port=configuration.port,
        )
    except BaseException:
        # Normal shutdown belongs exclusively to the ASGI lifespan.  This is
        # the construction/bind-failure fallback for a server that never
        # entered that lifespan; ControlPlane.close() is idempotent if it did.
        control_plane.close()
        raise


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    try:
        configuration = parse_args(argv)
        run(configuration)
    except (LookupError, OSError, RuntimeError, TypeError, ValueError) as error:
        detail = bounded_public_error_detail(
            str(error),
            fallback=_SERVER_ERROR_FALLBACK,
        )
        parser.exit(1, f"router-dump-server: error: {detail}\n")


if __name__ == "__main__":
    main()


__all__ = [
    "ServerConfiguration",
    "build_parser",
    "main",
    "parse_args",
    "run",
]
