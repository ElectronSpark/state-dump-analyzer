"""Core-owned command line entry point for one analyzer plug-in and input."""

from __future__ import annotations

import argparse
import threading
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from .plugin_loading import load_plugin_entry_point, load_plugin_module
from .runtime import (
    RuntimeApplicationFactory,
    RuntimeApplicationRequest,
    create_runtime_application,
    require_plugin_runtime,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "port must be an integer from 1 through 65535"
        ) from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(
            "port must be an integer from 1 through 65535"
        )
    return port


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


def parse_args(argv: Sequence[str] | None = None) -> LaunchConfiguration:
    namespace = build_parser().parse_args(argv)
    host = str(namespace.host).strip()
    if not host:
        build_parser().error("--host must be non-empty")
    return LaunchConfiguration(
        plugin_name=namespace.plugin,
        plugin_module=namespace.plugin_module,
        input_path=namespace.input,
        host=host,
        port=namespace.port,
        no_browser=namespace.no_browser,
        frontend_dir=namespace.frontend_dir,
        api_only=namespace.api_only,
    )


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
    return f"http://{browser_host}:{port}"


def _schedule_browser(
    url: str,
    opener: Callable[[str], Any],
) -> None:
    timer = threading.Timer(0.8, opener, args=(url,))
    timer.daemon = True
    timer.start()


def _run_uvicorn(application: Any, *, host: str, port: int) -> None:
    try:
        import uvicorn
    except ImportError as error:
        raise RuntimeError(
            "web serving requires the 'router-dump-analyzer-core[web]' extra"
        ) from error
    uvicorn.run(application, host=host, port=port)


def run(
    configuration: LaunchConfiguration,
    *,
    entry_point_loader: Callable[[str], Any] = load_plugin_entry_point,
    module_loader: Callable[[str], Any] = load_plugin_module,
    application_factory: RuntimeApplicationFactory | None = None,
    server_runner: Callable[..., None] = _run_uvicorn,
    browser_opener: Callable[[str], Any] = webbrowser.open,
) -> None:
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
        )
    )
    if not configuration.no_browser:
        _schedule_browser(
            (
                f"{_browser_url(configuration.host, configuration.port)}/docs"
                if configuration.api_only
                else _browser_url(configuration.host, configuration.port)
            ),
            browser_opener,
        )
    server_runner(
        application,
        host=configuration.host,
        port=configuration.port,
    )


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    namespace = parser.parse_args(argv)
    host = str(namespace.host).strip()
    if not host:
        parser.error("--host must be non-empty")
    configuration = LaunchConfiguration(
        plugin_name=namespace.plugin,
        plugin_module=namespace.plugin_module,
        input_path=namespace.input,
        host=host,
        port=namespace.port,
        no_browser=namespace.no_browser,
        frontend_dir=namespace.frontend_dir,
        api_only=namespace.api_only,
    )
    try:
        run(configuration)
    except (LookupError, OSError, RuntimeError, TypeError, ValueError) as error:
        parser.exit(1, f"router-dump-analyzer: error: {error}\n")


if __name__ == "__main__":
    main()
