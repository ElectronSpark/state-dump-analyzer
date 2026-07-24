"""Host the separately owned Router State Lab frontend distribution.

The backend deliberately knows only the frontend manifest contract.  Page
filenames, asset locations, and route-to-page mappings remain in ``frontend/``
and are not embedded in Python application code.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import PlainTextResponse
from starlette.types import Receive, Scope, Send


FRONTEND_DIR_ENV = "ROUTER_DUMP_FRONTEND_DIR"
SERVE_FRONTEND_ENV = "ROUTER_DUMP_SERVE_FRONTEND"
FRONTEND_MANIFEST = "frontend-manifest.json"
REQUIRED_PAGE_ROUTES = frozenset({"/", "/topology", "/node"})


class FrontendBundleError(RuntimeError):
    """Raised when a frontend distribution violates the hosting contract."""


@dataclass(frozen=True)
class FrontendBundle:
    """Validated paths exported by one frontend distribution."""

    root: Path
    manifest_path: Path
    assets_url_prefix: str
    assets_directory: Path
    pages_by_route: dict[str, Path]

    @property
    def page_routes(self) -> tuple[str, ...]:
        return tuple(self.pages_by_route)

    def page_for_route(self, route: str) -> Path:
        try:
            return self.pages_by_route[route]
        except KeyError as error:
            raise HTTPException(
                status_code=404,
                detail="frontend page is not declared by the frontend manifest",
            ) from error

    def owns_request_path(self, path: str) -> bool:
        return path in self.pages_by_route or (
            path == self.assets_url_prefix
            or path.startswith(f"{self.assets_url_prefix}/")
        )


def _boolean_environment(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise FrontendBundleError(
        f"{name} must be one of 1/0, true/false, yes/no, or on/off"
    )


def _frontend_root_candidates(explicit_root: Path | None) -> list[Path]:
    if explicit_root is not None:
        return [explicit_root.expanduser()]
    environment_root = os.environ.get(FRONTEND_DIR_ENV)
    if environment_root:
        return [Path(environment_root).expanduser()]
    module_path = Path(__file__).resolve()
    candidates = [
        module_path.parent / "frontend",
        module_path.parents[2] / "frontend",
        Path.cwd() / "frontend",
    ]
    unique: list[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in unique:
            unique.append(resolved)
    return unique


def resolve_frontend_root(explicit_root: Path | None = None) -> Path:
    """Locate a source checkout or wheel-packaged frontend distribution."""

    candidates = _frontend_root_candidates(explicit_root)
    for candidate in candidates:
        root = candidate.resolve()
        if (root / FRONTEND_MANIFEST).is_file():
            return root
    checked = ", ".join(str(candidate.resolve()) for candidate in candidates)
    override = f" Set {FRONTEND_DIR_ENV} to the frontend directory."
    raise FrontendBundleError(
        f"Could not find {FRONTEND_MANIFEST}; checked: {checked}.{override}"
    )


def _relative_file(root: Path, value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise FrontendBundleError(
            f"{field} must be a non-empty POSIX-style relative path"
        )
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise FrontendBundleError(f"{field} must remain inside the frontend root")
    candidate = root.joinpath(*relative.parts).resolve()
    if root != candidate and root not in candidate.parents:
        raise FrontendBundleError(f"{field} escapes the frontend root")
    if not candidate.is_file():
        raise FrontendBundleError(f"{field} does not exist: {candidate}")
    return candidate


def load_frontend_bundle(explicit_root: Path | None = None) -> FrontendBundle:
    """Validate and load the frontend-owned deployment manifest."""

    root = resolve_frontend_root(explicit_root)
    manifest_path = root / FRONTEND_MANIFEST
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FrontendBundleError(
            f"Could not read frontend manifest {manifest_path}: {error}"
        ) from error
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise FrontendBundleError("frontend manifest schema_version must equal 1")

    assets = payload.get("assets")
    if not isinstance(assets, dict):
        raise FrontendBundleError("frontend manifest assets must be an object")
    assets_url_prefix = assets.get("url_prefix")
    if assets_url_prefix != "/assets":
        raise FrontendBundleError(
            "frontend manifest assets.url_prefix must be /assets"
        )
    assets_directory_value = assets.get("directory")
    if (
        not isinstance(assets_directory_value, str)
        or not assets_directory_value
        or "\\" in assets_directory_value
    ):
        raise FrontendBundleError(
            "frontend manifest assets.directory must be a POSIX-style relative path"
        )
    assets_relative = PurePosixPath(assets_directory_value)
    if assets_relative.is_absolute() or ".." in assets_relative.parts:
        raise FrontendBundleError(
            "frontend manifest assets.directory must remain inside the frontend root"
        )
    assets_directory = root.joinpath(*assets_relative.parts).resolve()
    if root not in assets_directory.parents or not assets_directory.is_dir():
        raise FrontendBundleError(
            f"frontend asset directory does not exist: {assets_directory}"
        )

    pages = payload.get("pages")
    if not isinstance(pages, dict) or not pages:
        raise FrontendBundleError("frontend manifest pages must be a non-empty object")
    pages_by_route: dict[str, Path] = {}
    for route, relative_path in pages.items():
        if (
            not isinstance(route, str)
            or not route.startswith("/")
            or "?" in route
            or "#" in route
        ):
            raise FrontendBundleError(
                "frontend page routes must be absolute URL paths without query/fragment"
            )
        pages_by_route[route] = _relative_file(
            root,
            relative_path,
            f"pages[{route!r}]",
        )
    missing_routes = REQUIRED_PAGE_ROUTES - pages_by_route.keys()
    unexpected_routes = pages_by_route.keys() - REQUIRED_PAGE_ROUTES
    if missing_routes or unexpected_routes:
        details: list[str] = []
        if missing_routes:
            details.append("missing " + ", ".join(sorted(missing_routes)))
        if unexpected_routes:
            details.append("unexpected " + ", ".join(sorted(unexpected_routes)))
        raise FrontendBundleError(
            "frontend manifest routes must exactly match the safe page-route "
            f"contract ({'; '.join(details)})"
        )
    return FrontendBundle(
        root=root,
        manifest_path=manifest_path,
        assets_url_prefix=assets_url_prefix,
        assets_directory=assets_directory,
        pages_by_route=pages_by_route,
    )


class FrontendHost:
    """Reconfigurable ASGI host for the standalone frontend distribution."""

    def __init__(
        self,
        frontend_root: Path | None = None,
        *,
        enabled: bool | None = None,
    ) -> None:
        self._frontend_root = frontend_root
        self._enabled = (
            _boolean_environment(SERVE_FRONTEND_ENV, True)
            if enabled is None
            else enabled
        )
        self._bundle: FrontendBundle | None = None
        self._static_files: StaticFiles | None = None
        self._configuration_lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def bundle(self) -> FrontendBundle | None:
        return self._bundle

    @property
    def page_routes(self) -> tuple[str, ...]:
        return tuple(sorted(REQUIRED_PAGE_ROUTES))

    def _ensure_ready(self) -> FrontendBundle | None:
        if not self._enabled:
            return None
        if self._bundle is not None:
            return self._bundle
        with self._configuration_lock:
            if self._bundle is None:
                bundle = load_frontend_bundle(self._frontend_root)
                self._bundle = bundle
                self._static_files = StaticFiles(
                    directory=bundle.assets_directory,
                    check_dir=True,
                )
        return self._bundle

    def validate_if_enabled(self) -> None:
        """Fail startup clearly for an enabled but incomplete distribution."""

        self._ensure_ready()

    def configure(
        self,
        frontend_root: Path | None = None,
        *,
        enabled: bool = True,
    ) -> None:
        """Select the frontend before serving requests.

        Reconfiguration is intended for CLI startup and tests, before Uvicorn
        begins accepting concurrent traffic.
        """

        if not enabled:
            self._enabled = False
            self._frontend_root = frontend_root
            self._bundle = None
            self._static_files = None
            return
        bundle = load_frontend_bundle(frontend_root)
        with self._configuration_lock:
            self._enabled = True
            self._frontend_root = frontend_root
            self._bundle = bundle
            self._static_files = StaticFiles(
                directory=bundle.assets_directory,
                check_dir=True,
            )

    def owns_request_path(self, path: str) -> bool:
        return self._enabled and (
            path in REQUIRED_PAGE_ROUTES
            or path == "/assets"
            or path.startswith("/assets/")
        )

    def page_response(self, route: str) -> FileResponse:
        bundle = self._ensure_ready()
        if bundle is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    "integrated frontend hosting is disabled; use the separate "
                    "frontend development server"
                ),
            )
        return FileResponse(
            bundle.page_for_route(route),
            media_type="text/html",
        )

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        self._ensure_ready()
        if self._static_files is None:
            response = PlainTextResponse("frontend hosting disabled", status_code=404)
            await response(scope, receive, send)
            return
        await self._static_files(scope, receive, send)


frontend_host = FrontendHost()
