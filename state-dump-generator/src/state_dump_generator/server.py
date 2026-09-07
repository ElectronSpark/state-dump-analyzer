"""Local-only stdlib HTTP server for the standalone scenario editor."""

from __future__ import annotations

import ipaddress
import json
import mimetypes
import re
import socket
import threading
from collections.abc import Mapping, Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, Final
from urllib.parse import unquote, urlsplit

from ._json_values import plain_value as _project_json_value
from ._json_values import stable_json_key
from .archive import (
    ArchiveProjectionError,
    compile_and_build,
)
from .path_safety import (
    lexical_absolute,
    path_has_link_component,
    resolve_regular_directory,
    resolve_regular_file,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8770
MAX_REQUEST_BYTES: Final[int] = 16 * 1024 * 1024
WEB_ROOT: Final[Path] = Path(__file__).with_name("web")
_SAFE_DOWNLOAD_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


class ScenarioRequestError(ValueError):
    """A scenario editor API request is invalid."""


def _plain_value(value: Any) -> Any:
    return _project_json_value(
        value,
        set_sort_key=lambda item: stable_json_key(item, allow_nan=True),
        error_type=ScenarioRequestError,
        unsupported_message="cannot serialize {kind} as scenario JSON",
    )


def _unwrap_scenario(payload: Any) -> Any:
    if isinstance(payload, Mapping) and "scenario" in payload:
        scenario = payload["scenario"]
    else:
        scenario = payload
    if not isinstance(scenario, Mapping):
        raise ScenarioRequestError("request must contain a scenario object")
    return dict(scenario)


def _document_from_mapping(payload: Mapping[str, Any]) -> Any:
    """Construct a model document without coupling to one constructor style."""

    from . import model

    for factory_name in (
        "scenario_from_dict",
        "scenario_from_mapping",
        "parse_scenario",
    ):
        factory = getattr(model, factory_name, None)
        if callable(factory):
            return factory(payload)
    document_type = getattr(model, "ScenarioDocument", None)
    if document_type is not None:
        for factory_name in ("from_dict", "from_mapping", "parse"):
            factory = getattr(document_type, factory_name, None)
            if callable(factory):
                return factory(payload)
        try:
            return document_type(**payload)
        except TypeError as error:
            raise ScenarioRequestError(str(error)) from error
    raise ScenarioRequestError("scenario model does not expose a document parser")


def load_document(path: Path | str) -> Any:
    """Load one saved authoring project."""

    try:
        source = resolve_regular_file(path, label="scenario project")
    except ValueError as error:
        raise ScenarioRequestError(str(error)) from error
    from . import model

    loader = getattr(model, "load_scenario", None)
    if callable(loader):
        return loader(source)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioRequestError(f"cannot read scenario project: {error}") from error
    if not isinstance(payload, Mapping):
        raise ScenarioRequestError("scenario project root must be an object")
    return _document_from_mapping(payload)


def new_document() -> Any:
    """Return a blank scenario document from the model layer."""

    from . import model

    for factory_name in ("new_scenario", "empty_scenario"):
        factory = getattr(model, factory_name, None)
        if callable(factory):
            return factory()
    document_type = getattr(model, "ScenarioDocument", None)
    if document_type is not None:
        for factory_name in ("new", "empty"):
            factory = getattr(document_type, factory_name, None)
            if callable(factory):
                return factory()
        try:
            return document_type()
        except TypeError as error:
            raise ScenarioRequestError(
                "scenario model must expose new_scenario()"
            ) from error
    raise ScenarioRequestError("scenario model does not expose ScenarioDocument")


def validate_document(document: Any) -> dict[str, Any]:
    """Run model validation and normalize its result for the web/CLI."""

    from . import model

    module_validator = getattr(model, "validate_scenario", None)
    document_validator = getattr(document, "validate", None)
    if callable(module_validator):
        validator = module_validator
        accepts_document = True
    elif callable(document_validator):
        validator = document_validator
        accepts_document = False
    else:
        raise ScenarioRequestError("scenario model does not expose validation")
    try:
        result = validator(document) if accepts_document else validator()
    except (TypeError, ValueError) as error:
        return {"ok": False, "errors": [str(error)], "warnings": []}

    if result is None or result is True:
        return {"ok": True, "errors": [], "warnings": []}
    if result is False:
        return {
            "ok": False,
            "errors": ["scenario validation failed"],
            "warnings": [],
        }
    plain = _plain_value(result)
    if isinstance(plain, Mapping):
        errors = plain.get("errors", [])
        warnings = plain.get("warnings", [])
        ok = bool(plain.get("ok", not errors))
        return {
            **dict(plain),
            "ok": ok,
            "errors": list(errors)
            if isinstance(errors, Sequence) and not isinstance(errors, str)
            else [str(errors)],
            "warnings": list(warnings)
            if isinstance(warnings, Sequence) and not isinstance(warnings, str)
            else [str(warnings)],
        }
    if isinstance(plain, list):
        errors: list[Any] = []
        warnings: list[Any] = []
        for issue in plain:
            if (
                isinstance(issue, Mapping)
                and str(issue.get("severity", "error")).lower() == "warning"
            ):
                warnings.append(issue)
            else:
                errors.append(issue)
        return {"ok": not errors, "errors": errors, "warnings": warnings}
    raise ScenarioRequestError("scenario validator returned an unsupported result")


def _counts_by(
    records: Sequence[Mapping[str, Any]],
    field: str,
    *,
    default: str,
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        value = str(record.get(field, default))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _merge_counts(
    target: dict[str, int],
    source: Mapping[str, int],
) -> None:
    for key, count in source.items():
        target[key] = target.get(key, 0) + int(count)


def preview_document(
    document: Any,
    *,
    at_time_ns: int | str | None = None,
) -> dict[str, Any]:
    """Return an as-of editor preview plus explicitly private medium truth."""

    from .simulation import reconstruct_scenario

    reconstruction = reconstruct_scenario(
        document,
        at_time_ns=at_time_ns,
    )
    plans = [
        reconstruction["node_plans"][node_id]
        for node_id in sorted(reconstruction["node_plans"])
    ]
    node_summaries: list[dict[str, Any]] = []
    total_statuses: dict[str, int] = {}
    total_resource_types: dict[str, int] = {}
    total_outcomes: dict[str, int] = {}
    total_state_changes = 0
    for plan in plans:
        final_state = plan["final_state"]
        logs = plan["logs"]
        status_counts = _counts_by(
            final_state,
            "status",
            default="unknown",
        )
        resource_type_counts = _counts_by(
            final_state,
            "resource_type",
            default="resource",
        )
        outcome_counts = _counts_by(
            logs,
            "outcome",
            default="unknown",
        )
        state_change_records = sum(
            1 for record in logs if record.get("state_changed") is True
        )
        _merge_counts(total_statuses, status_counts)
        _merge_counts(total_resource_types, resource_type_counts)
        _merge_counts(total_outcomes, outcome_counts)
        total_state_changes += state_change_records
        node_summaries.append(
            {
                "node_id": plan["node_id"],
                "captured_at_ns": plan["captured_at_ns"],
                "final_state_records": len(final_state),
                "history_records": len(logs),
                "state_change_records": state_change_records,
                "status_counts": status_counts,
                "resource_type_counts": resource_type_counts,
                "history_outcome_counts": outcome_counts,
            }
        )
    return {
        "ok": True,
        "at_time_ns": reconstruction["at_time_ns"],
        "relative_time_ns": reconstruction["at_time_ns"],
        "capture_time_ns": reconstruction["capture_time_ns"],
        "is_final": reconstruction["is_final"],
        "node_count": len(plans),
        "nodes": node_summaries,
        "totals": {
            "final_state_records": sum(len(plan["final_state"]) for plan in plans),
            "history_records": sum(len(plan["logs"]) for plan in plans),
            "state_change_records": total_state_changes,
            "status_counts": dict(sorted(total_statuses.items())),
            "resource_type_counts": dict(sorted(total_resource_types.items())),
            "history_outcome_counts": dict(sorted(total_outcomes.items())),
        },
        "private_truth": reconstruction["private_truth"],
    }


def _loopback_host(value: str) -> bool:
    host = value.strip().lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_loopback_bind(host: str) -> None:
    """Refuse accidental LAN exposure of the unauthenticated editor."""

    if not _loopback_host(host):
        raise ValueError(
            "the scenario editor is local-only; bind to 127.0.0.1, ::1, or localhost"
        )


def _host_header_is_local(value: str) -> bool:
    host = value.strip()
    if host.startswith("["):
        end = host.find("]")
        host = host[1:end] if end >= 0 else host
    else:
        host = host.rsplit(":", 1)[0]
    return _loopback_host(host)


class ScenarioEditorServer(ThreadingHTTPServer):
    """Threaded local server carrying an explicit static-asset root."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        web_root: Path = WEB_ROOT,
    ) -> None:
        require_loopback_bind(server_address[0])
        try:
            address_version = ipaddress.ip_address(server_address[0]).version
        except ValueError:
            address_version = 4
        if address_version == 6:
            self.address_family: int = socket.AF_INET6
        self.web_root: Path = resolve_regular_directory(
            web_root,
            label="web asset root",
        )
        super().__init__(server_address, ScenarioEditorHandler)


class ScenarioEditorHandler(BaseHTTPRequestHandler):
    """Serve the editor and its small JSON/binary API."""

    server: ScenarioEditorServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        # A local editor still accepts input from a browser-facing socket.
        # Bound every request-body read so a partial client cannot retain a
        # worker indefinitely.
        self.connection.settimeout(10.0)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep the CLI useful without emitting a line for every static asset.
        return

    def _common_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        content: bytes,
        content_type: str,
        *,
        extra_headers: Mapping[str, str] | None = None,
        send_body: bool = True,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self._common_headers()
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        if send_body:
            self.wfile.write(content)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: Mapping[str, Any],
        *,
        send_body: bool = True,
    ) -> None:
        content = (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        self._send_bytes(
            status,
            content,
            "application/json; charset=utf-8",
            send_body=send_body,
        )

    def _request_path(self) -> str:
        try:
            return unquote(urlsplit(self.path).path)
        except ValueError as error:
            raise ScenarioRequestError("malformed request path") from error

    def _check_local_host(self) -> bool:
        host = self.headers.get("Host", "")
        if host and _host_header_is_local(host):
            return True
        # The request body has not been consumed. HTTP/1.1 reuse would parse
        # those bytes as the next request, so reject-and-close atomically.
        self.close_connection = True
        self._send_json(
            HTTPStatus.FORBIDDEN,
            {"ok": False, "error": "local Host header required"},
        )
        return False

    def _read_json(self) -> Any:
        content_type = self.headers.get("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            self.close_connection = True
            raise ScenarioRequestError("Content-Type must be application/json")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self.close_connection = True
            raise ScenarioRequestError("Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError as error:
            self.close_connection = True
            raise ScenarioRequestError("invalid Content-Length") from error
        if length < 0 or length > MAX_REQUEST_BYTES:
            self.close_connection = True
            raise ScenarioRequestError(
                f"request exceeds the {MAX_REQUEST_BYTES}-byte limit"
            )
        content = self.rfile.read(length)
        if len(content) != length:
            self.close_connection = True
            raise ScenarioRequestError(
                f"incomplete request body: expected {length} bytes, received {len(content)}"
            )
        try:
            return json.loads(content)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ScenarioRequestError(f"invalid JSON: {error}") from error

    def _static_file(self, request_path: str) -> Path | None:
        logical = "index.html" if request_path == "/" else request_path.lstrip("/")
        logical = logical.removeprefix("assets/")
        path = PurePosixPath(logical)
        if (
            not logical
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            return None
        lexical_candidate = lexical_absolute(self.server.web_root.joinpath(*path.parts))
        if path_has_link_component(lexical_candidate):
            return None
        candidate = lexical_candidate.resolve()
        try:
            candidate.relative_to(self.server.web_root)
        except ValueError:
            return None
        if not candidate.is_file():
            return None
        return candidate

    def do_HEAD(self) -> None:
        self._handle_get(send_body=False)

    def do_GET(self) -> None:
        self._handle_get(send_body=True)

    def _handle_get(self, *, send_body: bool) -> None:
        if not self._check_local_host():
            return
        try:
            request_path = self._request_path()
            if request_path == "/api/health":
                self._send_json(
                    HTTPStatus.OK,
                    {"ok": True, "service": "state-dump-generator"},
                    send_body=send_body,
                )
                return
            if request_path == "/api/scenario/new":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "scenario": _plain_value(new_document()),
                    },
                    send_body=send_body,
                )
                return
            static_file = self._static_file(request_path)
            if static_file is None:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"ok": False, "error": "not found"},
                    send_body=send_body,
                )
                return
            content = static_file.read_bytes()
            media_type = (
                mimetypes.guess_type(static_file.name)[0] or "application/octet-stream"
            )
            if media_type.startswith("text/") or media_type in {
                "application/javascript",
                "application/json",
            }:
                media_type += "; charset=utf-8"
            self._send_bytes(
                HTTPStatus.OK,
                content,
                media_type,
                send_body=send_body,
            )
        except (OSError, ScenarioRequestError, ValueError) as error:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": str(error)},
                send_body=send_body,
            )

    def do_POST(self) -> None:
        if not self._check_local_host():
            return
        try:
            path = self._request_path()
            if path not in {
                "/api/scenario/validate",
                "/api/scenario/preview",
                "/api/scenario/propagation",
                "/api/scenario/generate",
            }:
                # No body was consumed, so this connection cannot safely be
                # reused even when a client pipelined another request.
                self.close_connection = True
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"ok": False, "error": "not found"},
                )
                return
            payload = self._read_json()
            document = _document_from_mapping(_unwrap_scenario(payload))
            report = validate_document(document)
            if path == "/api/scenario/validate":
                self._send_json(
                    HTTPStatus.OK if report["ok"] else HTTPStatus.UNPROCESSABLE_ENTITY,
                    report,
                )
                return
            if not report["ok"]:
                self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, report)
                return
            if path == "/api/scenario/propagation":
                from .simulation import _preview_propagation

                self._send_json(
                    HTTPStatus.OK,
                    _preview_propagation(document, str(payload.get("event_id", ""))),
                )
                return
            if path == "/api/scenario/preview":
                if payload.get("view") == "physical":
                    from .simulation import _preview_physical_truth

                    self._send_json(
                        HTTPStatus.OK,
                        _preview_physical_truth(
                            document, at_time_ns=payload.get("at_time_ns")
                        ),
                    )
                    return
                preview = preview_document(
                    document,
                    at_time_ns=(
                        payload.get("at_time_ns")
                        if isinstance(payload, Mapping)
                        else None
                    ),
                )
                preview["validation"] = report
                self._send_json(HTTPStatus.OK, preview)
                return

            content = compile_and_build(document)
            requested_name = (
                payload.get("filename", "state-dumps.tgz")
                if isinstance(payload, Mapping)
                else "state-dumps.tgz"
            )
            filename = _SAFE_DOWNLOAD_NAME.sub("-", str(requested_name))
            if not filename.lower().endswith((".tgz", ".tar.gz")):
                filename += ".tgz"
            self._send_bytes(
                HTTPStatus.OK,
                content,
                "application/gzip",
                extra_headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except (
            ArchiveProjectionError,
            OSError,
            ScenarioRequestError,
            TypeError,
            ValueError,
        ) as error:
            # Some failures happen before the declared body is consumed. A
            # conservative close prevents request-smuggling/desynchronization
            # while keeping successful HTTP/1.1 requests reusable.
            self.close_connection = True
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": str(error)},
            )


def create_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    web_root: Path = WEB_ROOT,
) -> ScenarioEditorServer:
    """Create, but do not start, a local scenario editor server."""

    if not 0 <= int(port) <= 65535:
        raise ValueError("port must be between 0 and 65535")
    return ScenarioEditorServer((host, int(port)), web_root=web_root)


def serve(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    web_root: Path = WEB_ROOT,
    ready: threading.Event | None = None,
) -> None:
    """Run the local editor until interrupted."""

    with create_server(host, port, web_root=web_root) as server:
        if ready is not None:
            ready.set()
        server.serve_forever(poll_interval=0.25)


__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "MAX_REQUEST_BYTES",
    "WEB_ROOT",
    "ScenarioEditorHandler",
    "ScenarioEditorServer",
    "ScenarioRequestError",
    "create_server",
    "load_document",
    "new_document",
    "preview_document",
    "require_loopback_bind",
    "serve",
    "validate_document",
]
