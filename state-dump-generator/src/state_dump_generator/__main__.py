"""Command-line entry point for the standalone state-dump generator."""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path
from typing import TextIO

from ._json_values import plain_value as _plain_value
from .archive import ArchiveProjectionError, write_assembly
from .path_safety import resolve_output_file
from .server import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    create_server,
    load_document,
    new_document,
    validate_document,
)


def _console_text(text: str, stream: TextIO) -> str:
    """Preserve Unicode unless the destination console cannot represent it."""

    encoding = getattr(stream, "encoding", None)
    if encoding is None:
        return text
    return text.encode(encoding, errors="backslashreplace").decode(encoding)


class _ConsoleArgumentParser(argparse.ArgumentParser):
    def _print_message(self, message: str | None, file: TextIO | None = None) -> None:
        if message:
            stream = sys.stderr if file is None else file
            super()._print_message(_console_text(message, stream), stream)


def _parser() -> argparse.ArgumentParser:
    parser = _ConsoleArgumentParser(
        prog="state-dump-generator",
        description=(
            "Author temporal router scenarios and generate topology-free, "
            "node-local state dump archives."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    new = commands.add_parser("new", help="write a blank authoring project")
    new.add_argument("output", type=Path, help="scenario JSON file to create")
    new.add_argument(
        "--force",
        action="store_true",
        help="replace an existing regular file",
    )

    validate = commands.add_parser(
        "validate",
        help="validate a saved authoring project",
    )
    validate.add_argument("project", type=Path)

    generate = commands.add_parser(
        "generate",
        help="compile a project into one assembly containing per-node dumps",
    )
    generate.add_argument("project", type=Path)
    generate.add_argument(
        "--output",
        type=Path,
        required=True,
        metavar="ASSEMBLY.tgz",
        help="outer TGZ to write; it contains one topology-free TGZ per node",
    )

    serve = commands.add_parser(
        "serve",
        help="run the local GNS2-style scenario editor",
    )
    serve.add_argument("--host", default=DEFAULT_HOST)
    serve.add_argument("--port", default=DEFAULT_PORT, type=int)
    serve.add_argument(
        "--open",
        action="store_true",
        help="open the editor in the default browser after binding",
    )
    return parser


def _write_new(output: Path, *, force: bool) -> int:
    destination = resolve_output_file(output, label="new project output")
    if destination.exists() and not force:
        raise ValueError(f"project already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = (
        json.dumps(
            _plain_value(new_document()),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    destination.write_text(content, encoding="utf-8", newline="\n")
    print(_console_text(str(destination), sys.stdout))
    return 0


def _validate(project: Path) -> int:
    document = load_document(project)
    report = validate_document(document)
    print(
        _console_text(
            json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True), sys.stdout
        )
    )
    return 0 if report["ok"] else 1


def _generate(project: Path, output: Path) -> int:
    document = load_document(project)
    report = validate_document(document)
    if not report["ok"]:
        print(
            _console_text(
                json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True),
                sys.stderr,
            ),
            file=sys.stderr,
        )
        return 1
    destination = write_assembly(document, output)
    print(_console_text(str(destination), sys.stdout))
    return 0


def _serve(host: str, port: int, *, open_browser: bool) -> int:
    with create_server(host, port) as server:
        address, selected_port = server.server_address[:2]
        display_host = "127.0.0.1" if address in {"0.0.0.0", "::"} else address
        url = f"http://{display_host}:{selected_port}/"
        print(_console_text(f"State dump generator editor: {url}", sys.stdout), flush=True)
        if open_browser:
            webbrowser.open(url)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            print(
                _console_text("\nStopping state dump generator editor.", sys.stderr),
                file=sys.stderr,
            )
        finally:
            server.shutdown()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "new":
            return _write_new(args.output, force=args.force)
        if args.command == "validate":
            return _validate(args.project)
        if args.command == "generate":
            return _generate(args.project, args.output)
        if args.command == "serve":
            return _serve(args.host, args.port, open_browser=args.open)
    except (
        ArchiveProjectionError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        parser.error(str(error))
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
