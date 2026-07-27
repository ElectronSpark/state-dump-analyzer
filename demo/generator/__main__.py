"""Command-line interface for the standalone demo fixture generator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import (
    DEFAULT_ASSEMBLY_NAME,
    DEFAULT_EVENT_COUNT,
    DEFAULT_RESOURCE_COUNT,
    DEFAULT_SEED,
    AssemblyConfig,
    ensure_demo_fixture_for_launch,
    parse_node_selection,
    probe_demo_fixture_for_launch,
    validate_demo_fixture,
)
from .assembly import _build_demo_fixture_with_report
from plugin import render_conformance_status_fixture


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate one deterministic assembly whose node dumps feed both "
            "single-node review and multi-node topology/route tracing."
        )
    )
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument(
        "--output",
        type=Path,
        default=Path.cwd() / DEFAULT_ASSEMBLY_NAME,
        help=(
            "assembly TGZ to create "
            f"(default: ./{DEFAULT_ASSEMBLY_NAME})"
        ),
    )
    parser.add_argument(
        "--events-per-node",
        type=int,
        default=DEFAULT_EVENT_COUNT,
        help=f"events per node (default: {DEFAULT_EVENT_COUNT})",
    )
    parser.add_argument(
        "--resources-per-node",
        type=int,
        default=DEFAULT_RESOURCE_COUNT,
        help=f"resources per node (default: {DEFAULT_RESOURCE_COUNT})",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="deterministic projection seed",
    )
    parser.add_argument(
        "--node",
        action="append",
        default=[],
        metavar="NODE_ID",
        help="generate only this catalog node; repeat to select more",
    )
    parser.add_argument(
        "--allow-small",
        action="store_true",
        help=(
            "allow below-production counts for tests/development; such an "
            "archive is marked non-full-scale"
        ),
    )
    operation.add_argument(
        "--validate",
        type=Path,
        metavar="ARCHIVE",
        help="validate an existing archive instead of generating one",
    )
    operation.add_argument(
        "--check-launchable",
        type=Path,
        metavar="ARCHIVE",
        help=(
            "cheaply verify that an existing archive is the canonical "
            "full-scale multi-node demo; nested packs are not decoded"
        ),
    )
    operation.add_argument(
        "--ensure-launchable",
        type=Path,
        metavar="ARCHIVE",
        help=(
            "reuse or safely preserve and regenerate the canonical "
            "full-scale multi-node demo"
        ),
    )
    parser.add_argument(
        "--force-rebuild",
        action="store_true",
        help="regenerate even when --ensure-launchable finds a valid archive",
    )
    parser.add_argument(
        "--path-only",
        action="store_true",
        help=(
            "with --ensure-launchable, print only the selected absolute "
            "archive path for launcher consumption"
        ),
    )
    parser.add_argument(
        "--deep-validate",
        action="store_true",
        help="stream normalized event/relationship IDs and checksums as well",
    )
    operation.add_argument(
        "--write-conformance-fixture",
        type=Path,
        metavar="JSONL",
        help=(
            "write the tiny plug-in parser conformance vector and exit; this "
            "does not create a second demo dump"
        ),
    )
    operation.add_argument(
        "--verify-conformance-fixture",
        type=Path,
        metavar="JSONL",
        help=(
            "verify that a conformance vector exactly matches the plug-in-owned "
            "fixture records and exit"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    launch_operation = (
        args.check_launchable is not None
        or args.ensure_launchable is not None
    )
    if launch_operation and (
        args.deep_validate
        or args.node
        or args.allow_small
        or args.events_per_node != DEFAULT_EVENT_COUNT
        or args.resources_per_node != DEFAULT_RESOURCE_COUNT
        or args.seed != DEFAULT_SEED
    ):
        parser.error(
            "launch preparation cannot be combined with generation-shape or "
            "deep-validation options"
        )
    if args.force_rebuild and args.ensure_launchable is None:
        parser.error("--force-rebuild requires --ensure-launchable")
    if args.path_only and args.ensure_launchable is None:
        parser.error("--path-only requires --ensure-launchable")
    if args.write_conformance_fixture is not None:
        output = args.write_conformance_fixture.expanduser().resolve()
        if output.is_symlink():
            parser.error("conformance fixture output cannot be a symlink")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(render_conformance_status_fixture())
        print(f"Generated plug-in conformance vector: {output}")
        return 0
    if args.verify_conformance_fixture is not None:
        fixture = args.verify_conformance_fixture.expanduser().resolve()
        if fixture.is_symlink() or not fixture.is_file():
            parser.error("conformance fixture must be a regular file")
        if fixture.read_bytes() != render_conformance_status_fixture():
            parser.error(
                "conformance fixture differs from the plug-in-owned records"
            )
        print(f"Validated plug-in conformance vector: {fixture}")
        return 0
    if args.validate is not None:
        report = validate_demo_fixture(
            args.validate,
            deep=args.deep_validate,
        )
        print(
            f"Validated {report.assembly_id}: {len(report.node_ids)} nodes, "
            f"{report.coverage_case_count} coverage cases, "
            f"sha256={report.archive_sha256}"
        )
        return 0
    if args.check_launchable is not None:
        try:
            report = probe_demo_fixture_for_launch(args.check_launchable)
        except RuntimeError as error:
            print(
                f"Generated assembly is not launch-ready: {error}",
                file=sys.stderr,
            )
            return 1
        print(
            f"Launch-ready {report.assembly_id}: "
            f"{len(report.node_ids)} full-scale node dumps, "
            f"{report.coverage_case_count} coverage cases"
        )
        return 0
    if args.ensure_launchable is not None:
        try:
            report = ensure_demo_fixture_for_launch(
                args.ensure_launchable,
                force_rebuild=args.force_rebuild,
            )
        except Exception as error:
            print(
                f"Could not prepare generated demo assembly: {error}",
                file=sys.stderr,
            )
            return 1
        if args.path_only:
            print(report.output_path)
            return 0
        if report.preserved_preferred:
            print(
                "Preserved the unsuitable preferred input in place: "
                f"{report.preferred_path}"
            )
        action = "Generated" if report.generated else "Reusing"
        print(
            f"{action} launch-ready {report.preflight.assembly_id}: "
            f"{report.output_path} "
            f"({len(report.preflight.node_ids)} full-scale node dumps, "
            f"{report.preflight.coverage_case_count} coverage cases)"
        )
        return 0
    try:
        nodes = parse_node_selection(args.node)
        config = AssemblyConfig(
            nodes=nodes,
            events_per_node=args.events_per_node,
            resources_per_node=args.resources_per_node,
            seed=args.seed,
            allow_small=args.allow_small,
        )
    except (ValueError, argparse.ArgumentTypeError) as error:
        parser.error(str(error))
    output, report = _build_demo_fixture_with_report(
        args.output,
        config=config,
        deep_validate=args.deep_validate,
    )
    printable = str(output).encode(
        "ascii",
        errors="backslashreplace",
    ).decode("ascii")
    print(
        f"Generated {report.assembly_id}: {printable} "
        f"({len(report.node_ids)} nodes, "
        f"{report.coverage_case_count} coverage cases)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
