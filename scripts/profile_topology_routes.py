"""Measure cold topology startup and warm route traces without changing identity checks.

Run against a stable repository checkout or an extracted ``git archive``. Each
timing sample uses a fresh Python process; a separate sample records cProfile
attribution so instrumentation overhead cannot be mistaken for request latency.
"""

from __future__ import annotations

import argparse
import cProfile
import hashlib
import json
import os
import platform
import pstats
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SEED = 20_260_725
TOPOLOGY_QUERY = {
    "resource_limit": 100,
    "network_segment_limit": 100,
    "segment_attachment_limit": 200,
}
ROUTE_QUERY = {
    "scenario_id": "single-active-primary",
    "max_hops": 32,
    "max_recursion": 8,
}
FOCUS_FUNCTIONS = {
    "executable_plugin_fingerprint",
    "executable_module_target_fingerprint",
    "_executable_scope_fingerprint",
    "_package_entries",
    "_read_regular_source_snapshot",
    "_declared_code_objects",
    "_declared_function_ast",
    "_preflight_python_source_tokens",
    "_validate_static_pin",
    "_validated_executor",
    "for_execution_pin",
}


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _bounded_integer(minimum: int, maximum: int) -> Any:
    def parse(value: str) -> int:
        number = int(value)
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}")
        return number

    return parse


def _source_digest(repository: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    count = 0
    size = 0
    for folder in ("src", "demo", "state-dump-generator/src"):
        for path in sorted((repository / folder).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            data = path.read_bytes()
            digest.update(path.relative_to(repository).as_posix().encode())
            digest.update(b"\0")
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
            count += 1
            size += len(data)
    return {"sha256": digest.hexdigest(), "files": count, "bytes": size}


def _configure_imports(repository: Path) -> None:
    sys.path[:0] = [str(repository / "src"), str(repository / "demo")]
    sys.dont_write_bytecode = True


def _profile_summary(profile: cProfile.Profile, repository: Path) -> dict[str, Any]:
    stats = pstats.Stats(profile)
    rows = []
    for (filename, line, name), (
        primitive,
        total,
        own,
        cumulative,
        _callers,
    ) in stats.stats.items():
        try:
            display = Path(filename).relative_to(repository).as_posix()
        except ValueError:
            display = filename.replace("\\", "/")
        rows.append(
            {
                "file": display,
                "line": line,
                "function": name,
                "primitive_calls": primitive,
                "total_calls": total,
                "self_seconds": own,
                "cumulative_seconds": cumulative,
            }
        )
    categories = {
        "identity_python_self_seconds": lambda row: row["file"].endswith(
            "/plugin_identity.py"
        ),
        "provider_router_self_seconds": lambda row: row["file"].endswith(
            "/capability_router.py"
        ),
        "provider_executor_self_seconds": lambda row: row["file"].endswith(
            "/capability_executor.py"
        ),
        "ast_python_self_seconds": lambda row: row["file"].endswith("/ast.py"),
        "compile_builtin_self_seconds": lambda row: (
            "builtins.compile" in row["function"]
        ),
    }
    return {
        "profile_total_seconds": stats.total_tt,
        "total_calls": stats.total_calls,
        "exclusive_categories": {
            name: sum(row["self_seconds"] for row in rows if select(row))
            for name, select in categories.items()
        },
        "focus": sorted(
            (
                row
                for row in rows
                if row["function"] in FOCUS_FUNCTIONS
                or "builtins.compile" in row["function"]
                or (row["file"].endswith("/ast.py") and row["function"] == "parse")
            ),
            key=lambda row: row["cumulative_seconds"],
            reverse=True,
        ),
        "top_cumulative": sorted(
            rows, key=lambda row: row["cumulative_seconds"], reverse=True
        )[:30],
        "top_self": sorted(rows, key=lambda row: row["self_seconds"], reverse=True)[
            :30
        ],
    }


def _prepare(args: argparse.Namespace) -> None:
    _configure_imports(args.repository)
    from rsl_demo_generator import DEMO_NODES, AssemblyConfig, build_demo_fixture

    started = time.perf_counter()
    archive = build_demo_fixture(
        args.output / "fixture.tgz",
        config=AssemblyConfig(
            nodes=DEMO_NODES,
            events_per_node=120,
            resources_per_node=120,
            seed=SEED,
            allow_small=True,
            assembly_id="demo.fabric.multi-node",
        ),
    )
    with tarfile.open(archive, "r:gz") as bundle:
        member = next(
            item for item in bundle.getmembers() if item.name.endswith("/manifest.json")
        )
        stream = bundle.extractfile(member)
        if stream is None:
            raise RuntimeError("generated fixture lacks its manifest")
        manifest = json.load(stream)
    _write_json(
        args.output / "fixture.json",
        {
            "generation_seconds": time.perf_counter() - started,
            "archive_bytes": archive.stat().st_size,
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "seed": SEED,
            "requested_events_per_node": 120,
            "requested_resources_per_node": 120,
            "node_count": manifest["node_count"],
            "nodes": manifest["nodes"],
        },
    )


def _worker(args: argparse.Namespace) -> None:
    _configure_imports(args.repository)
    result: dict[str, Any] = {"phases": {}, "warm_route_seconds": []}

    def measured(name: str, operation: Any) -> Any:
        profile = cProfile.Profile() if args.profile else None
        if profile is not None:
            profile.enable()
        started = time.perf_counter()
        try:
            return operation()
        finally:
            elapsed = time.perf_counter() - started
            if profile is not None:
                profile.disable()
                profile.dump_stats(str(args.output / f"profile-{name}.pstats"))
            result["phases"][name] = {"seconds": elapsed}
            if profile is not None:
                result["phases"][name]["attribution"] = _profile_summary(
                    profile, args.repository
                )
            print(f"{name}: {elapsed:.6f}s", flush=True)

    def import_runtime() -> Any:
        from rsl_demo_plugin import plugin

        return plugin.runtime

    runtime = measured("runtime_import", import_runtime)
    session_context = runtime.open(args.output / "fixture.tgz")
    session = measured("runtime_open", session_context.__enter__)
    try:
        topology = measured("cold_topology_construction", session.topology_provider.get)
        snapshot = measured(
            "first_topology_query", lambda: topology.query(dict(TOPOLOGY_QUERY))
        )
        routes = measured("route_construction", session.route_provider.get)
        route_query = dict(ROUTE_QUERY)
        if args.reuse_topology_context:
            route_query["topology_context_id"] = snapshot["context_id"]
        trace = measured("first_route_trace", lambda: routes.trace(dict(route_query)))

        def shape(payload: dict[str, Any]) -> dict[str, Any]:
            paths = payload["paths"]
            return {
                "path_count": len(paths),
                "path_results": [path.get("result") for path in paths],
                "segments_per_path": [len(path.get("segments", [])) for path in paths],
                "active_path_count": payload["multipath"]["active_path_count"],
            }

        expected = shape(trace)
        if expected != {
            "path_count": 2,
            "path_results": ["resolved", "resolved"],
            "segments_per_path": [5, 5],
            "active_path_count": 1,
        }:
            raise RuntimeError(
                f"representative trace did not execute both declared candidates: {expected}"
            )

        def warm_traces() -> None:
            for _index in range(args.warm_traces):
                started = time.perf_counter()
                payload = routes.trace(dict(route_query))
                result["warm_route_seconds"].append(time.perf_counter() - started)
                if shape(payload) != expected:
                    raise RuntimeError("warm route trace changed candidate outcomes")

        measured("warm_route_traces", warm_traces)
        result["route_query"] = route_query
        result["fixture_runtime"] = {
            "topology_nodes": len(topology.contract["nodes"]),
            "topology_resources_returned": sum(
                len(node.get("resources", [])) for node in snapshot["nodes"]
            ),
            "network_segments_returned": len(snapshot.get("network_segments", [])),
            "segment_attachments_returned": len(
                snapshot.get("segment_attachments", [])
            ),
            "trace": expected,
        }
        for name, module in tuple(sys.modules.items()):
            if name.split(".")[0] in {
                "router_dump_analyzer",
                "rsl_demo_plugin",
                "rsl_demo_generator",
            } and not Path(module.__file__).resolve().is_relative_to(args.repository):
                raise RuntimeError(f"profile imported a different checkout: {name}")
    finally:
        session_context.__exit__(None, None, None)
    _write_json(args.output / args.worker_result, result)


def _run_child(args: argparse.Namespace, flags: list[str], label: str) -> None:
    command = [
        sys.executable,
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--repository",
        str(args.repository),
        "--output",
        str(args.output),
        "--warm-traces",
        str(args.warm_traces),
        *(["--reuse-topology-context"] if args.reuse_topology_context else []),
        *flags,
    ]
    print(f"Starting {label}", flush=True)
    with (args.output / f"{label}.log").open("w", encoding="utf-8") as log:
        subprocess.run(
            command,
            check=True,
            timeout=args.timeout,
            stdout=log,
            stderr=subprocess.STDOUT,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source-label", default="working checkout; inspect source digest"
    )
    parser.add_argument("--samples", type=_bounded_integer(1, 5), default=3)
    parser.add_argument("--warm-traces", type=_bounded_integer(1, 20), default=3)
    parser.add_argument("--timeout", type=_bounded_integer(1, 600), default=300)
    parser.add_argument(
        "--reuse-topology-context",
        action="store_true",
        help="trace from the first query's recorded context, as the topology browser does",
    )
    parser.add_argument("--prepare", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-result", help=argparse.SUPPRESS)
    parser.add_argument("--profile", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.repository = args.repository.resolve()
    args.output = args.output.resolve()
    if not all(
        (args.repository / name).is_file()
        for name in (
            "src/router_dump_analyzer/__init__.py",
            "demo/rsl_demo_plugin/__init__.py",
        )
    ):
        parser.error("repository must contain the core and demo source packages")
    if args.output.is_relative_to(args.repository):
        parser.error(
            "output must be outside the measured repository to keep package bytes stable"
        )
    args.output.mkdir(parents=True, exist_ok=True)
    if args.prepare:
        _prepare(args)
        return
    if args.worker_result:
        _worker(args)
        return
    before = _source_digest(args.repository)
    with tempfile.TemporaryDirectory(prefix="rsl-profile-") as state:
        os.environ["ROUTER_DUMP_SEARCH_CACHE_DIR"] = str(Path(state) / "search-cache")
        _run_child(args, ["--prepare"], "prepare")
        for index in range(args.samples):
            _run_child(
                args,
                ["--worker-result", f"timing-{index + 1}.json"],
                f"timing-{index + 1}",
            )
        _run_child(args, ["--profile", "--worker-result", "profile.json"], "profile")
    after = _source_digest(args.repository)
    if before != after:
        raise RuntimeError(
            "measured source bytes changed; discard timings and repeat on stable source"
        )
    samples = [
        json.loads((args.output / f"timing-{index + 1}.json").read_text())
        for index in range(args.samples)
    ]
    phases = {}
    for phase in samples[0]["phases"]:
        values = [sample["phases"][phase]["seconds"] for sample in samples]
        phases[phase] = {
            "seconds": values,
            "median_seconds": statistics.median(values),
            "min_seconds": min(values),
            "max_seconds": max(values),
        }
    warm = [elapsed for sample in samples for elapsed in sample["warm_route_seconds"]]
    _write_json(
        args.output / "summary.json",
        {
            "source_label": args.source_label,
            "source": before,
            "python": sys.version,
            "platform": platform.platform(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
            "samples": args.samples,
            "warm_traces_per_sample": args.warm_traces,
            "topology_query": TOPOLOGY_QUERY,
            "route_query": ROUTE_QUERY,
            "reuse_topology_context": args.reuse_topology_context,
            "phases": phases,
            "warm_route_seconds": warm,
            "warm_route_median_seconds": statistics.median(warm),
            "warm_route_min_seconds": min(warm),
            "warm_route_max_seconds": max(warm),
            "fixture_runtime": samples[0]["fixture_runtime"],
            "limitations": [
                "Fresh Python process and no bytecode writes; OS filesystem cache is uncontrolled.",
                "Fixture generation is outside startup and trace timings.",
                "Direct provider/service calls exclude HTTP, browser rendering and server startup.",
                "A separate cProfile run is attribution evidence, not latency evidence.",
                "Warm calls reuse the service; topology context reuse is recorded separately.",
                "Live identity checks, safety limits and provider validation remain enabled.",
            ],
        },
    )
    print(f"Completed: {args.output / 'summary.json'}", flush=True)


if __name__ == "__main__":
    main()
