"""Run the repository's plug-in API conformance groups with one interpreter.

The inventory check detects unmapped hooks and protocols, not behavioral test
coverage. The named suites exercise individual boundaries and combined flows.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

GROUPS: dict[str, tuple[str, ...]] = {
    "foundation": (
        "plugin_api", "plugin_loading", "plugin_validation", "artifact_core",
        "canonical", "source_record_core", "contract_validation",
        "contract_validation_boundaries", "resource_property_policy",
        "property_visibility", "ingestion", "ingestion_execution_boundaries",
    ),
    "revision": (
        "capability_executor", "reconstruction_boundaries",
        "public_reconstruction_reads", "relationship_projection_materialization",
        "relationship_projection_ingestion", "consistency_materialization",
        "consistency_ingestion", "revision_world", "condition_contract",
    ),
    "presentation": (
        "dashboard_core", "dashboard_query_api", "history_search_core",
        "topology_core", "topology_federation", "federation_executor",
        "multi_node_topology", "resource_property_policy",
    ),
    "forwarding": (
        "packet_trace_core", "route_packet_projection", "route_presentation_layers",
        "multi_node_route", "multi_node_route_regressions",
        "endpoint_pair_advanced", "route_topology_access",
    ),
    "evidence": (
        "private_ai_tool_service", "private_ai_evidence_binding",
        "private_analysis_revision_evidence", "control_plane_private_analysis_evidence",
    ),
    "runtime": (
        "normalized_data_service", "runtime_execution_boundaries",
        "provider_execution_boundaries", "runtime_revision_scope",
        "runtime_capability_advertising", "web_execution_boundaries",
        "core_cli", "core_web_app",
    ),
    "composition": (
        "plugin_composition", "plugin_composition_deployment",
        "plugin_execution_plan", "capability_router", "session_execution_plan",
        "plugin_process_boundaries", "ingestion_pipeline",
        "control_plane_api", "session_store",
    ),
    "combined": (
        "plugin_authoring_docs", "demo_durable_review", "demo_workbench",
        "demo_cross_node_consistency", "generated_assembly_api_integration",
        "control_plane_private_analysis_evidence",
    ),
}

HOOK_GROUPS = {
    "describe": "foundation", "probe": "foundation", "locate_inputs": "foundation",
    "parse_status": "foundation", "parse_ctf": "foundation",
    "parse_text_trace": "foundation", "apply": "revision", "revert": "revision",
    "correlate": "revision", "project_relationships": "revision",
    "check_consistency": "revision", "project_topology": "presentation",
    "project_forwarding": "forwarding", "resolve_forwarding_step": "forwarding",
    "analyze_evidence": "evidence",
}

# Every public Protocol in these three plug-in-facing modules has an owner.
# RuntimeApplicationFactory is included as a host extension, not a parser hook.
PROTOCOL_GROUPS = {
    "plugin_api": {
        "ArtifactReader": "foundation", "TraceDecoder": "foundation",
        "FederationLinkerPlugin": "presentation", "ReadOnlyWorld": "revision",
        "CorrelationReader": "revision", "AnalyzerPlugin": "foundation",
    },
    "runtime": {
        "RuntimeTemporalProvider": "runtime", "RuntimeTopologyProvider": "runtime",
        "RuntimeRouteProvider": "runtime", "PluginRuntimeSession": "runtime",
        "PluginRuntimeCapability": "runtime", "RuntimeApplicationFactory": "runtime",
    },
    "normalized_data": {
        "IndexedHistory": "runtime", "NormalizedDatasetSource": "runtime",
        "NormalizedDataPolicy": "runtime",
    },
}


def public_protocol_names(source: str) -> set[str]:
    """Include generic and qualified Protocol bases in the declaration check."""
    names = set()
    for node in ast.parse(source).body:
        if not isinstance(node, ast.ClassDef) or node.name.startswith("_"):
            continue
        for base in node.bases:
            if isinstance(base, ast.Subscript):
                base = base.value
            if ((isinstance(base, ast.Name) and base.id == "Protocol")
                    or (isinstance(base, ast.Attribute) and base.attr == "Protocol")):
                names.add(node.name)
    return names


def check_inventory() -> list[str]:
    """Check declared hook ownership and test targets without importing fixtures."""
    from router_dump_analyzer.plugin_api import (
        AnalyzerPlugin, PLUGIN_CAPABILITY_HOOKS, PluginCapability,
        REQUIRED_PLUGIN_HOOKS,
    )

    errors = []
    hooks = set(REQUIRED_PLUGIN_HOOKS)
    for names in PLUGIN_CAPABILITY_HOOKS.values():
        hooks.update(names)
    if set(PLUGIN_CAPABILITY_HOOKS) != set(PluginCapability):
        errors.append("PluginCapability and PLUGIN_CAPABILITY_HOOKS differ")
    if hooks != set(HOOK_GROUPS):
        errors.append(f"Unmapped/stale hooks: {sorted(hooks ^ set(HOOK_GROUPS))}")
    protocol_hooks = {
        name for name, value in vars(AnalyzerPlugin).items()
        if not name.startswith("_") and callable(value)
    }
    if hooks != protocol_hooks:
        errors.append(f"AnalyzerPlugin hook drift: {sorted(hooks ^ protocol_hooks)}")
    for module, owners in PROTOCOL_GROUPS.items():
        path = ROOT / "src" / "router_dump_analyzer" / f"{module}.py"
        protocols = public_protocol_names(path.read_text(encoding="utf-8"))
        if protocols != set(owners):
            errors.append(f"{module} protocol drift: {sorted(protocols ^ set(owners))}")
    assigned_groups = list(HOOK_GROUPS.values()) + [
        group for mapping in PROTOCOL_GROUPS.values() for group in mapping.values()
    ]
    for group in sorted(set(assigned_groups) - set(GROUPS)):
        errors.append(f"Unknown conformance group: {group}")
    for modules in GROUPS.values():
        for module in modules:
            if not (ROOT / "tests" / f"test_{module}.py").is_file():
                errors.append(f"Missing test module: test_{module}.py")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true", help="check inventory and list groups")
    mode.add_argument("--group", action="append", choices=tuple(GROUPS),
                      help="run one group; repeat to combine groups")
    mode.add_argument("--all", action="store_true", help="run all groups, deduplicating tests")
    args = parser.parse_args(argv)
    errors = check_inventory()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if args.list:
        for group, test_names in GROUPS.items():
            hooks = ", ".join(name for name, owner in HOOK_GROUPS.items() if owner == group)
            protocols = ", ".join(
                name for mapping in PROTOCOL_GROUPS.values()
                for name, owner in mapping.items() if owner == group
            )
            print(f"{group}: {len(test_names)} test modules")
            if hooks:
                print(f"  hooks: {hooks}")
            if protocols:
                print(f"  protocols: {protocols}")
        return 0
    selected = tuple(GROUPS) if args.all else args.group
    modules = list(dict.fromkeys(
        f"tests.test_{module}" for group in selected for module in GROUPS[group]
    ))
    print(f"Running {len(modules)} modules: {', '.join(selected)}", flush=True)
    # unittest leaves fixture plug-in bytecode unchanged for identity validation.
    return subprocess.run(
        [sys.executable, "-X", "utf8", "-m", "unittest", *modules, "-v"],
        cwd=ROOT, check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
