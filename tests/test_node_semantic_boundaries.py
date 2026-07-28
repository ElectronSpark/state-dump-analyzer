from __future__ import annotations

import ast
import re
import unittest
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_SOURCE = ROOT / "src" / "router_dump_analyzer"
PLUGIN_API_PY = CORE_SOURCE / "plugin_api.py"
APP_JS = ROOT / "frontend" / "assets" / "app.js"
TEMPORAL_TOPOLOGY_PY = (
    ROOT / "src" / "router_dump_analyzer" / "temporal_topology.py"
)
CORE_RUNTIME_API_PY = (
    ROOT / "src" / "router_dump_analyzer" / "web" / "runtime_api.py"
)

# These names have device-, protocol-, or fixture-owned meaning.  They may
# appear in contract docstrings, but not in executable core literals/imports.
# Keep this list deliberately small and high-signal: generic L1-L3 mechanics
# such as an interface, address, or subnet are not plug-in vocabulary.
PLUGIN_OWNED_TOKENS = frozenset(
    {
        "arista",
        "bfd",
        "bgp",
        "cisco",
        "dte",
        "eigrp",
        "eos",
        "ete",
        "etg",
        "evpn",
        "geneve",
        "gns3",
        "gre",
        "ios-xr",
        "iosxe",
        "is-is",
        "isis",
        "juniper",
        "junos",
        "lag",
        "lacp",
        "ldp",
        "lldp",
        "mpls",
        "nx-os",
        "nokia",
        "ospf",
        "rsvp",
        "sonic",
        "sros",
        "srv6",
        "vlan",
        "vpls",
        "vxlan",
    }
)
PLUGIN_OWNED_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])("
    + "|".join(
        re.escape(token)
        for token in sorted(
            PLUGIN_OWNED_TOKENS - {"lag"},
            key=len,
            reverse=True,
        )
    )
    + r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)
PLUGIN_OWNED_CASED_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])LAG(?![A-Za-z0-9])"
)
DEMO_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])demo(?![A-Za-z0-9])",
    re.IGNORECASE,
)
GENERATED_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])generated(?![A-Za-z0-9])",
    re.IGNORECASE,
)

# This is an ownership disclosure returned by the generic topology capability
# endpoint, not a branch that interprets any of these terms.  The full literal
# and scope are exact so this exception cannot silently become inference.
ALLOWED_PROTOCOL_DISCLOSURES = frozenset(
    {
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "<module>.MultiNodeTopologyService.capabilities",
            (
                "VLAN, LAG, subinterface, physical-member, neighbor, and route "
                "inference details"
            ),
        ),
    }
)

# The public bootstrap envelope still carries one legacy fixture namespace.
# Its exact reads/allowlist entry are migration debt, not a permitted way for
# core code to learn demo semantics.
ALLOWED_DEMO_COMPATIBILITY_LITERALS = Counter(
    {
        (
            "src/router_dump_analyzer/normalized_data.py",
            "<module>",
            "demo",
        ): 1,
        (
            "src/router_dump_analyzer/normalized_data.py",
            "<module>._client_dataset_envelope",
            "demo",
        ): 2,
    }
)

# multi_node_route.py still adapts the legacy "generated projection" mapping.
# New identifiers or additional references fail the guard.  Deleting entries
# is intentionally allowed so migration can only reduce this exception.
GENERATED_ROUTE_IDENTIFIER_BUDGET = {
    "_apply_generated_candidate_semantics": 2,
    "_attach_generated_forwarding_projection": 2,
    "_bind_generated_packet_declaration": 2,
    "_generated_candidate_for_path": 2,
    "_generated_coverage_by_id": 7,
    "_generated_coverage_registry_id": 5,
    "_generated_destination_attachment_node_ids": 1,
    "_generated_destination_attachment_specs": 3,
    "_generated_directional_decision": 4,
    "_generated_directional_pairs": 2,
    "_generated_forwarding_rows": 5,
    "_generated_inventory_projection": 3,
    "_generated_network_model": 2,
    "_generated_packet_cases": 4,
    "_generated_plugin_provider": 5,
    "_generated_projection_for_scenario": 2,
    "_generated_provider_by_node": 7,
    "_generated_resource_owner_by_id": 6,
    "_generated_revision_by_node": 7,
    "_generated_route_endpoints": 2,
    "_generated_route_family_descriptors": 2,
    "_generated_route_resolvers": 2,
    "_generated_route_rows": 13,
    "_generated_route_table_entries": 2,
    "_generated_route_table_entry": 2,
    "_generated_route_type_descriptors": 2,
    "_generated_routed_nodes": 5,
    "_generated_router_descriptors": 2,
    "_generated_scenario_descriptors": 2,
    "_generated_vrf_descriptors": 2,
    "_generic_paths_from_generated_candidates": 2,
    "_materialize_generated_findings": 2,
    "_public_generated_projection_row": 4,
    "_reconcile_generated_route_evidence": 2,
}
GENERATED_ROUTE_LITERAL_BUDGET = 109

type BranchFingerprint = tuple[str, str, str, tuple[str, ...]]
type OpaqueBranchFingerprint = tuple[str, str, str]

# This codec interprets a core-owned canonical wire format, not a plug-in
# payload.  Keep the exception at function granularity so it cannot turn into
# a module-wide escape hatch.
CORE_OWNED_MAPPING_CODEC_SCOPES = frozenset(
    {
        (
            "src/router_dump_analyzer/canonical.py",
            "_normalized_opaque_value_json",
        ),
    }
)

# Raw mapping decisions below predate the typed executable data plane.  Each
# exception identifies the exact file, lexical scope, field, and raw values.
# The structural test accepts only a subset of this Counter, so deletion is
# free while a new field/value/scope or a higher occurrence count fails.
RAW_MAPPING_BRANCH_MIGRATION_LEDGER: Counter[BranchFingerprint] = Counter(
    {
        (
            "src/router_dump_analyzer/dashboard_core.py",
            "evaluate_dashboards",
            "aggregation",
            ("precomputed",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._set_segment_resolution",
            "role",
            ("l3-resolution",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generated_projection_for_scenario",
            "semantic_owner",
            ("plugin",),
        ): 2,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._bidirectional_response",
            "multipath_mode",
            ("all_active",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generic_path",
            "segment_kind",
            ("inter_node_boundary",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generated_projection_for_scenario",
            "direction",
            ("forward", "reverse"),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generated_projection_for_scenario",
            "_projection_semantic_owner",
            ("plugin",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._reconcile_generated_route_evidence",
            "operational",
            ("unusable",),
        ): 4,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._project_candidate_traversal",
            "segment_kind",
            ("inter_node_boundary",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generated_destination_attachment_specs",
            "direction",
            ("forward",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generated_inventory_projection",
            "decision",
            ("active",),
        ): 2,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService.route_tables",
            "simultaneity",
            ("not_implied",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService.trace",
            "state",
            ("complete",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._attach_packet_trace",
            "segment_kind",
            ("node_resolution",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            (
                "MultiNodeRouteService._decorate_route_presentations."
                "target_topology_reference"
            ),
            "kind",
            ("topology_link",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            (
                "MultiNodeRouteService._decorate_route_presentations."
                "target_topology_reference"
            ),
            "kind",
            ("topology_match",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._resolve_endpoints",
            "state",
            ("available",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generic_path",
            "segment_kind",
            ("node_resolution",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._refresh_path",
            "state",
            ("best_effort_inferred",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generated_projection_for_scenario",
            "reference_kind",
            ("connectivity_domain",),
        ): 2,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._attach_generated_forwarding_projection",
            "segment_kind",
            ("node_resolution",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._reconcile_generated_route_evidence",
            "segment_kind",
            ("node_resolution",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._reconcile_generated_route_evidence",
            "segment_kind",
            ("inter_node_boundary",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._materialize_control_plane_only_issue",
            "alternative_state",
            ("control_plane_only",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generated_inventory_projection",
            "semantic_owner",
            ("plugin",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._declare_plugin_terminal_evidence",
            "state",
            ("unavailable", "withdrawn"),
        ): 2,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._annotate_endpoint_reachability",
            "state",
            ("unavailable", "withdrawn"),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._resolve_trace_start",
            "state",
            ("unavailable", "withdrawn"),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._validate_pair_reverse_start",
            "state",
            ("unavailable", "withdrawn"),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._bidirectional_response",
            "state",
            ("unavailable", "withdrawn"),
        ): 2,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._boundary_segment",
            "resolution",
            ("ambiguous",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generated_scenario_descriptors",
            "direction",
            ("forward",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._apply_generated_candidate_semantics",
            "segment_kind",
            ("inter_node_boundary",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generated_inventory_projection",
            "coverage_category",
            ("inventory_continuation",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService.route_tables",
            "resolution",
            ("exact",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._annotate_endpoint_reachability",
            "classification",
            ("not_delivered",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._decorate_route_presentations",
            "segment_kind",
            ("inter_node_boundary",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._attach_route_entry_refs",
            "data_kind",
            ("generated_route_table_row",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._attach_route_entry_refs",
            "install_state",
            ("control_plane_only",),
        ): 2,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._refresh_path",
            "operational",
            ("unusable",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService.trace",
            "category",
            ("boundary", "cross_layer", "directional", "forwarding"),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService.trace",
            "state",
            ("best_effort_inferred",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._decorate_route_presentations",
            "ownership",
            ("node_plugin",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._decorate_route_presentations",
            "decision_owner",
            ("node_route_plugin",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_route.py",
            "MultiNodeRouteService._generated_projection_for_scenario",
            "steering_profile_id",
            ("observed",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService._query_one_node",
            "resolution",
            ("clock_unaligned",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService.query",
            "resolution",
            ("unsupported_matcher_contract",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService._run_projection",
            "status_class",
            ("usable",),
        ): 2,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService._assemble_network_segments",
            "match_semantics",
            ("exact_token",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService._assemble_network_segments",
            "result_shape",
            ("connectivity_domain",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService.query",
            "simultaneity",
            ("not_implied",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService._run_projection",
            "status_class",
            ("unusable",),
        ): 2,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService._assemble_network_segments",
            "basis_kind",
            ("absolute_time",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService._join_claims",
            "basis_kind",
            ("absolute_time",),
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService._assemble_network_segments",
            "role",
            ("external",),
        ): 1,
        (
            "src/router_dump_analyzer/normalized_data.py",
            "NormalizedDataService.dashboard_query",
            "aggregation",
            ("precomputed",),
        ): 1,
        (
            "src/router_dump_analyzer/temporal_topology.py",
            "TemporalTopologyService._operational_status",
            "temporal_resolution",
            ("ambiguous",),
        ): 1,
        (
            "src/router_dump_analyzer/temporal_topology.py",
            "TemporalTopologyService.query",
            "resolution",
            ("bounded", "exact", "local_exact"),
        ): 1,
        (
            "src/router_dump_analyzer/temporal_topology.py",
            "TemporalTopologyService.query",
            "status",
            ("degraded", "unusable", "usable"),
        ): 1,
        (
            "src/router_dump_analyzer/temporal_topology.py",
            "TemporalTopologyService.query_changes",
            "resolution",
            ("bounded", "exact", "local_exact"),
        ): 1,
        (
            "src/router_dump_analyzer/topology_core.py",
            "resolve_connectivity_domain_reference",
            "reference_kind",
            ("connectivity_domain",),
        ): 1,
        (
            "src/router_dump_analyzer/topology_core.py",
            "_current_usable_attachment",
            "operational_status",
            ("usable",),
        ): 1,
        (
            "src/router_dump_analyzer/topology_core.py",
            "resolve_connectivity_domain_reference",
            "operational_status",
            ("usable",),
        ): 1,
        (
            "src/router_dump_analyzer/web/runtime_api.py",
            "event_log_selection",
            "kind",
            ("event",),
        ): 1,
        (
            "src/router_dump_analyzer/web/runtime_api.py",
            "_resolve_route_payload",
            "decision",
            ("active",),
        ): 1,
    }
)

# Opaque extension maps may be retained or forwarded by core, but core must
# not decide behavior from their undeclared fields.  These two exact reads are
# the known topology-v1 compatibility debt; the ledger cannot grow.
OPAQUE_PAYLOAD_BRANCH_MIGRATION_LEDGER: Counter[
    OpaqueBranchFingerprint
] = Counter(
    {
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService._assemble_network_segments",
            "role",
        ): 1,
        (
            "src/router_dump_analyzer/multi_node_topology.py",
            "MultiNodeTopologyService._assemble_network_segments",
            "coverage_complete",
        ): 1,
    }
)

OPAQUE_PAYLOAD_FIELD_NAMES = frozenset(
    {
        "extension_payload",
        "extensions",
        "opaque_payload",
        "plugin_data",
        "plugin_payload",
        "plugin_semantics",
    }
)
OPAQUE_PAYLOAD_NAME_PATTERN = re.compile(
    r"(?:^|_)(?:extension|opaque|plugin)_(?:data|payload|semantics)$"
)


def javascript_function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    match = re.search(r"\nfunction [A-Za-z0-9_$]+\(", source[start + 1 :])
    return source[start:] if match is None else source[start : start + 1 + match.start()]


class _ExecutableLiteralVisitor(ast.NodeVisitor):
    """Collect strings outside module/class/function docstrings with scopes."""

    def __init__(self) -> None:
        self.scope = ["<module>"]
        self.literals: list[tuple[str, str]] = []

    def _visit_body(self, body: list[ast.stmt]) -> None:
        for index, statement in enumerate(body):
            if (
                index == 0
                and isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            ):
                continue
            self.visit(statement)

    def visit_Module(self, node: ast.Module) -> None:
        self._visit_body(node.body)

    def _visit_definition(
        self,
        node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        # Decorators/defaults are executable in the enclosing scope.
        for decorator in node.decorator_list:
            self.visit(decorator)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for default in (*node.args.defaults, *node.args.kw_defaults):
                if default is not None:
                    self.visit(default)
            if node.returns is not None:
                self.visit(node.returns)
        self.scope.append(node.name)
        self._visit_body(node.body)
        self.scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_definition(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_definition(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_definition(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self.literals.append((".".join(self.scope), node.value))


def _python_files(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(path for path in root.rglob("*.py") if path.is_file()))


def _executable_literals(path: Path) -> tuple[tuple[str, str], ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    visitor = _ExecutableLiteralVisitor()
    visitor.visit(tree)
    return tuple(visitor.literals)


def _import_names(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
        elif (
            isinstance(node, ast.Call)
            and node.args
            and (
                isinstance(node.func, ast.Name)
                and node.func.id == "__import__"
                or isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
            )
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            names.append(node.args[0].value)
    return tuple(names)


def _identifier_counts(path: Path, fragment: str) -> Counter[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    counts: Counter[str] = Counter()
    for node in ast.walk(tree):
        identifiers: tuple[str, ...] = ()
        if isinstance(node, ast.Name):
            identifiers = (node.id,)
        elif isinstance(node, ast.Attribute):
            identifiers = (node.attr,)
        elif isinstance(
            node,
            (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            identifiers = (node.name,)
        for identifier in identifiers:
            if fragment in identifier:
                counts[identifier] += 1
    return counts


def _declared_contract_branch_values(
    path: Path,
) -> tuple[dict[str, frozenset[str]], frozenset[str]]:
    """Return wire-field enum values and typed decoder class names."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    enum_values: dict[str, set[str]] = {}
    descriptor_names: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        if node.name.endswith("Descriptor"):
            descriptor_names.add(node.name)
        base_names = {
            item.id
            for base in node.bases
            for item in ast.walk(base)
            if isinstance(item, ast.Name)
        }
        if not base_names.intersection({"Enum", "StrEnum"}):
            continue
        values = {
            value.value
            for statement in node.body
            if isinstance(statement, (ast.Assign, ast.AnnAssign))
            for value in (statement.value,)
            if isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        }
        enum_values[node.name] = values

    field_values: defaultdict[str, set[str]] = defaultdict(set)
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in node.body:
            if not (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
            ):
                continue
            annotation_names = {
                item.id
                for item in ast.walk(statement.annotation)
                if isinstance(item, ast.Name)
            }
            for enum_name in annotation_names.intersection(enum_values):
                field_values[statement.target.id].update(
                    enum_values[enum_name]
                )
            # Literal["..."] annotations also declare closed vocabulary.
            field_values[statement.target.id].update(
                item.value
                for item in ast.walk(statement.annotation)
                if isinstance(item, ast.Constant)
                and isinstance(item.value, str)
            )

    return (
        {
            field_name: frozenset(values)
            for field_name, values in field_values.items()
        },
        frozenset((*enum_values, *descriptor_names)),
    )


DECLARED_CONTRACT_BRANCH_VALUES, DECLARED_CONTRACT_DECODERS = (
    _declared_contract_branch_values(PLUGIN_API_PY)
)


def _lexical_scopes(tree: ast.AST) -> dict[ast.AST, str]:
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    result: dict[ast.AST, str] = {}
    for node in ast.walk(tree):
        names: list[str] = []
        current = node
        while current in parents:
            current = parents[current]
            if isinstance(
                current,
                (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                names.append(current.name)
        result[node] = ".".join(reversed(names)) or "<module>"
    return result


def _called_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _mapping_field(node: ast.expr) -> str | None:
    """Return the terminal mapping key whose value is being compared."""

    if isinstance(node, ast.Call):
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return node.args[0].value
        if (
            _called_name(node) in {"bool", "str"}
            and node.args
        ):
            return _mapping_field(node.args[0])
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"casefold", "lower", "strip", "upper"}
            and not node.args
        ):
            return _mapping_field(node.func.value)
        return None
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ):
        return node.slice.value
    if isinstance(node, ast.BoolOp):
        fields = {
            field
            for value in node.values
            if (field := _mapping_field(value)) is not None
        }
        if len(fields) == 1:
            return fields.pop()
    return None


def _raw_string_values(node: ast.expr) -> tuple[str, ...]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value,)
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return tuple(
            sorted(
                item.value
                for item in node.elts
                if isinstance(item, ast.Constant)
                and isinstance(item.value, str)
            )
        )
    return ()


def _match_string_values(node: ast.pattern) -> tuple[str, ...]:
    return tuple(
        sorted(
            item.value.value
            for item in ast.walk(node)
            if isinstance(item, ast.MatchValue)
            and isinstance(item.value, ast.Constant)
            and isinstance(item.value.value, str)
        )
    )


def _assignment_targets(node: ast.AST) -> tuple[str, ...]:
    targets: list[ast.expr] = []
    if isinstance(node, ast.Assign):
        targets.extend(node.targets)
    elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
        targets.append(node.target)
    result: list[str] = []
    for target in targets:
        result.extend(
            item.id
            for item in ast.walk(target)
            if isinstance(item, ast.Name)
            and isinstance(item.ctx, ast.Store)
        )
    return tuple(result)


def _assignment_value(node: ast.AST) -> ast.expr | None:
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        return node.value
    return None


def _opaque_origins(
    node: ast.AST,
    origins_by_name: dict[str, frozenset[str]],
    *,
    ignore_comparisons: bool = False,
) -> frozenset[str]:
    """Trace reads from an explicitly opaque plug-in extension mapping."""

    if ignore_comparisons and isinstance(node, ast.Compare):
        return frozenset()
    if isinstance(node, ast.Name):
        if OPAQUE_PAYLOAD_NAME_PATTERN.search(node.id):
            return frozenset({"<payload>"})
        return origins_by_name.get(node.id, frozenset())
    if isinstance(node, ast.Call):
        if _called_name(node) in DECLARED_CONTRACT_DECODERS:
            # A declared enum/descriptor is the executable semantic boundary.
            return frozenset()
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            field_name = node.args[0].value
            receiver_origins = _opaque_origins(
                node.func.value,
                origins_by_name,
                ignore_comparisons=ignore_comparisons,
            )
            if field_name in OPAQUE_PAYLOAD_FIELD_NAMES:
                return frozenset({"<payload>"})
            if receiver_origins:
                return frozenset({field_name})
        return frozenset().union(
            *(
                _opaque_origins(
                    child,
                    origins_by_name,
                    ignore_comparisons=ignore_comparisons,
                )
                for child in ast.iter_child_nodes(node)
            )
        )
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ):
        field_name = node.slice.value
        receiver_origins = _opaque_origins(
            node.value,
            origins_by_name,
            ignore_comparisons=ignore_comparisons,
        )
        if field_name in OPAQUE_PAYLOAD_FIELD_NAMES:
            return frozenset({"<payload>"})
        if receiver_origins:
            return frozenset({field_name})
    child_origins = [
        _opaque_origins(
            child,
            origins_by_name,
            ignore_comparisons=ignore_comparisons,
        )
        for child in ast.iter_child_nodes(node)
    ]
    return (
        frozenset().union(*child_origins)
        if child_origins
        else frozenset()
    )


def _scope_opaque_origins(
    tree: ast.AST,
    scopes: dict[ast.AST, str],
) -> dict[str, dict[str, frozenset[str]]]:
    assignments: defaultdict[str, list[ast.AST]] = defaultdict(list)
    for node in ast.walk(tree):
        if _assignment_value(node) is not None:
            assignments[scopes[node]].append(node)

    result: dict[str, dict[str, frozenset[str]]] = {}
    for scope, nodes in assignments.items():
        known: dict[str, frozenset[str]] = {}
        changed = True
        while changed:
            changed = False
            for node in nodes:
                value = _assignment_value(node)
                assert value is not None
                origins = _opaque_origins(value, known)
                if not origins:
                    continue
                for name in _assignment_targets(node):
                    combined = known.get(name, frozenset()).union(origins)
                    if combined != known.get(name):
                        known[name] = frozenset(combined)
                        changed = True
        result[scope] = known
    return result


def _semantic_mapping_branch_debt(
    source: str,
    *,
    relative_path: str,
) -> tuple[
    Counter[BranchFingerprint],
    Counter[OpaqueBranchFingerprint],
]:
    """Find raw wire vocabulary and opaque extension reads in decisions."""

    tree = ast.parse(source, filename=relative_path)
    scopes = _lexical_scopes(tree)
    origins_by_scope = _scope_opaque_origins(tree, scopes)
    raw_debt: Counter[BranchFingerprint] = Counter()
    opaque_debt: Counter[OpaqueBranchFingerprint] = Counter()
    seen_opaque_sites: set[tuple[int, int, str]] = set()

    for node in ast.walk(tree):
        scope = scopes[node]
        if (relative_path, scope) in CORE_OWNED_MAPPING_CODEC_SCOPES:
            continue
        if isinstance(node, ast.Compare):
            operands = (node.left, *node.comparators)
            for index, operand in enumerate(operands):
                field_name = _mapping_field(operand)
                if field_name is None:
                    continue
                raw_values = tuple(
                    value
                    for other_index, other in enumerate(operands)
                    if other_index != index
                    for value in _raw_string_values(other)
                    if value
                    not in DECLARED_CONTRACT_BRANCH_VALUES.get(
                        field_name,
                        frozenset(),
                    )
                )
                if raw_values:
                    raw_debt[
                        (
                            relative_path,
                            scope,
                            field_name,
                            tuple(sorted(set(raw_values))),
                        )
                    ] += 1
        elif isinstance(node, ast.Match):
            field_name = _mapping_field(node.subject)
            if field_name is not None:
                raw_values = tuple(
                    value
                    for case in node.cases
                    for value in _match_string_values(case.pattern)
                    if value
                    not in DECLARED_CONTRACT_BRANCH_VALUES.get(
                        field_name,
                        frozenset(),
                    )
                )
                if raw_values:
                    raw_debt[
                        (
                            relative_path,
                            scope,
                            field_name,
                            tuple(sorted(set(raw_values))),
                        )
                    ] += 1

        decision_expressions: tuple[ast.AST, ...] = ()
        if isinstance(node, (ast.If, ast.IfExp, ast.While, ast.Assert)):
            decision_expressions = (node.test,)
        elif isinstance(node, ast.comprehension):
            decision_expressions = tuple(node.ifs)
        elif isinstance(node, ast.Compare):
            decision_expressions = (node,)
        elif isinstance(node, ast.Match):
            decision_expressions = (node.subject,)

        for expression in decision_expressions:
            for field_name in _opaque_origins(
                expression,
                origins_by_scope.get(scope, {}),
                ignore_comparisons=not isinstance(node, ast.Compare),
            ):
                if field_name == "<payload>":
                    continue
                site = (expression.lineno, expression.col_offset, field_name)
                if site in seen_opaque_sites:
                    continue
                seen_opaque_sites.add(site)
                opaque_debt[(relative_path, scope, field_name)] += 1

    return raw_debt, opaque_debt


def _counter_excess[
    Key: tuple[str, ...]
](
    actual: Counter[Key],
    ledger: Counter[Key],
) -> Counter[Key]:
    return actual - ledger


class NodeSemanticBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = APP_JS.read_text(encoding="utf-8")

    def test_event_semantics_use_only_normalized_contract_fields(self) -> None:
        failed = javascript_function(self.script, "eventFailed")
        changed = javascript_function(self.script, "eventChangesState")
        effect_condition = javascript_function(self.script, "resourceEffectCondition")
        effect_class = javascript_function(self.script, "resourceEffectStatusClass")
        normalize = javascript_function(self.script, "normalizeMark")
        interval = javascript_function(self.script, "normalizeInterval")
        derive = javascript_function(self.script, "deriveLaneIntervals")
        mark_class = javascript_function(self.script, "eventMarkClass")

        self.assertIn("normalizedEventOutcome(event)", failed)
        self.assertNotRegex(failed, r"status|rejected|accepted")
        self.assertIn("effect.state_changed", changed)
        self.assertNotRegex(changed, r"event\?\.(?:action|operation)|observe|noop")
        self.assertIn('hasOwnProperty.call(effect, "condition")', effect_condition)
        self.assertLess(
            effect_condition.index('hasOwnProperty.call(effect, "condition")'),
            effect_condition.index("resourceEffectState(effect)"),
        )
        self.assertNotIn("return stateValue", effect_condition)
        self.assertIn('hasOwnProperty.call(effect, "status_class")', effect_class)
        self.assertIn('hasOwnProperty.call(effect, "condition_class")', effect_class)
        self.assertLess(effect_class.index('"status_class"'), effect_class.index('"condition_class"'))
        self.assertNotRegex(effect_class, r"healthy|failed|active|down|includes\(|match\(")
        self.assertLess(
            normalize.index("effect?.state_changed"),
            normalize.index("raw?.state_changed"),
        )
        self.assertLess(
            normalize.index("effect?.effect_type"),
            normalize.index("raw?.effect_type"),
        )
        self.assertIn("condition_field", interval)
        self.assertIn('raw?.status_class', interval)
        self.assertNotRegex(interval, r"includes\(|match\(")
        self.assertIn("mark.effectType", derive)
        self.assertNotIn("mark.action", derive)
        self.assertIn("mark.stateChanged === true", derive)
        self.assertIn("if (mark.stateChanged !== true) continue", derive)
        self.assertNotIn("!mark.failure", derive)
        self.assertNotIn("if (mark.failure)", derive)
        self.assertIn("resourceEffectStatusClass(mark.effect, mark.event)", derive)
        self.assertIn("mark.effectType", mark_class)
        self.assertNotIn("mark.action", mark_class)

    def test_relationship_labels_and_direction_come_from_plugin_descriptors(self) -> None:
        presentation = javascript_function(self.script, "relationshipPresentation")
        hover = javascript_function(self.script, "graphEdgeHoverHtml")
        graph = javascript_function(self.script, "normalizedGraph")

        self.assertIn("relationshipTypeDescriptor(rawType)", presentation)
        self.assertIn('Unknown relationship', presentation)
        self.assertIn("descriptor.directed", presentation)
        self.assertIn("descriptor?.structural", presentation)
        self.assertIn("presentation.displayLabel", hover)
        self.assertIn("presentation.directed === true", hover)
        self.assertNotIn("titleCase(edge.type)", hover)
        self.assertIn("relationship_label: presentation.displayLabel", graph)
        self.assertIn("directed: presentation.directed", graph)

    def test_resource_ids_remain_opaque_and_are_never_rebuilt_from_keys(self) -> None:
        resource_id = javascript_function(self.script, "resourceIdOf")
        kind = javascript_function(self.script, "resourceKind")
        layer = javascript_function(self.script, "resourceLayer")
        label = javascript_function(self.script, "resourceLabel")
        subject = javascript_function(self.script, "canonicalResourceForSubject")
        register = javascript_function(self.script, "registerResource")

        self.assertIn("canonicalResourceId(direct)", resource_id)
        self.assertNotIn("record.key", resource_id)
        self.assertNotIn("split", f"{kind}\n{layer}\n{label}")
        self.assertNotIn("raw_key", subject)
        self.assertNotIn("tokens", subject)
        self.assertNotIn("resourceAliases", register)

    def test_resource_type_labels_come_only_from_plugin_descriptors(self) -> None:
        formatter = javascript_function(self.script, "humanResourceType")

        self.assertIn("resourceKindDescriptor(kind)", formatter)
        self.assertIn("descriptor?.display_name", formatter)
        self.assertIn("return String(kind ||", formatter)
        self.assertNotIn("RESOURCE_TYPE_ACRONYMS", self.script)
        self.assertNotRegex(formatter, r"ETG|EVPN|MPLS|SRV6|ISIS")

    def test_tagged_values_render_readably_but_do_not_participate_in_identity(self) -> None:
        readable = javascript_function(self.script, "readableTypedValue")
        identity = javascript_function(self.script, "canonicalResourceId")
        subject = javascript_function(self.script, "canonicalResourceForSubject")
        event_row = javascript_function(self.script, "renderEventRow")

        self.assertIn("typedValueTag(value)", readable)
        self.assertIn("typedValuePayload(value)", readable)
        self.assertIn("Object.keys(value).sort()", readable)
        self.assertIn('typeof value === "string"', identity)
        self.assertNotIn("readableTypedValue", identity)
        self.assertNotIn("readableTypedValue", subject)
        self.assertIn("subject.raw_key ??", event_row)
        self.assertIn("formatValue(subjectKey)", event_row)
        self.assertNotIn("canonicalResourceId(subjectKey)", event_row)

    def test_temporal_topology_does_not_treat_failure_as_no_mutation(self) -> None:
        source = TEMPORAL_TOPOLOGY_PY.read_text(encoding="utf-8")
        event_projection = source[
            source.index("def _perspective_status_events(") :
            source.index("def _perspective_state_at(")
        ]
        changes_projection = source[
            source.index("def event_changes()") :
            source.index("def mutation_changes()")
        ]

        self.assertNotIn('event.get("outcome") == "failure"', event_projection)
        self.assertIn('"applied": bool(event.get("state_changed", False))', changes_projection)
        self.assertNotIn('event.get("outcome") != "failure"', changes_projection)

        state_projection = source[
            source.index("def _perspective_state_at(") :
            source.index("def _unknown_resource(")
        ]
        self.assertNotIn("if native and exists is None", state_projection)

    def test_node_workspace_adapter_preserves_plugin_vocabulary(self) -> None:
        source = CORE_RUNTIME_API_PY.read_text(encoding="utf-8")
        adapter = source[
            source.index("def _node_workspace_dataset(") :
            source.index('@api_router.get("/v1/nodes/{node_id}/workspace")')
        ]

        self.assertNotIn('or "RESOURCE"', adapter)
        self.assertNotIn('or "observed"', adapter)
        self.assertNotIn('or "related_to"', adapter)
        self.assertNotRegex(
            adapter,
            r'(?:kind|relation_type|projection_id|perspective_id)\.replace\(',
        )
        self.assertIn('item.get("kind") or "unknown"', adapter)
        self.assertIn('item.get("status_perspective_label")', adapter)
        self.assertIn('selection.get("projection_label")', adapter)
        self.assertIn('selection.get("status_perspective_label")', adapter)

    def test_structural_guard_detects_opaque_and_raw_payload_decisions(
        self,
    ) -> None:
        source = """
def decide(item):
    semantics = item.get("plugin_semantics") or {}
    if (
        semantics.get("role") == "external"
        and semantics.get("coverage_complete") is True
    ):
        return True
    return False
"""
        raw_debt, opaque_debt = _semantic_mapping_branch_debt(
            source,
            relative_path="synthetic.py",
        )

        self.assertEqual(
            raw_debt,
            Counter(
                {
                    (
                        "synthetic.py",
                        "decide",
                        "role",
                        ("external",),
                    ): 1
                }
            ),
        )
        self.assertEqual(
            opaque_debt,
            Counter(
                {
                    ("synthetic.py", "decide", "role"): 1,
                    (
                        "synthetic.py",
                        "decide",
                        "coverage_complete",
                    ): 1,
                }
            ),
        )

    def test_structural_guard_allows_declared_enum_boundary(self) -> None:
        source = """
def decide(item):
    semantics = item.get("plugin_semantics") or {}
    role = StatusPerspectiveRole(semantics.get("role"))
    if role is StatusPerspectiveRole.OBSERVED:
        return True
    return False

def event_failed(event):
    return event.get("outcome") == "failure"
"""
        raw_debt, opaque_debt = _semantic_mapping_branch_debt(
            source,
            relative_path="synthetic.py",
        )

        self.assertEqual(raw_debt, Counter())
        self.assertEqual(opaque_debt, Counter())

    def test_structural_guard_detects_match_vocabulary(self) -> None:
        source = """
def decide(item):
    match (item.get("plugin_semantics") or {}).get("mode"):
        case "vendor-special":
            return True
        case _:
            return False
"""
        raw_debt, opaque_debt = _semantic_mapping_branch_debt(
            source,
            relative_path="synthetic.py",
        )

        self.assertEqual(
            raw_debt,
            Counter(
                {
                    (
                        "synthetic.py",
                        "decide",
                        "mode",
                        ("vendor-special",),
                    ): 1
                }
            ),
        )
        self.assertEqual(
            opaque_debt,
            Counter({("synthetic.py", "decide", "mode"): 1}),
        )

    def test_core_mapping_branches_use_declared_contract_vocabulary(
        self,
    ) -> None:
        raw_debt: Counter[BranchFingerprint] = Counter()
        opaque_debt: Counter[OpaqueBranchFingerprint] = Counter()
        for path in _python_files(CORE_SOURCE):
            relative = path.relative_to(ROOT).as_posix()
            raw, opaque = _semantic_mapping_branch_debt(
                path.read_text(encoding="utf-8"),
                relative_path=relative,
            )
            raw_debt.update(raw)
            opaque_debt.update(opaque)

        raw_excess = _counter_excess(
            raw_debt,
            RAW_MAPPING_BRANCH_MIGRATION_LEDGER,
        )
        opaque_excess = _counter_excess(
            opaque_debt,
            OPAQUE_PAYLOAD_BRANCH_MIGRATION_LEDGER,
        )
        self.assertEqual(
            raw_excess,
            Counter(),
            "core branches on raw mapping vocabulary not declared by a "
            "plug-in contract enum/Literal and not present in the exact "
            "downward-only migration ledger:\n"
            + "\n".join(
                f"{count}x {fingerprint!r}"
                for fingerprint, count in sorted(raw_excess.items())
            ),
        )
        self.assertEqual(
            opaque_excess,
            Counter(),
            "core branches on undeclared fields read directly from an opaque "
            "plug-in payload:\n"
            + "\n".join(
                f"{count}x {fingerprint!r}"
                for fingerprint, count in sorted(opaque_excess.items())
            ),
        )

    def test_core_has_no_plugin_owned_inference_literals_or_imports(self) -> None:
        literal_violations: list[str] = []
        import_violations: list[str] = []
        demo_literals: Counter[tuple[str, str, str]] = Counter()

        for path in _python_files(CORE_SOURCE):
            relative = path.relative_to(ROOT).as_posix()
            for scope, literal in _executable_literals(path):
                occurrence = (relative, scope, literal)
                if (
                    (
                        PLUGIN_OWNED_TOKEN_PATTERN.search(literal)
                        or PLUGIN_OWNED_CASED_TOKEN_PATTERN.search(literal)
                    )
                    and occurrence not in ALLOWED_PROTOCOL_DISCLOSURES
                ):
                    literal_violations.append(
                        f"{relative}:{scope}: {literal!r}"
                    )
                if DEMO_TOKEN_PATTERN.search(literal):
                    demo_literals[occurrence] += 1

            for import_name in _import_names(path):
                components = {
                    component.lower().replace("-", "").replace("_", "")
                    for component in import_name.split(".")
                    if component
                }
                owned_components = {
                    token.lower().replace("-", "").replace("_", "")
                    for token in (*PLUGIN_OWNED_TOKENS, "demo")
                }
                if components & owned_components:
                    import_violations.append(
                        f"{relative}: imports {import_name!r}"
                    )

        self.assertEqual(
            literal_violations,
            [],
            "core embeds plug-in-owned executable vocabulary:\n"
            + "\n".join(literal_violations),
        )
        self.assertEqual(
            import_violations,
            [],
            "core imports a demo-, device-, vendor-, or protocol-owned module:\n"
            + "\n".join(import_violations),
        )
        self.assertEqual(
            demo_literals,
            ALLOWED_DEMO_COMPATIBILITY_LITERALS,
            "the exact legacy demo bootstrap exception changed; reduce it or "
            "update the architecture migration ledger explicitly",
        )

    def test_generated_route_compatibility_exception_cannot_grow(self) -> None:
        route_path = CORE_SOURCE / "multi_node_route.py"
        identifier_counts = _identifier_counts(route_path, "_generated_")
        unexpected = sorted(
            set(identifier_counts) - set(GENERATED_ROUTE_IDENTIFIER_BUDGET)
        )
        over_budget = {
            identifier: count
            for identifier, count in identifier_counts.items()
            if count > GENERATED_ROUTE_IDENTIFIER_BUDGET.get(identifier, 0)
        }
        generated_literals: list[tuple[str, str, str]] = []
        for path in _python_files(CORE_SOURCE):
            relative = path.relative_to(ROOT).as_posix()
            generated_literals.extend(
                (relative, scope, literal)
                for scope, literal in _executable_literals(path)
                if GENERATED_TOKEN_PATTERN.search(literal)
            )
        wrong_files = sorted(
            {
                relative
                for relative, _scope, _literal in generated_literals
                if relative
                != "src/router_dump_analyzer/multi_node_route.py"
            }
        )

        self.assertEqual(
            unexpected,
            [],
            "new generated-projection coupling identifiers are not allowed: "
            + repr(unexpected),
        )
        self.assertEqual(
            over_budget,
            {},
            "generated-projection compatibility references grew: "
            + repr(over_budget),
        )
        self.assertEqual(
            wrong_files,
            [],
            "generated-projection vocabulary escaped its exact migration "
            f"exception: {wrong_files!r}",
        )
        self.assertLessEqual(
            len(generated_literals),
            GENERATED_ROUTE_LITERAL_BUDGET,
            "generated-projection executable literals grew beyond the "
            "temporary migration budget",
        )


if __name__ == "__main__":
    unittest.main()
