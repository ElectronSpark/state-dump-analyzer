from __future__ import annotations

import ast
from collections import Counter
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE_SOURCE = ROOT / "src" / "router_dump_analyzer"
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
            "VLAN, LAG, subinterface, physical-member, neighbor, and route "
            "inference details",
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
        self.assertNotIn("split", "\n".join((kind, layer, label)))
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
