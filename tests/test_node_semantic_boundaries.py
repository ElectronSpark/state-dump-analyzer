from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "frontend" / "assets" / "app.js"
TEMPORAL_TOPOLOGY_PY = (
    ROOT / "src" / "router_dump_analyzer" / "temporal_topology.py"
)
CORE_RUNTIME_API_PY = (
    ROOT / "src" / "router_dump_analyzer" / "web" / "runtime_api.py"
)


def javascript_function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    match = re.search(r"\nfunction [A-Za-z0-9_$]+\(", source[start + 1 :])
    return source[start:] if match is None else source[start : start + 1 + match.start()]


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


if __name__ == "__main__":
    unittest.main()
