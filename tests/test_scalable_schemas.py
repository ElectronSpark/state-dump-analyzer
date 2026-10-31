from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer.capability_executor import (
    PluginCapabilityExecutor,
    PluginCapabilityOutputError,
)
from router_dump_analyzer.ingestion import IngestionCoordinator, IngestionError
from router_dump_analyzer.normalized_data import (
    descriptor_property_rules,
    redact_resource_view,
    resource_search_text,
)
from router_dump_analyzer.plugin_api import (
    ChangeSet,
    PropertyDescriptor,
    PropertyPatch,
    SnapshotObservation,
    SourceRecordTypeDescriptor,
)
from router_dump_analyzer.plugin_schema_identity import (
    PluginSchemaIdentityError,
    plugin_schema_dataset,
    plugin_schema_digest,
    snapshot_plugin_schema,
)
from router_dump_analyzer.property_schema import validate_property_patch
from tests.test_capability_executor import EVENT, _Plugin, _state_mutation, _World
from tests.test_ingestion import ParseOnlyPlugin


def _nested_property() -> PropertyDescriptor:
    return PropertyDescriptor("details", "Details", "object", properties=(
        PropertyDescriptor("count", "Count", "integer", nullable=False),
        PropertyDescriptor("entries", "Entries", "array", items=PropertyDescriptor(
            "item", "Item", "object", properties=(
                PropertyDescriptor("label", "Label", "string", searchable=True),
                PropertyDescriptor("secret", "Secret", "string", searchable=True, sensitive=True),
            ),
        )),
    ))


class _SchemaPlugin(ParseOnlyPlugin):
    def __init__(self, values=None, catalog_size=0):
        self.values = values
        self.catalog_size = catalog_size

    def describe(self):
        schema = super().describe()
        kind = schema.resource_kinds[0]
        return replace(schema, resource_kinds=(replace(
            kind, properties=(*kind.properties, _nested_property()),
        ),), source_record_types=(*schema.source_record_types, *(
            SourceRecordTypeDescriptor(f"event-{i}", f"Event {i}")
            for i in range(self.catalog_size)
        )))

    def parse_status(self, reader, spec):
        for output in super().parse_status(reader, spec):
            if isinstance(output, SnapshotObservation) and self.values is not None:
                output = replace(output, state=PropertyPatch(set_values=self.values))
            yield output


class ScalableSchemaTests(unittest.TestCase):
    def ingest(self, plugin):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "status.jsonl"
            source.write_text('{"captured_at_ns":100,"ifindex":7,"name":"sample","oper_status":"up"}\n')
            return IngestionCoordinator().ingest(plugin, source)

    def test_large_catalog_crosses_ingestion_and_capability_boundaries(self):
        plugin = _SchemaPlugin(catalog_size=10_000)
        result = self.ingest(plugin)
        self.assertEqual(len(result.schema.source_record_types), 10_001)
        executor = PluginCapabilityExecutor(plugin, result.schema)
        self.assertEqual(plugin_schema_digest(executor.schema), plugin_schema_digest(plugin.describe()))
        self.assertEqual(len(result.dataset["source_record_descriptors"]), 10_001)

    def test_nested_types_search_and_sensitive_fields(self):
        result = self.ingest(_SchemaPlugin({"details": {
            "count": 3, "entries": [{"label": "needle-visible", "secret": "never-search"}],
        }}))
        descriptor = result.dataset["kind_descriptors"][0]
        record = result.dataset["resources"][0]
        view = {"state": record["state"], "resource": record, "resource_id": record["resource_id"]}
        text = resource_search_text(record, view, descriptor)
        self.assertIn("needle-visible", text)
        self.assertNotIn("never-search", text)
        public = redact_resource_view(view, descriptor)
        self.assertNotIn("secret", public["state"]["details"]["entries"][0])

    def test_invalid_nested_values_and_references_are_rejected(self):
        for values, message in (
            ({"details": {"count": True}}, "requires integer"),
            ({"details.count": "three"}, "requires integer"),
            ({"details.count": None}, "cannot be null"),
            ({"details": {"extra": 1}}, "undeclared nested"),
            ({"details.extra": 1}, "undeclared nested"),
            ({"details": {"entries": [{"label": 7}]}}, "requires string"),
        ):
            with self.subTest(values=values), self.assertRaisesRegex(IngestionError, message):
                self.ingest(_SchemaPlugin(values))

    def test_schema_snapshot_is_detached(self):
        schema = _SchemaPlugin().describe()
        frozen = snapshot_plugin_schema(schema)
        object.__setattr__(schema.resource_kinds[0].properties[-1].properties[0], "label", "Changed")
        self.assertEqual(frozen.resource_kinds[0].properties[-1].properties[0].label, "Count")

    def test_schema_rejects_mutable_foreign_enum_and_spoofed_record(self):
        class Foreign(str, Enum):
            LABEL = "Before"

        @dataclass
        class Fake:
            payload: str = "injected"

        Fake.__module__ = "router_dump_analyzer.plugin_api"
        for value in (Foreign.LABEL, Fake()):
            schema = _SchemaPlugin().describe()
            object.__setattr__(schema.resource_kinds[0], "label", value)
            with self.subTest(value=value), self.assertRaises(PluginSchemaIdentityError):
                snapshot_plugin_schema(schema)

    def test_dotted_typed_leaf_requires_object_ancestors(self):
        descriptors = (PropertyDescriptor("a.b", "B", "integer", nullable=False),)
        for value in (42, None, {"b": True}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_property_patch(PropertyPatch(set_values={"a": value}), descriptors)
        validate_property_patch(PropertyPatch(set_values={"a": {"b": 3}}), descriptors)

    def test_property_tree_bounds_precede_allocation_and_reject_duplicate_paths(self):
        with self.assertRaisesRegex(ValueError, "bounded sequence"):
            descriptor_property_rules({"properties": iter(())})
        with self.assertRaisesRegex(ValueError, "bounded sequence"):
            descriptor_property_rules({"properties": [{}] * 1_025})
        with self.assertRaisesRegex(ValueError, "unique"):
            descriptor_property_rules({"properties": [{"name": "a"}, {"name": "a"}]})
        schema = _SchemaPlugin().describe()
        kind = schema.resource_kinds[0]
        with self.assertRaisesRegex(ValueError, "paths must be unique"):
            replace(kind, properties=(*kind.properties, PropertyDescriptor("details.count", "Count", "string")))

    def test_reducers_validate_typed_fields_against_detached_schema(self):
        plugin = _Plugin()
        schema = plugin.describe()
        kind = schema.resource_kinds[0]
        schema = replace(schema, resource_kinds=(replace(kind, properties=(
            PropertyDescriptor("state", "State", "integer", validate_type=True),
        )),))
        executor = PluginCapabilityExecutor(plugin, schema)
        object.__setattr__(schema.resource_kinds[0].properties[0], "value_type", "string")
        plugin.apply_output = ChangeSet(state=(_state_mutation(),))
        with self.assertRaisesRegex(PluginCapabilityOutputError, "requires integer"):
            executor.apply(EVENT, _World())
        plugin.apply_output = ChangeSet(state=(replace(
            _state_mutation(), after=PropertyPatch(set_values={"state": 1}),
        ),))
        self.assertEqual(executor.apply(EVENT, _World()).state[0].after.set_values["state"], 1)

    def test_catalog_aggregate_depth_and_cycle_budgets_remain_bounded(self):
        schema = _SchemaPlugin(catalog_size=4).describe()
        for budget, value, message in (
            ("MAX_SOURCE_RECORD_TYPES", 4, "sequence exceeds"),
            ("MAX_SCHEMA_UNITS", 20, "value-unit"),
            ("MAX_SCHEMA_TEXT_BYTES", 10, "text-byte"),
        ):
            with self.subTest(budget=budget), patch(
                f"router_dump_analyzer.plugin_schema_identity.{budget}", value
            ), self.assertRaisesRegex(PluginSchemaIdentityError, message):
                plugin_schema_dataset(schema)
        nested = schema.resource_kinds[0].properties[-1]
        object.__setattr__(nested, "properties", (nested,))
        with self.assertRaisesRegex(PluginSchemaIdentityError, "cycle"):
            snapshot_plugin_schema(schema)


if __name__ == "__main__":
    unittest.main()
