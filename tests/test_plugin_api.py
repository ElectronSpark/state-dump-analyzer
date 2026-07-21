from __future__ import annotations

import inspect
import sys
import typing
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from router_dump_analyzer import plugin_api
from router_dump_analyzer.plugin_api import (
    AnalyzerPlugin,
    CaptureRange,
    ChangeSet,
    DashboardAggregation,
    DashboardColumnDescriptor,
    DashboardDescriptor,
    DashboardFilterDescriptor,
    DashboardFilterOperator,
    DashboardStatisticDescriptor,
    DashboardTableDescriptor,
    DashboardValueFormat,
    ForwardingMutation,
    ForwardingOperation,
    IconRenderMode,
    PropertyDescriptor,
    PropertyPatch,
    Provenance,
    Quality,
    RecordLanePreset,
    ResourceEffect,
    ResourceIconDescriptor,
    ResourceKindDescriptor,
    ResourceKey,
    PluginSchema,
    SourceRecordTypeDescriptor,
    UnknownField,
    VrfForwardingState,
    WorldBasis,
    WorldBasisKind,
)


class PluginApiTests(unittest.TestCase):
    def test_public_contract_annotations_resolve(self) -> None:
        for name, value in vars(plugin_api).items():
            if name.startswith("_") or not inspect.isclass(value):
                continue
            with self.subTest(name=name):
                typing.get_type_hints(value)
                for member in vars(value).values():
                    if inspect.isfunction(member):
                        typing.get_type_hints(member)

    def test_property_patch_distinguishes_null_remove_and_unknown(self) -> None:
        patch = PropertyPatch(
            set_values={"nullable": None},
            remove_fields=("removed",),
            unknown_fields=(UnknownField("unclear", "missing", "not captured"),),
            field_quality={
                "nullable": Quality.EXACT,
                "removed": Quality.EXACT,
                "unclear": Quality.UNKNOWN,
            },
            field_provenance={
                "nullable": Provenance.OBSERVED,
                "removed": Provenance.EVENT_DERIVED,
                "unclear": Provenance.RECONSTRUCTED,
            },
        )
        self.assertIsNone(patch.set_values["nullable"])

    def test_property_patch_rejects_contradictory_or_orphan_metadata(self) -> None:
        invalid = (
            {"set_values": {"field": 1}, "remove_fields": ("field",)},
            {"remove_fields": ("field", "field")},
            {
                "unknown_fields": (
                    UnknownField("field", "one", "first"),
                    UnknownField("field", "two", "second"),
                )
            },
            {"set_values": {"field": 1}, "field_quality": {"other": Quality.EXACT}},
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                PropertyPatch(**arguments)

    def test_ctf_hook_receives_records_not_native_decoder_or_reader(self) -> None:
        parameters = inspect.signature(AnalyzerPlugin.parse_ctf).parameters
        self.assertEqual(tuple(parameters), ("self", "spec", "messages"))
        self.assertNotIn("reader", parameters)
        self.assertNotIn("decoder", parameters)

    def test_forwarding_projection_negotiates_ir_and_accepts_delta(self) -> None:
        parameters = inspect.signature(AnalyzerPlugin.project_forwarding).parameters
        self.assertEqual(
            tuple(parameters),
            ("self", "ir_version", "changes", "world"),
        )

    def test_resource_keys_reject_boolean_integer_aliasing(self) -> None:
        with self.assertRaisesRegex(ValueError, "Boolean"):
            ResourceKey(
                namespace="test",
                node="node-a",
                layer="control-plane",
                kind="flagged",
                parts=(("flag", True),),  # type: ignore[arg-type]
            )

    def test_resource_presentation_is_generic_and_empty_change_set_is_valid(self) -> None:
        icon = ResourceIconDescriptor(
            path="M4 12h16M12 4v16",
            render_mode=IconRenderMode.STROKE,
            stroke_width=1.5,
        )
        descriptor = ResourceKindDescriptor(
            kind="SYNTHETIC_CONNECTOR",
            label="Synthetic connector",
            key_fields=("id",),
            properties=(
                PropertyDescriptor("condition", "Condition", "string"),
            ),
            display_name_fields=("id",),
            default_table_fields=("condition",),
            condition_field="condition",
            presentation_tags=("connector", "compact"),
            icon=icon,
        )
        self.assertIn("connector", descriptor.presentation_tags)
        self.assertIs(descriptor.icon, icon)
        with self.assertRaisesRegex(ValueError, "SVG path geometry"):
            ResourceIconDescriptor(path="<svg onload=alert(1)>")
        with self.assertRaisesRegex(ValueError, "positive size"):
            ResourceIconDescriptor(path="M0 0", view_box=(0, 0, 0, 24))
        with self.assertRaisesRegex(ValueError, "stroke or fill"):
            ResourceIconDescriptor(
                path="M0 0",
                render_mode="paint",  # type: ignore[arg-type]
            )
        self.assertEqual(ChangeSet().state, ())
        self.assertEqual(ResourceEffect.MODIFIED.value, "modified")

    def test_plugin_dashboards_use_validated_common_widgets(self) -> None:
        resource = ResourceKindDescriptor(
            kind="SYNTHETIC_RESOURCE",
            label="Synthetic resource",
            key_fields=("id",),
            properties=(PropertyDescriptor("status", "Status", "string"),),
        )
        dashboard = DashboardDescriptor(
            dashboard_id="synthetic.health",
            title="Synthetic health",
            description="Generic point-in-time health.",
            statistics=(
                DashboardStatisticDescriptor(
                    statistic_id="resource-count",
                    label="Resources",
                    aggregation=DashboardAggregation.COUNT,
                    resource_kinds=("SYNTHETIC_RESOURCE",),
                    filters=(
                        DashboardFilterDescriptor(
                            field="status",
                            operator=DashboardFilterOperator.NOT_EQ,
                            value="deleted",
                        ),
                    ),
                ),
            ),
            tables=(
                DashboardTableDescriptor(
                    table_id="resource-table",
                    title="Resources",
                    resource_kinds=("SYNTHETIC_RESOURCE",),
                    columns=(
                        DashboardColumnDescriptor(
                            field="label",
                            label="Resource",
                            value_format=DashboardValueFormat.RESOURCE,
                        ),
                        DashboardColumnDescriptor(
                            field="status",
                            label="Status",
                            value_format=DashboardValueFormat.STATUS,
                        ),
                    ),
                ),
            ),
            default_open=True,
        )
        schema = PluginSchema(
            resource_kinds=(resource,),
            relationship_types=(),
            dashboards=(dashboard,),
        )
        self.assertEqual(schema.dashboards[0].dashboard_id, "synthetic.health")
        with self.assertRaisesRegex(ValueError, "unknown resource kinds"):
            PluginSchema(
                resource_kinds=(resource,),
                relationship_types=(),
                dashboards=(
                    DashboardDescriptor(
                        dashboard_id="invalid.resources",
                        title="Invalid",
                        description="References a missing kind.",
                        statistics=(
                            DashboardStatisticDescriptor(
                                statistic_id="missing-count",
                                label="Missing",
                                aggregation=DashboardAggregation.COUNT,
                                resource_kinds=("MISSING_KIND",),
                            ),
                        ),
                    ),
                ),
            )
        with self.assertRaisesRegex(ValueError, "tuple"):
            DashboardFilterDescriptor(
                field="status",
                operator=DashboardFilterOperator.IN,
                value="up",
            )

    def test_plugin_source_types_and_regex_lane_presets_are_declarative(self) -> None:
        source_type = SourceRecordTypeDescriptor(
            source_type="vendor-syslog",
            label="Vendor syslog",
            description="Decoded lines retained before normalization.",
            color="#f5b85b",
        )
        preset = RecordLanePreset(
            lane_id="vendor.unmatched-es",
            label="Unmatched ES signals",
            pattern="ESI|mass withdraw",
            source_types=("vendor-syslog",),
            unmatched_only=True,
            default_enabled=True,
        )
        schema = PluginSchema(
            resource_kinds=(),
            relationship_types=(),
            source_record_types=(source_type,),
            record_lane_presets=(preset,),
        )
        self.assertTrue(schema.record_lane_presets[0].default_enabled)
        with self.assertRaisesRegex(ValueError, "unknown source types"):
            PluginSchema(
                resource_kinds=(),
                relationship_types=(),
                source_record_types=(source_type,),
                record_lane_presets=(
                    RecordLanePreset(
                        lane_id="invalid.unknown",
                        label="Unknown",
                        pattern=".+",
                        source_types=("missing-source",),
                    ),
                ),
            )
        with self.assertRaisesRegex(ValueError, "invalid record lane pattern"):
            RecordLanePreset(
                lane_id="invalid.regex",
                label="Invalid",
                pattern="[",
            )
        with self.assertRaisesRegex(ValueError, "unsupported regex"):
            RecordLanePreset(
                lane_id="invalid.extension",
                label="Invalid",
                pattern="(?=ESI)",
            )

    def test_forwarding_mutation_enforces_operation_shape(self) -> None:
        key = ResourceKey(
            namespace="test",
            node="node-a",
            layer="control-plane",
            kind="VRF",
            parts=(("name", "blue"),),
        )
        other_key = ResourceKey(
            namespace="test",
            node="node-a",
            layer="control-plane",
            kind="VRF",
            parts=(("name", "red"),),
        )
        record = VrfForwardingState(key=key, name="blue", active=True, attributes={})
        other_record = VrfForwardingState(
            key=other_key,
            name="red",
            active=True,
            attributes={},
        )
        basis = WorldBasis(
            kind=WorldBasisKind.RECONSTRUCTED_TIME,
            requested_time_ns=1,
            resolved_at_min_ns=1,
            resolved_at_max_ns=1,
            capture_ranges=(CaptureRange("test", 1, 1),),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.EXACT,
        )
        common = {
            "key": key,
            "effective_time_ns": 1,
            "time_uncertainty_ns": 0,
            "cause_event_uid": None,
            "provenance": Provenance.RECONSTRUCTED,
            "quality": Quality.EXACT,
            "basis": basis,
        }
        ForwardingMutation(
            operation=ForwardingOperation.UPSERT,
            record=record,
            **common,
        )
        with self.assertRaisesRegex(ValueError, "requires a record"):
            ForwardingMutation(
                operation=ForwardingOperation.UPSERT,
                record=None,
                **common,
            )
        with self.assertRaisesRegex(ValueError, "must not include"):
            ForwardingMutation(
                operation=ForwardingOperation.DELETE,
                record=record,
                **common,
            )
        with self.assertRaisesRegex(ValueError, "does not match"):
            ForwardingMutation(
                operation=ForwardingOperation.UPSERT,
                record=other_record,
                **common,
            )


if __name__ == "__main__":
    unittest.main()
