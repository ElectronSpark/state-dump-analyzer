from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from router_dump_analyzer.artifact_core import ArtifactLimits
from router_dump_analyzer.ingestion import (
    IngestionCoordinator,
    IngestionError,
    IngestionLimits,
    _json_value,
    _snapshot_parser_output_value,
    snapshot_ingestion_result_for_publication,
)
from router_dump_analyzer.plugin_api import (
    PropertyDescriptor,
    PropertyPatch,
    SnapshotObservation,
    SourceRecordEmission,
)
from router_dump_analyzer.property_schema import validate_property_patch
from tests.test_ingestion import ParseOnlyPlugin
from tests.test_package_preflight import SyntheticDecoder, VersionedPackagePlugin


class CounterSamplesPlugin(ParseOnlyPlugin):
    """Synthetic counter history: no vendor formats or device-specific semantics."""

    def __init__(self):
        self.samples = [
            {"time": index, "received": index * 2, "sent": index * 3}
            for index in range(1_023)
        ]

    def describe(self):
        schema = super().describe()
        kind = schema.resource_kinds[0]
        return replace(
            schema,
            resource_kinds=(
                replace(
                    kind,
                    properties=(
                        *kind.properties,
                        PropertyDescriptor(
                            "samples",
                            "Counter samples",
                            "array",
                            items=PropertyDescriptor(
                                "sample",
                                "Sample",
                                "object",
                                properties=tuple(
                                    PropertyDescriptor(
                                        name, name.title(), "integer", nullable=False
                                    )
                                    for name in ("time", "received", "sent")
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

    def parse_status(self, reader, spec):
        for output in super().parse_status(reader, spec):
            if isinstance(output, SnapshotObservation):
                output = replace(
                    output, state=PropertyPatch(set_values={"samples": self.samples})
                )
            yield output


class AttributeOutputPlugin(ParseOnlyPlugin):
    def __init__(self, values, copies=1):
        self.values = values
        self.copies = copies

    def parse_status(self, reader, spec):
        for output in super().parse_status(reader, spec):
            if isinstance(output, SourceRecordEmission):
                for _ in range(self.copies):
                    yield replace(output, attributes=self.values)
            else:
                yield output


class LargePackagePlugin(VersionedPackagePlugin):
    def locate_inputs(self, inventory):
        for spec in super().locate_inputs(inventory):
            yield replace(
                spec, options={"groups": [list(range(1_024)) for _ in range(5)]}
            )

    def preflight_package(self, inventory, reader, inputs, records):
        context = super().preflight_package(inventory, reader, inputs, records)
        message = next(iter(records.ctf_messages(1)))
        return replace(
            context, values={**context.values, "groups": message.payload["groups"]}
        )

    def parse_ctf(self, spec, messages):
        for output in super().parse_ctf(spec, messages):
            yield replace(
                output, attributes={"groups": spec.package_context.values["groups"]}
            )


class IngestionValueLimitTests(unittest.TestCase):
    def ingest(self, plugin, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "status.jsonl"
            source.write_text(
                '{"captured_at_ns":100,"ifindex":7,"name":"sample","oper_status":"up"}\n',
                encoding="utf-8",
            )
            return IngestionCoordinator(**kwargs).ingest(plugin, source)

    def test_default_rejects_schema_valid_counter_samples(self):
        plugin = CounterSamplesPlugin()
        # 1 array + 1,023 objects + 3,069 integers = 4,093 typed-property units.
        # Every container is <= 1,024 items, but the observation envelope adds
        # enough values to exceed ingestion's separate 4,096-unit output limit.
        validate_property_patch(
            PropertyPatch(set_values={"samples": plugin.samples}),
            plugin.describe().resource_kinds[0].properties,
        )
        with self.assertRaisesRegex(IngestionError, "maximum value unit count"):
            self.ingest(plugin)

    def test_host_limit_accepts_and_detaches_schema_valid_output(self):
        plugin = CounterSamplesPlugin()
        limits = IngestionLimits(max_output_value_units=16_384)
        result = self.ingest(plugin, limits=limits)
        retained = result.snapshots[0].state.set_values["samples"]
        self.assertEqual(list(retained), plugin.samples)
        self.assertEqual(
            result.dataset["resources"][0]["state"]["samples"], plugin.samples
        )
        with self.assertRaises(TypeError):
            retained[0]["sent"] = -1
        plugin.samples[0]["sent"] = -1
        self.assertEqual(retained[0]["sent"], 0)
        self.assertEqual(
            result.dataset["resources"][0]["state"]["samples"][0]["sent"], 0
        )

        publication_args = {
            "plugin_id": plugin.manifest.plugin_id,
            "timeline_time_basis": plugin.manifest.timeline_time_basis,
            "timeline_clock_domain": plugin.manifest.timeline_clock_domain,
            "expected_node_id": result.node_id,
        }
        published = snapshot_ingestion_result_for_publication(
            result, limits=limits, **publication_args
        )
        self.assertEqual(published.dataset, result.dataset)
        self.assertIsNot(published.snapshots[0], result.snapshots[0])
        with self.assertRaisesRegex(IngestionError, "maximum value unit count"):
            snapshot_ingestion_result_for_publication(
                result, limits=IngestionLimits(), **publication_args
            )

    def test_configured_quota_still_rejects_oversized_output(self):
        values = {"groups": [list(range(1_024)) for _ in range(17)]}
        with self.assertRaisesRegex(IngestionError, "maximum value unit count"):
            self.ingest(
                AttributeOutputPlugin(values),
                limits=IngestionLimits(max_output_value_units=16_384),
            )

    def test_validation_and_snapshotting_enforce_the_same_unit_bound(self):
        for operation in (_json_value, _snapshot_parser_output_value):
            with self.subTest(operation=operation.__name__):
                value = {"values": [1, 2]}  # Mapping, sequence, two scalars.
                self.assertEqual(
                    list(operation(value, max_value_units=4)["values"]), [1, 2]
                )
                with self.assertRaisesRegex(IngestionError, "maximum value unit count"):
                    operation(value, max_value_units=3)
                value = {"groups": [list(range(1_024)) for _ in range(5)]}
                with self.assertRaisesRegex(IngestionError, "maximum value unit count"):
                    operation(value)
                self.assertEqual(
                    len(operation(value, max_value_units=16_384)["groups"]), 5
                )

    def test_limits_preserve_all_existing_positional_arguments_and_default(self):
        artifacts = ArtifactLimits()
        original_names = (
            "max_located_inputs",
            "max_parsed_outputs",
            "max_total_outputs",
            "max_decoder_outputs",
            "max_diagnostics",
            "max_evidence_items",
            "max_subject_references",
            "max_event_links",
            "max_total_value_units",
            "max_total_text_bytes",
            "max_evidence_per_output",
            "max_subjects_per_event",
            "max_event_links_per_record",
            "artifact_limits",
            "max_preflight_records",
            "max_preflight_bytes",
        )
        original_values = (*range(1, 14), artifacts, 15, 16)
        limits = IngestionLimits(*original_values)
        self.assertEqual(
            tuple(getattr(limits, name) for name in original_names), original_values
        )
        self.assertEqual(limits.max_output_value_units, 4_096)
        self.assertEqual(IngestionLimits().max_output_value_units, 4_096)
        self.assertEqual(
            IngestionLimits(max_output_value_units=65_536).max_output_value_units,
            65_536,
        )
        for value in (0, -1, True, 1.5, "16384", None, 65_537):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "max_output_value_units"),
            ):
                IngestionLimits(max_output_value_units=value)

    def test_larger_quota_keeps_depth_container_cycle_and_atom_protections(self):
        deep = 0
        for _ in range(17):
            deep = {"nested": deep}
        cycle = {}
        cycle["self"] = cycle
        cases = (
            ({"deep": deep}, "maximum value depth"),
            (
                {str(index): 0 for index in range(1_025)},
                "mapping exceeds the item limit",
            ),
            ({"items": [0] * 1_025}, "sequence exceeds the item limit"),
            (cycle, "reference cycle"),
            ({"text": "x" * 65_537}, "oversized string"),
            ({"number": 1 << 4_096}, "oversized integer"),
        )
        for values, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(IngestionError, message),
            ):
                self.ingest(
                    AttributeOutputPlugin(values),
                    limits=IngestionLimits(max_output_value_units=65_536),
                )
        for operation in (_json_value, _snapshot_parser_output_value):
            for values, message in cases[:4]:
                with (
                    self.subTest(operation=operation.__name__, message=message),
                    self.assertRaisesRegex(IngestionError, message),
                ):
                    operation(values, max_value_units=65_536)

    def test_larger_quota_keeps_typed_property_validation(self):
        plugin = CounterSamplesPlugin()
        plugin.samples.append({"time": 1_023, "received": 2_046, "sent": 3_069})
        with self.assertRaisesRegex(IngestionError, "structural validation budget"):
            self.ingest(plugin, limits=IngestionLimits(max_output_value_units=16_384))
        plugin.samples.pop()
        plugin.samples[0]["sent"] = True
        with self.assertRaisesRegex(IngestionError, "requires integer"):
            self.ingest(plugin, limits=IngestionLimits(max_output_value_units=16_384))

    def test_larger_quota_keeps_aggregate_protections(self):
        cases = (
            (
                {"groups": [list(range(1_024)) for _ in range(5)]},
                {"max_total_value_units": 8_000},
                "aggregate value-unit",
            ),
            (
                {"text": "x" * 30_000},
                {"max_total_text_bytes": 40_000},
                "aggregate text-byte",
            ),
            ({}, {"max_evidence_items": 1}, "evidence references"),
            ({}, {"max_total_outputs": 2}, "aggregate output"),
        )
        for values, bounds, message in cases:
            with (
                self.subTest(bounds=bounds),
                self.assertRaisesRegex(IngestionError, message),
            ):
                self.ingest(
                    AttributeOutputPlugin(values, copies=2),
                    limits=IngestionLimits(
                        max_output_value_units=16_384,
                        **bounds,
                    ),
                )

    def test_different_host_limits_are_isolated_across_concurrent_packages(self):
        plugin = CounterSamplesPlugin()

        def run(limit):
            try:
                result = self.ingest(
                    plugin, limits=IngestionLimits(max_output_value_units=limit)
                )
                return len(result.snapshots[0].state.set_values["samples"])
            except IngestionError as error:
                self.assertIn("maximum value unit count", str(error))
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(
                list(pool.map(run, (4_096, 16_384, 16_384, 4_096))),
                ["rejected", 1_023, 1_023, "rejected"],
            )

    def test_large_discovery_decoder_preflight_and_source_values_share_host_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "status.txt").write_text("v1", encoding="utf-8")
            (root / "trace.ctf").write_text(
                json.dumps(
                    [
                        {
                            "versions": ["v1"],
                            "groups": [list(range(1_024)) for _ in range(5)],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            plugin, decoder = LargePackagePlugin(), SyntheticDecoder()
            result = IngestionCoordinator(
                limits=IngestionLimits(
                    max_output_value_units=16_384,
                ),
                trace_decoder=decoder,
            ).ingest(plugin, root)
            self.assertEqual((decoder.calls, decoder.closed), (1, 1))
            self.assertIs(plugin.contexts[0][1], plugin.contexts[1][1])
            groups = plugin.contexts[0][1].values["groups"]
            self.assertEqual(groups[4][-1], 1_023)
            with self.assertRaises(TypeError):
                groups[0][0] = -1
            self.assertEqual(result.source_records[-1].attributes["groups"], groups)
            source_row = next(
                row
                for row in result.dataset["source_records"]
                if "groups" in row["attributes"]
            )
            self.assertEqual(source_row["attributes"]["groups"][4][-1], 1_023)
            with self.assertRaisesRegex(IngestionError, "byte replay limit"):
                IngestionCoordinator(
                    limits=IngestionLimits(
                        max_output_value_units=16_384,
                        max_preflight_bytes=100,
                    ),
                    trace_decoder=SyntheticDecoder(),
                ).ingest(LargePackagePlugin(), root)


if __name__ == "__main__":
    unittest.main()
