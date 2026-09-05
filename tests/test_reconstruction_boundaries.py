from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from router_dump_analyzer.capability_executor import (
    PluginCapabilityOutputError,
    _BoundedWorld,
)
from router_dump_analyzer.consistency_materialization import (
    ConsistencyMaterializationError,
)
from router_dump_analyzer.consistency_materialization import (
    _AggregateWorld as ConsistencyWorld,
)
from router_dump_analyzer.ingestion import (
    IngestionCoordinator,
    IngestionResult,
    _bind_primary_ingestion_perspectives,
    _build_dataset,
)
from router_dump_analyzer.ingestion_pipeline import (
    PluginRegistry,
    _dataset_with_execution_plan,
    _snapshot_coordinator_result,
)
from router_dump_analyzer.plugin_api import (
    DumpInventory,
    PluginCapability,
    PluginSchema,
    PropertyPatch,
    Quality,
    RelationshipTypeDescriptor,
    ResourceKindDescriptor,
    SnapshotObservation,
    StatusPerspectiveRef,
    TimelineTimeBasis,
)
from router_dump_analyzer.plugin_execution_plan import PluginExecutionPlanAuthority
from router_dump_analyzer.plugin_schema_identity import plugin_schema_digest
from router_dump_analyzer.relationship_projection_materialization import (
    RelationshipProjectionMaterializationError,
)
from router_dump_analyzer.relationship_projection_materialization import (
    _AggregateWorld as RelationshipWorld,
)
from router_dump_analyzer.revision_world import IngestionRevisionWorld
from tests.support.normalized_data import static_data_service
from tests.test_ingestion import RichObservationPlugin
from tests.test_revision_world import _basis, _relationship, _resource, _snapshot

_MIXED_SCHEMA_DIGEST = plugin_schema_digest(RichObservationPlugin().describe())


class _MixedQualificationPlugin(RichObservationPlugin):
    def parse_status(self, reader, spec):
        for output in super().parse_status(reader, spec):
            if not isinstance(output, SnapshotObservation):
                yield output
                continue
            yield replace(
                output,
                state=PropertyPatch(set_values={"name": "eth0"}),
            )
            yield replace(
                output,
                observed_at_min_ns=output.observed_at_min_ns + 1,
                observed_at_max_ns=output.observed_at_max_ns + 1,
                state=PropertyPatch(set_values={"oper_status": "up"}),
                perspective_ref=StatusPerspectiveRef(
                    "interface-observed", "primary", _MIXED_SCHEMA_DIGEST
                ),
            )
            return


def _dataset(
    *, snapshots=(), relationships=(), directed=True, schema=None, **authority
):
    return _build_dataset(
        plugin_id="test.plugin",
        inventory=DumpInventory(None, ()),
        schema=schema
        or PluginSchema(
            # These fixtures intentionally use their opaque id as public
            # presentation/search text; declare it before label generation.
            resource_kinds=(
                ResourceKindDescriptor("item", "Item", ("id",), ()),
                ResourceKindDescriptor("group", "Group", ("id",), ()),
            ),
            relationship_types=(
                RelationshipTypeDescriptor("link", "Link", directed, True),
            ),
        ),
        revision_id="revision",
        node_id="node-a",
        snapshots=snapshots,
        relationship_observations=relationships,
        relationship_collections=(),
        events=(),
        source_records=(),
        diagnostics=(),
        timeline_time_basis=TimelineTimeBasis.ABSOLUTE_UNIX_NS,
        timeline_clock_domain=None,
        **authority,
    )


class ReconstructionBoundaryTests(unittest.TestCase):
    def test_named_tables_keep_ambiguous_children_in_search_and_indexed_history(self):
        parent = _resource("parent", kind="group")
        child = _resource("ambiguous-child")
        dataset = _dataset(
            snapshots=(
                _snapshot(parent, 10, PropertyPatch(), locator="parent"),
                _snapshot(
                    child,
                    10,
                    PropertyPatch(set_values={"x": 1}),
                    locator="p",
                    perspective_ref=StatusPerspectiveRef("p"),
                ),
                _snapshot(
                    child,
                    20,
                    PropertyPatch(set_values={"x": 2}),
                    locator="q",
                    perspective_ref=StatusPerspectiveRef("q"),
                ),
            ),
            relationships=(
                _relationship(
                    parent, child, "link", 10, True, PropertyPatch(), locator="link"
                ),
            ),
        )
        dataset["kind_descriptors"] = [
            {"kind": "item", "key_fields": ["id"], "properties": [{"name": "x"}]},
            {"kind": "group", "key_fields": ["id"], "properties": []},
        ]
        dataset["resource_table_view_descriptors"] = [
            {
                "view_id": "tree",
                "root_kinds": ["group"],
                "include_absent": False,
                "levels": [{"relation_types": ["link"], "target_kinds": ["item"]}],
            }
        ]
        resource_by_id = {item["resource_id"]: item for item in dataset["resources"]}
        runtime = SimpleNamespace(
            resource_by_id=resource_by_id,
            resource_counts={"group": 1, "item": 1},
            resources_by_kind={
                kind: [item for item in dataset["resources"] if item["kind"] == kind]
                for kind in ("group", "item")
            },
            lifecycle_by_resource={
                identifier: [
                    item
                    for item in dataset["lifecycle_intervals"]
                    if item["resource"] == identifier
                ]
                for identifier in resource_by_id
            },
            state_by_resource={
                identifier: [
                    item
                    for item in dataset["state_intervals"]
                    if item["resource"] == identifier
                ]
                for identifier in resource_by_id
            },
            relationships_by_endpoint={
                identifier: [
                    item
                    for item in dataset["relationship_intervals"]
                    if identifier in (item["source"], item["target"])
                ]
                for identifier in resource_by_id
            },
        )
        for history in (None, runtime):
            dataset["_scale_runtime"] = history
            service = static_data_service(dataset)
            for search in (None, "ambiguous-child"):
                with self.subTest(indexed=history is not None, search=search):
                    result = service.resources_at(30, view_id="tree", search=search)
                    self.assertEqual(len(result["bundles"]), 1)
                    children = result["bundles"][0]["children"]
                    self.assertEqual(len(children), 1)
                    self.assertIsNone(children[0]["resource"]["exists"])
                    self.assertEqual(children[0]["resource"]["quality"], "ambiguous")

    def test_publication_binds_perspectives_after_validating_unplanned_result(self):
        plugin = _MixedQualificationPlugin()
        coordinator = IngestionCoordinator()
        registered = PluginRegistry().register(
            plugin, coordinator=coordinator, instance_id="primary"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_bytes(
                json.dumps(
                    {
                        "captured_at_ns": 10,
                        "ifindex": 1,
                        "name": "eth0",
                        "oper_status": "up",
                    }
                ).encode("utf-8")
                + b"\n"
            )
            unplanned = coordinator.ingest(plugin, path)
            self.assertEqual(unplanned.dataset["resources"][0]["state"], {})
            self.assertIsNone(unplanned.snapshots[0].perspective_ref.plugin_instance_id)
            validated = _snapshot_coordinator_result(
                unplanned, registered=registered, expected_node_id=unplanned.node_id
            )
            dataset_bytes, plan = _dataset_with_execution_plan(
                registered,
                validated,
                execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
            )
        planned = json.loads(dataset_bytes)
        self.assertEqual(
            planned["resources"][0]["state"], {"name": "eth0", "oper_status": "up"}
        )
        self.assertEqual(
            [item["valid_to_ns"] for item in planned["state_intervals"]], ["11", None]
        )
        self.assertEqual(
            planned["_ingestion"]["plugin_execution_plan_digest"], plan.plan_digest
        )
        self.assertTrue(
            all(
                item["perspective_ref"]["plugin_instance_id"] == "primary"
                and item["perspective_ref"]["schema_digest"]
                == plugin_schema_digest(plugin.describe())
                for item in planned["state_intervals"]
            )
        )
        view = static_data_service(planned).resource_state_at(
            planned["resources"][0]["resource_id"], 20
        )
        self.assertTrue(view["exists"])
        self.assertEqual(view["quality"], "exact")
        self.assertEqual(view["state"], {"name": "eth0", "oper_status": "up"})

    def test_real_resource_reads_and_tables_keep_overlapping_perspectives_unknown(self):
        resource = _resource("read-perspectives")
        snapshots = tuple(
            _snapshot(
                resource,
                timestamp,
                PropertyPatch(set_values={"x": value}),
                locator=perspective,
                perspective_ref=StatusPerspectiveRef(perspective),
            )
            for timestamp, value, perspective in (
                (10, "intended", "p"),
                (20, "actual", "q"),
            )
        )
        dataset = _dataset(snapshots=snapshots)
        dataset["kind_descriptors"] = [
            {"kind": "item", "key_fields": ["id"], "properties": [{"name": "x"}]}
        ]
        dataset["resource_table_view_descriptors"] = [
            {
                "view_id": "items",
                "root_kinds": ["item"],
                "include_absent": False,
                "levels": [],
            }
        ]
        identifier = dataset["resources"][0]["resource_id"]
        service = static_data_service(dataset)
        for view in (
            service.resource_state_at(identifier, 30),
            service.resources_at(30)["items"][0],
            service.resources_at(30, view_id="items")["items"][0],
            service.resources_at(30, view_id="items", search="read-perspectives")[
                "items"
            ][0],
        ):
            self.assertIsNone(view["exists"])
            self.assertEqual(view["quality"], "ambiguous")
            self.assertEqual(view["status"], "unknown")
            self.assertEqual(view["status_class"], "unknown")
            self.assertEqual(view["state"], {})
            self.assertEqual(view["resource"]["state"], {})
        self.assertEqual(
            service.resource_state_at(identifier, 15)["state"], {"x": "intended"}
        )
        # Multiple intervals within one perspective still select its latest state.
        dataset["state_intervals"][1]["perspective_ref"] = dataset["state_intervals"][
            0
        ]["perspective_ref"]
        self.assertEqual(
            service.resource_state_at(identifier, 30)["state"], {"x": "actual"}
        )

    def test_primary_binding_merges_local_and_qualified_histories_before_projection(
        self,
    ):
        resource = _resource("bound-perspective")
        schema = PluginSchema(resource_kinds=(), relationship_types=())
        digest = plugin_schema_digest(schema)
        qualified = StatusPerspectiveRef("p", "primary", digest)
        snapshots = (
            _snapshot(
                resource,
                10,
                PropertyPatch(set_values={"x": 1}),
                locator="local",
                perspective_ref=StatusPerspectiveRef("p"),
            ),
            _snapshot(
                resource,
                20,
                PropertyPatch(set_values={"y": 2}),
                locator="qualified",
                perspective_ref=qualified,
            ),
        )
        unplanned = _dataset(snapshots=snapshots, schema=schema)
        self.assertEqual(unplanned["resources"][0]["state"], {})
        authority = {
            "primary_plugin_instance_id": "primary",
            "primary_schema_digest": digest,
        }
        planned = _dataset(snapshots=snapshots, schema=schema, **authority)
        world = IngestionRevisionWorld(
            basis=_basis(),
            snapshots=snapshots,
            relationship_observations=(),
            **authority,
        )
        self.assertEqual(
            planned["resources"][0]["state"], dict(world.state_of(resource).properties)
        )
        self.assertEqual(planned["resources"][0]["state"], {"x": 1, "y": 2})
        self.assertEqual(
            [item["valid_to_ns"] for item in planned["state_intervals"]], ["20", None]
        )
        self.assertTrue(
            all(
                item["perspective_ref"]["plugin_instance_id"] == "primary"
                for item in planned["state_intervals"]
            )
        )
        result = IngestionResult(
            inventory=DumpInventory(None, ()),
            schema=schema,
            revision_id="revision",
            node_id="node-a",
            dataset={**unplanned, "extra_field": {"retained": True}},
            diagnostics=(),
            snapshots=snapshots,
            relationship_observations=(),
            relationship_collections=(),
            events=(),
            source_records=(),
        )
        bound_result = _bind_primary_ingestion_perspectives(
            result,
            plugin_id="test.plugin",
            timeline_time_basis=TimelineTimeBasis.ABSOLUTE_UNIX_NS,
            timeline_clock_domain=None,
            **authority,
        )
        self.assertEqual(bound_result.dataset["extra_field"], {"retained": True})
        self.assertEqual(bound_result.dataset["resources"], planned["resources"])
        self.assertTrue(
            all(item.perspective_ref == qualified for item in bound_result.snapshots)
        )
        self.assertEqual(result.snapshots[0].perspective_ref, StatusPerspectiveRef("p"))

    def test_unknown_and_ambiguous_world_views_are_deeply_immutable(self):
        resource = _resource("immutable-unknown")
        snapshots = tuple(
            _snapshot(
                resource,
                10,
                PropertyPatch(),
                locator=name,
                perspective_ref=StatusPerspectiveRef(name),
            )
            for name in ("p", "q")
        )
        for selected in (None, StatusPerspectiveRef("missing")):
            world = IngestionRevisionWorld(
                basis=_basis(),
                snapshots=snapshots,
                relationship_observations=(),
                perspective_ref=selected,
            )
            state = world.state_of(resource)
            for mapping in (state.properties, state.field_quality):
                with self.assertRaises(TypeError):
                    mapping["injected"] = Quality.EXACT
            self.assertEqual(dict(world.state_of(resource).field_quality), {})
            self.assertEqual(state.evidence, ())

    def test_snapshot_perspectives_have_independent_patches_and_open_intervals(self):
        resource = _resource("perspectives")
        p, q = StatusPerspectiveRef("p"), StatusPerspectiveRef("q")
        snapshots = (
            _snapshot(
                resource,
                10,
                PropertyPatch(set_values={"intended": "yes"}),
                locator="p1",
                perspective_ref=p,
            ),
            _snapshot(
                resource,
                20,
                PropertyPatch(set_values={"actual": "no"}),
                locator="q1",
                perspective_ref=q,
            ),
            _snapshot(
                resource,
                30,
                PropertyPatch(set_values={"intended": "changed"}),
                locator="p2",
                perspective_ref=p,
            ),
        )
        dataset = _dataset(snapshots=snapshots)
        intervals = dataset["state_intervals"]
        p_intervals = [
            item
            for item in intervals
            if item["perspective_ref"]["perspective_id"] == "p"
        ]
        q_intervals = [
            item
            for item in intervals
            if item["perspective_ref"]["perspective_id"] == "q"
        ]
        self.assertEqual([item["valid_to_ns"] for item in p_intervals], ["30", None])
        self.assertEqual(q_intervals[0]["valid_to_ns"], None)
        self.assertEqual(q_intervals[0]["properties"], {"actual": "no"})
        self.assertEqual(p_intervals[-1]["properties"], {"intended": "changed"})
        self.assertEqual(dataset["resources"][0]["state"], {})
        self.assertEqual(dataset["resources"][0]["status_class"], "unknown")

        world = IngestionRevisionWorld(
            basis=_basis(), snapshots=snapshots, relationship_observations=()
        )
        self.assertEqual(len(tuple(world.iter_states())), 2)
        ambiguous = world.state_of(resource)
        self.assertIsNotNone(ambiguous)
        self.assertIsNone(ambiguous.exists)
        self.assertEqual(ambiguous.quality, Quality.AMBIGUOUS)
        self.assertEqual(dict(ambiguous.properties), {})
        selected = IngestionRevisionWorld(
            basis=_basis(),
            snapshots=snapshots,
            relationship_observations=(),
            perspective_ref=p,
        )
        self.assertEqual(
            dict(selected.state_of(resource).properties), {"intended": "changed"}
        )
        self.assertEqual(selected.state_of(resource).perspective_ref, p)
        missing = IngestionRevisionWorld(
            basis=_basis(),
            snapshots=snapshots,
            relationship_observations=(),
            perspective_ref=StatusPerspectiveRef("missing"),
        )
        self.assertIsNone(missing.state_of(resource).exists)
        self.assertEqual(missing.state_of(resource).quality, Quality.UNKNOWN)
        self.assertEqual(dict(missing.state_of(resource).properties), {})

    def test_relationship_perspective_tombstone_does_not_remove_another_view(self):
        a, b = _resource("a"), _resource("b")
        p, q = StatusPerspectiveRef("p"), StatusPerspectiveRef("q")
        relationships = (
            _relationship(
                a,
                b,
                "link",
                10,
                True,
                PropertyPatch(set_values={"p": 1}),
                locator="p",
                perspective_ref=p,
            ),
            _relationship(
                a, b, "link", 20, False, PropertyPatch(), locator="q", perspective_ref=q
            ),
        )
        dataset = _dataset(relationships=relationships)
        self.assertEqual(len(dataset["relationships"]), 1)
        self.assertEqual(
            dataset["relationships"][0]["perspective_ref"]["perspective_id"], "p"
        )
        self.assertTrue(
            all(
                item["valid_to_ns"] is None
                for item in dataset["relationship_intervals"]
            )
        )
        for perspective, count in ((None, 1), (p, 1), (q, 0)):
            world = IngestionRevisionWorld(
                basis=_basis(),
                snapshots=(),
                relationship_observations=relationships,
                perspective_ref=perspective,
            )
            self.assertEqual(len(tuple(world.iter_relationships())), count)

    def test_undirected_reversed_tombstone_matches_world_without_rekeying_resources(
        self,
    ):
        a, b = _resource("a"), _resource("b")
        first = _relationship(a, b, "link", 10, True, PropertyPatch(), locator="add")
        second = _relationship(
            b, a, "link", 20, False, PropertyPatch(), locator="remove"
        )
        for directed, expected_count in ((True, 1), (False, 0)):
            dataset = _dataset(relationships=(first, second), directed=directed)
            world = IngestionRevisionWorld(
                basis=_basis(),
                snapshots=(),
                relationship_observations=(first, second),
                undirected_relationship_types=frozenset()
                if directed
                else frozenset({"link"}),
            )
            self.assertEqual(len(dataset["relationships"]), expected_count)
            self.assertEqual(len(tuple(world.iter_relationships())), expected_count)
        identifiers = {
            item["resource_id"]
            for item in _dataset(relationships=(first,))["resources"]
        }
        self.assertEqual(
            identifiers, {item["resource_id"] for item in dataset["resources"]}
        )
        intervals = dataset["relationship_intervals"]
        self.assertEqual(
            (intervals[0]["source"], intervals[0]["target"]),
            (intervals[1]["source"], intervals[1]["target"]),
        )
        self.assertEqual(intervals[0]["valid_to_ns"], "20")

    def test_qualified_and_local_perspectives_share_primary_authority(self):
        p = StatusPerspectiveRef("p")
        snapshots = (
            _snapshot(
                _resource("a"),
                10,
                PropertyPatch(set_values={"x": 1}),
                locator="p",
                perspective_ref=p,
            ),
        )
        bound = StatusPerspectiveRef("p", "primary", "sha256:" + "a" * 64)
        world = IngestionRevisionWorld(
            basis=_basis(),
            snapshots=snapshots,
            relationship_observations=(),
            perspective_ref=bound,
            primary_plugin_instance_id="primary",
            primary_schema_digest=bound.schema_digest,
        )
        self.assertEqual(world.state_of(snapshots[0].resource).perspective_ref, bound)
        foreign = replace(
            snapshots[0],
            perspective_ref=StatusPerspectiveRef("p", "foreign", bound.schema_digest),
        )
        with self.assertRaises(ValueError):
            IngestionRevisionWorld(
                basis=_basis(),
                snapshots=(foreign,),
                relationship_observations=(),
                primary_plugin_instance_id="primary",
                primary_schema_digest=bound.schema_digest,
            )


class SharedWorldBudgetBoundaryTests(unittest.TestCase):
    def _world(self):
        return IngestionRevisionWorld(
            basis=_basis(),
            snapshots=tuple(
                _snapshot(_resource(name), 10, PropertyPatch(), locator=name)
                for name in ("a", "b")
            ),
            relationship_observations=(),
        )

    def _wrappers(self, world, maximum):
        yield _BoundedWorld(
            world,
            maximum,
            PluginCapability.CONSISTENCY_CHECK,
            basis=world.basis,
            perspective_ref=None,
            maximum_evidence=128,
        )
        yield ConsistencyWorld(
            world, basis=world.basis, perspective_ref=None, maximum_reads=maximum
        )
        yield RelationshipWorld(world, maximum, perspective_ref=None)

    def test_explicit_exact_and_zero_limits_are_pages_in_every_wrapper(self):
        for wrapper in self._wrappers(self._world(), 1):
            with self.subTest(wrapper=type(wrapper).__module__):
                self.assertEqual(len(tuple(wrapper.iter_states(limit=1))), 1)
                self.assertEqual(tuple(wrapper.iter_states(limit=0)), ())

    def test_point_read_then_exact_page_does_not_depend_on_provider_order(self):
        for wrapper in self._wrappers(self._world(), 2):
            with self.subTest(wrapper=type(wrapper).__module__):
                wrapper.state_of(_resource("a"))
                self.assertEqual(len(tuple(wrapper.iter_states(limit=1))), 1)

    def test_unbounded_or_oversized_scan_still_fails_when_truncated(self):
        errors = (
            PluginCapabilityOutputError,
            ConsistencyMaterializationError,
            RelationshipProjectionMaterializationError,
        )
        for limit in (None, 2):
            for wrapper in self._wrappers(self._world(), 1):
                with (
                    self.subTest(wrapper=type(wrapper).__module__, limit=limit),
                    self.assertRaises(errors),
                ):
                    tuple(wrapper.iter_states(limit=limit))
