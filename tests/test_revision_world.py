from __future__ import annotations

import unittest
from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType
from typing import cast
from uuid import UUID

from router_dump_analyzer.plugin_api import (
    CaptureRange,
    Evidence,
    PropertyPatch,
    Provenance,
    Quality,
    RelationDirection,
    RelationshipObservation,
    ResourceKey,
    SnapshotObservation,
    StatusPerspectiveRef,
    UnknownField,
    Value,
    WorldBasis,
    WorldBasisKind,
)
from router_dump_analyzer.revision_world import IngestionRevisionWorld

ARTIFACT = UUID("00000000-0000-0000-0000-000000000001")
PERSPECTIVE = StatusPerspectiveRef("test.observed")


def _resource(
    identifier: str,
    *,
    layer: str = "control",
    kind: str = "item",
) -> ResourceKey:
    return ResourceKey(
        namespace="test.plugin",
        node="node-a",
        layer=layer,
        kind=kind,
        parts=(("id", identifier),),
    )


def _evidence(locator: str, timestamp_ns: int) -> Evidence:
    return Evidence(
        artifact_id=ARTIFACT,
        locator=locator,
        raw_timestamp_ns=timestamp_ns,
        clock_domain="node-a-clock",
    )


def _snapshot(
    resource: ResourceKey,
    timestamp_ns: int | None,
    patch: PropertyPatch,
    *,
    locator: str,
    quality: Quality = Quality.EXACT,
    provenance: Provenance = Provenance.OBSERVED,
    perspective_ref: StatusPerspectiveRef | None = PERSPECTIVE,
) -> SnapshotObservation:
    raw_timestamp = timestamp_ns if timestamp_ns is not None else 0
    return SnapshotObservation(
        resource=resource,
        observed_at_min_ns=timestamp_ns,
        observed_at_max_ns=timestamp_ns,
        state=patch,
        provenance=provenance,
        quality=quality,
        evidence=_evidence(locator, raw_timestamp),
        perspective_ref=perspective_ref,
    )


def _relationship(
    source: ResourceKey,
    target: ResourceKey,
    relation_type: str,
    timestamp_ns: int,
    present: bool | None,
    patch: PropertyPatch,
    *,
    locator: str,
    quality: Quality = Quality.EXACT,
) -> RelationshipObservation:
    return RelationshipObservation(
        source=source,
        target=target,
        relation_type=relation_type,
        observed_at_min_ns=timestamp_ns,
        observed_at_max_ns=timestamp_ns,
        present=present,
        attributes=patch,
        provenance=Provenance.OBSERVED,
        quality=quality,
        evidence=_evidence(locator, timestamp_ns),
        perspective_ref=PERSPECTIVE,
    )


def _basis() -> WorldBasis:
    return WorldBasis(
        kind=WorldBasisKind.OBSERVED_CAPTURE_VECTOR,
        requested_time_ns=None,
        resolved_at_min_ns=None,
        resolved_at_max_ns=None,
        capture_ranges=(
            CaptureRange(
                scope="resource:a",
                observed_at_min_ns=10,
                observed_at_max_ns=10,
                evidence=(_evidence("a", 10),),
                clock_domain="node-a-clock",
            ),
            CaptureRange(
                scope="resource:b",
                observed_at_min_ns=25,
                observed_at_max_ns=30,
                evidence=(_evidence("b", 25),),
                clock_domain="node-a-clock",
            ),
        ),
        provenance=Provenance.OBSERVED,
        quality=Quality.BEST_EFFORT,
    )


class IngestionRevisionWorldTests(unittest.TestCase):
    def test_reconstructs_latest_patched_states_in_ingestion_order(self) -> None:
        resource_a = _resource("a")
        resource_b = _resource("b", kind="other")
        stale_unknown = UnknownField(
            name="stale_unknown",
            reason_code="not-captured",
            message="not captured",
        )
        latest_unknown = UnknownField(
            name="retained",
            reason_code="ambiguous",
            message="two values observed",
            evidence=(_evidence("unknown", 20),),
        )
        early = _snapshot(
            resource_a,
            10,
            PropertyPatch(
                set_values={
                    "retained": "old",
                    "removed": 1,
                    "nested": {"path": ("a", "b")},
                },
                unknown_fields=(stale_unknown,),
                complete=True,
            ),
            locator="early",
        )
        late = _snapshot(
            resource_a,
            20,
            PropertyPatch(
                set_values={"status": "ready"},
                remove_fields=("removed",),
                unknown_fields=(latest_unknown,),
                field_quality={"status": Quality.AMBIGUOUS},
            ),
            locator="late",
            quality=Quality.BEST_EFFORT,
            provenance=Provenance.RECONSTRUCTED,
        )
        other = _snapshot(
            resource_b,
            15,
            PropertyPatch(set_values={"value": 2}, complete=True),
            locator="other",
        )

        # Intentionally pass observations out of temporal and resource order.
        basis = _basis()
        world = IngestionRevisionWorld(
            basis=basis,
            snapshots=(late, other, early),
            relationship_observations=(),
        )

        self.assertIs(world.basis, basis)
        self.assertIsNone(world.perspective_ref)
        state = world.state_of(resource_a)
        assert state is not None
        self.assertTrue(state.exists)
        self.assertEqual(
            dict(state.properties),
            {"nested": MappingProxyType({"path": ("a", "b")}), "status": "ready"},
        )
        self.assertEqual(
            [field.name for field in state.unknown_fields],
            ["stale_unknown", "retained"],
        )
        self.assertEqual(state.field_quality["status"], Quality.AMBIGUOUS)
        self.assertEqual(
            state.field_quality["stale_unknown"],
            Quality.EXACT,
        )
        self.assertEqual(state.provenance, Provenance.RECONSTRUCTED)
        self.assertEqual(state.quality, Quality.BEST_EFFORT)
        self.assertEqual(state.valid_from_ns, 20)
        self.assertIsNone(state.valid_to_ns)
        self.assertEqual(state.observed_at_min_ns, 20)
        self.assertEqual(state.observed_at_max_ns, 20)
        self.assertEqual(state.evidence, (late.evidence,))
        self.assertEqual(state.perspective_ref, PERSPECTIVE)

        self.assertEqual(
            [item.resource for item in world.iter_states()],
            [resource_a, resource_b],
        )
        self.assertEqual(
            tuple(world.iter_states(kinds=frozenset({"other"}))),
            (world.state_of(resource_b),),
        )
        self.assertEqual(
            tuple(world.iter_states(layers=frozenset({"missing"}))),
            (),
        )

    def test_complete_patch_and_equal_time_stable_order_match_ingestion(self) -> None:
        resource = _resource("same-time")
        evidence = _evidence("same", 10)
        first = SnapshotObservation(
            resource=resource,
            observed_at_min_ns=10,
            observed_at_max_ns=10,
            state=PropertyPatch(set_values={"winner": "first"}, complete=True),
            provenance=Provenance.OBSERVED,
            quality=Quality.EXACT,
            evidence=evidence,
        )
        second = replace(
            first,
            state=PropertyPatch(set_values={"winner": "second"}, complete=True),
        )
        world = IngestionRevisionWorld(
            basis=_basis(),
            snapshots=(first, second),
            relationship_observations=(),
        )
        state = world.state_of(resource)
        assert state is not None
        self.assertEqual(state.properties["winner"], "second")

    def test_resource_scan_uses_persisted_canonical_identity_order(self) -> None:
        resources = {name: _resource(name) for name in ("a", "b", "c", "d")}
        world = IngestionRevisionWorld(
            basis=_basis(),
            snapshots=tuple(
                _snapshot(
                    resource,
                    10,
                    PropertyPatch(set_values={"id": name}, complete=True),
                    locator=name,
                )
                for name, resource in resources.items()
            ),
            relationship_observations=(),
        )
        # This is the canonical hashed-resource-ID order produced by
        # ingestion._resource_identity(), not lexical ResourceKey order.
        self.assertEqual(
            [state.resource for state in world.iter_states()],
            [resources[name] for name in ("d", "b", "a", "c")],
        )

    def test_relationship_indexes_filters_and_presence_are_exact(self) -> None:
        resource_a = _resource("a", layer="control")
        resource_b = _resource("b", layer="data")
        relationship_only = _resource("c", layer="hardware")
        initial = _relationship(
            resource_a,
            resource_b,
            "depends_on",
            10,
            True,
            PropertyPatch(
                set_values={"interface": "eth0", "metric": 10},
                complete=True,
            ),
            locator="initial",
        )
        removed = _relationship(
            resource_a,
            resource_b,
            "depends_on",
            20,
            False,
            PropertyPatch(),
            locator="removed",
        )
        restored = _relationship(
            resource_a,
            resource_b,
            "depends_on",
            30,
            True,
            PropertyPatch(set_values={"metric": 20}),
            locator="restored",
            quality=Quality.BEST_EFFORT,
        )
        second = _relationship(
            resource_b,
            relationship_only,
            "uses",
            30,
            True,
            PropertyPatch(set_values={"slot": 2}, complete=True),
            locator="second",
        )
        unknown_latest = _relationship(
            relationship_only,
            resource_a,
            "uncertain",
            40,
            None,
            PropertyPatch(),
            locator="uncertain",
        )
        self_loop = _relationship(
            resource_b,
            resource_b,
            "self",
            40,
            True,
            PropertyPatch(),
            locator="self",
        )
        world = IngestionRevisionWorld(
            basis=_basis(),
            snapshots=(),
            relationship_observations=(
                restored,
                unknown_latest,
                initial,
                second,
                removed,
                self_loop,
            ),
        )

        relationships = tuple(world.iter_relationships())
        self.assertEqual(
            [(item.source, item.target, item.relation_type) for item in relationships],
            [
                (resource_a, resource_b, "depends_on"),
                (resource_b, resource_b, "self"),
                (resource_b, relationship_only, "uses"),
            ],
        )
        first = relationships[0]
        self.assertEqual(
            dict(first.attributes),
            {"interface": "eth0", "metric": 20},
        )
        self.assertEqual(first.valid_from_ns, 30)
        self.assertEqual(first.quality, Quality.BEST_EFFORT)
        self.assertEqual(first.evidence, (restored.evidence,))
        self.assertEqual(first.perspective_ref, PERSPECTIVE)

        # Relationship endpoints never acquire fabricated resource state.
        self.assertIsNone(world.state_of(relationship_only))
        self.assertEqual(
            [item.relation_type for item in world.related(resource_a)],
            ["depends_on"],
        )
        self.assertEqual(
            [
                item.relation_type
                for item in world.related(
                    resource_b,
                    direction=RelationDirection.INCOMING,
                )
            ],
            ["depends_on", "self"],
        )
        self.assertEqual(
            [
                item.relation_type
                for item in world.related(
                    resource_b,
                    direction=RelationDirection.BOTH,
                )
            ],
            ["depends_on", "self", "uses"],
        )
        self.assertEqual(
            [
                item.relation_type
                for item in world.related(
                    resource_b,
                    direction=RelationDirection.BOTH,
                    relation_types=frozenset({"uses"}),
                )
            ],
            ["uses"],
        )
        self.assertEqual(
            [
                item.relation_type
                for item in world.iter_relationships(layers=frozenset({"hardware"}))
            ],
            ["uses"],
        )
        self.assertEqual(
            [
                item.relation_type
                for item in world.iter_relationships(
                    relation_types=frozenset({"depends_on"})
                )
            ],
            ["depends_on"],
        )

    def test_values_are_detached_and_deeply_immutable(self) -> None:
        resource = _resource("immutable")
        nested: dict[str, Value] = {"members": ("one", "two")}
        values: dict[str, Value] = {"nested": nested}
        world = IngestionRevisionWorld(
            basis=_basis(),
            snapshots=(
                _snapshot(
                    resource,
                    10,
                    PropertyPatch(set_values=values, complete=True),
                    locator="immutable",
                ),
            ),
            relationship_observations=(),
        )
        nested["members"] = ("changed",)
        values["added"] = True

        state = world.state_of(resource)
        assert state is not None
        frozen_nested = cast(Mapping[str, Value], state.properties["nested"])
        self.assertEqual(frozen_nested["members"], ("one", "two"))
        self.assertNotIn("added", state.properties)
        with self.assertRaises(TypeError):
            state.properties["new"] = "value"  # type: ignore[index]
        with self.assertRaises(TypeError):
            frozen_nested["members"] = ()  # type: ignore[index]

    def test_capture_vector_is_preserved_without_synthetic_timestamp(self) -> None:
        basis = _basis()
        world = IngestionRevisionWorld(
            basis=basis,
            snapshots=(),
            relationship_observations=(),
            perspective_ref=PERSPECTIVE,
        )
        self.assertIs(world.basis, basis)
        self.assertEqual(world.basis.kind, WorldBasisKind.OBSERVED_CAPTURE_VECTOR)
        self.assertIsNone(world.basis.requested_time_ns)
        self.assertIsNone(world.basis.resolved_at_min_ns)
        self.assertIsNone(world.basis.resolved_at_max_ns)
        self.assertEqual(world.basis.capture_ranges, basis.capture_ranges)
        self.assertEqual(world.perspective_ref, PERSPECTIVE)

    def test_only_caller_limits_reads_and_limit_validation_is_exact(self) -> None:
        snapshots = tuple(
            _snapshot(
                _resource(f"item-{index:04d}"),
                index,
                PropertyPatch(set_values={"index": index}, complete=True),
                locator=f"item:{index}",
            )
            for index in range(257)
        )
        world = IngestionRevisionWorld(
            basis=_basis(),
            snapshots=snapshots,
            relationship_observations=(),
        )
        self.assertEqual(len(tuple(world.iter_states())), 257)
        self.assertEqual(len(tuple(world.iter_states(limit=256))), 256)
        self.assertEqual(tuple(world.iter_states(limit=0)), ())
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            tuple(world.iter_states(limit=-1))
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            tuple(world.iter_relationships(limit=True))
        with self.assertRaisesRegex(ValueError, "unsupported relationship direction"):
            tuple(world.related(_resource("item-0000"), direction="sideways"))  # type: ignore[arg-type]

    def test_constructor_rejects_untyped_values(self) -> None:
        with self.assertRaisesRegex(TypeError, "exact WorldBasis"):
            IngestionRevisionWorld(
                basis=cast(WorldBasis, object()),
                snapshots=(),
                relationship_observations=(),
            )
        with self.assertRaisesRegex(TypeError, "SnapshotObservation"):
            IngestionRevisionWorld(
                basis=_basis(),
                snapshots=cast(tuple[SnapshotObservation, ...], (object(),)),
                relationship_observations=(),
            )
        with self.assertRaisesRegex(TypeError, "RelationshipObservation"):
            IngestionRevisionWorld(
                basis=_basis(),
                snapshots=(),
                relationship_observations=cast(
                    tuple[RelationshipObservation, ...],
                    (object(),),
                ),
            )


if __name__ == "__main__":
    unittest.main()
