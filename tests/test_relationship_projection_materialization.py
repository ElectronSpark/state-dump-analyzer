from __future__ import annotations

import unittest
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from typing import Any
from uuid import UUID

from router_dump_analyzer.canonical import (
    strict_canonical_json,
    strict_canonical_json_bytes,
)
from router_dump_analyzer.capability_router import (
    CapabilityProviderRegistry,
    PlanBoundCapabilityRouter,
)
from router_dump_analyzer.ingestion_pipeline import PluginRegistry, RegisteredPlugin
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    DiagnosticOrigin,
    DiagnosticSeverity,
    DiagnosticStage,
    Evidence,
    PluginCapability,
    PluginDiagnostic,
    PluginManifest,
    PluginSchema,
    PropertyPatch,
    Provenance,
    Quality,
    ReconstructionSupport,
    RelationshipDeclaration,
    RelationshipTypeDescriptor,
    ResourceKey,
    ResourceKindDescriptor,
    SnapshotObservation,
    StatusPerspectiveDescriptor,
    StatusPerspectiveRef,
    StatusPerspectiveRole,
    WorldBasis,
    WorldBasisKind,
)
from router_dump_analyzer.plugin_composition import (
    REVISION_RELATIONSHIP_PROJECTION_ROLE,
)
from router_dump_analyzer.plugin_execution_plan import (
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
    PluginExecutionPlanAuthority,
)
from router_dump_analyzer.plugin_schema_identity import plugin_schema_digest
from router_dump_analyzer.relationship_projection_materialization import (
    RelationshipProjectionMaterializationError,
    RelationshipProjectionMaterializationLimits,
    RelationshipProjectionMaterializationStatus,
    _resource_projection,
    _validate_patch_projection,
    materialize_revision_relationship_projection,
    revision_relationship_projection_selected_pins,
    validate_relationship_projection_dataset_fragment,
    validate_relationship_projection_storage_fragment,
)
from router_dump_analyzer.revision_world import IngestionRevisionWorld

ARTIFACT_ID = UUID("00000000-0000-0000-0000-000000000101")
SECOND_ARTIFACT_ID = UUID("00000000-0000-0000-0000-000000000102")
BASIS = WorldBasis(
    kind=WorldBasisKind.OBSERVED_CAPTURE_VECTOR,
    requested_time_ns=None,
    resolved_at_min_ns=10,
    resolved_at_max_ns=20,
    capture_ranges=(),
    provenance=Provenance.OBSERVED,
    quality=Quality.EXACT,
)
SOURCE = ResourceKey(
    namespace="test",
    node="node-a",
    layer="control",
    kind="test.item",
    parts=(("id", "source"),),
)
TARGET = ResourceKey(
    namespace="test",
    node="node-a",
    layer="hardware",
    kind="test.item",
    parts=(("id", "target"),),
)
MISSING = ResourceKey(
    namespace="test",
    node="node-a",
    layer="hardware",
    kind="test.item",
    parts=(("id", "missing"),),
)


def _rehash_record(record: dict[str, Any], identity_field: str) -> None:
    payload = dict(record)
    payload.pop(identity_field, None)
    record[identity_field] = "sha256:" + sha256(
        strict_canonical_json_bytes(payload)
    ).hexdigest()


def _schema() -> PluginSchema:
    return PluginSchema(
        resource_kinds=(
            ResourceKindDescriptor(
                kind="test.item",
                label="Test item",
                key_fields=("id",),
                properties=(),
            ),
        ),
        relationship_types=(
            RelationshipTypeDescriptor(
                relation_type="same-object",
                label="Same object",
                directed=False,
                structural=True,
            ),
        ),
        status_perspectives=(
            StatusPerspectiveDescriptor(
                perspective_id="observed",
                label="Observed",
                layer_id="control",
                role=StatusPerspectiveRole.OBSERVED,
            ),
            StatusPerspectiveDescriptor(
                perspective_id="programmed",
                label="Programmed",
                layer_id="hardware",
                role=StatusPerspectiveRole.PROGRAMMED,
            ),
        ),
    )


def _world(
    *,
    perspective_ref: StatusPerspectiveRef | None = None,
) -> IngestionRevisionWorld:
    evidence = Evidence(ARTIFACT_ID, "snapshot", 15, "clock-a")
    snapshots = tuple(
        SnapshotObservation(
            resource=resource,
            observed_at_min_ns=10,
            observed_at_max_ns=20,
            state=PropertyPatch(set_values={}, complete=True),
            provenance=Provenance.OBSERVED,
            quality=Quality.EXACT,
            evidence=evidence,
            perspective_ref=perspective_ref,
        )
        for resource in (SOURCE, TARGET)
    )
    return IngestionRevisionWorld(
        basis=BASIS,
        snapshots=snapshots,
        relationship_observations=(),
        perspective_ref=perspective_ref,
    )


def _declaration(
    *,
    source: ResourceKey = SOURCE,
    target: ResourceKey = TARGET,
    relation_type: str = "same-object",
    attributes: dict[str, Any] | None = None,
    quality: Quality = Quality.EXACT,
    locator: str = "match:1",
    perspective: str | None = "observed",
) -> RelationshipDeclaration:
    return RelationshipDeclaration(
        source=source,
        target=target,
        relation_type=relation_type,
        attributes=PropertyPatch(
            set_values=attributes or {"method": "exact", "score": 100},
            complete=True,
        ),
        evidence=(Evidence(ARTIFACT_ID, locator, 15, "clock-a"),),
        provenance=Provenance.CORRELATED,
        quality=quality,
        perspective_ref=(
            StatusPerspectiveRef(perspective) if perspective is not None else None
        ),
    )


class _ProjectionPlugin(AnalyzerPluginBase):
    def __init__(
        self,
        plugin_id: str,
        *,
        outputs: tuple[Any, ...] = (),
        capability: bool = True,
        schema: PluginSchema | None = None,
        scan_relationships: bool = False,
        state_lookup: bool = False,
        state_scan_limit: int | None = None,
    ) -> None:
        self.manifest = PluginManifest(
            plugin_id=plugin_id,
            plugin_version="1",
            core_api_version=CORE_PLUGIN_API_VERSION,
            supported_platforms=("test",),
            supported_software_versions="*",
            capabilities=(
                frozenset({PluginCapability.RELATIONSHIP_PROJECTION})
                if capability
                else frozenset()
            ),
            reconstruction_default=ReconstructionSupport.EXACT,
        )
        self.schema = schema or _schema()
        self.outputs = outputs
        self.calls = 0
        self.bases: list[WorldBasis] = []
        self.scan_relationships = scan_relationships
        self.state_lookup = state_lookup
        self.state_scan_limit = state_scan_limit
        self.relationship_counts: list[int] = []

    def describe(self) -> PluginSchema:
        return self.schema

    def project_relationships(self, world: Any):
        self.calls += 1
        self.bases.append(world.basis)
        if self.scan_relationships:
            self.relationship_counts.append(len(tuple(world.iter_relationships())))
        if self.state_lookup:
            world.state_of(SOURCE)
        if self.state_scan_limit is not None:
            tuple(world.iter_states(limit=self.state_scan_limit))
        return self.outputs


def _register(
    registry: PluginRegistry,
    plugin: _ProjectionPlugin,
    instance_id: str,
    marker: str,
) -> RegisteredPlugin:
    return registry.register(
        plugin,
        package_hash="manifest-sha256:" + marker * 64,
        instance_id=instance_id,
        distribution_name=f"{plugin.manifest.plugin_id}.distribution",
        distribution_version="1",
        entry_point_name=instance_id,
    )


def _pin(
    record: RegisteredPlugin,
    schema: PluginSchema,
    *roles: str,
) -> PluginExecutionPin:
    return PluginExecutionPin(
        instance_id=record.instance_id,
        plugin_id=record.plugin_id,
        plugin_version=record.plugin_version,
        core_api_version=record.core_api_version,
        artifact=PluginArtifactIdentity(
            distribution_name=record.distribution_name,
            distribution_version=record.distribution_version,
            package_hash=record.package_hash,
            entry_point_name=record.entry_point_name,
            module_target=record.module_target,
        ),
        configuration_digest=record.configuration_digest,
        schema_digest=plugin_schema_digest(schema),
        registered_execution_identity=record.registered_execution_identity,
        schema_versions=record.schema_versions,
        capabilities=record.capabilities,
        roles=tuple(sorted(roles)),
    )


def _plan(*pins: PluginExecutionPin) -> PluginExecutionPlan:
    return PluginExecutionPlan(
        node_id="node-a",
        basis_revision_id="basis-a",
        plugins=tuple(pins),
        execution_plan_authority=PluginExecutionPlanAuthority.TRUSTED_INLINE_MANIFEST,
    )


def _router(
    records: tuple[RegisteredPlugin, ...],
    plan: PluginExecutionPlan,
) -> PlanBoundCapabilityRouter:
    return PlanBoundCapabilityRouter(
        CapabilityProviderRegistry(records),
        plan,
        catalog_revision_id="revision-a",
        member_id=plan.basis_revision_id,
        allow_inline_only=True,
    )


class RelationshipProjectionMaterializationTests(unittest.TestCase):
    def test_storage_patch_validation_matches_executable_field_domains(self) -> None:
        base_patch = {
            "set_values": {},
            "remove_fields": [],
            "unknown_fields": [],
            "field_quality": {},
            "field_provenance": {},
            "complete": True,
        }
        nul_name = deepcopy(base_patch)
        nul_name["set_values"] = {
            "bad\x00name": {"type": "string", "value": "value"}
        }
        with self.assertRaisesRegex(ValueError, "invalid name"):
            _validate_patch_projection(
                nul_name,
                "patch",
                artifact_ids=frozenset({ARTIFACT_ID}),
            )

        empty_unknown_message = deepcopy(base_patch)
        empty_unknown_message["unknown_fields"] = [
            {
                "name": "field",
                "reason_code": "missing",
                "message": "",
                "evidence": [],
            }
        ]
        with self.assertRaisesRegex(ValueError, "unknown_fields"):
            _validate_patch_projection(
                empty_unknown_message,
                "patch",
                artifact_ids=frozenset({ARTIFACT_ID}),
            )

        oversized_metadata = deepcopy(base_patch)
        oversized_metadata["field_quality"] = {
            f"field-{index}": "exact" for index in range(1_025)
        }
        with self.assertRaisesRegex(ValueError, "field_quality is invalid"):
            _validate_patch_projection(
                oversized_metadata,
                "patch",
                artifact_ids=frozenset({ARTIFACT_ID}),
            )

    def test_complete_storage_requires_a_selected_provider(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        absent = _ProjectionPlugin("test.absent-projector", capability=False)
        selected = _ProjectionPlugin("test.selected-projector")
        absent_record = _register(registry, absent, "primary-absent", "a")
        selected_record = _register(registry, selected, "primary-selected", "b")
        absent_plan = _plan(
            _pin(absent_record, absent.schema, "primary_parser"),
        )
        selected_plan = _plan(
            _pin(selected_record, selected.schema, "primary_parser"),
        )
        not_applicable = materialize_revision_relationship_projection(
            plan=absent_plan,
            router=_router((absent_record,), absent_plan),
            world=_world(),
            primary_schema=absent.schema,
            artifact_ids={ARTIFACT_ID},
        ).dataset_fragment()
        complete = materialize_revision_relationship_projection(
            plan=selected_plan,
            router=_router((selected_record,), selected_plan),
            world=_world(),
            primary_schema=selected.schema,
            artifact_ids={ARTIFACT_ID},
        ).dataset_fragment()
        forged = deepcopy(not_applicable)
        forged_metadata = forged["relationship_projection_materialization"]
        complete_metadata = complete["relationship_projection_materialization"]
        forged_metadata["status"] = "complete"
        forged_metadata["basis"] = complete_metadata["basis"]
        forged_metadata["basis_digest"] = complete_metadata["basis_digest"]
        with self.assertRaisesRegex(ValueError, "selected provider"):
            validate_relationship_projection_storage_fragment(
                forged,
                plan=absent_plan,
                expected_basis_digest=complete_metadata["basis_digest"],
                base_resource_ids={
                    _resource_projection(SOURCE)["resource_id"],
                    _resource_projection(TARGET)["resource_id"],
                },
                relationship_type_directions={"same-object": False},
                perspective_ids={"observed"},
                artifact_ids={ARTIFACT_ID},
            )

    def test_not_applicable_fragment_obeys_the_serialized_byte_limit(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ProjectionPlugin("test.absent-projector", capability=False)
        record = _register(registry, plugin, "primary-absent", "a")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        router = _router((record,), plan)
        world = _world()

        with self.assertRaisesRegex(
            RelationshipProjectionMaterializationError,
            "aggregate byte limit",
        ):
            materialize_revision_relationship_projection(
                plan=plan,
                router=router,
                world=world,
                primary_schema=plugin.schema,
                artifact_ids={ARTIFACT_ID},
                limits=RelationshipProjectionMaterializationLimits(
                    max_serialized_bytes=1,
                ),
            )

        fragment = materialize_revision_relationship_projection(
            plan=plan,
            router=router,
            world=world,
            primary_schema=plugin.schema,
            artifact_ids={ARTIFACT_ID},
        ).dataset_fragment()
        with self.assertRaisesRegex(ValueError, "fragment exceeds the byte limit"):
            validate_relationship_projection_dataset_fragment(
                fragment,
                plan=plan,
                world=world,
                primary_schema=plugin.schema,
                artifact_ids={ARTIFACT_ID},
                limits=RelationshipProjectionMaterializationLimits(
                    max_serialized_bytes=1,
                ),
            )

    def test_primary_is_automatic_and_only_exact_role_selects_auxiliary(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        primary = _ProjectionPlugin("test.primary", scan_relationships=True)
        selected = _ProjectionPlugin("test.selected", scan_relationships=True)
        ignored = _ProjectionPlugin("test.ignored")
        records = (
            _register(registry, primary, "primary", "a"),
            _register(registry, selected, "selected", "b"),
            _register(registry, ignored, "ignored", "c"),
        )
        plan = _plan(
            _pin(records[0], primary.schema, "primary_parser"),
            _pin(
                records[1],
                selected.schema,
                REVISION_RELATIONSHIP_PROJECTION_ROLE,
            ),
            _pin(records[2], ignored.schema, "some_other_role"),
        )
        pins = revision_relationship_projection_selected_pins(plan)
        self.assertEqual(tuple(pin.instance_id for pin in pins), ("primary", "selected"))
        result = materialize_revision_relationship_projection(
            plan=plan,
            router=_router(records, plan),
            world=_world(perspective_ref=StatusPerspectiveRef("observed")),
            primary_schema=primary.schema,
            artifact_ids={ARTIFACT_ID},
        )
        self.assertEqual(result.status, RelationshipProjectionMaterializationStatus.COMPLETE)
        self.assertEqual((primary.calls, selected.calls, ignored.calls), (1, 1, 0))
        self.assertEqual(primary.bases, selected.bases)
        self.assertEqual((primary.relationship_counts, selected.relationship_counts), ([0], [0]))

    def test_exact_aggregate_world_read_limit_is_provider_order_independent(
        self,
    ) -> None:
        def materialize(*, primary_scans: bool):
            registry = PluginRegistry(allow_manifest_identity=True)
            primary = _ProjectionPlugin(
                "test.read-budget-primary",
                state_lookup=not primary_scans,
                state_scan_limit=1 if primary_scans else None,
            )
            auxiliary = _ProjectionPlugin(
                "test.read-budget-auxiliary",
                state_lookup=primary_scans,
                state_scan_limit=None if primary_scans else 1,
            )
            records = (
                _register(registry, primary, "primary", "8"),
                _register(registry, auxiliary, "auxiliary", "9"),
            )
            plan = _plan(
                _pin(records[0], primary.schema, "primary_parser"),
                _pin(
                    records[1],
                    auxiliary.schema,
                    REVISION_RELATIONSHIP_PROJECTION_ROLE,
                ),
            )
            return materialize_revision_relationship_projection(
                plan=plan,
                router=_router(records, plan),
                world=_world(),
                primary_schema=primary.schema,
                artifact_ids={ARTIFACT_ID},
                limits=RelationshipProjectionMaterializationLimits(max_world_reads=4),
            )

        lookup_then_scan = materialize(primary_scans=False)
        scan_then_lookup = materialize(primary_scans=True)
        self.assertEqual(lookup_then_scan.world_reads, 4)
        self.assertEqual(scan_then_lookup.world_reads, 4)
        self.assertEqual(
            lookup_then_scan.status,
            RelationshipProjectionMaterializationStatus.COMPLETE,
        )
        self.assertEqual(
            scan_then_lookup.status,
            RelationshipProjectionMaterializationStatus.COMPLETE,
        )

    def test_auxiliary_declarations_use_primary_revision_schema_authority(
        self,
    ) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        primary = _ProjectionPlugin(
            "test.primary-schema-owner",
            capability=False,
        )
        auxiliary = _ProjectionPlugin(
            "test.aux-independent-schema",
            outputs=(_declaration(),),
            schema=PluginSchema(resource_kinds=(), relationship_types=()),
        )
        records = (
            _register(registry, primary, "primary", "a"),
            _register(registry, auxiliary, "aux", "b"),
        )
        plan = _plan(
            _pin(records[0], primary.schema, "primary_parser"),
            _pin(
                records[1],
                auxiliary.schema,
                REVISION_RELATIONSHIP_PROJECTION_ROLE,
            ),
        )

        result = materialize_revision_relationship_projection(
            plan=plan,
            router=_router(records, plan),
            world=_world(perspective_ref=StatusPerspectiveRef("observed")),
            primary_schema=primary.schema,
            artifact_ids={ARTIFACT_ID},
        )

        self.assertEqual(result.status, RelationshipProjectionMaterializationStatus.COMPLETE)
        self.assertEqual(len(result.declarations), 1)
        self.assertEqual(result.declarations[0].declaration.relation_type, "same-object")

    def test_undirected_endpoint_order_matches_augmented_world_for_escaped_ids(
        self,
    ) -> None:
        source = replace(SOURCE, namespace='a"')
        target = replace(TARGET, namespace="a#")
        evidence = Evidence(ARTIFACT_ID, "escaped-identities", 15, "clock-a")
        snapshots = tuple(
            SnapshotObservation(
                resource=resource,
                observed_at_min_ns=10,
                observed_at_max_ns=20,
                state=PropertyPatch(set_values={}, complete=True),
                provenance=Provenance.OBSERVED,
                quality=Quality.EXACT,
                evidence=evidence,
            )
            for resource in (source, target)
        )
        world = IngestionRevisionWorld(
            basis=BASIS,
            snapshots=snapshots,
            relationship_observations=(),
        )
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ProjectionPlugin(
            "test.escaped-endpoint-order",
            outputs=(_declaration(source=source, target=target, perspective=None),),
        )
        record = _register(registry, plugin, "primary", "6")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        result = materialize_revision_relationship_projection(
            plan=plan,
            router=_router((record,), plan),
            world=world,
            primary_schema=plugin.schema,
            artifact_ids={ARTIFACT_ID},
        )
        fragment = result.dataset_fragment()
        validate_relationship_projection_dataset_fragment(
            fragment,
            plan=plan,
            world=world,
            primary_schema=plugin.schema,
            artifact_ids={ARTIFACT_ID},
        )
        augmented = IngestionRevisionWorld(
            basis=BASIS,
            snapshots=snapshots,
            relationship_observations=(),
            projected_relationships=result.augmented_relationships,
            undirected_relationship_types=frozenset({"same-object"}),
        )
        persisted_source = fragment["relationship_projection_edges"][0]["source"][
            "resource_id"
        ]
        augmented_source = next(iter(augmented.iter_relationships())).source
        self.assertEqual(persisted_source, _resource_projection(source)["resource_id"])
        self.assertEqual(augmented_source, source)

    def test_auxiliary_role_without_capability_fails_plan_selection(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        primary = _ProjectionPlugin("test.primary-no-capability", capability=False)
        invalid = _ProjectionPlugin("test.invalid-role", capability=False)
        records = (
            _register(registry, primary, "primary", "a"),
            _register(registry, invalid, "invalid", "b"),
        )
        plan = _plan(
            _pin(records[0], primary.schema, "primary_parser"),
            _pin(
                records[1],
                invalid.schema,
                REVISION_RELATIONSHIP_PROJECTION_ROLE,
            ),
        )
        with self.assertRaisesRegex(
            RelationshipProjectionMaterializationError,
            "role requires the declared capability",
        ):
            revision_relationship_projection_selected_pins(plan)

    def test_duplicate_budgeting_and_contributions_are_deterministic(self) -> None:
        declaration = _declaration()
        registry = PluginRegistry(allow_manifest_identity=True)
        primary = _ProjectionPlugin(
            "test.primary-duplicates", outputs=(declaration, declaration)
        )
        auxiliary = _ProjectionPlugin(
            "test.aux-duplicates", outputs=(declaration,)
        )
        records = (
            _register(registry, primary, "primary", "d"),
            _register(registry, auxiliary, "aux", "e"),
        )
        plan = _plan(
            _pin(records[0], primary.schema, "primary_parser"),
            _pin(
                records[1],
                auxiliary.schema,
                REVISION_RELATIONSHIP_PROJECTION_ROLE,
            ),
        )
        result = materialize_revision_relationship_projection(
            plan=plan,
            router=_router(records, plan),
            world=_world(),
            primary_schema=primary.schema,
            artifact_ids={ARTIFACT_ID},
        )
        self.assertEqual(result.emitted_declarations, 3)
        self.assertEqual(result.duplicate_emissions_collapsed, 1)
        self.assertEqual(len(result.declarations), 1)
        self.assertEqual(
            tuple(item.occurrence_count for item in result.declarations[0].contributions),
            (1, 2),
        )
        with self.assertRaisesRegex(RelationshipProjectionMaterializationError, "aggregate limit"):
            materialize_revision_relationship_projection(
                plan=plan,
                router=_router(records, plan),
                world=_world(),
                primary_schema=primary.schema,
                artifact_ids={ARTIFACT_ID},
                limits=RelationshipProjectionMaterializationLimits(max_declarations=2),
            )

    def test_one_declaration_can_retain_evidence_from_independent_artifacts(self) -> None:
        declaration = replace(
            _declaration(),
            evidence=(
                Evidence(ARTIFACT_ID, "control:row:7", 15, "control-clock"),
                Evidence(
                    SECOND_ARTIFACT_ID,
                    "hardware:row:19",
                    18,
                    "hardware-clock",
                ),
            ),
        )
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ProjectionPlugin(
            "test.cross-artifact",
            outputs=(declaration,),
        )
        record = _register(registry, plugin, "primary", "0")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        result = materialize_revision_relationship_projection(
            plan=plan,
            router=_router((record,), plan),
            world=_world(),
            primary_schema=plugin.schema,
            artifact_ids={ARTIFACT_ID, SECOND_ARTIFACT_ID},
        )

        evidence = result.dataset_fragment()["relationship_declarations"][0][
            "contributions"
        ][0]["evidence"]
        self.assertEqual(
            {item["artifact_id"] for item in evidence},
            {str(ARTIFACT_ID), str(SECOND_ARTIFACT_ID)},
        )

    def test_general_property_values_and_diagnostics_survive_materialization(self) -> None:
        nested: dict[str, Any] = {"leaf": tuple(range(40))}
        for depth in range(6):
            nested = {f"level-{depth}": nested}
        declaration = _declaration(attributes={"nested": nested})
        diagnostic = PluginDiagnostic(
            stage=DiagnosticStage.RELATIONSHIP_PROJECTION,
            severity=DiagnosticSeverity.WARNING,
            code="projection-note",
            message="projection retained a bounded diagnostic",
            recoverable=True,
            evidence=(Evidence(ARTIFACT_ID, "diagnostic:1", 15, "clock-a"),),
            details={"context": {"values": tuple(range(40))}},
            origin=DiagnosticOrigin.PLUGIN,
        )
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ProjectionPlugin(
            "test.general-properties",
            outputs=(declaration, diagnostic),
        )
        record = _register(registry, plugin, "primary", "7")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))

        result = materialize_revision_relationship_projection(
            plan=plan,
            router=_router((record,), plan),
            world=_world(),
            primary_schema=plugin.schema,
            artifact_ids={ARTIFACT_ID},
        )
        fragment = result.dataset_fragment()

        self.assertEqual(len(fragment["relationship_projection_diagnostics"]), 1)
        self.assertEqual(
            fragment["relationship_declarations"][0]["attributes"]["set_values"][
                "nested"
            ]["type"],
            "mapping",
        )
        self.assertEqual(
            validate_relationship_projection_dataset_fragment(
                fragment,
                plan=plan,
                world=_world(),
                primary_schema=plugin.schema,
                artifact_ids={ARTIFACT_ID},
            ),
            fragment,
        )

    def test_conflicts_are_retained_and_resolved_conservatively(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        primary = _ProjectionPlugin(
            "test.primary-conflict",
            outputs=(
                _declaration(
                    attributes={"common": "same", "owner": "control"},
                    locator="control",
                ),
            ),
        )
        auxiliary = _ProjectionPlugin(
            "test.aux-conflict",
            outputs=(
                _declaration(
                    attributes={"common": "same", "owner": "hardware"},
                    quality=Quality.BEST_EFFORT,
                    locator="hardware",
                ),
            ),
        )
        records = (
            _register(registry, primary, "primary", "f"),
            _register(registry, auxiliary, "aux", "1"),
        )
        plan = _plan(
            _pin(records[0], primary.schema, "primary_parser"),
            _pin(
                records[1],
                auxiliary.schema,
                REVISION_RELATIONSHIP_PROJECTION_ROLE,
            ),
        )
        result = materialize_revision_relationship_projection(
            plan=plan,
            router=_router(records, plan),
            world=_world(),
            primary_schema=primary.schema,
            artifact_ids={ARTIFACT_ID},
        )
        self.assertEqual(len(result.declarations), 2)
        self.assertEqual(result.semantic_conflict_groups, 1)
        group_ids = {item.ambiguity_group_id for item in result.declarations}
        self.assertEqual(len(group_ids), 1)
        self.assertNotIn(None, group_ids)
        self.assertEqual(len(result.augmented_relationships), 1)
        resolved = result.augmented_relationships[0]
        self.assertEqual(resolved.attributes, {"common": "same"})
        self.assertEqual(resolved.quality, Quality.AMBIGUOUS)
        self.assertEqual(resolved.provenance, Provenance.CORRELATED)
        self.assertIsNone(resolved.valid_from_ns)
        self.assertIsNone(resolved.valid_to_ns)
        fragment = result.dataset_fragment()
        self.assertFalse(
            any(
                "timestamp" in key or "valid_from" in key or "valid_to" in key
                for record in fragment["relationship_declarations"]
                for key in record
            )
        )
        validated = validate_relationship_projection_dataset_fragment(
            fragment,
            plan=plan,
            world=_world(),
            primary_schema=primary.schema,
            artifact_ids={ARTIFACT_ID},
        )
        self.assertEqual(validated, fragment)
        storage_validated = validate_relationship_projection_storage_fragment(
            fragment,
            plan=plan,
            expected_basis_digest=result.basis_digest,
            base_resource_ids={
                fragment["relationship_declarations"][0]["source"]["resource_id"],
                fragment["relationship_declarations"][0]["target"]["resource_id"],
            },
            relationship_type_directions={"same-object": False},
            perspective_ids={"observed"},
            artifact_ids={ARTIFACT_ID},
        )
        self.assertEqual(storage_validated, fragment)
        for field in ("member_id", "node_id", "basis_revision_id"):
            with self.subTest(provider_coordinate=field):
                tampered = deepcopy(fragment)
                tampered["relationship_projection_materialization"]["providers"][0][
                    field
                ] = "outside-revision"
                with self.assertRaisesRegex(ValueError, "revision authority"):
                    validate_relationship_projection_storage_fragment(
                        tampered,
                        plan=plan,
                        expected_basis_digest=result.basis_digest,
                        base_resource_ids={
                            fragment["relationship_declarations"][0]["source"][
                                "resource_id"
                            ],
                            fragment["relationship_declarations"][0]["target"][
                                "resource_id"
                            ],
                        },
                        relationship_type_directions={"same-object": False},
                        perspective_ids={"observed"},
                        artifact_ids={ARTIFACT_ID},
                    )

    def test_distinct_perspectives_are_independent_edges_not_conflicts(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ProjectionPlugin(
            "test.multi-perspective",
            outputs=(
                _declaration(
                    attributes={"state": "observed"},
                    perspective="observed",
                ),
                _declaration(
                    attributes={"state": "programmed"},
                    perspective="programmed",
                ),
            ),
        )
        record = _register(registry, plugin, "primary", "8")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))

        result = materialize_revision_relationship_projection(
            plan=plan,
            router=_router((record,), plan),
            world=_world(),
            primary_schema=plugin.schema,
            artifact_ids={ARTIFACT_ID},
        )

        self.assertEqual(result.semantic_conflict_groups, 0)
        self.assertEqual(len(result.augmented_relationships), 2)
        self.assertEqual(
            {
                item.perspective_ref.perspective_id
                for item in result.augmented_relationships
                if item.perspective_ref is not None
            },
            {"observed", "programmed"},
        )

    def test_endpoint_schema_and_perspective_fail_closed(self) -> None:
        invalid = (
            (_declaration(target=MISSING), "endpoint"),
            (_declaration(relation_type="undeclared"), "projector failed"),
            (_declaration(perspective="undeclared"), "projector failed"),
        )
        for ordinal, (declaration, message) in enumerate(invalid):
            with self.subTest(message=message):
                registry = PluginRegistry(allow_manifest_identity=True)
                plugin = _ProjectionPlugin(
                    f"test.invalid-{ordinal}", outputs=(declaration,)
                )
                record = _register(registry, plugin, "primary", str(ordinal + 2))
                plan = _plan(_pin(record, plugin.schema, "primary_parser"))
                with self.assertRaisesRegex(RelationshipProjectionMaterializationError, message):
                    materialize_revision_relationship_projection(
                        plan=plan,
                        router=_router((record,), plan),
                        world=_world(),
                        primary_schema=plugin.schema,
                        artifact_ids={ARTIFACT_ID},
                    )

    def test_persisted_fragment_rejects_tampering(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ProjectionPlugin(
            "test.tamper", outputs=(_declaration(),)
        )
        record = _register(registry, plugin, "primary", "9")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        fragment = materialize_revision_relationship_projection(
            plan=plan,
            router=_router((record,), plan),
            world=_world(),
            primary_schema=plugin.schema,
            artifact_ids={ARTIFACT_ID},
        ).dataset_fragment()
        mutations = []
        wrong_basis = deepcopy(fragment)
        wrong_basis["relationship_projection_materialization"]["basis_digest"] = "sha256:" + "0" * 64
        mutations.append(wrong_basis)
        wrong_basis_record = deepcopy(fragment)
        materialization = wrong_basis_record[
            "relationship_projection_materialization"
        ]
        materialization["basis"]["resolved_at_max_ns"] = "19"
        materialization["basis_digest"] = "sha256:" + sha256(
            strict_canonical_json_bytes(materialization["basis"])
        ).hexdigest()
        mutations.append(wrong_basis_record)
        partial_resolved_basis = deepcopy(fragment)
        partial_resolved_basis["relationship_projection_materialization"]["basis"][
            "resolved_at_min_ns"
        ] = None
        mutations.append(partial_resolved_basis)
        wrong_provider = deepcopy(fragment)
        wrong_provider["relationship_declarations"][0]["contributions"][0]["producer"]["instance_id"] = "other"
        mutations.append(wrong_provider)
        wrong_edge = deepcopy(fragment)
        wrong_edge["relationship_projection_edges"][0]["quality"] = "exact"
        wrong_edge["relationship_projection_edges"][0]["relationship_id"] = "sha256:" + "0" * 64
        mutations.append(wrong_edge)
        for candidate in mutations:
            with self.assertRaises(ValueError):
                validate_relationship_projection_dataset_fragment(
                    candidate,
                    plan=plan,
                    world=_world(),
                    primary_schema=plugin.schema,
                    artifact_ids={ARTIFACT_ID},
                )

    def test_persisted_diagnostics_revalidate_the_full_typed_contract(self) -> None:
        diagnostic = PluginDiagnostic(
            stage=DiagnosticStage.RELATIONSHIP_PROJECTION,
            severity=DiagnosticSeverity.WARNING,
            code="projection-note",
            message="bounded projection diagnostic",
            recoverable=True,
            evidence=(Evidence(ARTIFACT_ID, "diagnostic:1", 15, "clock-a"),),
            details={"blob": b"\xaa"},
            origin=DiagnosticOrigin.PLUGIN,
        )
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ProjectionPlugin(
            "test.diagnostic-tamper",
            outputs=(_declaration(), diagnostic),
        )
        record = _register(registry, plugin, "primary", "a")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        fragment = materialize_revision_relationship_projection(
            plan=plan,
            router=_router((record,), plan),
            world=_world(),
            primary_schema=plugin.schema,
            artifact_ids={ARTIFACT_ID},
        ).dataset_fragment()

        mutations: list[dict[str, Any]] = []
        for field, value in (
            ("stage", DiagnosticStage.CONSISTENCY.value),
            ("severity", "not-a-severity"),
            ("origin", DiagnosticOrigin.CORE_DECODER.value),
            ("recoverable", False),
            ("code", ""),
            ("message", "bad\x00message"),
        ):
            candidate = deepcopy(fragment)
            stored = candidate["relationship_projection_diagnostics"][0]
            stored[field] = value
            _rehash_record(stored, "diagnostic_id")
            mutations.append(candidate)

        scalar_details = deepcopy(fragment)
        stored = scalar_details["relationship_projection_diagnostics"][0]
        stored["details"] = {"type": "string", "value": "not-a-mapping"}
        _rehash_record(stored, "diagnostic_id")
        mutations.append(scalar_details)

        oversized_time = deepcopy(fragment)
        stored = oversized_time["relationship_projection_diagnostics"][0]
        stored["evidence"][0]["raw_timestamp_ns"] = str(1 << 63)
        _rehash_record(stored, "diagnostic_id")
        mutations.append(oversized_time)

        noncanonical_bytes = deepcopy(fragment)
        stored = noncanonical_bytes["relationship_projection_diagnostics"][0]
        stored["details"]["entries"]["blob"]["value"] = "aa  "
        _rehash_record(stored, "diagnostic_id")
        mutations.append(noncanonical_bytes)

        boolean_count = deepcopy(fragment)
        boolean_count["relationship_projection_materialization"][
            "provider_count"
        ] = True
        mutations.append(boolean_count)

        for candidate in mutations:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_relationship_projection_dataset_fragment(
                    candidate,
                    plan=plan,
                    world=_world(),
                    primary_schema=plugin.schema,
                    artifact_ids={ARTIFACT_ID},
                )

    def test_reload_reconstructs_pre_dedup_evidence_and_byte_budgets(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        declaration = _declaration()
        plugin = _ProjectionPlugin(
            "test.pre-dedup-budget",
            outputs=tuple(declaration for _index in range(128)),
        )
        record = _register(registry, plugin, "primary", "b")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        fragment = materialize_revision_relationship_projection(
            plan=plan,
            router=_router((record,), plan),
            world=_world(),
            primary_schema=plugin.schema,
            artifact_ids={ARTIFACT_ID},
        ).dataset_fragment()

        with self.assertRaisesRegex(ValueError, "evidence exceeds"):
            validate_relationship_projection_dataset_fragment(
                fragment,
                plan=plan,
                world=_world(),
                primary_schema=plugin.schema,
                artifact_ids={ARTIFACT_ID},
                limits=RelationshipProjectionMaterializationLimits(
                    max_evidence_references=127,
                ),
            )

        compact_size = len(strict_canonical_json(fragment).encode("utf-8"))
        with self.assertRaisesRegex(ValueError, "pre-dedup output"):
            validate_relationship_projection_dataset_fragment(
                fragment,
                plan=plan,
                world=_world(),
                primary_schema=plugin.schema,
                artifact_ids={ARTIFACT_ID},
                limits=RelationshipProjectionMaterializationLimits(
                    max_serialized_bytes=compact_size + 1,
                ),
            )


if __name__ == "__main__":
    unittest.main()
