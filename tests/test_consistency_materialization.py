from __future__ import annotations

import unittest
from copy import deepcopy
from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256
from typing import Any
from uuid import UUID

from router_dump_analyzer.canonical import (
    canonical_json,
    strict_canonical_json,
    strict_canonical_json_bytes,
)
from router_dump_analyzer.capability_router import (
    CapabilityProviderRegistry,
    PlanBoundCapabilityRouter,
)
from router_dump_analyzer.consistency_materialization import (
    ConsistencyMaterializationError,
    ConsistencyMaterializationLimits,
    ConsistencyMaterializationStatus,
    _published_consistency_storage_projection,
    legacy_consistency_materialization_envelope,
    materialize_revision_consistency,
    not_applicable_consistency_materialization,
    revision_consistency_selected_pins,
    validate_materialized_consistency_basis,
    validate_materialized_consistency_diagnostic,
    validate_materialized_consistency_finding,
)
from router_dump_analyzer.ingestion import _resource_identity
from router_dump_analyzer.ingestion_pipeline import PluginRegistry, RegisteredPlugin
from router_dump_analyzer.normalized_data import (
    project_consistency_materialization_for_client,
)
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    CaptureRange,
    ConsistencyFinding,
    DiagnosticOrigin,
    DiagnosticSeverity,
    DiagnosticStage,
    Evidence,
    FindingResult,
    PluginCapability,
    PluginDiagnostic,
    PluginManifest,
    PluginSchema,
    PropertyPatch,
    Provenance,
    Quality,
    ReconstructionSupport,
    ReconstructionWatermark,
    RelationDirection,
    RelationshipObservation,
    ResolvedNodeBasis,
    ResourceKey,
    ResourceKindDescriptor,
    SnapshotObservation,
    WatermarkScope,
    WorldBasis,
    WorldBasisKind,
)
from router_dump_analyzer.plugin_composition import REVISION_CONSISTENCY_ROLE
from router_dump_analyzer.plugin_execution_plan import (
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
    PluginExecutionPlanAuthority,
)
from router_dump_analyzer.plugin_schema_identity import plugin_schema_digest
from router_dump_analyzer.revision_world import IngestionRevisionWorld

ARTIFACT_ID = UUID("00000000-0000-0000-0000-000000000001")
FOREIGN_ARTIFACT_ID = UUID("00000000-0000-0000-0000-000000000002")
RESOURCE = ResourceKey(
    namespace="test",
    node="node-a",
    layer="control",
    kind="opaque.item",
    parts=(("id", "one"),),
)
BASIS = WorldBasis(
    kind=WorldBasisKind.OBSERVED_CAPTURE_VECTOR,
    requested_time_ns=None,
    resolved_at_min_ns=10,
    resolved_at_max_ns=20,
    capture_ranges=(),
    provenance=Provenance.OBSERVED,
    quality=Quality.EXACT,
)


def _schema() -> PluginSchema:
    return PluginSchema(
        resource_kinds=(
            ResourceKindDescriptor(
                kind="opaque.item",
                label="Opaque item",
                key_fields=("id",),
                properties=(),
            ),
        ),
        relationship_types=(),
    )


class _World:
    def __init__(self, basis: WorldBasis = BASIS) -> None:
        self._basis = basis

    @property
    def basis(self) -> WorldBasis:
        return self._basis

    @property
    def perspective_ref(self) -> None:
        return None

    def state_of(self, resource: ResourceKey) -> None:
        del resource

    def iter_states(self, *, layers=None, kinds=None, limit=None):
        del layers, kinds, limit
        return ()

    def related(
        self,
        resource: ResourceKey,
        direction: RelationDirection = RelationDirection.OUTGOING,
        relation_types=None,
        limit=None,
    ):
        del resource, direction, relation_types, limit
        return ()

    def iter_relationships(self, *, relation_types=None, layers=None, limit=None):
        del relation_types, layers, limit
        return ()


class _ExplodingWorld:
    @property
    def basis(self):
        raise AssertionError("not-applicable materialization touched the world")

    @property
    def perspective_ref(self):
        raise AssertionError("not-applicable materialization touched the world")


class _ConsistencyPlugin(AnalyzerPluginBase):
    def __init__(
        self,
        plugin_id: str,
        *,
        capability: bool = True,
        outputs: tuple[Any, ...] = (),
        read_world: bool = False,
        scan_world: bool = False,
    ) -> None:
        self.manifest = PluginManifest(
            plugin_id=plugin_id,
            plugin_version="1",
            core_api_version=CORE_PLUGIN_API_VERSION,
            supported_platforms=("test",),
            supported_software_versions="*",
            capabilities=(
                frozenset({PluginCapability.CONSISTENCY_CHECK})
                if capability
                else frozenset()
            ),
            reconstruction_default=ReconstructionSupport.EXACT,
        )
        self.schema = _schema()
        self.outputs = outputs
        self.read_world = read_world
        self.scan_world = scan_world
        self.calls = 0

    def describe(self) -> PluginSchema:
        return self.schema

    def check_consistency(self, world: Any):
        self.calls += 1
        if self.read_world:
            world.state_of(RESOURCE)
        if self.scan_world:
            tuple(world.iter_states())
        return self.outputs


def _finding(
    *,
    result: FindingResult = FindingResult.FAIL,
    basis: WorldBasis = BASIS,
    artifact_id: UUID = ARTIFACT_ID,
    summary: str = "Cross-layer mismatch",
    resource: ResourceKey = RESOURCE,
) -> ConsistencyFinding:
    return ConsistencyFinding(
        rule_id="test.cross-layer",
        severity=DiagnosticSeverity.ERROR,
        result=result,
        summary=summary,
        resources=(resource,),
        provenance=Provenance.RECONSTRUCTED,
        quality=Quality.EXACT,
        basis=basis,
        evidence=(Evidence(artifact_id, "record:1", 15, "clock-a"),),
        details={"expected": "up", "actual": "down"},
    )


def _diagnostic() -> PluginDiagnostic:
    return PluginDiagnostic(
        stage=DiagnosticStage.CONSISTENCY,
        severity=DiagnosticSeverity.WARNING,
        code="test.partial",
        message="A recoverable source was unavailable.",
        recoverable=True,
        evidence=(Evidence(ARTIFACT_ID, "record:2", 16, "clock-a"),),
        details={"source": "secondary"},
        origin=DiagnosticOrigin.PLUGIN,
    )


def _register(
    registry: PluginRegistry,
    plugin: _ConsistencyPlugin,
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
    record: RegisteredPlugin, schema: PluginSchema, *roles: str
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


class ConsistencyMaterializationTests(unittest.TestCase):
    def test_new_node_resolution_limit_preserves_existing_positional_order(
        self,
    ) -> None:
        limits = ConsistencyMaterializationLimits(
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
        )
        self.assertEqual(limits.max_capture_ranges, 8)
        self.assertEqual(limits.max_basis_value_units, 9)
        self.assertEqual(limits.max_serialized_bytes, 10)
        self.assertEqual(limits.max_node_resolutions, 100_000)

    def test_resource_reference_id_matches_ingestion_for_non_ascii_key(self) -> None:
        resource = ResourceKey(
            namespace="pilote-é",
            node="routeur-東京",
            layer="control",
            kind="opaque.item",
            parts=(("id", "café/网络"),),
        )

        normalized_id, normalized_key = _resource_identity(resource)
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.unicode-key",
            outputs=(_finding(resource=resource),),
        )
        record = _register(registry, plugin, "primary", "e")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))

        result = materialize_revision_consistency(
            plan=plan,
            router=_router((record,), plan),
            world=_World(),
            artifact_ids={ARTIFACT_ID},
        )
        reference = result.client_findings()[0]["resource_references"][0]

        self.assertEqual(reference["resource_id"], normalized_id)
        self.assertEqual(reference["typed_resource_key"], normalized_key)

    def test_legacy_plan_digest_is_exact_lowercase_sha256(self) -> None:
        with self.assertRaisesRegex(ValueError, "sha256-prefixed"):
            legacy_consistency_materialization_envelope(
                plan_digest="sha256:" + ("z" * 64),
                finding_count=0,
            )

        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin("test.digest", capability=False)
        record = _register(registry, plugin, "primary", "d")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        result = not_applicable_consistency_materialization(plan)
        with self.assertRaisesRegex(ValueError, "sha256-prefixed"):
            replace(result, plan_digest="sha256:" + ("G" * 64))

    def test_materialized_record_ids_commit_to_their_exact_payloads(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.record-identity",
            outputs=(_finding(), _diagnostic()),
        )
        record = _register(registry, plugin, "primary", "f")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        result = materialize_revision_consistency(
            plan=plan,
            router=_router((record,), plan),
            world=_World(),
            artifact_ids={ARTIFACT_ID},
        )
        forged_id = "sha256:" + ("0" * 64)

        finding_record = result.findings[0].client_projection()
        finding_record["finding_id"] = forged_id
        with self.assertRaisesRegex(ValueError, "canonical finding record"):
            replace(
                result.findings[0],
                finding_id=forged_id,
                canonical_record=strict_canonical_json(finding_record),
            )

        diagnostic_record = result.diagnostics[0].client_projection()
        diagnostic_record["diagnostic_id"] = forged_id
        with self.assertRaisesRegex(ValueError, "canonical diagnostic record"):
            replace(
                result.diagnostics[0],
                diagnostic_id=forged_id,
                canonical_record=strict_canonical_json(diagnostic_record),
            )

    def test_primary_and_explicit_auxiliary_are_selected_exactly(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        primary = _ConsistencyPlugin(
            "test.primary",
            outputs=(_finding(result=FindingResult.PASS, summary="Primary pass"),),
        )
        auxiliary = _ConsistencyPlugin(
            "test.auxiliary",
            outputs=(_finding(), _diagnostic()),
        )
        ignored = _ConsistencyPlugin(
            "test.ignored",
            outputs=(_finding(summary="Must not run"),),
        )
        records = (
            _register(registry, primary, "primary", "1"),
            _register(registry, auxiliary, "auxiliary", "2"),
            _register(registry, ignored, "ignored", "3"),
        )
        plan = _plan(
            _pin(records[0], primary.schema, "primary_parser"),
            _pin(records[2], ignored.schema, "observer"),
            _pin(records[1], auxiliary.schema, REVISION_CONSISTENCY_ROLE),
        )

        result = materialize_revision_consistency(
            plan=plan,
            router=_router(records, plan),
            world=_World(),
            artifact_ids={ARTIFACT_ID},
        )

        self.assertIs(result.status, ConsistencyMaterializationStatus.COMPLETE)
        self.assertEqual((primary.calls, auxiliary.calls, ignored.calls), (1, 1, 0))
        self.assertEqual(
            [provider.pin.instance_id for provider in result.providers],
            ["primary", "auxiliary"],
        )
        self.assertEqual(
            result.summary.client_projection(), {"pass": 1, "fail": 1, "unknown": 0}
        )
        self.assertEqual(len(result.plugin_diagnostics), 1)
        findings = result.client_findings()
        self.assertEqual(len(findings), 2)
        self.assertTrue(
            all(item["execution_plan_digest"] == plan.plan_digest for item in findings)
        )
        self.assertEqual(
            {item["producer"]["instance_id"] for item in findings},
            {"primary", "auxiliary"},
        )
        self.assertTrue(all(item["resources"] for item in findings))
        self.assertTrue(all(item["resource_references"] for item in findings))
        metadata = result.metadata_projection()
        self.assertEqual(metadata["basis"]["kind"], BASIS.kind.value)
        self.assertRegex(metadata["basis_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertNotIn("catalog_revision_id", str(result.dataset_fragment()))
        diagnostics = result.client_diagnostics()
        self.assertEqual(diagnostics[0]["producer"]["instance_id"], "auxiliary")
        self.assertEqual(
            result.dataset_fragment()["consistency_diagnostics"], diagnostics
        )

    def test_no_selected_provider_is_explicitly_not_applicable(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin("test.none", capability=False)
        record = _register(registry, plugin, "primary", "4")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))

        result = materialize_revision_consistency(
            plan=plan,
            router=_router((record,), plan),
            world=_ExplodingWorld(),
            artifact_ids=(),
        )

        self.assertIs(result.status, ConsistencyMaterializationStatus.NOT_APPLICABLE)
        self.assertEqual(plugin.calls, 0)
        fragment = result.dataset_fragment()
        self.assertEqual(fragment["findings"], [])
        self.assertIsNone(fragment["consistency_materialization"]["basis"])
        self.assertIsNone(fragment["consistency_materialization"]["basis_digest"])
        self.assertEqual(revision_consistency_selected_pins(plan), ())
        self.assertEqual(not_applicable_consistency_materialization(plan), result)

    def test_not_applicable_helper_rejects_a_selected_provider(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin("test.selected")
        record = _register(registry, plugin, "primary", "c")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))

        with self.assertRaisesRegex(
            ConsistencyMaterializationError,
            "requires no selected provider",
        ):
            not_applicable_consistency_materialization(plan)

    def test_reserved_auxiliary_role_requires_the_capability(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        primary = _ConsistencyPlugin("test.primary-none", capability=False)
        auxiliary = _ConsistencyPlugin("test.aux-none", capability=False)
        records = (
            _register(registry, primary, "primary", "5"),
            _register(registry, auxiliary, "auxiliary", "6"),
        )
        plan = _plan(
            _pin(records[0], primary.schema, "primary_parser"),
            _pin(records[1], auxiliary.schema, REVISION_CONSISTENCY_ROLE),
        )
        with self.assertRaisesRegex(
            ConsistencyMaterializationError,
            "does not declare consistency_check",
        ):
            materialize_revision_consistency(
                plan=plan,
                router=_router(records, plan),
                world=_World(),
                artifact_ids=(),
            )

    def test_basis_and_evidence_are_bound_to_the_revision(self) -> None:
        scenarios = (
            (
                "basis",
                _finding(basis=replace(BASIS, resolved_at_max_ns=21)),
                "basis does not match",
            ),
            (
                "evidence",
                _finding(artifact_id=FOREIGN_ARTIFACT_ID),
                "outside the revision",
            ),
        )
        for index, (label, finding, message) in enumerate(scenarios, start=7):
            with self.subTest(label=label):
                registry = PluginRegistry(allow_manifest_identity=True)
                plugin = _ConsistencyPlugin(f"test.{label}", outputs=(finding,))
                record = _register(registry, plugin, "primary", str(index))
                plan = _plan(_pin(record, plugin.schema, "primary_parser"))
                with self.assertRaisesRegex(ConsistencyMaterializationError, message):
                    materialize_revision_consistency(
                        plan=plan,
                        router=_router((record,), plan),
                        world=_World(),
                        artifact_ids={ARTIFACT_ID},
                    )

    def test_duplicates_are_stable_but_count_toward_limits(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        finding = _finding()
        diagnostic = _diagnostic()
        plugin = _ConsistencyPlugin(
            "test.duplicates",
            outputs=(finding, finding, diagnostic, diagnostic),
        )
        record = _register(registry, plugin, "primary", "9")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        router = _router((record,), plan)

        first = materialize_revision_consistency(
            plan=plan,
            router=router,
            world=_World(),
            artifact_ids={ARTIFACT_ID},
        )
        second = materialize_revision_consistency(
            plan=plan,
            router=router,
            world=_World(),
            artifact_ids={ARTIFACT_ID},
        )
        self.assertEqual(first.client_findings(), second.client_findings())
        self.assertEqual(
            (len(first.findings), first.duplicate_findings_discarded), (1, 1)
        )
        self.assertEqual(
            (len(first.diagnostics), first.duplicate_diagnostics_discarded), (1, 1)
        )

        with self.assertRaisesRegex(
            ConsistencyMaterializationError, "findings exceeded"
        ):
            materialize_revision_consistency(
                plan=plan,
                router=router,
                world=_World(),
                artifact_ids={ARTIFACT_ID},
                limits=ConsistencyMaterializationLimits(max_findings=1),
            )

    def test_plan_router_mismatch_and_aggregate_world_budget_fail_closed(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.world",
            outputs=(_finding(),),
            read_world=True,
        )
        record = _register(registry, plugin, "primary", "a")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        router = _router((record,), plan)
        other_plan = replace(plan, basis_revision_id="other-basis", plan_digest="")
        with self.assertRaisesRegex(ConsistencyMaterializationError, "not bound"):
            materialize_revision_consistency(
                plan=other_plan,
                router=router,
                world=_World(),
                artifact_ids={ARTIFACT_ID},
            )

        # Two providers each stay within their per-provider budget but exceed
        # the one shared revision-wide read allowance.
        auxiliary = _ConsistencyPlugin(
            "test.world-aux",
            outputs=(_finding(summary="Auxiliary"),),
            read_world=True,
        )
        auxiliary_record = _register(registry, auxiliary, "auxiliary", "b")
        composed = _plan(
            _pin(record, plugin.schema, "primary_parser"),
            _pin(auxiliary_record, auxiliary.schema, REVISION_CONSISTENCY_ROLE),
        )
        with self.assertRaisesRegex(ConsistencyMaterializationError, "provider failed"):
            materialize_revision_consistency(
                plan=composed,
                router=_router((record, auxiliary_record), composed),
                world=_World(),
                artifact_ids={ARTIFACT_ID},
                limits=ConsistencyMaterializationLimits(max_world_reads=1),
            )

    def test_router_member_must_match_plan_basis_before_plugin_invocation(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin("test.wrong-member", outputs=(_finding(),))
        record = _register(registry, plugin, "primary", "d")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        router = PlanBoundCapabilityRouter(
            CapabilityProviderRegistry((record,)),
            plan,
            catalog_revision_id="revision-a",
            member_id="different-revision",
            allow_inline_only=True,
        )

        with self.assertRaisesRegex(
            ConsistencyMaterializationError,
            "member does not match",
        ):
            materialize_revision_consistency(
                plan=plan,
                router=router,
                world=_World(),
                artifact_ids={ARTIFACT_ID},
            )
        self.assertEqual(plugin.calls, 0)

    def test_one_provider_cannot_mutate_the_world_seen_by_the_next(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        mutator = _ConsistencyPlugin("test.world-mutator")
        observer = _ConsistencyPlugin("test.world-observer")
        observed_reasons: list[str | None] = []
        observed_states: list[str | None] = []
        observed_relations: list[str] = []
        snapshot = SnapshotObservation(
            resource=RESOURCE,
            observed_at_min_ns=15,
            observed_at_max_ns=15,
            state=PropertyPatch(
                set_values={"status": "up"},
                complete=True,
            ),
            provenance=Provenance.OBSERVED,
            quality=Quality.EXACT,
            evidence=Evidence(ARTIFACT_ID, "record:state", 15, "clock-a"),
        )
        relationship = RelationshipObservation(
            source=RESOURCE,
            target=RESOURCE,
            relation_type="opaque.link",
            observed_at_min_ns=15,
            observed_at_max_ns=15,
            present=True,
            attributes=PropertyPatch(
                set_values={"status": "usable"},
                complete=True,
            ),
            provenance=Provenance.OBSERVED,
            quality=Quality.EXACT,
            evidence=Evidence(ARTIFACT_ID, "record:relationship", 15, "clock-a"),
        )
        revision_world = IngestionRevisionWorld(
            basis=BASIS,
            snapshots=(snapshot,),
            relationship_observations=(relationship,),
        )

        def mutate(world: Any):
            object.__setattr__(
                world.basis,
                "unresolved_reason",
                "mutated-by-first-provider",
            )
            state_by_key = world.state_of(RESOURCE)
            state_by_scan = next(iter(world.iter_states()))
            relation_by_key = next(iter(world.related(RESOURCE)))
            relation_by_scan = next(iter(world.iter_relationships()))
            object.__setattr__(state_by_key, "properties", {"status": "down"})
            object.__setattr__(state_by_scan, "exists", False)
            object.__setattr__(relation_by_key, "relation_type", "mutated.link")
            object.__setattr__(
                relation_by_scan,
                "attributes",
                {"status": "failed"},
            )
            return ()

        def observe(world: Any):
            observed_reasons.append(world.basis.unresolved_reason)
            state = world.state_of(RESOURCE)
            assert state is not None
            observed_states.append(state.properties.get("status"))
            observed_relations.append(
                next(iter(world.related(RESOURCE))).relation_type
            )
            return (_finding(basis=world.basis),)

        mutator.check_consistency = mutate  # type: ignore[method-assign]
        observer.check_consistency = observe  # type: ignore[method-assign]
        primary = _register(registry, mutator, "primary", "1")
        auxiliary = _register(registry, observer, "auxiliary", "2")
        plan = _plan(
            _pin(primary, mutator.schema, "primary_parser"),
            _pin(auxiliary, observer.schema, REVISION_CONSISTENCY_ROLE),
        )

        result = materialize_revision_consistency(
            plan=plan,
            router=_router((primary, auxiliary), plan),
            world=revision_world,
            artifact_ids={ARTIFACT_ID},
        )

        self.assertEqual(observed_reasons, [None])
        self.assertEqual(observed_states, ["up"])
        self.assertEqual(observed_relations, ["opaque.link"])
        self.assertIsNone(BASIS.unresolved_reason)
        self.assertEqual(len(result.findings), 1)

    def test_real_revision_world_scan_cannot_silently_truncate_at_budget(self) -> None:
        second_resource = ResourceKey(
            namespace="test",
            node="node-a",
            layer="control",
            kind="opaque.item",
            parts=(("id", "two"),),
        )
        snapshots = tuple(
            SnapshotObservation(
                resource=resource,
                observed_at_min_ns=10 + index,
                observed_at_max_ns=10 + index,
                state=PropertyPatch(set_values={"status": "up"}, complete=True),
                provenance=Provenance.OBSERVED,
                quality=Quality.EXACT,
                evidence=Evidence(
                    ARTIFACT_ID,
                    f"record:{index}",
                    10 + index,
                    "clock-a",
                ),
            )
            for index, resource in enumerate((RESOURCE, second_resource))
        )
        world = IngestionRevisionWorld(
            basis=BASIS,
            snapshots=snapshots,
            relationship_observations=(),
        )
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.real-world-scan",
            outputs=(_finding(),),
            scan_world=True,
        )
        record = _register(registry, plugin, "primary", "c")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))

        with self.assertRaisesRegex(
            ConsistencyMaterializationError,
            "provider failed",
        ):
            materialize_revision_consistency(
                plan=plan,
                router=_router((record,), plan),
                world=world,
                artifact_ids={ARTIFACT_ID},
                limits=ConsistencyMaterializationLimits(max_world_reads=1),
            )

    def test_large_valid_capture_vector_uses_its_explicit_basis_budget(self) -> None:
        capture_count = 10_000
        basis = replace(
            BASIS,
            capture_ranges=tuple(
                CaptureRange(
                    scope=f"node:node-a/artifact:{index:05d}/clock:utc",
                    observed_at_min_ns=index,
                    observed_at_max_ns=index,
                    clock_domain="utc",
                )
                for index in range(capture_count)
            ),
        )
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.large-capture-vector",
            outputs=(_finding(basis=basis),),
        )
        record = _register(registry, plugin, "primary", "d")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))

        result = materialize_revision_consistency(
            plan=plan,
            router=_router((record,), plan),
            world=_World(basis),
            artifact_ids={ARTIFACT_ID},
        )

        self.assertEqual(
            len(result.metadata_projection()["basis"]["capture_ranges"]),
            capture_count,
        )
        with self.assertRaisesRegex(
            ConsistencyMaterializationError,
            "capture-range limit",
        ):
            materialize_revision_consistency(
                plan=plan,
                router=_router((record,), plan),
                world=_World(basis),
                artifact_ids={ARTIFACT_ID},
                limits=ConsistencyMaterializationLimits(
                    max_capture_ranges=capture_count - 1,
                ),
            )

    def test_node_resolution_count_is_bounded_before_provider_output_projection(
        self,
    ) -> None:
        resolution = ResolvedNodeBasis(
            node_id="node-a",
            local_clock_domain=None,
            local_min_ns=None,
            local_max_ns=None,
            absolute_min_ns=None,
            absolute_max_ns=None,
            mapping_method=None,
            quality=Quality.UNKNOWN,
            reason_code="not-observed",
        )
        basis = replace(
            BASIS,
            node_resolutions=(resolution, replace(resolution, node_id="node-b")),
        )
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.node-resolution-bound",
            outputs=(_finding(),),
        )
        record = _register(registry, plugin, "primary", "e")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))

        with self.assertRaisesRegex(
            ConsistencyMaterializationError,
            "node-resolution limit",
        ):
            materialize_revision_consistency(
                plan=plan,
                router=_router((record,), plan),
                world=_World(basis),
                artifact_ids={ARTIFACT_ID},
                limits=ConsistencyMaterializationLimits(max_node_resolutions=1),
            )

    def test_mutated_basis_containers_fail_closed_before_traversal(self) -> None:
        class ExplodingContainer:
            def __len__(self):
                raise AssertionError("must not inspect a non-tuple container")

            def __iter__(self):
                raise AssertionError("must not traverse a non-tuple container")

        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.mutated-basis-container",
            outputs=(_finding(),),
        )
        record = _register(registry, plugin, "primary", "f")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        router = _router((record,), plan)

        invalid_bases: list[WorldBasis] = []
        for invalid_capture_ranges in (None, [], ExplodingContainer()):
            basis = replace(BASIS)
            object.__setattr__(basis, "capture_ranges", invalid_capture_ranges)
            invalid_bases.append(basis)
        capture = CaptureRange(
            scope="node:node-a/artifact:one/clock:utc",
            observed_at_min_ns=1,
            observed_at_max_ns=1,
            clock_domain="utc",
        )
        object.__setattr__(capture, "evidence", ExplodingContainer())
        invalid_bases.append(replace(BASIS, capture_ranges=(capture,)))

        for basis in invalid_bases:
            with (
                self.subTest(capture_ranges=type(basis.capture_ranges).__name__),
                self.assertRaises(ConsistencyMaterializationError),
            ):
                materialize_revision_consistency(
                    plan=plan,
                    router=router,
                    world=_World(basis),
                    artifact_ids={ARTIFACT_ID},
                )

    def test_mutated_basis_scalars_fail_before_generic_projection(self) -> None:
        class ForeignKind(Enum):
            VALUE = "x" * 70_000

        @dataclass(frozen=True)
        class ForeignScalar:
            payload: str

        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin("test.mutated-basis-scalar", outputs=())
        record = _register(registry, plugin, "primary", "a")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        router = _router((record,), plan)

        invalid_bases: list[WorldBasis] = []
        invalid_kind = replace(BASIS)
        object.__setattr__(invalid_kind, "kind", ForeignKind.VALUE)
        invalid_bases.append(invalid_kind)
        invalid_clock = replace(BASIS)
        object.__setattr__(invalid_clock, "clock_domain", ForeignScalar("unsafe"))
        invalid_bases.append(invalid_clock)

        for basis in invalid_bases:
            with (
                self.subTest(field=type(basis.kind).__name__),
                self.assertRaisesRegex(
                    ConsistencyMaterializationError,
                    "world basis",
                ),
            ):
                materialize_revision_consistency(
                    plan=plan,
                    router=router,
                    world=_World(basis),
                    artifact_ids={ARTIFACT_ID},
                )

    def test_maximum_core_capture_scope_survives_client_projection(self) -> None:
        node_id = "n" * 256
        clock_domain = "c" * 256
        scope = (
            f"node:{node_id}/artifact:{ARTIFACT_ID}/clock:{clock_domain}"
        )
        basis = replace(
            BASIS,
            capture_ranges=(
                CaptureRange(
                    scope=scope,
                    observed_at_min_ns=1,
                    observed_at_max_ns=1,
                    clock_domain=clock_domain,
                ),
            ),
        )
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.maximum-capture-scope",
            outputs=(_finding(basis=basis),),
        )
        record = _register(registry, plugin, "primary", "b")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))

        result = materialize_revision_consistency(
            plan=plan,
            router=_router((record,), plan),
            world=_World(basis),
            artifact_ids={ARTIFACT_ID},
        )
        projected = project_consistency_materialization_for_client(
            result.metadata_projection()
        )

        self.assertGreater(len(scope), 512)
        self.assertEqual(projected["basis"]["capture_ranges"][0]["scope"], scope)

    def test_serialized_budget_counts_every_published_diagnostic_copy(self) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.storage-budget",
            outputs=(_finding(summary="é" * 100), _diagnostic()),
        )
        record = _register(registry, plugin, "primary", "e")
        plan = _plan(_pin(record, plugin.schema, "primary_parser"))
        router = _router((record,), plan)
        generous = materialize_revision_consistency(
            plan=plan,
            router=router,
            world=_World(),
            artifact_ids={ARTIFACT_ID},
        )
        published_projection = _published_consistency_storage_projection(generous)
        self.assertEqual(
            published_projection["_ingestion"],
            {
                "mode": "core-ingestion-v3",
                "plugin_execution_plan_digest": generous.plan_digest,
                "consistency_materialization_status": "complete",
            },
        )
        self.assertEqual(
            published_projection["inventory"], {"mode": "core-ingestion-v3"}
        )
        exact_bytes = len(canonical_json(published_projection).encode("utf-8"))
        self.assertGreater(
            exact_bytes,
            len(
                strict_canonical_json_bytes(
                    _published_consistency_storage_projection(generous)
                )
            ),
        )

        exact = materialize_revision_consistency(
            plan=plan,
            router=router,
            world=_World(),
            artifact_ids={ARTIFACT_ID},
            limits=ConsistencyMaterializationLimits(max_serialized_bytes=exact_bytes),
        )
        self.assertEqual(exact.dataset_fragment(), generous.dataset_fragment())
        with self.assertRaisesRegex(
            ConsistencyMaterializationError,
            "aggregate byte limit",
        ):
            materialize_revision_consistency(
                plan=plan,
                router=router,
                world=_World(),
                artifact_ids={ARTIFACT_ID},
                limits=ConsistencyMaterializationLimits(
                    max_serialized_bytes=exact_bytes - 1
                ),
            )

    def test_persisted_consistency_records_reject_impossible_canonical_shapes(
        self,
    ) -> None:
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.persisted-contract",
            outputs=(_finding(), _diagnostic()),
        )
        registered = _register(registry, plugin, "primary", "f")
        plan = _plan(_pin(registered, plugin.schema, "primary_parser"))
        result = materialize_revision_consistency(
            plan=plan,
            router=_router((registered,), plan),
            world=_World(),
            artifact_ids={ARTIFACT_ID},
        )
        fragment = result.dataset_fragment()
        finding = fragment["findings"][0]
        diagnostic = fragment["consistency_diagnostics"][0]
        admitted = frozenset({ARTIFACT_ID})
        validate_materialized_consistency_finding(
            finding,
            artifact_ids=admitted,
        )
        validate_materialized_consistency_diagnostic(
            diagnostic,
            artifact_ids=admitted,
        )

        tuple_registry = PluginRegistry(allow_manifest_identity=True)
        tuple_plugin = _ConsistencyPlugin(
            "test.persisted-tuple-details",
            outputs=(
                replace(_finding(), details={"items": ("a", "b")}),
                replace(_diagnostic(), details={"items": ("a", "b")}),
            ),
        )
        tuple_registered = _register(tuple_registry, tuple_plugin, "tuple", "e")
        tuple_plan = _plan(
            _pin(tuple_registered, tuple_plugin.schema, "primary_parser")
        )
        tuple_fragment = materialize_revision_consistency(
            plan=tuple_plan,
            router=_router((tuple_registered,), tuple_plan),
            world=_World(),
            artifact_ids={ARTIFACT_ID},
        ).dataset_fragment()
        self.assertEqual(tuple_fragment["findings"][0]["details"]["items"], ["a", "b"])
        self.assertEqual(
            tuple_fragment["consistency_diagnostics"][0]["details"]["items"],
            ["a", "b"],
        )
        validate_materialized_consistency_finding(
            tuple_fragment["findings"][0],
            artifact_ids=admitted,
        )
        validate_materialized_consistency_diagnostic(
            tuple_fragment["consistency_diagnostics"][0],
            artifact_ids=admitted,
        )

        def reidentify(record: dict[str, Any], identity_field: str) -> None:
            payload = dict(record)
            payload.pop(identity_field, None)
            record[identity_field] = "sha256:" + sha256(
                strict_canonical_json_bytes(payload)
            ).hexdigest()

        def reidentify_resource(reference: dict[str, Any]) -> None:
            identity = reference["typed_resource_key"]
            digest = sha256(canonical_json(identity).encode("utf-8")).hexdigest()[:32]
            reference["resource_id"] = (
                f"{identity['namespace']}/{identity['node']}/{identity['layer']}/"
                f"{identity['kind']}/{digest}"
            )

        wrong_finding_identity = deepcopy(finding)
        wrong_finding_identity["finding_id"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_materialized_consistency_finding(
                wrong_finding_identity,
                artifact_ids=admitted,
            )

        wrong_diagnostic_identity = deepcopy(diagnostic)
        wrong_diagnostic_identity["diagnostic_id"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_materialized_consistency_diagnostic(
                wrong_diagnostic_identity,
                artifact_ids=admitted,
            )

        empty_finding_producer = deepcopy(finding)
        empty_finding_producer["producer"] = {}
        reidentify(empty_finding_producer, "finding_id")
        with self.assertRaisesRegex(ValueError, "exact canonical fields"):
            validate_materialized_consistency_finding(
                empty_finding_producer,
                artifact_ids=admitted,
            )

        empty_diagnostic_producer = deepcopy(diagnostic)
        empty_diagnostic_producer["producer"] = {}
        reidentify(empty_diagnostic_producer, "diagnostic_id")
        with self.assertRaisesRegex(ValueError, "exact canonical fields"):
            validate_materialized_consistency_diagnostic(
                empty_diagnostic_producer,
                artifact_ids=admitted,
            )

        for label, field, replacement in (
            ("whitespace-plugin-id", "plugin_id", " "),
            ("unselected-roles", "roles", []),
        ):
            with self.subTest(provider_shape=label):
                invalid_finding_provider = deepcopy(finding)
                invalid_finding_provider["producer"][field] = replacement
                reidentify(invalid_finding_provider, "finding_id")
                with self.assertRaises(ValueError):
                    validate_materialized_consistency_finding(
                        invalid_finding_provider,
                        artifact_ids=admitted,
                    )

                invalid_diagnostic_provider = deepcopy(diagnostic)
                invalid_diagnostic_provider["producer"][field] = replacement
                reidentify(invalid_diagnostic_provider, "diagnostic_id")
                with self.assertRaises(ValueError):
                    validate_materialized_consistency_diagnostic(
                        invalid_diagnostic_provider,
                        artifact_ids=admitted,
                    )

        overlong_artifact_set = frozenset({ARTIFACT_ID, FOREIGN_ARTIFACT_ID})
        artifact_limits = ConsistencyMaterializationLimits(max_artifact_ids=1)
        with self.assertRaisesRegex(ValueError, "artifact limit"):
            validate_materialized_consistency_basis(
                finding["basis"],
                artifact_ids=overlong_artifact_set,
                limits=artifact_limits,
            )
        with self.assertRaisesRegex(ValueError, "artifact limit"):
            validate_materialized_consistency_finding(
                finding,
                artifact_ids=overlong_artifact_set,
                limits=artifact_limits,
            )
        with self.assertRaisesRegex(ValueError, "artifact limit"):
            validate_materialized_consistency_diagnostic(
                diagnostic,
                artifact_ids=overlong_artifact_set,
                limits=artifact_limits,
            )

        overlong_resources = deepcopy(finding)
        overlong_resources["resources"] = [finding["resources"][0]] * 2
        reidentify(overlong_resources, "finding_id")
        with self.assertRaisesRegex(ValueError, "resources do not match"):
            validate_materialized_consistency_finding(
                overlong_resources,
                artifact_ids=admitted,
                limits=ConsistencyMaterializationLimits(
                    max_resource_references=1,
                ),
            )

        for label, mutate in (
            (
                "empty",
                lambda identity: identity.__setitem__("parts", []),
            ),
            (
                "too-many",
                lambda identity: identity.__setitem__(
                    "parts",
                    [
                        {
                            "name": f"part_{index}",
                            "value": {"type": "integer", "value": str(index)},
                        }
                        for index in range(33)
                    ],
                ),
            ),
            (
                "duplicate",
                lambda identity: identity.__setitem__(
                    "parts",
                    [
                        {"name": "same", "value": {"type": "integer", "value": "1"}},
                        {"name": "same", "value": {"type": "integer", "value": "2"}},
                    ],
                ),
            ),
            (
                "arbitrary",
                lambda identity: identity["parts"][0].__setitem__(
                    "value",
                    {"arbitrary": True},
                ),
            ),
        ):
            with self.subTest(resource_key_shape=label):
                candidate = deepcopy(finding)
                reference = candidate["resource_references"][0]
                mutate(reference["typed_resource_key"])
                reidentify_resource(reference)
                candidate["resources"] = [reference["resource_id"]]
                reidentify(candidate, "finding_id")
                with self.assertRaises(ValueError):
                    validate_materialized_consistency_finding(
                        candidate,
                        artifact_ids=admitted,
                    )

        for unsafe_integer in (1 << 60, -(1 << 60)):
            with self.subTest(unsafe_integer=unsafe_integer):
                candidate = deepcopy(finding)
                candidate["details"]["unsafe"] = unsafe_integer
                reidentify(candidate, "finding_id")
                with self.assertRaisesRegex(ValueError, "details are not canonical"):
                    validate_materialized_consistency_finding(
                        candidate,
                        artifact_ids=admitted,
                    )

        long_text = deepcopy(finding)
        long_text["details"] = {"text": "漢" * 30_000}
        reidentify(long_text, "finding_id")
        validate_materialized_consistency_finding(
            long_text,
            artifact_ids=admitted,
        )

        foreign = deepcopy(finding)
        foreign["evidence"][0]["artifact_id"] = str(FOREIGN_ARTIFACT_ID)
        reidentify(foreign, "finding_id")
        with self.assertRaisesRegex(ValueError, "outside the revision"):
            validate_materialized_consistency_finding(
                foreign,
                artifact_ids=admitted,
            )

        unsafe_diagnostic = deepcopy(diagnostic)
        unsafe_diagnostic["details"]["unsafe"] = 1 << 60
        reidentify(unsafe_diagnostic, "diagnostic_id")
        with self.assertRaisesRegex(ValueError, "details are not canonical"):
            validate_materialized_consistency_diagnostic(
                unsafe_diagnostic,
                artifact_ids=admitted,
            )

    def test_basis_evidence_digest_is_canonical_at_every_storage_location(self) -> None:
        uppercase = Evidence(
            ARTIFACT_ID,
            "basis:uppercase",
            15,
            "clock-a",
            "A" * 64,
        )
        basis = WorldBasis(
            kind=WorldBasisKind.OBSERVED_CAPTURE_VECTOR,
            requested_time_ns=None,
            resolved_at_min_ns=10,
            resolved_at_max_ns=20,
            capture_ranges=(CaptureRange("capture", 10, 20, (uppercase,), "clock-a"),),
            provenance=Provenance.OBSERVED,
            quality=Quality.EXACT,
            clock_domain="clock-a",
            node_resolutions=(
                ResolvedNodeBasis(
                    node_id="node-a",
                    local_clock_domain="clock-a",
                    local_min_ns=10,
                    local_max_ns=20,
                    absolute_min_ns=10,
                    absolute_max_ns=20,
                    mapping_method="identity",
                    quality=Quality.EXACT,
                    evidence=(uppercase,),
                ),
            ),
            watermark=ReconstructionWatermark(
                scope=WatermarkScope("node-a", "default"),
                local_time_ns=20,
                clock_domain="clock-a",
                provenance=Provenance.OBSERVED,
                quality=Quality.EXACT,
                absolute_min_ns=20,
                absolute_max_ns=20,
                mapping_method="identity",
                evidence=(uppercase,),
            ),
        )
        registry = PluginRegistry(allow_manifest_identity=True)
        plugin = _ConsistencyPlugin(
            "test.basis-evidence-canonical",
            outputs=(_finding(basis=basis),),
        )
        registered = _register(registry, plugin, "basis", "b")
        plan = _plan(_pin(registered, plugin.schema, "primary_parser"))
        fragment = materialize_revision_consistency(
            plan=plan,
            router=_router((registered,), plan),
            world=_World(basis),
            artifact_ids={ARTIFACT_ID},
        ).dataset_fragment()
        stored_basis = fragment["consistency_materialization"]["basis"]
        excerpts = (
            stored_basis["capture_ranges"][0]["evidence"][0]["excerpt_sha256"],
            stored_basis["node_resolutions"][0]["evidence"][0]["excerpt_sha256"],
            stored_basis["watermark"]["evidence"][0]["excerpt_sha256"],
        )
        self.assertEqual(excerpts, ("a" * 64,) * 3)
        self.assertEqual(fragment["findings"][0]["basis"], stored_basis)
        validate_materialized_consistency_basis(
            stored_basis,
            artifact_ids=frozenset({ARTIFACT_ID}),
        )
        validate_materialized_consistency_finding(
            fragment["findings"][0],
            artifact_ids=frozenset({ARTIFACT_ID}),
        )


if __name__ == "__main__":
    unittest.main()
