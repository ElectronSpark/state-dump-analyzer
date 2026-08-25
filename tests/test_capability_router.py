from __future__ import annotations

import unittest
from dataclasses import replace
from typing import Any
from unittest.mock import patch

from router_dump_analyzer.capability_executor import (
    PluginCapabilityExecutor,
    PluginCapabilityOutputError,
)
from router_dump_analyzer.capability_router import (
    CapabilityPlanUnavailableError,
    CapabilityProviderRegistry,
    CapabilityRouteAmbiguousError,
    CapabilityRouteMissingError,
    CapabilityRouteSelector,
    CapabilityRouteStaleError,
    PlanBoundCapabilityRouter,
    RevisionSetCapabilityFailureCode,
    RevisionSetCapabilityKey,
    RevisionSetCapabilityRouter,
)
from router_dump_analyzer.ingestion import IngestionCoordinator
from router_dump_analyzer.ingestion_pipeline import PluginRegistry, RegisteredPlugin
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    CorrelationWindow,
    EvidenceAnalysisFact,
    EvidenceAnalysisKind,
    EvidenceAnalysisObservation,
    EvidenceAnalysisRequest,
    PluginCapability,
    PluginManifest,
    PluginSchema,
    Provenance,
    Quality,
    ReadOnlyWorld,
    ReconstructionSupport,
    ResourceKindDescriptor,
    WorldBasis,
    WorldBasisKind,
)
from router_dump_analyzer.plugin_execution_plan import (
    PLUGIN_EXECUTION_PLAN_VERSION,
    PLUGIN_EXECUTION_PLAN_VERSION_V1,
    PLUGIN_EXECUTION_PLAN_VERSION_V3,
    DecoderIdentity,
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
    PluginExecutionPlanAuthority,
)
from router_dump_analyzer.plugin_identity import PluginExecutableIdentityError
from router_dump_analyzer.plugin_schema_identity import (
    PluginSchemaIdentityError,
    plugin_schema_digest,
)

EMPTY_CONFIGURATION = (
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
)


class _NoopTraceDecoder:
    def iter_ctf(self, *args: Any, **kwargs: Any) -> tuple[()]:
        del args, kwargs
        return ()


def _schema(kind: str = "opaque.item") -> PluginSchema:
    return PluginSchema(
        resource_kinds=(
            ResourceKindDescriptor(
                kind=kind,
                label="Opaque item",
                key_fields=("id",),
                properties=(),
            ),
        ),
        relationship_types=(),
    )


class _RoutingPlugin(AnalyzerPluginBase):
    def __init__(
        self,
        plugin_id: str,
        schema: PluginSchema | None = None,
        *,
        plugin_version: str = "1",
        capabilities: frozenset[PluginCapability] | None = None,
    ) -> None:
        self.manifest = PluginManifest(
            plugin_id=plugin_id,
            plugin_version=plugin_version,
            core_api_version=CORE_PLUGIN_API_VERSION,
            supported_platforms=("test",),
            supported_software_versions="*",
            capabilities=(
                frozenset({PluginCapability.CORRELATION})
                if capabilities is None
                else capabilities
            ),
            reconstruction_default=ReconstructionSupport.EXACT,
        )
        self.schema = schema or _schema()
        self.correlate_calls = 0
        self.project_relationships_calls = 0
        self.mutate_schema_during_correlation = False
        self.analyze_calls = 0

    def describe(self) -> PluginSchema:
        return self.schema

    def correlate(self, reader: Any, window: CorrelationWindow):
        del reader, window
        self.correlate_calls += 1
        if self.mutate_schema_during_correlation:
            self.schema = _schema("opaque.changed")
        return ()

    def project_relationships(self, world: ReadOnlyWorld):
        del world
        self.project_relationships_calls += 1
        return ()

    def analyze_evidence(self, request: EvidenceAnalysisRequest):
        self.analyze_calls += 1
        digest = request.facts[0].reference_digest
        return (
            EvidenceAnalysisObservation(
                observation_id="observation-1",
                category="route_resolution",
                summary="The selected provider interpreted the route evidence.",
                cited_reference_digests=(digest,),
                quality=Quality.EXACT,
            ),
        )


def _registered(
    plugin: _RoutingPlugin,
    instance_id: str,
    *,
    configuration_digest: str = EMPTY_CONFIGURATION,
    decoder_identity: DecoderIdentity | None = None,
) -> RegisteredPlugin:
    registry = PluginRegistry()
    return registry.register(
        plugin,
        coordinator=(
            IngestionCoordinator(trace_decoder=_NoopTraceDecoder())
            if decoder_identity is not None
            else None
        ),
        instance_id=instance_id,
        distribution_name=f"{plugin.manifest.plugin_id}.distribution",
        distribution_version="1+test",
        entry_point_name=instance_id,
        configuration_digest=configuration_digest,
        decoder_identity=decoder_identity,
    )


def _pin(
    registered: RegisteredPlugin,
    schema: PluginSchema,
    *roles: str,
) -> PluginExecutionPin:
    return PluginExecutionPin(
        instance_id=registered.instance_id,
        plugin_id=registered.plugin_id,
        plugin_version=registered.plugin_version,
        core_api_version=registered.core_api_version,
        artifact=PluginArtifactIdentity(
            distribution_name=registered.distribution_name,
            distribution_version=registered.distribution_version,
            package_hash=registered.package_hash,
            entry_point_name=registered.entry_point_name,
            module_target=registered.module_target,
        ),
        configuration_digest=registered.configuration_digest,
        schema_digest=plugin_schema_digest(schema),
        registered_execution_identity=registered.registered_execution_identity,
        schema_versions=registered.schema_versions,
        capabilities=registered.capabilities,
        roles=tuple(roles),
    )


def _plan(
    node_id: str,
    basis: str,
    *pins: PluginExecutionPin,
    authority: PluginExecutionPlanAuthority = PluginExecutionPlanAuthority.PROCESS,
    contract_version: str = PLUGIN_EXECUTION_PLAN_VERSION_V3,
) -> PluginExecutionPlan:
    return PluginExecutionPlan(
        node_id=node_id,
        basis_revision_id=basis,
        plugins=tuple(pins),
        execution_plan_authority=authority,
        contract_version=contract_version,
    )


def _router(
    providers: CapabilityProviderRegistry,
    plan: PluginExecutionPlan | None,
    *,
    catalog_revision_id: str = "catalog-revision-1",
    member_id: str = "member-1",
    allow_inline_only: bool = False,
) -> PlanBoundCapabilityRouter:
    return PlanBoundCapabilityRouter(
        providers,
        plan,
        catalog_revision_id=catalog_revision_id,
        member_id=member_id,
        allow_inline_only=allow_inline_only,
    )


class _World:
    @property
    def basis(self) -> WorldBasis:
        return WorldBasis(
            kind=WorldBasisKind.OBSERVED_CAPTURE_VECTOR,
            requested_time_ns=None,
            resolved_at_min_ns=None,
            resolved_at_max_ns=None,
            capture_ranges=(),
            provenance=Provenance.RECONSTRUCTED,
            quality=Quality.EXACT,
        )

    @property
    def perspective_ref(self) -> None:
        return None

    def state_of(self, resource: Any) -> None:
        del resource
        return None

    def iter_states(self, **_kwargs: Any) -> tuple[()]:
        return ()

    def related(self, resource: Any, **_kwargs: Any) -> tuple[()]:
        del resource
        return ()

    def iter_relationships(self, **_kwargs: Any) -> tuple[()]:
        return ()


class CapabilityRouterTests(unittest.TestCase):
    def test_relationship_projection_routes_to_the_selected_plan_provider(
        self,
    ) -> None:
        capabilities = frozenset({PluginCapability.RELATIONSHIP_PROJECTION})
        first = _RoutingPlugin("test.project.first", capabilities=capabilities)
        second = _RoutingPlugin("test.project.second", capabilities=capabilities)
        first_registered = _registered(first, "project.first")
        second_registered = _registered(second, "project.second")
        router = _router(
            CapabilityProviderRegistry((first_registered, second_registered)),
            _plan(
                "node-a",
                "basis-a",
                _pin(first_registered, first.schema, "primary_parser"),
                _pin(
                    second_registered,
                    second.schema,
                    "revision_relationship_projection",
                ),
            ),
        )
        route = router.resolve(
            CapabilityRouteSelector(
                PluginCapability.RELATIONSHIP_PROJECTION,
                role="revision_relationship_projection",
            )
        )

        invocation = route.project_relationships(_World())  # type: ignore[arg-type]

        self.assertEqual(invocation.provider.pin.instance_id, "project.second")
        self.assertEqual(invocation.result.declarations, ())
        self.assertEqual(first.project_relationships_calls, 0)
        self.assertEqual(second.project_relationships_calls, 1)

    def test_evidence_analysis_routes_to_one_exact_plan_instance(self) -> None:
        capabilities = frozenset({PluginCapability.EVIDENCE_ANALYSIS})
        first = _RoutingPlugin("test.analysis", capabilities=capabilities)
        second = _RoutingPlugin("test.analysis", capabilities=capabilities)
        first_registered = _registered(first, "analysis.first")
        second_registered = _registered(second, "analysis.second")
        router = _router(
            CapabilityProviderRegistry((first_registered, second_registered)),
            _plan(
                "node-a",
                "basis-a",
                _pin(first_registered, first.schema, "primary_parser"),
                _pin(second_registered, second.schema, "analysis_assistant"),
            ),
            catalog_revision_id="revision-a",
            member_id="revision-a",
        )
        route = router.resolve(
            CapabilityRouteSelector(
                PluginCapability.EVIDENCE_ANALYSIS,
                instance_id="analysis.second",
            )
        )
        digest = "sha256:" + "a" * 64
        request = EvidenceAnalysisRequest(
            invocation_id="invocation-a",
            analysis_kind=EvidenceAnalysisKind.ROUTE_TRACE,
            facts=(
                EvidenceAnalysisFact(
                    reference_digest=digest,
                    evidence_kind="event",
                    subject_kind="normalized_event",
                    node_id="node-a",
                    revision_id="revision-a",
                    payload_schema="example.event.v1",
                    fact_provenance="log_derived",
                    time_basis="revision_start_relative_ns",
                    time_start_ns=1,
                    time_end_ns=1,
                    time_clock_domain=None,
                    payload={"event": "route-change"},
                ),
            ),
            max_observations=2,
        )
        invocation = route.analyze_evidence(request)
        self.assertEqual(invocation.provider.pin.instance_id, "analysis.second")
        self.assertEqual(invocation.provider.catalog_revision_id, "revision-a")
        self.assertEqual(len(invocation.result.observations), 1)
        self.assertEqual(first.analyze_calls, 0)
        self.assertEqual(second.analyze_calls, 1)

    def test_retained_v1_plan_is_passive_and_cannot_bind_provider(self) -> None:
        plugin = _RoutingPlugin("test.legacy")
        registered = _registered(plugin, "legacy.primary")
        legacy_pin = replace(
            _pin(registered, plugin.schema, "primary_parser", "correlator"),
            registered_execution_identity="sha256:" + "0" * 64,
            process_bootstrap_digest=None,
        )
        plan = PluginExecutionPlan(
            node_id="node-a",
            basis_revision_id="basis-a",
            plugins=(legacy_pin,),
            contract_version=PLUGIN_EXECUTION_PLAN_VERSION_V1,
        )
        with self.assertRaisesRegex(
            CapabilityPlanUnavailableError,
            "passive catalog records",
        ):
            _router(
                CapabilityProviderRegistry((registered,)),
                plan,
            )
        self.assertEqual(plugin.correlate_calls, 0)

    def test_v4_process_bootstrap_digest_binds_exact_registered_provider(self) -> None:
        plugin = _RoutingPlugin("test.v4-bootstrap")
        record = _registered(plugin, "v4-bootstrap.primary")
        pin = replace(
            _pin(record, plugin.schema, "primary_parser", "correlator"),
            process_bootstrap_digest=record.process_bootstrap_digest,
        )
        providers = CapabilityProviderRegistry((record,))
        router = _router(
            providers,
            _plan(
                "node-a",
                "basis-a",
                pin,
                contract_version=PLUGIN_EXECUTION_PLAN_VERSION,
            ),
        )
        router.resolve(CapabilityRouteSelector(PluginCapability.CORRELATION))
        with self.assertRaises(CapabilityRouteStaleError):
            _router(
                providers,
                _plan(
                    "node-a",
                    "basis-a",
                    replace(
                        pin,
                        process_bootstrap_digest="sha256:" + "0" * 64,
                    ),
                    contract_version=PLUGIN_EXECUTION_PLAN_VERSION,
                ),
            )

    def test_two_nodes_bind_different_plugins_for_the_same_capability(self) -> None:
        alpha = _RoutingPlugin("test.alpha")
        beta = _RoutingPlugin("test.beta")
        alpha_record = _registered(alpha, "alpha.primary")
        beta_record = _registered(beta, "beta.primary")
        providers = CapabilityProviderRegistry((beta_record, alpha_record))
        selector = CapabilityRouteSelector(PluginCapability.CORRELATION)

        alpha_route = _router(
            providers,
            _plan(
                "node-a",
                "source-a",
                _pin(alpha_record, alpha.schema, "primary_parser"),
            ),
        ).resolve(selector)
        beta_route = _router(
            providers,
            _plan(
                "node-b",
                "source-b",
                _pin(beta_record, beta.schema, "primary_parser"),
            ),
            catalog_revision_id="catalog-revision-2",
            member_id="member-2",
        ).resolve(selector)

        alpha_result = alpha_route.correlate(
            object(),  # type: ignore[arg-type]
            CorrelationWindow(0, 1, max_events=1, max_world_reads=1),
        )
        beta_result = beta_route.correlate(
            object(),  # type: ignore[arg-type]
            CorrelationWindow(0, 1, max_events=1, max_world_reads=1),
        )

        self.assertEqual(alpha.correlate_calls, 1)
        self.assertEqual(beta.correlate_calls, 1)
        self.assertEqual(alpha_result.provider.pin.plugin_id, "test.alpha")
        self.assertEqual(beta_result.provider.pin.plugin_id, "test.beta")
        self.assertEqual(alpha_result.provider.node_id, "node-a")
        self.assertEqual(beta_result.provider.member_id, "member-2")

    def test_same_plugin_instances_require_role_or_instance_disambiguation(
        self,
    ) -> None:
        first = _RoutingPlugin("test.same")
        second = _RoutingPlugin("test.same")
        first_record = _registered(first, "same.primary")
        second_record = _registered(
            second,
            "same.observer",
            configuration_digest="sha256:" + "b" * 64,
        )
        providers = CapabilityProviderRegistry((first_record, second_record))
        first_pin = _pin(first_record, first.schema, "primary_parser", "active")
        second_pin = _pin(second_record, second.schema, "observer")
        router = _router(
            providers,
            _plan(
                "node-a",
                "source-a",
                first_pin,
                second_pin,
                authority=PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED,
            ),
            allow_inline_only=True,
        )

        with self.assertRaises(CapabilityRouteAmbiguousError):
            router.resolve(CapabilityRouteSelector(PluginCapability.CORRELATION))
        by_role = router.resolve(
            CapabilityRouteSelector(
                PluginCapability.CORRELATION,
                role="observer",
            )
        )
        by_instance = router.resolve(
            CapabilityRouteSelector(
                PluginCapability.CORRELATION,
                instance_id="same.primary",
            )
        )
        self.assertEqual(by_role.provider.pin.instance_id, "same.observer")
        self.assertEqual(by_instance.provider.pin.instance_id, "same.primary")

    def test_registration_and_plan_order_never_break_a_qualified_route(self) -> None:
        first = _RoutingPlugin("test.order")
        second = _RoutingPlugin("test.order")
        first_record = _registered(first, "order.primary")
        second_record = _registered(
            second,
            "order.observer",
            configuration_digest="sha256:" + "c" * 64,
        )
        primary = _pin(first_record, first.schema, "primary_parser")
        observer = _pin(second_record, second.schema, "observer")
        selector = CapabilityRouteSelector(
            PluginCapability.CORRELATION,
            instance_id="order.observer",
        )
        selected = []
        for records, pins in (
            ((first_record, second_record), (primary, observer)),
            ((second_record, first_record), (observer, primary)),
        ):
            route = _router(
                CapabilityProviderRegistry(records),
                _plan(
                    "node-a",
                    "source-a",
                    *pins,
                    authority=(PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED),
                ),
                allow_inline_only=True,
            ).resolve(selector)
            selected.append(route.provider.pin.instance_id)
        self.assertEqual(selected, ["order.observer", "order.observer"])

    def test_planless_missing_and_wrong_method_fail_closed(self) -> None:
        plugin = _RoutingPlugin("test.missing")
        record = _registered(plugin, "missing.primary")
        providers = CapabilityProviderRegistry((record,))
        with self.assertRaises(CapabilityPlanUnavailableError):
            _router(providers, None)
        router = _router(
            providers,
            _plan(
                "node-a",
                "source-a",
                _pin(record, plugin.schema, "primary_parser"),
            ),
        )
        with self.assertRaises(CapabilityRouteMissingError):
            router.resolve(CapabilityRouteSelector(PluginCapability.CONSISTENCY_CHECK))
        route = router.resolve(CapabilityRouteSelector(PluginCapability.CORRELATION))
        with self.assertRaises(CapabilityRouteMissingError):
            route.check_consistency(object())  # type: ignore[arg-type]
        self.assertEqual(plugin.correlate_calls, 0)

    def test_every_pinned_identity_dimension_is_checked_before_hooks(self) -> None:
        plugin = _RoutingPlugin("test.stale")
        record = _registered(plugin, "stale.primary")
        baseline = _pin(record, plugin.schema, "primary_parser")
        artifact = baseline.artifact
        mutations = (
            replace(baseline, plugin_id="test.other"),
            replace(baseline, plugin_version="2"),
            replace(baseline, core_api_version="other"),
            replace(
                baseline,
                artifact=replace(artifact, distribution_name="other.distribution"),
            ),
            replace(
                baseline,
                artifact=replace(artifact, distribution_version="other"),
            ),
            replace(
                baseline,
                artifact=replace(
                    artifact,
                    package_hash="package-sha256:" + "d" * 64,
                ),
            ),
            replace(
                baseline,
                artifact=replace(artifact, entry_point_name="other.entry"),
            ),
            replace(
                baseline,
                artifact=replace(artifact, module_target="other:plugin"),
            ),
            replace(baseline, configuration_digest="sha256:" + "e" * 64),
            replace(baseline, schema_digest="sha256:" + "f" * 64),
            replace(baseline, schema_versions=("other.schema",)),
            replace(baseline, capabilities=(PluginCapability.STATUS_PARSE.value,)),
        )
        providers = CapabilityProviderRegistry((record,))
        for changed in mutations:
            with (
                self.subTest(pin=changed),
                self.assertRaises(CapabilityRouteStaleError),
            ):
                _router(providers, _plan("node-a", "source-a", changed))
        self.assertEqual(plugin.correlate_calls, 0)

    def test_live_schema_change_and_mid_call_mutation_discard_results(self) -> None:
        plugin = _RoutingPlugin("test.mutable")
        record = _registered(plugin, "mutable.primary")
        plan = _plan(
            "node-a",
            "source-a",
            _pin(record, plugin.schema, "primary_parser"),
        )
        providers = CapabilityProviderRegistry((record,))
        router = _router(providers, plan)
        route = router.resolve(CapabilityRouteSelector(PluginCapability.CORRELATION))
        plugin.mutate_schema_during_correlation = True
        with self.assertRaises(CapabilityRouteStaleError):
            route.correlate(
                object(),  # type: ignore[arg-type]
                CorrelationWindow(0, 1, max_events=1, max_world_reads=1),
            )
        self.assertEqual(plugin.correlate_calls, 1)

        with self.assertRaises(CapabilityRouteStaleError):
            _router(providers, plan)

    def test_registry_allows_same_plugin_version_as_distinct_instances(self) -> None:
        first = _registered(_RoutingPlugin("test.instances"), "instances.1")
        second = _registered(
            _RoutingPlugin("test.instances"),
            "instances.2",
            configuration_digest="sha256:" + "1" * 64,
        )
        providers = CapabilityProviderRegistry((second, first))
        self.assertEqual(providers.instance_ids(), ("instances.1", "instances.2"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            providers.add_registered(first)

    def test_manifest_only_provider_requires_matching_inline_plan_and_opt_in(
        self,
    ) -> None:
        plugin = _RoutingPlugin("test.manifest-only")
        compatibility = PluginRegistry(allow_manifest_identity=True)
        record = compatibility.register(
            plugin,
            package_hash="manifest-sha256:" + "6" * 64,
            instance_id="manifest.primary",
        )
        self.assertFalse(record.verify_package_bytes)
        providers = CapabilityProviderRegistry((record,))
        plan = _plan(
            "node-a",
            "basis-a",
            _pin(record, plugin.schema, "primary_parser"),
            authority=PluginExecutionPlanAuthority.TRUSTED_INLINE_MANIFEST,
        )
        with self.assertRaises(CapabilityRouteStaleError):
            _router(providers, plan)
        router = _router(providers, plan, allow_inline_only=True)
        route = router.resolve(CapabilityRouteSelector(PluginCapability.CORRELATION))
        self.assertEqual(route.provider.pin.instance_id, record.instance_id)

    def test_plan_bound_router_rejects_inline_only_primary_and_auxiliary(self) -> None:
        package_identity = "package-sha256:" + "7" * 64
        fallback_plugin = _RoutingPlugin("test.inline-only")
        with (
            patch(
                "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
                return_value=package_identity,
            ),
            patch(
                "router_dump_analyzer.ingestion_pipeline."
                "executable_module_target_fingerprint",
                side_effect=PluginExecutableIdentityError(
                    "target attestation unavailable"
                ),
            ),
        ):
            fallback = PluginRegistry(allow_manifest_identity=True).register(
                fallback_plugin,
                instance_id="inline-only",
            )

        # The compatibility record remains usable by trusted local callers and
        # may remain in their mutable provider directory. Only plan-bound use is
        # forbidden.
        PluginCapabilityExecutor(fallback.execution_plugin)
        strict_plugin = _RoutingPlugin("test.strict")
        strict = _registered(strict_plugin, "strict-primary")
        with patch(
            "router_dump_analyzer.ingestion_pipeline.executable_plugin_fingerprint",
            side_effect=lambda plugin: (
                package_identity if plugin is fallback_plugin else strict.package_hash
            ),
        ):
            providers = CapabilityProviderRegistry((strict, fallback))
            self.assertIs(
                providers.get_by_execution_identity(
                    fallback.instance_id,
                    fallback.registered_execution_identity,
                ),
                fallback,
            )
            with self.assertRaisesRegex(ValueError, "process provider snapshots"):
                providers.snapshot_exact(
                    (
                        (
                            fallback.instance_id,
                            fallback.registered_execution_identity,
                        ),
                    )
                )
            scenarios = (
                (
                    "primary",
                    _plan(
                        "node-primary",
                        "basis-primary",
                        _pin(
                            fallback,
                            fallback_plugin.schema,
                            "primary_parser",
                        ),
                        authority=(
                            PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED
                        ),
                    ),
                ),
                (
                    "auxiliary",
                    _plan(
                        "node-auxiliary",
                        "basis-auxiliary",
                        _pin(strict, strict_plugin.schema, "primary_parser"),
                        _pin(
                            fallback,
                            fallback_plugin.schema,
                            "analysis_assistant",
                        ),
                        authority=(
                            PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED
                        ),
                    ),
                ),
            )
            for role, plan in scenarios:
                with (
                    self.subTest(role=role),
                    self.assertRaises(CapabilityRouteStaleError),
                ):
                    _router(providers, plan)
                with self.subTest(role=role, opted=True):
                    _router(providers, plan, allow_inline_only=True)

            process_claim = _plan(
                "node-process-claim",
                "basis-process-claim",
                _pin(fallback, fallback_plugin.schema, "primary_parser"),
            )
            with self.assertRaises(CapabilityRouteStaleError):
                _router(providers, process_claim, allow_inline_only=True)
            with self.assertRaisesRegex(TypeError, "exact boolean"):
                PlanBoundCapabilityRouter(
                    providers,
                    scenarios[0][1],
                    catalog_revision_id="catalog",
                    member_id="member",
                    allow_inline_only=1,  # type: ignore[arg-type]
                )

    def test_configuration_change_requires_a_new_logical_instance(self) -> None:
        first = _registered(_RoutingPlugin("test.lineage"), "lineage.primary")
        second = _registered(
            _RoutingPlugin("test.lineage"),
            "lineage.primary",
            configuration_digest="sha256:" + "9" * 64,
        )
        providers = CapabilityProviderRegistry((first,))
        with self.assertRaisesRegex(ValueError, "configuration"):
            providers.add_registered(second)

    def test_one_logical_instance_can_replay_two_installed_releases(self) -> None:
        old_plugin = _RoutingPlugin("test.upgrade", plugin_version="1")
        new_plugin = _RoutingPlugin("test.upgrade", plugin_version="2")
        old_record = _registered(old_plugin, "upgrade.primary")
        new_record = _registered(new_plugin, "upgrade.primary")
        providers = CapabilityProviderRegistry((new_record, old_record))
        selector = CapabilityRouteSelector(PluginCapability.CORRELATION)

        old_route = _router(
            providers,
            _plan(
                "node-a",
                "source-old",
                _pin(old_record, old_plugin.schema, "primary_parser"),
            ),
            catalog_revision_id="catalog-old",
        ).resolve(selector)
        new_route = _router(
            providers,
            _plan(
                "node-a",
                "source-new",
                _pin(new_record, new_plugin.schema, "primary_parser"),
            ),
            catalog_revision_id="catalog-new",
        ).resolve(selector)

        self.assertEqual(old_route.provider.pin.plugin_version, "1")
        self.assertEqual(new_route.provider.pin.plugin_version, "2")

    def test_unused_primary_decoder_does_not_block_optional_capabilities(self) -> None:
        decoder = DecoderIdentity(
            "test.decoder",
            "1",
            "sha256:" + "8" * 64,
        )
        plugin = _RoutingPlugin("test.decoder-capable")
        record = _registered(
            plugin,
            "decoder.primary",
            decoder_identity=decoder,
        )
        route = _router(
            CapabilityProviderRegistry((record,)),
            _plan(
                "node-a",
                "non-ctf-source",
                _pin(record, plugin.schema, "primary_parser"),
            ),
        ).resolve(CapabilityRouteSelector(PluginCapability.CORRELATION))

        result = route.correlate(
            object(),  # type: ignore[arg-type]
            CorrelationWindow(0, 1, max_events=1, max_world_reads=1),
        )
        self.assertEqual(result.provider.pin.instance_id, "decoder.primary")

    def test_decoder_is_rejected_for_a_non_primary_provider(self) -> None:
        decoder = DecoderIdentity(
            "test.decoder",
            "1",
            "sha256:" + "7" * 64,
        )
        primary_plugin = _RoutingPlugin("test.primary")
        observer_plugin = _RoutingPlugin("test.observer")
        primary = _registered(primary_plugin, "primary.instance")
        observer = _registered(
            observer_plugin,
            "observer.instance",
            decoder_identity=decoder,
        )
        with self.assertRaises(CapabilityRouteStaleError):
            _router(
                CapabilityProviderRegistry((primary, observer)),
                _plan(
                    "node-a",
                    "source-a",
                    _pin(primary, primary_plugin.schema, "primary_parser"),
                    _pin(observer, observer_plugin.schema, "observer"),
                ),
            )

    def test_ingestion_capabilities_are_not_returned_as_unusable_routes(self) -> None:
        with self.assertRaisesRegex(ValueError, "ingestion-owned"):
            CapabilityRouteSelector(PluginCapability.STATUS_PARSE)

    def test_schema_identity_budget_applies_across_all_descriptors(self) -> None:
        schema = PluginSchema(
            resource_kinds=tuple(
                ResourceKindDescriptor(
                    kind=f"opaque.item.{index}",
                    label="Opaque item",
                    key_fields=("id",),
                    properties=(),
                )
                for index in range(1_025)
            ),
            relationship_types=(),
        )
        with self.assertRaises(PluginSchemaIdentityError):
            plugin_schema_digest(schema)

    def test_revision_set_has_exact_unique_bounded_canonical_keys(self) -> None:
        plugin = _RoutingPlugin("test.revision-set")
        record = _registered(plugin, "revision-set.primary")
        providers = CapabilityProviderRegistry((record,))
        plan = _plan(
            "node-a",
            "source-a",
            _pin(record, plugin.schema, "primary_parser"),
        )
        first = _router(
            providers,
            plan,
            catalog_revision_id="catalog-b",
            member_id="member-b",
        )
        second = _router(
            providers,
            plan,
            catalog_revision_id="catalog-a",
            member_id="member-a",
        )
        revision_set = RevisionSetCapabilityRouter((first, second))

        self.assertEqual(
            revision_set.keys,
            (
                RevisionSetCapabilityKey("catalog-a", "member-a"),
                RevisionSetCapabilityKey("catalog-b", "member-b"),
            ),
        )
        selected = revision_set.resolve(
            RevisionSetCapabilityKey("catalog-b", "member-b"),
            CapabilityRouteSelector(PluginCapability.CORRELATION),
        )
        self.assertEqual(selected.provider.catalog_revision_id, "catalog-b")
        with self.assertRaises(CapabilityRouteMissingError):
            revision_set.resolve(
                RevisionSetCapabilityKey("catalog-missing", "member-missing"),
                CapabilityRouteSelector(PluginCapability.CORRELATION),
            )
        with self.assertRaisesRegex(ValueError, "unique"):
            RevisionSetCapabilityRouter((first, first))
        with self.assertRaisesRegex(ValueError, "at least one"):
            RevisionSetCapabilityRouter(())

        over_limit = tuple(
            _router(
                providers,
                plan,
                catalog_revision_id=f"catalog-{index:03d}",
                member_id=f"member-{index:03d}",
            )
            for index in range(129)
        )
        with self.assertRaisesRegex(ValueError, "at most 128"):
            RevisionSetCapabilityRouter(over_limit)

    def test_revision_set_resolve_all_reports_missing_without_first_match(self) -> None:
        capable = _RoutingPlugin("test.capable")
        incapable = _RoutingPlugin(
            "test.incapable",
            capabilities=frozenset(),
        )
        capable_record = _registered(capable, "capable.primary")
        incapable_record = _registered(incapable, "incapable.primary")
        providers = CapabilityProviderRegistry((incapable_record, capable_record))
        capable_router = _router(
            providers,
            _plan(
                "node-b",
                "source-b",
                _pin(capable_record, capable.schema, "primary_parser"),
            ),
            catalog_revision_id="catalog-b",
            member_id="member-b",
        )
        incapable_router = _router(
            providers,
            _plan(
                "node-a",
                "source-a",
                _pin(incapable_record, incapable.schema, "primary_parser"),
            ),
            catalog_revision_id="catalog-a",
            member_id="member-a",
        )

        resolution = RevisionSetCapabilityRouter(
            (capable_router, incapable_router)
        ).resolve_all(CapabilityRouteSelector(PluginCapability.CORRELATION))

        self.assertEqual(
            tuple(route.provider.member_id for route in resolution.routes),
            ("member-b",),
        )
        self.assertEqual(
            resolution.missing,
            (RevisionSetCapabilityKey("catalog-a", "member-a"),),
        )

    def test_revision_set_resolve_all_rejects_one_ambiguous_member(self) -> None:
        primary_plugin = _RoutingPlugin("test.ambiguous")
        observer_plugin = _RoutingPlugin("test.ambiguous")
        primary = _registered(primary_plugin, "ambiguous.primary")
        observer = _registered(
            observer_plugin,
            "ambiguous.observer",
            configuration_digest="sha256:" + "a" * 64,
        )
        providers = CapabilityProviderRegistry((primary, observer))
        router = _router(
            providers,
            _plan(
                "node-a",
                "source-a",
                _pin(primary, primary_plugin.schema, "primary_parser"),
                _pin(observer, observer_plugin.schema, "observer"),
                authority=PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED,
            ),
            allow_inline_only=True,
        )

        with self.assertRaises(CapabilityRouteAmbiguousError):
            RevisionSetCapabilityRouter((router,)).resolve_all(
                CapabilityRouteSelector(PluginCapability.CORRELATION)
            )

    def test_revision_set_fanout_keeps_successes_and_bounded_failures(self) -> None:
        plugins = tuple(
            _RoutingPlugin(f"test.fanout.{suffix}") for suffix in ("a", "b", "c")
        )
        records = tuple(
            _registered(plugin, f"fanout.{suffix}")
            for plugin, suffix in zip(plugins, ("a", "b", "c"), strict=True)
        )
        providers = CapabilityProviderRegistry(reversed(records))
        routers = tuple(
            _router(
                providers,
                _plan(
                    f"node-{suffix}",
                    f"source-{suffix}",
                    _pin(record, plugin.schema, "primary_parser"),
                ),
                catalog_revision_id=f"catalog-{suffix}",
                member_id=f"member-{suffix}",
            )
            for plugin, record, suffix in zip(
                plugins,
                records,
                ("a", "b", "c"),
                strict=True,
            )
        )
        window = CorrelationWindow(0, 1, max_events=1, max_world_reads=1)

        def invoke(route):
            if route.provider.member_id == "member-b":
                raise PluginCapabilityOutputError(
                    "hostile detail must not be retained",
                    capability=PluginCapability.CORRELATION,
                )
            return route.correlate(object(), window)  # type: ignore[arg-type]

        result = RevisionSetCapabilityRouter(reversed(routers)).fanout(
            CapabilityRouteSelector(PluginCapability.CORRELATION),
            invoke,
        )

        self.assertEqual(
            tuple(item.provider.member_id for item in result.invocations),
            ("member-a", "member-c"),
        )
        self.assertEqual(result.missing, ())
        self.assertEqual(len(result.failures), 1)
        self.assertEqual(result.failures[0].key.member_id, "member-b")
        self.assertEqual(
            result.failures[0].code,
            RevisionSetCapabilityFailureCode.OUTPUT_REJECTED,
        )
        self.assertNotIn("hostile", repr(result.failures[0]))
        self.assertEqual(
            tuple(plugin.correlate_calls for plugin in plugins),
            (1, 0, 1),
        )

    def test_revision_set_fanout_never_downgrades_stale_provider(self) -> None:
        plugin = _RoutingPlugin("test.fanout-stale")
        record = _registered(plugin, "fanout-stale.primary")
        providers = CapabilityProviderRegistry((record,))
        router = _router(
            providers,
            _plan(
                "node-a",
                "source-a",
                _pin(record, plugin.schema, "primary_parser"),
            ),
        )
        plugin.schema = _schema("opaque.stale")

        with self.assertRaises(CapabilityRouteStaleError):
            RevisionSetCapabilityRouter((router,)).fanout(
                CapabilityRouteSelector(PluginCapability.CORRELATION),
                lambda route: route.correlate(
                    object(),  # type: ignore[arg-type]
                    CorrelationWindow(0, 1, max_events=1, max_world_reads=1),
                ),
            )


if __name__ == "__main__":
    unittest.main()
