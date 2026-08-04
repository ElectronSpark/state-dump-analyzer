from __future__ import annotations

import unittest
from dataclasses import replace
from typing import Any

from router_dump_analyzer.capability_router import (
    CapabilityPlanUnavailableError,
    CapabilityProviderRegistry,
    CapabilityRouteAmbiguousError,
    CapabilityRouteMissingError,
    CapabilityRouteSelector,
    CapabilityRouteStaleError,
    PlanBoundCapabilityRouter,
)
from router_dump_analyzer.ingestion import IngestionCoordinator
from router_dump_analyzer.ingestion_pipeline import PluginRegistry, RegisteredPlugin
from router_dump_analyzer.plugin_api import (
    CORE_PLUGIN_API_VERSION,
    AnalyzerPluginBase,
    CorrelationWindow,
    PluginCapability,
    PluginManifest,
    PluginSchema,
    ReconstructionSupport,
    ResourceKindDescriptor,
)
from router_dump_analyzer.plugin_execution_plan import (
    DecoderIdentity,
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
)
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
    ) -> None:
        self.manifest = PluginManifest(
            plugin_id=plugin_id,
            plugin_version=plugin_version,
            core_api_version=CORE_PLUGIN_API_VERSION,
            supported_platforms=("test",),
            supported_software_versions="*",
            capabilities=frozenset({PluginCapability.CORRELATION}),
            reconstruction_default=ReconstructionSupport.EXACT,
        )
        self.schema = schema or _schema()
        self.correlate_calls = 0
        self.mutate_schema_during_correlation = False

    def describe(self) -> PluginSchema:
        return self.schema

    def correlate(self, reader: Any, window: CorrelationWindow):
        del reader, window
        self.correlate_calls += 1
        if self.mutate_schema_during_correlation:
            self.schema = _schema("opaque.changed")
        return ()


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
        module_target=f"tests:{instance_id}",
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
        schema_versions=registered.schema_versions,
        capabilities=registered.capabilities,
        roles=tuple(roles),
    )


def _plan(node_id: str, basis: str, *pins: PluginExecutionPin) -> PluginExecutionPlan:
    return PluginExecutionPlan(
        node_id=node_id,
        basis_revision_id=basis,
        plugins=tuple(pins),
    )


def _router(
    providers: CapabilityProviderRegistry,
    plan: PluginExecutionPlan | None,
    *,
    catalog_revision_id: str = "catalog-revision-1",
    member_id: str = "member-1",
) -> PlanBoundCapabilityRouter:
    return PlanBoundCapabilityRouter(
        providers,
        plan,
        catalog_revision_id=catalog_revision_id,
        member_id=member_id,
    )


class CapabilityRouterTests(unittest.TestCase):
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

    def test_same_plugin_instances_require_role_or_instance_disambiguation(self) -> None:
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
            _plan("node-a", "source-a", first_pin, second_pin),
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
                _plan("node-a", "source-a", *pins),
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
            router.resolve(
                CapabilityRouteSelector(PluginCapability.CONSISTENCY_CHECK)
            )
        route = router.resolve(
            CapabilityRouteSelector(PluginCapability.CORRELATION)
        )
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
        route = router.resolve(
            CapabilityRouteSelector(PluginCapability.CORRELATION)
        )
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

    def test_manifest_only_provider_identity_is_never_routable(self) -> None:
        plugin = _RoutingPlugin("test.manifest-only")
        compatibility = PluginRegistry(allow_manifest_identity=True)
        record = compatibility.register(
            plugin,
            package_hash="manifest-sha256:" + "6" * 64,
            instance_id="manifest.primary",
        )
        self.assertFalse(record.verify_package_bytes)
        with self.assertRaisesRegex(ValueError, "revalidatable executable"):
            CapabilityProviderRegistry((record,))

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


if __name__ == "__main__":
    unittest.main()
