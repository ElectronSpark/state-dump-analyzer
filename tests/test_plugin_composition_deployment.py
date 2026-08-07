from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer.capability_router import CapabilityProviderRegistry
from router_dump_analyzer.ingestion_pipeline import PluginRegistry
from router_dump_analyzer.plugin_composition import (
    PluginCompositionPolicy,
    PluginCompositionRule,
    PluginParticipationSelection,
)
from router_dump_analyzer.plugin_composition_deployment import (
    PluginCompositionDeployment,
    PluginCompositionDeploymentContext,
    PluginCompositionDeploymentLoadError,
    load_plugin_composition_deployment,
)
from router_dump_analyzer.plugin_loading import LoadedPlugin
from tests.test_ingestion import ParseOnlyPlugin

_CONFIG_A = "sha256:" + "a" * 64
_CONFIG_B = "sha256:" + "b" * 64


class _HostileFailure(BaseException):
    pass


def _registries() -> tuple[
    PluginRegistry,
    CapabilityProviderRegistry,
    object,
    object,
]:
    primary_registry = PluginRegistry()
    primary = LoadedPlugin(ParseOnlyPlugin()).register(
        primary_registry,
        instance_id="platform-a.primary",
        configuration_digest=_CONFIG_A,
    )
    second_registry = PluginRegistry()
    alternate = LoadedPlugin(ParseOnlyPlugin()).register(
        second_registry,
        instance_id="platform-a.alternate",
        configuration_digest=_CONFIG_B,
    )
    providers = CapabilityProviderRegistry((primary, alternate))
    return primary_registry, providers, primary, alternate


def _deployment() -> PluginCompositionDeployment:
    primary_registry, providers, primary, alternate = _registries()
    policy = PluginCompositionPolicy(
        (
            PluginCompositionRule(
                primary_instance_id=primary.instance_id,
                primary_registered_execution_identity=(
                    primary.registered_execution_identity
                ),
                auxiliaries=(
                    PluginParticipationSelection(
                        instance_id=alternate.instance_id,
                        registered_execution_identity=(
                            alternate.registered_execution_identity
                        ),
                        roles=("private_analysis_evidence",),
                    ),
                ),
            ),
        )
    )
    return PluginCompositionDeployment(primary_registry, providers, policy)


class PluginCompositionDeploymentTests(unittest.TestCase):
    def test_context_is_frozen_and_exposes_only_resolved_state_dir(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = PluginCompositionDeploymentContext(
                Path(directory) / "child" / ".." / "state"
            )
            self.assertEqual(
                tuple(field.name for field in dataclasses.fields(context)),
                ("state_dir",),
            )
            self.assertEqual(context.state_dir, (Path(directory) / "state").resolve())
            with self.assertRaises(dataclasses.FrozenInstanceError):
                context.state_dir = Path(directory)  # type: ignore[misc]

    def test_descriptor_binds_exact_objects_and_content_addresses_coordinates(
        self,
    ) -> None:
        deployment = _deployment()
        self.assertIs(type(deployment.primary_registry), PluginRegistry)
        self.assertIs(type(deployment.capability_providers), CapabilityProviderRegistry)
        self.assertIs(type(deployment.policy), PluginCompositionPolicy)
        self.assertRegex(deployment.deployment_digest, r"^sha256:[0-9a-f]{64}$")
        replay = PluginCompositionDeployment(
            deployment.primary_registry,
            deployment.capability_providers,
            deployment.policy,
            deployment.deployment_digest,
        )
        self.assertEqual(replay.deployment_digest, deployment.deployment_digest)
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            PluginCompositionDeployment(
                deployment.primary_registry,
                deployment.capability_providers,
                deployment.policy,
                "sha256:" + "0" * 64,
            )

    def test_same_plugin_release_from_separate_registries_coexists(self) -> None:
        _primary_registry, providers, primary, alternate = _registries()
        self.assertEqual(len(providers.records()), 2)
        self.assertEqual(primary.plugin_id, alternate.plugin_id)
        self.assertEqual(primary.plugin_version, alternate.plugin_version)
        self.assertNotEqual(primary.instance_id, alternate.instance_id)
        self.assertNotEqual(
            primary.registered_execution_identity,
            alternate.registered_execution_identity,
        )

    def test_descriptor_rejects_missing_or_nonexact_primary_provider(self) -> None:
        primary_registry, _providers, primary, alternate = _registries()
        policy = PluginCompositionPolicy()
        with self.assertRaisesRegex(ValueError, "every primary plug-in"):
            PluginCompositionDeployment(
                primary_registry,
                CapabilityProviderRegistry((alternate,)),
                policy,
            )

        duplicate_registry = PluginRegistry()
        duplicate = LoadedPlugin(ParseOnlyPlugin()).register(
            duplicate_registry,
            instance_id=primary.instance_id,
            configuration_digest=_CONFIG_A,
        )
        self.assertEqual(
            duplicate.registered_execution_identity,
            primary.registered_execution_identity,
        )
        with self.assertRaisesRegex(ValueError, "exact primary record"):
            PluginCompositionDeployment(
                primary_registry,
                CapabilityProviderRegistry((duplicate, alternate)),
                policy,
            )

    def test_descriptor_rejects_unused_primary_and_missing_auxiliary_rules(
        self,
    ) -> None:
        primary_registry, providers, primary, _alternate = _registries()
        unknown_identity = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "exact primary"):
            PluginCompositionDeployment(
                primary_registry,
                providers,
                PluginCompositionPolicy(
                    (
                        PluginCompositionRule(
                            primary_instance_id="unused.primary",
                            primary_registered_execution_identity=unknown_identity,
                            auxiliaries=(),
                        ),
                    )
                ),
            )
        with self.assertRaisesRegex(ValueError, "auxiliary selection"):
            PluginCompositionDeployment(
                primary_registry,
                providers,
                PluginCompositionPolicy(
                    (
                        PluginCompositionRule(
                            primary_instance_id=primary.instance_id,
                            primary_registered_execution_identity=(
                                primary.registered_execution_identity
                            ),
                            auxiliaries=(
                                PluginParticipationSelection(
                                    instance_id="missing.auxiliary",
                                    registered_execution_identity=unknown_identity,
                                    roles=("private_analysis_evidence",),
                                ),
                            ),
                        ),
                    )
                ),
            )

    def test_extra_historical_providers_are_permitted_and_affect_digest(self) -> None:
        deployment = _deployment()
        primary = deployment.primary_registry.records()[0]
        smaller = PluginCompositionDeployment(
            deployment.primary_registry,
            CapabilityProviderRegistry((primary,)),
            PluginCompositionPolicy(),
        )
        self.assertNotEqual(smaller.deployment_digest, deployment.deployment_digest)

    def test_loader_accepts_exact_value_and_calls_factory_once_with_detached_context(
        self,
    ) -> None:
        deployment = _deployment()
        received: list[PluginCompositionDeploymentContext] = []

        def factory(context: PluginCompositionDeploymentContext) -> object:
            received.append(context)
            return deployment

        with tempfile.TemporaryDirectory() as directory:
            supplied = PluginCompositionDeploymentContext(Path(directory))
            with patch(
                "router_dump_analyzer.plugin_composition_deployment.importlib.import_module",
                return_value=SimpleNamespace(build=factory, configured=deployment),
            ):
                loaded = load_plugin_composition_deployment(
                    "trusted.composition:build",
                    context=supplied,
                )
                exact = load_plugin_composition_deployment(
                    "trusted.composition:configured",
                    context=supplied,
                )
        self.assertEqual(len(received), 1)
        self.assertIsNot(received[0], supplied)
        self.assertEqual(received[0], supplied)
        self.assertIs(loaded.primary_registry, deployment.primary_registry)
        self.assertIs(exact.capability_providers, deployment.capability_providers)

    def test_loader_bounds_failures_and_preserves_process_control(self) -> None:
        secret = r"failed at C:\private\proprietary\deployment.py"

        def hostile(_context: PluginCompositionDeploymentContext) -> object:
            raise _HostileFailure(secret)

        with tempfile.TemporaryDirectory() as directory:
            context = PluginCompositionDeploymentContext(Path(directory))
            with (
                patch(
                    "router_dump_analyzer.plugin_composition_deployment.importlib.import_module",
                    return_value=SimpleNamespace(build=hostile),
                ),
                self.assertRaises(PluginCompositionDeploymentLoadError) as caught,
            ):
                load_plugin_composition_deployment(
                    "trusted.composition:build",
                    context=context,
                )
            self.assertEqual(
                str(caught.exception),
                "plug-in composition deployment factory failed",
            )
            self.assertNotIn(secret, str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)

            for exception_type in (KeyboardInterrupt, SystemExit, GeneratorExit):
                with (
                    self.subTest(exception_type=exception_type),
                    patch(
                        "router_dump_analyzer.plugin_composition_deployment.importlib.import_module",
                        side_effect=exception_type(),
                    ),
                    self.assertRaises(exception_type),
                ):
                    load_plugin_composition_deployment(
                        "trusted.composition:value",
                        context=context,
                    )


if __name__ == "__main__":
    unittest.main()
