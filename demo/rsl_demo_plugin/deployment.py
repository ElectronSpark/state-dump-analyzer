"""Trusted plug-in composition descriptor for the runnable demo.

Real deployments normally register several platform/firmware-specific primary
and auxiliary instances here. The public demo composes one parser with a
separate evidence-analysis provider, exercising the same exact retained-plan
path without embedding proprietary platform identities.
"""

from __future__ import annotations

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
)
from router_dump_analyzer.plugin_loading import load_plugin_module_with_coordinates


def build_plugin_deployment(
    context: PluginCompositionDeploymentContext,
) -> PluginCompositionDeployment:
    """Build the demo's exact primary/provider/policy deployment."""

    # The state root is intentionally the only core value disclosed to a
    # trusted deployment factory. This demo needs no per-installation secrets.
    del context
    primary_registry = PluginRegistry(require_executable_identity=True)
    primary = load_plugin_module_with_coordinates(
        "rsl_demo_plugin:plugin"
    ).register(
        primary_registry,
        instance_id="demo.example-router.primary",
    )
    auxiliary_registry = PluginRegistry(require_executable_identity=True)
    evidence = load_plugin_module_with_coordinates(
        "rsl_demo_plugin:evidence_plugin"
    ).register(
        auxiliary_registry,
        instance_id="demo.example-router.evidence-analysis",
    )
    return PluginCompositionDeployment(
        primary_registry=primary_registry,
        capability_providers=CapabilityProviderRegistry((primary, evidence)),
        policy=PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(
                        PluginParticipationSelection(
                            instance_id=evidence.instance_id,
                            registered_execution_identity=(
                                evidence.registered_execution_identity
                            ),
                            roles=("private_analysis_evidence",),
                        ),
                    ),
                ),
            )
        ),
    )


__all__ = ["build_plugin_deployment"]
