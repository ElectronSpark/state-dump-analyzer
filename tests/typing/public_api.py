"""Strict consumer of representative APIs from every shipped distribution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from io import BytesIO
from pathlib import PurePosixPath
from typing import Any, BinaryIO
from uuid import UUID

from rsl_demo_generator import AssemblyConfig, NodeSpec, parse_node_selection
from rsl_demo_plugin import (
    ExampleRouterPlugin,
    RuntimeAttachedExampleRouterPlugin,
    plugin,
)

from router_dump_analyzer import (
    ControlPlaneApplicationFactory,
    ControlPlaneApplicationRequest,
    FederationExecutionError,
    FederationLinkerIdentity,
    FederationLinkerLimits,
    FederationLinkerRegistry,
    FederationLinkExecutor,
    PLUGIN_PROCESS_BOOTSTRAP_DESCRIPTOR_ATTRIBUTE,
    PluginProcessBootstrapDescriptor,
    RevisionSetCapabilityRouter,
    TopologyFederationAssembly,
    TopologyFederationCoordinator,
    TopologyFederationLimits,
    TopologyProjectionBasisSnapshot,
    TopologyProjectionInvocation,
)
from router_dump_analyzer.plugin_api import (
    AnalyzerPlugin,
    ArtifactReader,
    PluginDiagnostic,
    WorldBasisKind,
)


class MemoryArtifactReader:
    """Minimal structural implementation of the public reader protocol."""

    def open_binary(self, artifact_id: UUID) -> BinaryIO:
        return BytesIO(artifact_id.bytes)

    def materialize_private_path(self, artifact_id: UUID) -> str:
        return f"private/{artifact_id}"

    def materialize_private_tree(
        self,
        artifact_ids: Sequence[UUID],
        logical_root: PurePosixPath | None = None,
    ) -> str:
        root = logical_root or PurePosixPath("artifacts")
        return f"{root}/{len(artifact_ids)}"


def _application_factory(request: ControlPlaneApplicationRequest) -> object:
    return request.control_plane


def _exercise_federation_coordinator(
    coordinator: TopologyFederationCoordinator,
) -> tuple[
    RevisionSetCapabilityRouter,
    FederationLinkExecutor,
    TopologyFederationLimits,
]:
    """Keep coordinator-owned collaborators precise in the public stubs."""

    return (
        coordinator.router,
        coordinator.federation_executor,
        coordinator.limits,
    )


def _exercise_topology_federation_result(
    coordinator: TopologyFederationCoordinator,
    snapshot: TopologyProjectionBasisSnapshot,
    invocation: TopologyProjectionInvocation,
    assembly: TopologyFederationAssembly,
) -> tuple[WorldBasisKind, int | None, int | None, int | None, bool, bool]:
    """Exercise temporal binding, completeness, and the keyword-only gate."""

    refreshed = coordinator.federate(
        (invocation,),
        invocations_complete=assembly.invocations_complete,
    )
    return (
        snapshot.kind,
        snapshot.requested_time_ns,
        snapshot.resolved_at_min_ns,
        snapshot.resolved_at_max_ns,
        refreshed.invocations_complete,
        refreshed.claims_complete,
    )


def exercise_public_surface(document: Mapping[str, Any]) -> None:
    reader: ArtifactReader = MemoryArtifactReader()
    analyzer: AnalyzerPlugin = ExampleRouterPlugin()
    entry_point: AnalyzerPlugin = plugin
    live_entry_point: RuntimeAttachedExampleRouterPlugin = plugin
    live_runtime: Any = live_entry_point.runtime
    application_factory: ControlPlaneApplicationFactory = _application_factory
    federation_executor = FederationLinkExecutor()
    federation_registry: FederationLinkerRegistry = federation_executor.registry
    federation_executor_limits: FederationLinkerLimits = federation_executor.limits
    federation_error = FederationExecutionError("typed boundary")
    linker_identity: FederationLinkerIdentity | None = (
        federation_error.linker_identity
    )
    federation_diagnostics: tuple[PluginDiagnostic, ...] = (
        federation_error.diagnostics
    )
    federation_limits = TopologyFederationLimits()
    process_bootstrap = PluginProcessBootstrapDescriptor(
        module_target="rsl_demo_plugin:ExampleRouterPlugin",
        construct_class=True,
    )
    process_bootstrap_attribute: str = (
        PLUGIN_PROCESS_BOOTSTRAP_DESCRIPTOR_ATTRIBUTE
    )

    nodes: tuple[NodeSpec, ...] = parse_node_selection(())
    config = AssemblyConfig(nodes=nodes)
    # Keep every imported contract live so mypy checks the complete assignment.
    _ = (
        reader,
        analyzer,
        entry_point,
        live_entry_point,
        live_runtime,
        application_factory,
        federation_executor,
        federation_registry,
        federation_executor_limits,
        federation_error,
        linker_identity,
        federation_diagnostics,
        federation_limits,
        process_bootstrap,
        process_bootstrap_attribute,
        _exercise_federation_coordinator,
        _exercise_topology_federation_result,
        config,
    )
