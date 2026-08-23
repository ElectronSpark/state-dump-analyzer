from .capability_executor import TopologyExecutionResult
from .capability_router import CapabilityInvocation, CapabilityProviderRef, RevisionSetCapabilityKey, RevisionSetCapabilityRouter
from .federation_executor import FederationExecutionResult, FederationLinkExecutor
from .plugin_api import ConnectorMatchPolicyDescriptor, FederatedConnectorClaim, PluginDiagnostic, ReadOnlyWorld, TopologyProjectionRequest, WorldBasisKind
from collections.abc import Callable
from dataclasses import dataclass

__all__ = ['TopologyFederationError', 'TopologyProjectionSelectionError', 'TopologyFederationPolicyConflictError', 'TopologyFederationLimits', 'TopologyProjectionSelection', 'TopologyProjectionBasisSnapshot', 'TopologyProjectionInvocation', 'TopologyFederationPolicyExecution', 'TopologyFederatedClaimContext', 'TopologyFederationFailure', 'TopologyFederationAssembly', 'TopologyFederationCoordinator']

class TopologyFederationError(RuntimeError): ...
class TopologyProjectionSelectionError(TopologyFederationError): ...
class TopologyFederationPolicyConflictError(TopologyFederationError): ...

@dataclass(frozen=True, slots=True)
class TopologyFederationLimits:
    max_invocations: int = ...
    max_claims: int = ...
    max_policy_groups: int = ...
    max_results_per_policy: int = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyProjectionSelection:
    key: RevisionSetCapabilityKey
    plugin_instance_id: str
    expected_node_id: str
    expected_basis_revision_id: str
    request: TopologyProjectionRequest
    basis_time_ns: int | None
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyProjectionBasisSnapshot:
    kind: WorldBasisKind
    requested_time_ns: int | None
    resolved_at_min_ns: int | None
    resolved_at_max_ns: int | None
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyProjectionInvocation:
    selection: TopologyProjectionSelection
    invocation: CapabilityInvocation[TopologyExecutionResult]
    world_basis: TopologyProjectionBasisSnapshot
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyFederationPolicyExecution:
    claim_contract_id: str
    policy: ConnectorMatchPolicyDescriptor
    execution: FederationExecutionResult
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyFederatedClaimContext:
    claim: FederatedConnectorClaim
    projection_id: str
    status_perspective_id: str
    basis_time_ns: int | None
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyFederationFailure:
    claim_contract_id: str
    policy_id: str
    reason_code: str
    linker_plugin_id: str | None = ...
    linker_plugin_version: str | None = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class TopologyFederationAssembly:
    invocations: tuple[TopologyProjectionInvocation, ...]
    claims: tuple[FederatedConnectorClaim, ...]
    claim_contexts: tuple[TopologyFederatedClaimContext, ...]
    policy_executions: tuple[TopologyFederationPolicyExecution, ...]
    failures: tuple[TopologyFederationFailure, ...]
    diagnostics: tuple[PluginDiagnostic, ...]
    total_claim_count: int
    inactive_claim_count: int
    temporal_basis_unknown_claim_count: int
    invocations_complete: bool
    claims_complete: bool
    complete: bool
    truncated: bool
    def __post_init__(self) -> None: ...

class TopologyFederationCoordinator:
    router: RevisionSetCapabilityRouter
    federation_executor: FederationLinkExecutor
    limits: TopologyFederationLimits
    def __init__(self, router: RevisionSetCapabilityRouter, *, federation_executor: FederationLinkExecutor | None = None, limits: TopologyFederationLimits | None = None) -> None: ...
    def projection_available(self, selection: TopologyProjectionSelection) -> bool: ...
    def project(self, selection: TopologyProjectionSelection, world: ReadOnlyWorld) -> TopologyProjectionInvocation: ...
    def project_with_world_factory(self, selection: TopologyProjectionSelection, world_factory: Callable[[CapabilityProviderRef], ReadOnlyWorld]) -> TopologyProjectionInvocation: ...
    def federate(self, invocations: tuple[TopologyProjectionInvocation, ...], *, invocations_complete: bool = True) -> TopologyFederationAssembly: ...
