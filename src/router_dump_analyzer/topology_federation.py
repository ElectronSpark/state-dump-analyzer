"""Frozen projection routing and cross-member connector federation.

Device plug-ins own node-local topology vocabulary.  This module is the
core-owned bridge from an immutable revision-set capability plan to the
federation executor: it invokes the exact selected topology provider, adds
assembly identities to local claims, rejects policy drift, and resolves each
claim group without exposing another node's world to a device plug-in.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .capability_executor import TopologyExecutionResult
from .capability_router import (
    CapabilityInvocation,
    CapabilityProviderRef,
    CapabilityRouteMissingError,
    CapabilityRouteSelector,
    RevisionSetCapabilityKey,
    RevisionSetCapabilityRouter,
)
from .federation_executor import (
    FederationExecutionError,
    FederationExecutionResult,
    FederationLinkExecutor,
)
from .plugin_api import (
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
    ConnectorClaim,
    ConnectorMatchPolicyDescriptor,
    FederatedConnectorClaim,
    GlobalResourceRef,
    PluginCapability,
    PluginDiagnostic,
    ReadOnlyWorld,
    TopologyProjectionRequest,
    WorldBasis,
    WorldBasisKind,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS


class TopologyFederationError(RuntimeError):
    """A frozen topology projection set cannot be federated safely."""


class TopologyProjectionSelectionError(TopologyFederationError):
    """A requested projection does not match its immutable execution plan."""


class TopologyFederationPolicyConflictError(TopologyFederationError):
    """Providers disagree about one shared connector-policy contract."""


@dataclass(frozen=True, slots=True)
class TopologyFederationLimits:
    """Core-owned aggregate ceilings above the per-provider executors."""

    max_invocations: int = 512
    max_claims: int = 100_000
    max_policy_groups: int = 4_096
    max_results_per_policy: int = 10_000

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("max_invocations", self.max_invocations, 10_000),
            ("max_claims", self.max_claims, 100_000),
            ("max_policy_groups", self.max_policy_groups, 10_000),
            ("max_results_per_policy", self.max_results_per_policy, 100_000),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(
                    f"{name} must be an integer between 1 and {maximum}"
                )


@dataclass(frozen=True, slots=True)
class TopologyProjectionSelection:
    """One exact member/provider projection selected by core policy."""

    key: RevisionSetCapabilityKey
    plugin_instance_id: str
    expected_node_id: str
    expected_basis_revision_id: str
    request: TopologyProjectionRequest
    basis_time_ns: int | None

    def __post_init__(self) -> None:
        if type(self.key) is not RevisionSetCapabilityKey:
            raise TypeError("key must be an exact RevisionSetCapabilityKey")
        for name, value in (
            ("plugin_instance_id", self.plugin_instance_id),
            ("expected_node_id", self.expected_node_id),
            ("expected_basis_revision_id", self.expected_basis_revision_id),
        ):
            if type(value) is not str or not value or len(value) > 256:
                raise ValueError(f"{name} must contain 1 to 256 characters")
        if type(self.request) is not TopologyProjectionRequest:
            raise TypeError("request must be an exact TopologyProjectionRequest")
        if self.basis_time_ns is not None and (
            type(self.basis_time_ns) is not int
            or not MIN_TIMESTAMP_NS <= self.basis_time_ns <= MAX_TIMESTAMP_NS
        ):
            raise ValueError("basis_time_ns must be a signed 64-bit integer or None")


@dataclass(frozen=True, slots=True)
class TopologyProjectionBasisSnapshot:
    """Immutable clock interval bound to one provider invocation."""

    kind: WorldBasisKind
    requested_time_ns: int | None
    resolved_at_min_ns: int | None
    resolved_at_max_ns: int | None

    def __post_init__(self) -> None:
        if type(self.kind) is not WorldBasisKind:
            raise TypeError("kind must be an exact WorldBasisKind")
        for name, value in (
            ("requested_time_ns", self.requested_time_ns),
            ("resolved_at_min_ns", self.resolved_at_min_ns),
            ("resolved_at_max_ns", self.resolved_at_max_ns),
        ):
            if value is not None and (
                type(value) is not int
                or not MIN_TIMESTAMP_NS <= value <= MAX_TIMESTAMP_NS
            ):
                raise ValueError(
                    f"{name} must be a signed 64-bit integer or None"
                )
        if (self.resolved_at_min_ns is None) != (
            self.resolved_at_max_ns is None
        ):
            raise ValueError("resolved world bounds must be both present or absent")
        if (
            self.resolved_at_min_ns is not None
            and self.resolved_at_max_ns is not None
            and self.resolved_at_min_ns > self.resolved_at_max_ns
        ):
            raise ValueError("resolved world bounds must be ordered")
        if (
            self.requested_time_ns is not None
            and self.resolved_at_min_ns is not None
            and self.resolved_at_max_ns is not None
            and not (
                self.resolved_at_min_ns
                <= self.requested_time_ns
                <= self.resolved_at_max_ns
            )
        ):
            raise ValueError("requested world time must lie within resolved bounds")


@dataclass(frozen=True, slots=True)
class TopologyProjectionInvocation:
    """One provider-qualified result plus the selection that authorized it."""

    selection: TopologyProjectionSelection
    invocation: CapabilityInvocation[TopologyExecutionResult]
    world_basis: TopologyProjectionBasisSnapshot

    def __post_init__(self) -> None:
        if type(self.selection) is not TopologyProjectionSelection:
            raise TypeError(
                "selection must be an exact TopologyProjectionSelection"
            )
        if type(self.invocation) is not CapabilityInvocation:
            raise TypeError("invocation must be an exact CapabilityInvocation")
        if type(self.world_basis) is not TopologyProjectionBasisSnapshot:
            raise TypeError(
                "world_basis must be an exact TopologyProjectionBasisSnapshot"
            )
        if self.selection.basis_time_ns != self.world_basis.requested_time_ns:
            raise ValueError("selection time does not match the bound world basis")
        provider = self.invocation.provider
        if provider.catalog_revision_id != self.selection.key.catalog_revision_id:
            raise ValueError("invocation catalog revision does not match selection")
        if provider.member_id != self.selection.key.member_id:
            raise ValueError("invocation member does not match selection")
        if provider.node_id != self.selection.expected_node_id:
            raise ValueError("invocation node does not match selection")
        if provider.basis_revision_id != self.selection.expected_basis_revision_id:
            raise ValueError("invocation basis revision does not match selection")
        if provider.pin.instance_id != self.selection.plugin_instance_id:
            raise ValueError("invocation provider does not match selection")
        if provider.capability is not PluginCapability.TOPOLOGY_PROJECTION:
            raise ValueError("invocation is not a topology projection")
        if type(self.invocation.result) is not TopologyExecutionResult:
            raise TypeError("invocation result must be a TopologyExecutionResult")


@dataclass(frozen=True, slots=True)
class TopologyFederationPolicyExecution:
    """One policy group and its deterministic exact or linker result."""

    claim_contract_id: str
    policy: ConnectorMatchPolicyDescriptor
    execution: FederationExecutionResult

    def __post_init__(self) -> None:
        if type(self.claim_contract_id) is not str or not self.claim_contract_id:
            raise ValueError("claim_contract_id must be non-empty")
        if type(self.policy) is not ConnectorMatchPolicyDescriptor:
            raise TypeError("policy must be an exact descriptor")
        if self.policy.claim_contract_id != self.claim_contract_id:
            raise ValueError("policy claim contract does not match the group")
        if type(self.execution) is not FederationExecutionResult:
            raise TypeError("execution must be an exact FederationExecutionResult")


@dataclass(frozen=True, slots=True)
class TopologyFederatedClaimContext:
    """Projection scope needed to bind a federated claim to its rendered row."""

    claim: FederatedConnectorClaim
    projection_id: str
    status_perspective_id: str
    basis_time_ns: int | None

    def __post_init__(self) -> None:
        if type(self.claim) is not FederatedConnectorClaim:
            raise TypeError("claim must be an exact FederatedConnectorClaim")
        for name, value in (
            ("projection_id", self.projection_id),
            ("status_perspective_id", self.status_perspective_id),
        ):
            if type(value) is not str or not value or len(value) > 256:
                raise ValueError(f"{name} must contain 1 to 256 characters")
        if self.basis_time_ns is not None and (
            type(self.basis_time_ns) is not int
            or not MIN_TIMESTAMP_NS <= self.basis_time_ns <= MAX_TIMESTAMP_NS
        ):
            raise ValueError("basis_time_ns must be a signed 64-bit integer or None")


@dataclass(frozen=True, slots=True)
class TopologyFederationFailure:
    """One contained policy/linker failure that makes only its group incomplete."""

    claim_contract_id: str
    policy_id: str
    reason_code: str
    linker_plugin_id: str | None = None
    linker_plugin_version: str | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("claim_contract_id", self.claim_contract_id),
            ("policy_id", self.policy_id),
            ("reason_code", self.reason_code),
        ):
            if type(value) is not str or not value or len(value) > 256:
                raise ValueError(f"{name} must contain 1 to 256 characters")
        for name, value in (
            ("linker_plugin_id", self.linker_plugin_id),
            ("linker_plugin_version", self.linker_plugin_version),
        ):
            if value is not None and (
                type(value) is not str or not value or len(value) > 256
            ):
                raise ValueError(f"{name} must be None or contain 1 to 256 characters")


@dataclass(frozen=True, slots=True)
class TopologyFederationAssembly:
    """Bounded assembly-wide output retaining every producer and policy."""

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

    def __post_init__(self) -> None:
        if type(self.invocations) is not tuple or any(
            type(item) is not TopologyProjectionInvocation
            for item in self.invocations
        ):
            raise TypeError("invocations must be an exact tuple")
        if type(self.claims) is not tuple or any(
            type(item) is not FederatedConnectorClaim for item in self.claims
        ):
            raise TypeError("claims must be an exact tuple")
        if type(self.claim_contexts) is not tuple or any(
            type(item) is not TopologyFederatedClaimContext
            for item in self.claim_contexts
        ):
            raise TypeError("claim_contexts must be an exact tuple")
        if tuple(item.claim for item in self.claim_contexts) != self.claims:
            raise ValueError("claim contexts must exactly cover the returned claims")
        if type(self.policy_executions) is not tuple or any(
            type(item) is not TopologyFederationPolicyExecution
            for item in self.policy_executions
        ):
            raise TypeError("policy_executions must be an exact tuple")
        if type(self.failures) is not tuple or any(
            type(item) is not TopologyFederationFailure for item in self.failures
        ):
            raise TypeError("failures must be an exact tuple")
        if type(self.diagnostics) is not tuple or any(
            type(item) is not PluginDiagnostic for item in self.diagnostics
        ):
            raise TypeError("diagnostics must be an exact tuple")
        for name, value in (
            ("total_claim_count", self.total_claim_count),
            ("inactive_claim_count", self.inactive_claim_count),
            (
                "temporal_basis_unknown_claim_count",
                self.temporal_basis_unknown_claim_count,
            ),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative exact integer")
        if self.total_claim_count != (
            len(self.claims)
            + self.inactive_claim_count
            + self.temporal_basis_unknown_claim_count
        ):
            raise ValueError("claim accounting must exactly cover every emitted claim")
        if (
            type(self.invocations_complete) is not bool
            or type(self.claims_complete) is not bool
            or type(self.complete) is not bool
            or type(self.truncated) is not bool
        ):
            raise TypeError("completeness flags must be booleans")
        if self.complete and self.truncated:
            raise ValueError("a truncated federation assembly cannot be complete")
        if self.complete and (
            self.failures
            or self.temporal_basis_unknown_claim_count
            or not self.invocations_complete
            or not self.claims_complete
        ):
            raise ValueError("a federation assembly with unresolved groups is incomplete")


class TopologyFederationCoordinator:
    """Invoke frozen node providers, then resolve their qualified claims."""

    def __init__(
        self,
        router: RevisionSetCapabilityRouter,
        *,
        federation_executor: FederationLinkExecutor | None = None,
        limits: TopologyFederationLimits | None = None,
    ) -> None:
        if type(router) is not RevisionSetCapabilityRouter:
            raise TypeError("router must be a RevisionSetCapabilityRouter")
        if federation_executor is not None and type(
            federation_executor
        ) is not FederationLinkExecutor:
            raise TypeError(
                "federation_executor must be an exact FederationLinkExecutor"
            )
        if limits is not None and type(limits) is not TopologyFederationLimits:
            raise TypeError("limits must be exact TopologyFederationLimits")
        self.router: RevisionSetCapabilityRouter = router
        self.federation_executor: FederationLinkExecutor = (
            federation_executor or FederationLinkExecutor()
        )
        self.limits: TopologyFederationLimits = (
            limits or TopologyFederationLimits()
        )

    @staticmethod
    def _snapshot_world_basis(
        selection: TopologyProjectionSelection,
        world: ReadOnlyWorld,
    ) -> TopologyProjectionBasisSnapshot:
        basis = world.basis
        if type(basis) is not WorldBasis:
            raise TopologyProjectionSelectionError(
                "topology projection world basis is not a core WorldBasis"
            )
        snapshot = TopologyProjectionBasisSnapshot(
            kind=basis.kind,
            requested_time_ns=basis.requested_time_ns,
            resolved_at_min_ns=basis.resolved_at_min_ns,
            resolved_at_max_ns=basis.resolved_at_max_ns,
        )
        if selection.basis_time_ns != snapshot.requested_time_ns:
            raise TopologyProjectionSelectionError(
                "selected topology time does not match the reconstructed world"
            )
        return snapshot

    def projection_available(
        self,
        selection: TopologyProjectionSelection,
    ) -> bool:
        """Return whether the immutable plan contains this exact provider route."""

        if type(selection) is not TopologyProjectionSelection:
            raise TypeError("selection must be an exact TopologyProjectionSelection")
        try:
            route = self.router.resolve(
                selection.key,
                CapabilityRouteSelector(
                    capability=PluginCapability.TOPOLOGY_PROJECTION,
                    instance_id=selection.plugin_instance_id,
                ),
            )
            provider = route.provider
            if (
                provider.node_id != selection.expected_node_id
                or provider.basis_revision_id
                != selection.expected_basis_revision_id
            ):
                raise TopologyProjectionSelectionError(
                    "selected topology provider does not match the requested node revision"
                )
            return True
        except CapabilityRouteMissingError:
            return False
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except TopologyFederationError:
            raise
        except BaseException as error:
            raise TopologyProjectionSelectionError(
                "topology projection route availability could not be established"
            ) from error

    def project(
        self,
        selection: TopologyProjectionSelection,
        world: ReadOnlyWorld,
    ) -> TopologyProjectionInvocation:
        """Invoke exactly one plan-owned provider with no member fallback."""

        if type(selection) is not TopologyProjectionSelection:
            raise TypeError("selection must be an exact TopologyProjectionSelection")
        try:
            route = self.router.resolve(
                selection.key,
                CapabilityRouteSelector(
                    capability=PluginCapability.TOPOLOGY_PROJECTION,
                    instance_id=selection.plugin_instance_id,
                ),
            )
            provider = route.provider
            if (
                provider.node_id != selection.expected_node_id
                or provider.basis_revision_id
                != selection.expected_basis_revision_id
            ):
                raise TopologyProjectionSelectionError(
                    "selected topology provider does not match the requested node revision"
                )
            world_basis = self._snapshot_world_basis(selection, world)
            invocation = route.project_topology(selection.request, world)
            if self._snapshot_world_basis(selection, world) != world_basis:
                raise TopologyProjectionSelectionError(
                    "topology projection world basis changed during invocation"
                )
            return TopologyProjectionInvocation(
                selection,
                invocation,
                world_basis,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except TopologyFederationError:
            raise
        except BaseException as error:
            raise TopologyProjectionSelectionError(
                "topology projection provider invocation failed"
            ) from error

    def project_with_world_factory(
        self,
        selection: TopologyProjectionSelection,
        world_factory: Callable[[CapabilityProviderRef], ReadOnlyWorld],
    ) -> TopologyProjectionInvocation:
        """Resolve the provider before constructing its schema-bound world."""

        if type(selection) is not TopologyProjectionSelection:
            raise TypeError("selection must be an exact TopologyProjectionSelection")
        if not callable(world_factory):
            raise TypeError("world_factory must be callable")
        try:
            route = self.router.resolve(
                selection.key,
                CapabilityRouteSelector(
                    capability=PluginCapability.TOPOLOGY_PROJECTION,
                    instance_id=selection.plugin_instance_id,
                ),
            )
            provider = route.provider
            if (
                provider.node_id != selection.expected_node_id
                or provider.basis_revision_id
                != selection.expected_basis_revision_id
            ):
                raise TopologyProjectionSelectionError(
                    "selected topology provider does not match the requested node revision"
                )
            world = world_factory(provider)
            world_basis = self._snapshot_world_basis(selection, world)
            invocation = route.project_topology(selection.request, world)
            if self._snapshot_world_basis(selection, world) != world_basis:
                raise TopologyProjectionSelectionError(
                    "topology projection world basis changed during invocation"
                )
            return TopologyProjectionInvocation(
                selection,
                invocation,
                world_basis,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except TopologyFederationError:
            raise
        except BaseException as error:
            raise TopologyProjectionSelectionError(
                "topology projection provider invocation failed"
            ) from error

    def federate(
        self,
        invocations: tuple[TopologyProjectionInvocation, ...],
        *,
        invocations_complete: bool = True,
    ) -> TopologyFederationAssembly:
        """Qualify claims and execute each declared policy exactly once."""

        if type(invocations) is not tuple or any(
            type(item) is not TopologyProjectionInvocation for item in invocations
        ):
            raise TypeError("invocations must be an exact tuple")
        if len(invocations) > self.limits.max_invocations:
            raise TopologyFederationError("topology invocation limit exceeded")
        if type(invocations_complete) is not bool:
            raise TypeError("invocations_complete must be an exact boolean")
        invocation_keys = [
            (
                item.invocation.provider.catalog_revision_id,
                item.invocation.provider.member_id,
                item.invocation.provider.pin.instance_id,
                item.selection.request.projection_id,
                item.selection.request.status_perspective_id,
            )
            for item in invocations
        ]
        if len(invocation_keys) != len(set(invocation_keys)):
            raise TopologyFederationError(
                "topology projection invocations must be uniquely selected"
            )
        ordered_invocations = tuple(
            item
            for _key, item in sorted(
                zip(invocation_keys, invocations, strict=True),
                key=lambda pair: pair[0],
            )
        )

        policies: dict[
            tuple[str, str], ConnectorMatchPolicyDescriptor
        ] = {}
        grouped_claims: dict[
            tuple[str, str], list[FederatedConnectorClaim]
        ] = {}
        qualified: list[FederatedConnectorClaim] = []
        contexts: list[TopologyFederatedClaimContext] = []
        diagnostics: list[PluginDiagnostic] = []
        encountered_claim_identities: set[tuple[str, str, str, str]] = set()
        total_claim_count = 0
        inactive_claim_count = 0
        temporal_basis_unknown_claim_count = 0
        claims_complete = True

        for item in ordered_invocations:
            provider = item.invocation.provider
            result = item.invocation.result
            claims_complete = claims_complete and result.claims_complete
            diagnostics.extend(result.diagnostics)
            declared = {policy.policy_id: policy for policy in result.match_policies}
            for claim in result.claims:
                total_claim_count += 1
                if total_claim_count > self.limits.max_claims:
                    raise TopologyFederationError(
                        "topology connector claim limit exceeded"
                    )
                if claim.endpoint.node != provider.node_id:
                    raise TopologyFederationError(
                        "connector claim endpoint belongs to a different node"
                    )
                policy = declared.get(claim.match_policy_id)
                if policy is None:
                    raise TopologyFederationError(
                        "connector claim has no validated match policy"
                    )
                group_key = (claim.claim_contract_id, claim.match_policy_id)
                previous = policies.get(group_key)
                if previous is not None and previous != policy:
                    raise TopologyFederationPolicyConflictError(
                        "connector providers disagree about one match policy"
                    )
                policies[group_key] = policy
                claim_identity = (
                    provider.member_id,
                    provider.basis_revision_id,
                    provider.pin.instance_id,
                    claim.claim_id,
                )
                if claim_identity in encountered_claim_identities:
                    raise TopologyFederationError(
                        "qualified topology connector claim identities must be unique"
                    )
                encountered_claim_identities.add(claim_identity)
                active = self._claim_active_at(
                    claim,
                    item.world_basis,
                )
                if active is None:
                    temporal_basis_unknown_claim_count += 1
                    continue
                if not active:
                    inactive_claim_count += 1
                    continue
                federated = FederatedConnectorClaim(
                    endpoint=GlobalResourceRef(
                        member_id=provider.member_id,
                        revision_id=provider.basis_revision_id,
                        plugin_instance_id=provider.pin.instance_id,
                        resource=claim.endpoint,
                    ),
                    claim=claim,
                )
                qualified.append(federated)
                contexts.append(
                    TopologyFederatedClaimContext(
                        claim=federated,
                        projection_id=item.selection.request.projection_id,
                        status_perspective_id=(
                            item.selection.request.status_perspective_id
                        ),
                        basis_time_ns=item.selection.basis_time_ns,
                    )
                )
                grouped_claims.setdefault(group_key, []).append(federated)

        if len(policies) > self.limits.max_policy_groups:
            raise TopologyFederationError("topology match-policy limit exceeded")
        claim_identities = [
            (
                claim.endpoint.member_id,
                claim.endpoint.revision_id,
                claim.endpoint.plugin_instance_id,
                claim.claim.claim_id,
            )
            for claim in qualified
        ]
        executions: list[TopologyFederationPolicyExecution] = []
        failures: list[TopologyFederationFailure] = []
        execution_complete = True
        truncated = not claims_complete or not invocations_complete
        for group_key in sorted(grouped_claims):
            policy = policies[group_key]
            claims = tuple(
                sorted(
                    grouped_claims[group_key],
                    key=lambda value: (
                        value.endpoint.member_id,
                        value.endpoint.revision_id,
                        value.endpoint.plugin_instance_id,
                        value.claim.claim_id,
                    ),
                )
            )
            try:
                execution = self.federation_executor.resolve(
                    policy,
                    claims,
                    max_results=min(
                        self.limits.max_results_per_policy,
                        self.federation_executor.limits.max_results,
                    ),
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except FederationExecutionError as error:
                diagnostics.extend(error.diagnostics)
                linker_identity = error.linker_identity
                failures.append(
                    TopologyFederationFailure(
                        claim_contract_id=group_key[0],
                        policy_id=group_key[1],
                        reason_code=(
                            "federation_linker_failed"
                            if linker_identity is not None
                            else "federation_policy_failed"
                        ),
                        linker_plugin_id=(
                            None
                            if linker_identity is None
                            else linker_identity.plugin_id
                        ),
                        linker_plugin_version=(
                            None
                            if linker_identity is None
                            else linker_identity.plugin_version
                        ),
                    )
                )
                execution_complete = False
                continue
            executions.append(
                TopologyFederationPolicyExecution(
                    claim_contract_id=group_key[0],
                    policy=policy,
                    execution=execution,
                )
            )
            diagnostics.extend(execution.diagnostics)
            execution_complete = execution_complete and execution.complete
            truncated = truncated or execution.truncated

        complete = (
            invocations_complete
            and claims_complete
            and execution_complete
            and not failures
            and temporal_basis_unknown_claim_count == 0
            and not truncated
        )
        ordered_claims_and_contexts = sorted(
            zip(claim_identities, qualified, contexts, strict=True),
            key=lambda item: item[0],
        )
        return TopologyFederationAssembly(
            invocations=ordered_invocations,
            claims=tuple(value for _identity, value, _context in ordered_claims_and_contexts),
            claim_contexts=tuple(
                context for _identity, _value, context in ordered_claims_and_contexts
            ),
            policy_executions=tuple(executions),
            failures=tuple(failures),
            diagnostics=tuple(diagnostics),
            total_claim_count=total_claim_count,
            inactive_claim_count=inactive_claim_count,
            temporal_basis_unknown_claim_count=temporal_basis_unknown_claim_count,
            invocations_complete=invocations_complete,
            claims_complete=claims_complete,
            complete=complete,
            truncated=truncated,
        )

    @staticmethod
    def _claim_active_at(
        claim: ConnectorClaim,
        basis: TopologyProjectionBasisSnapshot,
    ) -> bool | None:
        minimum_ns = basis.resolved_at_min_ns
        maximum_ns = basis.resolved_at_max_ns
        if minimum_ns is None or maximum_ns is None:
            if claim.valid_from_ns is not None or claim.valid_to_ns is not None:
                return None
            return True
        if (
            claim.valid_to_ns is not None
            and claim.valid_to_ns <= minimum_ns
        ) or (
            claim.valid_from_ns is not None
            and claim.valid_from_ns > maximum_ns
        ):
            return False
        if (
            claim.valid_from_ns is None
            or claim.valid_from_ns <= minimum_ns
        ) and (
            claim.valid_to_ns is None
            or maximum_ns < claim.valid_to_ns
        ):
            return True
        return None


__all__ = [
    "TopologyFederatedClaimContext",
    "TopologyFederationAssembly",
    "TopologyFederationCoordinator",
    "TopologyFederationError",
    "TopologyFederationFailure",
    "TopologyFederationLimits",
    "TopologyFederationPolicyConflictError",
    "TopologyFederationPolicyExecution",
    "TopologyProjectionInvocation",
    "TopologyProjectionBasisSnapshot",
    "TopologyProjectionSelection",
    "TopologyProjectionSelectionError",
]
