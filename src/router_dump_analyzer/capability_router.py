"""Deterministic capability routing bound to immutable execution plans.

Parser probing chooses a primary interpreter for an uploaded dump.  This
module owns a separate decision: which exact configured provider may execute
an optional capability for an already-published revision.  It never falls
back to currently installed plug-ins, registration order, or a last writer.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum

from .capability_executor import (
    ConsistencyExecutionResult,
    CorrelationExecutionResult,
    EvidenceAnalysisExecutionResult,
    ForwardingProjectionExecutionResult,
    ForwardingStepExecutionResult,
    PluginCapabilityBindingError,
    PluginCapabilityExecutionError,
    PluginCapabilityExecutor,
    PluginCapabilityInputError,
    PluginCapabilityLimits,
    PluginCapabilityOutputError,
    PluginCapabilityUnavailableError,
    TopologyExecutionResult,
)
from .ingestion_pipeline import (
    PluginRegistry,
    RegisteredPlugin,
    _require_no_inline_only_plugin_compatibility,
    registered_plugin_matches_execution_pin,
)
from .plugin_api import (
    ChangeSet,
    CorrelationReader,
    CorrelationWindow,
    DomainEvent,
    EvidenceAnalysisRequest,
    ForwardingProjectionRequest,
    ForwardingStepRequest,
    PluginCapability,
    ReadOnlyWorld,
    TopologyProjectionRequest,
)
from .plugin_execution_plan import (
    PluginExecutionPin,
    PluginExecutionPlan,
    plugin_execution_plan_is_executable,
    primary_parser_execution_pin,
    snapshot_plugin_execution_pin,
    snapshot_plugin_execution_plan,
)
from .plugin_schema_identity import plugin_schema_digest
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .public_text import contains_unsafe_identifier_text, has_visible_identity_anchor

_MAX_PROVIDERS = 100_000
_MAX_REVISION_SET_ROUTERS = 128
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_ROUTABLE_CAPABILITIES = frozenset(
    {
        PluginCapability.EVENT_REDUCTION,
        PluginCapability.EVENT_REVERSION,
        PluginCapability.CORRELATION,
        PluginCapability.CONSISTENCY_CHECK,
        PluginCapability.TOPOLOGY_PROJECTION,
        PluginCapability.FORWARDING_PROJECTION,
        PluginCapability.FORWARDING_TRACE,
        PluginCapability.EVIDENCE_ANALYSIS,
    }
)


class CapabilityRoutingError(RuntimeError):
    """Base class for deterministic capability-routing failures."""


class CapabilityPlanUnavailableError(CapabilityRoutingError):
    """The selected revision has no usable immutable execution plan."""


class CapabilityRouteMissingError(CapabilityRoutingError):
    """No plan pin matches the exact requested route selector."""


class CapabilityRouteAmbiguousError(CapabilityRoutingError):
    """More than one plan pin matches an under-specified selector."""


class CapabilityRouteStaleError(CapabilityRoutingError):
    """A configured provider no longer matches its immutable plan pin."""


class RevisionSetCapabilityFailureCode(str, Enum):
    """Closed, payload-free reason for one member's failed fan-out call."""

    INPUT_REJECTED = "input_rejected"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    OUTPUT_REJECTED = "output_rejected"
    EXECUTION_FAILED = "execution_failed"
    ROUTING_FAILED = "routing_failed"


def _opaque(value: object, label: str) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise ValueError(f"{label} must contain 1 to 256 characters")
    if (
        value != value.strip()
        or contains_unsafe_identifier_text(value)
        or not has_visible_identity_anchor(value)
    ):
        raise ValueError(f"{label} must be an opaque identifier")
    return value


class CapabilityProviderRegistry:
    """Deployment-owned directory keyed by stable logical instance ID.

    Records must come from :class:`PluginRegistry`, which remains the single
    owner of executable fingerprinting, manifest snapshots, configuration
    digests, and decoder binding.  Separate ``PluginRegistry`` instances may
    register different configurations of the same plug-in/version and their
    records may coexist here under distinct instance IDs. Historical releases
    of one logical instance may coexist, but changing its plug-in identity or
    configuration requires a new instance ID.
    """

    def __init__(self, providers: Iterable[RegisteredPlugin] = ()) -> None:
        self._providers: dict[str, list[RegisteredPlugin]] = {}
        self._schema_digests: dict[tuple[str, str], str] = {}
        self._provider_count = 0
        self._sealed = False
        self._mutation_lock = threading.RLock()
        for provider in providers:
            self.add_registered(provider)

    @classmethod
    def from_primary_registry(
        cls,
        registry: PluginRegistry,
    ) -> CapabilityProviderRegistry:
        if type(registry) is not PluginRegistry:
            raise TypeError("registry must be an exact PluginRegistry")
        # Compatibility-only manifest identities remain valid primary parser
        # registrations for legacy/embedded ingestion, but they are not
        # eligible capability providers.  Omitting them here keeps a default
        # no-composition pipeline backward compatible while any policy that
        # tries to select one still fails closed as a missing exact provider.
        return cls(
            provider
            for provider in registry.records()
            if provider.verify_package_bytes
        )

    def add_registered(self, provider: RegisteredPlugin) -> str:
        with self._mutation_lock:
            if self._sealed:
                raise RuntimeError("capability provider registry is sealed")
            if type(provider) is not RegisteredPlugin:
                raise TypeError("provider must be an exact RegisteredPlugin")
            if provider._registered_execution_identity_snapshot is None:
                raise ValueError("provider must be created by PluginRegistry.register()")
            if not provider.verify_package_bytes:
                raise ValueError(
                    "capability providers require a revalidatable executable identity"
                )
            instance_id = _opaque(provider.instance_id, "provider instance_id")
            if self._provider_count >= _MAX_PROVIDERS:
                raise ValueError(
                    f"at most {_MAX_PROVIDERS} providers may be registered"
                )
            try:
                PluginRegistry.revalidate_registered_identity(provider)
                declared_schema_digest = plugin_schema_digest(
                    provider.execution_plugin.describe()
                )
                PluginRegistry.revalidate_registered_identity(provider)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise ValueError(
                    "capability provider identity or declared schema is not valid"
                ) from error
            bucket = self._providers.setdefault(instance_id, [])
            execution_identity = provider.registered_execution_identity
            if any(item.plugin_id != provider.plugin_id for item in bucket):
                raise ValueError(
                    "one capability provider instance_id cannot name different plug-ins"
                )
            if any(
                item.configuration_digest != provider.configuration_digest
                for item in bucket
            ):
                raise ValueError(
                    "a different capability provider configuration requires a new "
                    "instance_id"
                )
            if any(
                item.registered_execution_identity == execution_identity
                for item in bucket
            ):
                raise ValueError(
                    "duplicate capability provider execution identity for "
                    f"instance {instance_id!r}"
                )
            bucket.append(provider)
            self._schema_digests[(instance_id, execution_identity)] = (
                declared_schema_digest
            )
            self._provider_count += 1
            return instance_id

    def instance_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))

    def records(self) -> tuple[RegisteredPlugin, ...]:
        """Return every admitted provider in canonical execution order."""

        with self._mutation_lock:
            return tuple(
                provider
                for instance_id in sorted(self._providers)
                for provider in sorted(
                    self._providers[instance_id],
                    key=lambda item: item._registered_execution_identity_snapshot or "",
                )
            )

    def _sealed_snapshot(self) -> CapabilityProviderRegistry:
        """Freeze the exact current provider directory for one authority owner."""

        with self._mutation_lock:
            snapshot = CapabilityProviderRegistry()
            snapshot._providers = {
                instance_id: list(providers)
                for instance_id, providers in self._providers.items()
            }
            snapshot._schema_digests = dict(self._schema_digests)
            snapshot._provider_count = self._provider_count
            snapshot._sealed = True
        return snapshot

    def get_by_execution_identity(
        self,
        instance_id: str,
        registered_execution_identity: str,
    ) -> RegisteredPlugin:
        """Resolve one exact configured provider without fallback behavior."""

        selected_instance = _opaque(instance_id, "provider instance_id")
        if (
            type(registered_execution_identity) is not str
            or _SHA256_PATTERN.fullmatch(registered_execution_identity) is None
        ):
            raise ValueError(
                "registered_execution_identity must be a lowercase SHA-256 digest"
            )
        matches = tuple(
            provider
            for provider in self._resolve(selected_instance)
            if provider.registered_execution_identity
            == registered_execution_identity
        )
        if len(matches) != 1:
            raise CapabilityRouteStaleError(
                "execution-plan provider identity is not installed"
            )
        return matches[0]

    def schema_digest_by_execution_identity(
        self,
        instance_id: str,
        registered_execution_identity: str,
    ) -> str:
        """Return the schema digest frozen when an exact provider was admitted."""

        provider = self.get_by_execution_identity(
            instance_id,
            registered_execution_identity,
        )
        return self._schema_digests[
            (provider.instance_id, provider.registered_execution_identity)
        ]

    def snapshot_exact(
        self,
        coordinates: tuple[tuple[str, str], ...],
    ) -> CapabilityProviderRegistry:
        """Freeze a bounded child-safe subset without re-invoking providers.

        Process ingestion needs only the auxiliaries selected by one primary
        policy rule.  Passing the deployment-wide directory through Windows
        spawn would pickle every configured platform instance, so this method
        copies only exact already-admitted records and their frozen schema
        digests.
        """

        if type(coordinates) is not tuple or len(coordinates) > 127:
            raise ValueError("provider snapshot supports at most 127 coordinates")
        if len(coordinates) != len(set(coordinates)):
            raise ValueError("provider snapshot coordinates must be unique")
        snapshot = CapabilityProviderRegistry()
        for coordinate in coordinates:
            if (
                type(coordinate) is not tuple
                or len(coordinate) != 2
                or any(type(value) is not str for value in coordinate)
            ):
                raise TypeError(
                    "provider snapshot coordinates must be exact string pairs"
                )
            instance_id, execution_identity = coordinate
            provider = self.get_by_execution_identity(
                instance_id,
                execution_identity,
            )
            _require_no_inline_only_plugin_compatibility(
                (provider,),
                boundary=(
                    "process provider snapshots require PROCESS-capable plug-ins"
                ),
            )
            snapshot._providers.setdefault(provider.instance_id, []).append(provider)
            snapshot._schema_digests[
                (provider.instance_id, provider.registered_execution_identity)
            ] = self.schema_digest_by_execution_identity(
                provider.instance_id,
                provider.registered_execution_identity,
            )
            snapshot._provider_count += 1
        snapshot._sealed = True
        return snapshot

    def _resolve(self, instance_id: str) -> tuple[RegisteredPlugin, ...]:
        try:
            return tuple(self._providers[instance_id])
        except KeyError as error:
            raise CapabilityRouteStaleError(
                "execution-plan provider is not installed"
            ) from error


@dataclass(frozen=True, slots=True)
class CapabilityRouteSelector:
    """One exact standard capability plus optional plan-owned qualifiers."""

    capability: PluginCapability
    role: str | None = None
    instance_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.capability) is not PluginCapability:
            raise TypeError("capability must be an exact PluginCapability")
        if self.capability not in _ROUTABLE_CAPABILITIES:
            raise ValueError(
                "capability is ingestion-owned and cannot be routed after publication"
            )
        if self.role is not None:
            _opaque(self.role, "route role")
        if self.instance_id is not None:
            _opaque(self.instance_id, "route instance_id")


@dataclass(frozen=True, slots=True)
class CapabilityProviderRef:
    """Detached producer provenance retained with every routed result."""

    catalog_revision_id: str
    member_id: str
    node_id: str
    basis_revision_id: str
    plan_digest: str
    capability: PluginCapability
    pin: PluginExecutionPin

    def __post_init__(self) -> None:
        _opaque(self.catalog_revision_id, "catalog_revision_id")
        _opaque(self.member_id, "member_id")
        _opaque(self.node_id, "node_id")
        _opaque(self.basis_revision_id, "basis_revision_id")
        if (
            type(self.plan_digest) is not str
            or _SHA256_PATTERN.fullmatch(self.plan_digest) is None
        ):
            raise ValueError("plan_digest must be a lowercase SHA-256 digest")
        if type(self.capability) is not PluginCapability:
            raise TypeError("capability must be an exact PluginCapability")
        object.__setattr__(self, "pin", snapshot_plugin_execution_pin(self.pin))


@dataclass(frozen=True, slots=True)
class CapabilityInvocation[ResultT]:
    """One validated result and the exact producer that created it."""

    provider: CapabilityProviderRef
    result: ResultT


@dataclass(frozen=True, slots=True, order=True)
class RevisionSetCapabilityKey:
    """Exact identity of one revision/member capability router."""

    catalog_revision_id: str
    member_id: str

    def __post_init__(self) -> None:
        _opaque(self.catalog_revision_id, "catalog_revision_id")
        _opaque(self.member_id, "member_id")


@dataclass(frozen=True, slots=True)
class RevisionSetCapabilityResolution:
    """Canonical routes and members that do not declare the capability."""

    routes: tuple[PlanBoundCapabilityRoute, ...]
    missing: tuple[RevisionSetCapabilityKey, ...]

    def __post_init__(self) -> None:
        if type(self.routes) is not tuple or type(self.missing) is not tuple:
            raise TypeError("revision-set resolution fields must be exact tuples")
        route_keys: list[RevisionSetCapabilityKey] = []
        for route in self.routes:
            if type(route) is not PlanBoundCapabilityRoute:
                raise TypeError("routes must contain exact plan-bound routes")
            route_keys.append(_provider_revision_key(route.provider))
        if any(type(key) is not RevisionSetCapabilityKey for key in self.missing):
            raise TypeError("missing must contain exact revision/member keys")
        _validate_revision_result_keys(route_keys, self.missing)


@dataclass(frozen=True, slots=True)
class RevisionSetCapabilityFailure:
    """One producer-qualified, bounded fan-out failure."""

    key: RevisionSetCapabilityKey
    provider: CapabilityProviderRef
    code: RevisionSetCapabilityFailureCode

    def __post_init__(self) -> None:
        if type(self.key) is not RevisionSetCapabilityKey:
            raise TypeError("key must be an exact RevisionSetCapabilityKey")
        if type(self.provider) is not CapabilityProviderRef:
            raise TypeError("provider must be an exact CapabilityProviderRef")
        if type(self.code) is not RevisionSetCapabilityFailureCode:
            raise TypeError("code must be an exact RevisionSetCapabilityFailureCode")
        if (
            self.provider.catalog_revision_id != self.key.catalog_revision_id
            or self.provider.member_id != self.key.member_id
        ):
            raise ValueError("failure provider does not match its revision/member key")


@dataclass(frozen=True, slots=True)
class RevisionSetCapabilityFanout[ResultT]:
    """Canonical successes, explicit absences, and bounded failures."""

    invocations: tuple[CapabilityInvocation[ResultT], ...]
    missing: tuple[RevisionSetCapabilityKey, ...]
    failures: tuple[RevisionSetCapabilityFailure, ...]

    def __post_init__(self) -> None:
        if (
            type(self.invocations) is not tuple
            or type(self.missing) is not tuple
            or type(self.failures) is not tuple
        ):
            raise TypeError("revision-set fan-out fields must be exact tuples")
        invocation_keys: list[RevisionSetCapabilityKey] = []
        for invocation in self.invocations:
            if type(invocation) is not CapabilityInvocation:
                raise TypeError("invocations must contain exact capability invocations")
            invocation_keys.append(_provider_revision_key(invocation.provider))
        if any(type(key) is not RevisionSetCapabilityKey for key in self.missing):
            raise TypeError("missing must contain exact revision/member keys")
        if any(
            type(failure) is not RevisionSetCapabilityFailure
            for failure in self.failures
        ):
            raise TypeError("failures must contain exact revision-set failures")
        _validate_revision_result_keys(
            invocation_keys,
            self.missing,
            tuple(failure.key for failure in self.failures),
        )


def _provider_revision_key(
    provider: CapabilityProviderRef,
) -> RevisionSetCapabilityKey:
    return RevisionSetCapabilityKey(
        catalog_revision_id=provider.catalog_revision_id,
        member_id=provider.member_id,
    )


def _validate_revision_result_keys(
    *groups: Iterable[RevisionSetCapabilityKey],
) -> None:
    materialized = tuple(tuple(group) for group in groups)
    flattened = tuple(key for group in materialized for key in group)
    if not 1 <= len(flattened) <= _MAX_REVISION_SET_ROUTERS:
        raise ValueError(
            "revision-set results must account for 1 to "
            f"{_MAX_REVISION_SET_ROUTERS} members"
        )
    if len(flattened) != len(set(flattened)):
        raise ValueError("revision-set result keys must be unique")
    if any(group != tuple(sorted(group)) for group in materialized):
        raise ValueError("each revision-set result group must use canonical key order")


@dataclass(frozen=True, slots=True)
class _BoundProvider:
    pin: PluginExecutionPin
    registered: RegisteredPlugin = field(repr=False, compare=False)


class PlanBoundCapabilityRouter:
    """Resolve and execute capabilities only through one immutable plan."""

    def __init__(
        self,
        providers: CapabilityProviderRegistry,
        plan: PluginExecutionPlan | None,
        *,
        catalog_revision_id: str,
        member_id: str,
        limits: PluginCapabilityLimits | None = None,
    ) -> None:
        if type(providers) is not CapabilityProviderRegistry:
            raise TypeError("providers must be a CapabilityProviderRegistry")
        if plan is None:
            raise CapabilityPlanUnavailableError(
                "selected revision has no immutable plug-in execution plan"
            )
        try:
            detached_plan = snapshot_plugin_execution_plan(plan)
            if not plugin_execution_plan_is_executable(detached_plan):
                raise CapabilityPlanUnavailableError(
                    "retained v1 plug-in execution plans are passive catalog "
                    "records and cannot bind capability providers"
                )
            primary_pin = primary_parser_execution_pin(detached_plan)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except CapabilityPlanUnavailableError:
            raise
        except (TypeError, ValueError) as error:
            raise CapabilityPlanUnavailableError(
                "selected revision has an invalid plug-in execution plan"
            ) from error
        self.catalog_revision_id: str = _opaque(
            catalog_revision_id,
            "catalog_revision_id",
        )
        self.member_id: str = _opaque(member_id, "member_id")
        self.plan: PluginExecutionPlan = detached_plan
        self.limits: PluginCapabilityLimits = limits or PluginCapabilityLimits()
        self._providers = providers
        self._bound: dict[str, _BoundProvider] = {}

        for pin in self.plan.plugins:
            candidates = providers._resolve(pin.instance_id)
            exact: list[RegisteredPlugin] = []
            for candidate in candidates:
                try:
                    if not registered_plugin_matches_execution_pin(pin, candidate):
                        continue
                    if "primary_parser" in pin.roles:
                        if (
                            self.plan.decoder is not None
                            and candidate.decoder_identity != self.plan.decoder
                        ):
                            continue
                    elif candidate.decoder_identity is not None:
                        continue
                except PROCESS_CONTROL_EXCEPTIONS:
                    raise
                except BaseException as error:
                    raise CapabilityRouteStaleError(
                        "capability provider decoder identity is unreadable"
                    ) from error
                try:
                    self._validated_executor(pin, candidate)
                except CapabilityRouteStaleError:
                    continue
                exact.append(candidate)
            if not exact:
                raise CapabilityRouteStaleError(
                    "no installed provider matches the execution-plan pin"
                )
            if len(exact) != 1:
                raise CapabilityRouteStaleError(
                    "more than one installed provider matches the execution-plan pin"
                )
            registered = exact[0]
            self._bound[pin.instance_id] = _BoundProvider(pin, registered)
        if primary_pin.instance_id not in self._bound:
            raise CapabilityPlanUnavailableError(
                "execution plan primary parser is not bound"
            )

    def _validate_static_pin(
        self,
        pin: PluginExecutionPin,
        registered: RegisteredPlugin,
    ) -> None:
        try:
            _require_no_inline_only_plugin_compatibility(
                (registered,),
                boundary=(
                    "plan-bound capability routing requires PROCESS-capable plug-ins"
                ),
            )
            PluginRegistry.revalidate_registered_identity(registered)
            matches = registered_plugin_matches_execution_pin(pin, registered)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise CapabilityRouteStaleError(
                "capability provider identity cannot be revalidated"
            ) from error
        if not matches:
            raise CapabilityRouteStaleError(
                "capability provider does not match the execution-plan pin"
            )

    def _validated_executor(
        self,
        pin: PluginExecutionPin,
        registered: RegisteredPlugin,
    ) -> PluginCapabilityExecutor:
        self._validate_static_pin(pin, registered)
        try:
            return PluginCapabilityExecutor.for_execution_pin(
                registered.execution_plugin,
                pin,
                member_id=self.member_id,
                limits=self.limits,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except (PluginCapabilityBindingError, TypeError, ValueError) as error:
            raise CapabilityRouteStaleError(
                "capability provider schema or manifest is stale"
            ) from error
        except BaseException as error:
            raise CapabilityRouteStaleError(
                "capability provider could not be safely bound"
            ) from error

    def resolve(
        self,
        selector: CapabilityRouteSelector,
    ) -> PlanBoundCapabilityRoute:
        if type(selector) is not CapabilityRouteSelector:
            raise TypeError("selector must be an exact CapabilityRouteSelector")
        capability = selector.capability.value
        matches = tuple(
            pin
            for pin in self.plan.plugins
            if capability in pin.capabilities
            and (selector.role is None or selector.role in pin.roles)
            and (
                selector.instance_id is None or selector.instance_id == pin.instance_id
            )
        )
        if not matches:
            raise CapabilityRouteMissingError(
                "no execution-plan provider matches the capability selector"
            )
        if len(matches) != 1:
            raise CapabilityRouteAmbiguousError(
                "capability selector matches more than one execution-plan provider"
            )
        pin = matches[0]
        bound = self._bound[pin.instance_id]
        return PlanBoundCapabilityRoute(
            _router=self,
            selector=selector,
            _pin=bound.pin,
        )

    def _reference(
        self,
        capability: PluginCapability,
        pin: PluginExecutionPin,
    ) -> CapabilityProviderRef:
        return CapabilityProviderRef(
            catalog_revision_id=self.catalog_revision_id,
            member_id=self.member_id,
            node_id=self.plan.node_id,
            basis_revision_id=self.plan.basis_revision_id,
            plan_digest=self.plan.plan_digest,
            capability=capability,
            pin=pin,
        )

    def _invoke[ResultT](
        self,
        capability: PluginCapability,
        pin: PluginExecutionPin,
        operation: Callable[[PluginCapabilityExecutor], ResultT],
    ) -> CapabilityInvocation[ResultT]:
        if type(pin) is not PluginExecutionPin:
            raise CapabilityRouteStaleError("capability route pin is invalid")
        try:
            bound = self._bound[pin.instance_id]
        except (KeyError, AttributeError) as error:
            raise CapabilityRouteStaleError(
                "capability route is not bound to this execution plan"
            ) from error
        if pin != bound.pin or capability.value not in pin.capabilities:
            raise CapabilityRouteStaleError(
                "capability route does not match its execution-plan binding"
            )
        registered = bound.registered
        executor = self._validated_executor(pin, registered)
        try:
            result = operation(executor)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except PluginCapabilityExecutionError as invocation_error:
            try:
                self._revalidate_failed_invocation(pin, registered)
            except CapabilityRouteStaleError as stale:
                raise stale from invocation_error
            raise
        except BaseException as invocation_error:
            try:
                self._revalidate_failed_invocation(pin, registered)
            except CapabilityRouteStaleError as stale:
                raise stale from invocation_error
            raise CapabilityRoutingError(
                "capability provider invocation failed"
            ) from invocation_error
        self._validated_executor(pin, registered)
        return CapabilityInvocation(
            provider=self._reference(capability, pin),
            result=result,
        )

    def _revalidate_failed_invocation(
        self,
        pin: PluginExecutionPin,
        registered: RegisteredPlugin,
    ) -> None:
        """Recheck identity while allowing process controls to escape unchanged."""

        self._validated_executor(pin, registered)


@dataclass(frozen=True, slots=True)
class PlanBoundCapabilityRoute:
    """One statically selected typed capability; never exposes its plug-in."""

    _router: PlanBoundCapabilityRouter = field(repr=False, compare=False)
    selector: CapabilityRouteSelector
    _pin: PluginExecutionPin = field(repr=False)

    def __post_init__(self) -> None:
        if type(self._router) is not PlanBoundCapabilityRouter:
            raise TypeError("_router must be an exact PlanBoundCapabilityRouter")
        if type(self.selector) is not CapabilityRouteSelector:
            raise TypeError("selector must be an exact CapabilityRouteSelector")
        if type(self._pin) is not PluginExecutionPin:
            raise TypeError("_pin must be an exact PluginExecutionPin")

    @property
    def provider(self) -> CapabilityProviderRef:
        return self._router._reference(self.selector.capability, self._pin)

    def _require(self, capability: PluginCapability) -> None:
        if self.selector.capability is not capability:
            raise CapabilityRouteMissingError(
                "the selected route is bound to a different capability"
            )

    def apply(
        self,
        event: DomainEvent,
        world: ReadOnlyWorld,
    ) -> CapabilityInvocation[ChangeSet]:
        capability = PluginCapability.EVENT_REDUCTION
        self._require(capability)
        return self._router._invoke(
            capability,
            self._pin,
            lambda executor: executor.apply(event, world),
        )

    def revert(
        self,
        event: DomainEvent,
        world_after: ReadOnlyWorld,
    ) -> CapabilityInvocation[ChangeSet]:
        capability = PluginCapability.EVENT_REVERSION
        self._require(capability)
        return self._router._invoke(
            capability,
            self._pin,
            lambda executor: executor.revert(event, world_after),
        )

    def correlate(
        self,
        reader: CorrelationReader,
        window: CorrelationWindow,
    ) -> CapabilityInvocation[CorrelationExecutionResult]:
        capability = PluginCapability.CORRELATION
        self._require(capability)
        return self._router._invoke(
            capability,
            self._pin,
            lambda executor: executor.correlate(reader, window),
        )

    def check_consistency(
        self,
        world: ReadOnlyWorld,
    ) -> CapabilityInvocation[ConsistencyExecutionResult]:
        capability = PluginCapability.CONSISTENCY_CHECK
        self._require(capability)
        return self._router._invoke(
            capability,
            self._pin,
            lambda executor: executor.check_consistency(world),
        )

    def project_topology(
        self,
        request: TopologyProjectionRequest,
        world: ReadOnlyWorld,
    ) -> CapabilityInvocation[TopologyExecutionResult]:
        capability = PluginCapability.TOPOLOGY_PROJECTION
        self._require(capability)
        return self._router._invoke(
            capability,
            self._pin,
            lambda executor: executor.project_topology(request, world),
        )

    def project_forwarding(
        self,
        request: ForwardingProjectionRequest,
        world: ReadOnlyWorld,
    ) -> CapabilityInvocation[ForwardingProjectionExecutionResult]:
        capability = PluginCapability.FORWARDING_PROJECTION
        self._require(capability)
        return self._router._invoke(
            capability,
            self._pin,
            lambda executor: executor.project_forwarding(request, world),
        )

    def resolve_forwarding_step(
        self,
        request: ForwardingStepRequest,
        world: ReadOnlyWorld,
    ) -> CapabilityInvocation[ForwardingStepExecutionResult]:
        capability = PluginCapability.FORWARDING_TRACE
        self._require(capability)
        return self._router._invoke(
            capability,
            self._pin,
            lambda executor: executor.resolve_forwarding_step(request, world),
        )

    def analyze_evidence(
        self,
        request: EvidenceAnalysisRequest,
    ) -> CapabilityInvocation[EvidenceAnalysisExecutionResult]:
        capability = PluginCapability.EVIDENCE_ANALYSIS
        self._require(capability)
        return self._router._invoke(
            capability,
            self._pin,
            lambda executor: executor.analyze_evidence(request),
        )


class RevisionSetCapabilityRouter:
    """Deterministically route capabilities across an immutable revision set.

    Each member retains its own execution plan and provider provenance.  Bulk
    resolution never selects a first match: it reports every matching route
    and every member where the capability is absent.  Ambiguous or stale
    member bindings remain fatal.
    """

    def __init__(
        self,
        routers: Iterable[PlanBoundCapabilityRouter],
    ) -> None:
        indexed: dict[RevisionSetCapabilityKey, PlanBoundCapabilityRouter] = {}
        for router in routers:
            if len(indexed) >= _MAX_REVISION_SET_ROUTERS:
                raise ValueError(
                    "a revision-set capability router supports at most "
                    f"{_MAX_REVISION_SET_ROUTERS} members"
                )
            if type(router) is not PlanBoundCapabilityRouter:
                raise TypeError(
                    "routers must contain exact PlanBoundCapabilityRouter objects"
                )
            key = RevisionSetCapabilityKey(
                catalog_revision_id=router.catalog_revision_id,
                member_id=router.member_id,
            )
            if key in indexed:
                raise ValueError("revision-set capability router keys must be unique")
            indexed[key] = router
        if not indexed:
            raise ValueError(
                "a revision-set capability router needs at least one member"
            )
        self._routers = indexed
        self._keys = tuple(sorted(indexed))

    @property
    def keys(self) -> tuple[RevisionSetCapabilityKey, ...]:
        """Return the canonical, input-order-independent member keys."""

        return self._keys

    def _router_for(
        self,
        key: RevisionSetCapabilityKey,
    ) -> PlanBoundCapabilityRouter:
        if type(key) is not RevisionSetCapabilityKey:
            raise TypeError("key must be an exact RevisionSetCapabilityKey")
        try:
            router = self._routers[key]
        except KeyError as error:
            raise CapabilityRouteMissingError(
                "revision-set member is not bound"
            ) from error
        if (
            router.catalog_revision_id != key.catalog_revision_id
            or router.member_id != key.member_id
        ):
            raise CapabilityRouteStaleError(
                "revision-set member identity changed after binding"
            )
        return router

    def resolve(
        self,
        key: RevisionSetCapabilityKey,
        selector: CapabilityRouteSelector,
    ) -> PlanBoundCapabilityRoute:
        """Resolve one exact revision/member without cross-member fallback."""

        return self._router_for(key).resolve(selector)

    def resolve_all(
        self,
        selector: CapabilityRouteSelector,
    ) -> RevisionSetCapabilityResolution:
        """Resolve every member, retaining explicit capability absences."""

        if type(selector) is not CapabilityRouteSelector:
            raise TypeError("selector must be an exact CapabilityRouteSelector")
        routes: list[PlanBoundCapabilityRoute] = []
        missing: list[RevisionSetCapabilityKey] = []
        for key in self._keys:
            try:
                routes.append(self._router_for(key).resolve(selector))
            except CapabilityRouteMissingError:
                missing.append(key)
        return RevisionSetCapabilityResolution(tuple(routes), tuple(missing))

    def fanout[ResultT](
        self,
        selector: CapabilityRouteSelector,
        operation: Callable[
            [PlanBoundCapabilityRoute],
            CapabilityInvocation[ResultT],
        ],
    ) -> RevisionSetCapabilityFanout[ResultT]:
        """Invoke all matching routes and retain bounded per-provider outcomes."""

        if not callable(operation):
            raise TypeError("operation must be callable")
        resolution = self.resolve_all(selector)
        invocations: list[CapabilityInvocation[ResultT]] = []
        failures: list[RevisionSetCapabilityFailure] = []
        for route in resolution.routes:
            key = _provider_revision_key(route.provider)
            try:
                invocation = operation(route)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except CapabilityRouteStaleError:
                raise
            except PluginCapabilityInputError:
                failures.append(
                    RevisionSetCapabilityFailure(
                        key,
                        route.provider,
                        RevisionSetCapabilityFailureCode.INPUT_REJECTED,
                    )
                )
                continue
            except PluginCapabilityUnavailableError:
                failures.append(
                    RevisionSetCapabilityFailure(
                        key,
                        route.provider,
                        RevisionSetCapabilityFailureCode.CAPABILITY_UNAVAILABLE,
                    )
                )
                continue
            except PluginCapabilityOutputError:
                failures.append(
                    RevisionSetCapabilityFailure(
                        key,
                        route.provider,
                        RevisionSetCapabilityFailureCode.OUTPUT_REJECTED,
                    )
                )
                continue
            except PluginCapabilityExecutionError:
                failures.append(
                    RevisionSetCapabilityFailure(
                        key,
                        route.provider,
                        RevisionSetCapabilityFailureCode.EXECUTION_FAILED,
                    )
                )
                continue
            except CapabilityRoutingError:
                failures.append(
                    RevisionSetCapabilityFailure(
                        key,
                        route.provider,
                        RevisionSetCapabilityFailureCode.ROUTING_FAILED,
                    )
                )
                continue
            if type(invocation) is not CapabilityInvocation:
                raise TypeError(
                    "fanout operation must return an exact CapabilityInvocation"
                )
            if invocation.provider != route.provider:
                raise CapabilityRoutingError(
                    "fanout operation returned an invocation for a different provider"
                )
            invocations.append(invocation)
        return RevisionSetCapabilityFanout(
            tuple(invocations),
            resolution.missing,
            tuple(failures),
        )


__all__ = [
    "CapabilityInvocation",
    "CapabilityPlanUnavailableError",
    "CapabilityProviderRef",
    "CapabilityProviderRegistry",
    "CapabilityRouteAmbiguousError",
    "CapabilityRouteMissingError",
    "CapabilityRouteSelector",
    "CapabilityRouteStaleError",
    "CapabilityRoutingError",
    "PlanBoundCapabilityRoute",
    "PlanBoundCapabilityRouter",
    "RevisionSetCapabilityFailure",
    "RevisionSetCapabilityFailureCode",
    "RevisionSetCapabilityFanout",
    "RevisionSetCapabilityKey",
    "RevisionSetCapabilityResolution",
    "RevisionSetCapabilityRouter",
]
