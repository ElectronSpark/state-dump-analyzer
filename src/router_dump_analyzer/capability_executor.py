"""Bounded core callers for optional analyzer plug-in capabilities.

The plug-in API deliberately describes domain-neutral records.  This module is
the matching trust boundary: it checks that a plug-in advertised a capability,
limits every world read and yielded result, validates references against the
plug-in's immutable schema, closes plug-in iterators, and preserves recoverable
diagnostics without assigning meaning to opaque plug-in vocabulary.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from math import isfinite
from typing import Any, cast
from uuid import UUID

from .plugin_api import (
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
    AbsoluteTimeSelector,
    Adjacency,
    AnalyzerPlugin,
    CaptureRange,
    CausalLink,
    ChangeSet,
    ClockAnchor,
    ConsistencyFinding,
    CorrelationReader,
    CorrelationWindow,
    DiagnosticOrigin,
    DiagnosticSeverity,
    DomainEvent,
    Evidence,
    FailoverGroup,
    FibEntry,
    FindingResult,
    ForwardingMutation,
    ForwardingOperation,
    ForwardingProjectionRequest,
    ForwardingStepRequest,
    ForwardingStepResult,
    ForwardingTransitionOrigin,
    InterfaceForwardingState,
    MutationOperation,
    NextHop,
    NextHopGroup,
    PluginCapability,
    PluginDiagnostic,
    PluginManifest,
    PluginSchema,
    PropertyPatch,
    Provenance,
    Quality,
    ReadOnlyWorld,
    ReconstructionWatermark,
    ReconstructionCoverage,
    RelativeToWatermarkSelector,
    RelationshipMutation,
    RelationshipOperation,
    RelationshipView,
    ResourceKey,
    ResourceStateView,
    ResolvedNodeBasis,
    StateMutation,
    StatusPerspectiveRef,
    TopologyEndpointRecord,
    TopologyEndpointReference,
    TopologyLinkRecord,
    TopologyProjectionRecord,
    TopologyProjectionRequest,
    TopologyResourceRecord,
    TopologyUsability,
    TunnelAction,
    UnknownChange,
    UnknownField,
    VrfForwardingState,
    WorldBasis,
    WorldBasisKind,
    validate_plugin_diagnostic,
)


class PluginCapabilityExecutionError(RuntimeError):
    """An optional plug-in capability could not produce a safe core result."""

    def __init__(
        self,
        message: str,
        *,
        capability: PluginCapability,
        diagnostics: tuple[PluginDiagnostic, ...] = (),
    ) -> None:
        super().__init__(message)
        self.capability = capability
        self.diagnostics = diagnostics


class PluginCapabilityUnavailableError(PluginCapabilityExecutionError):
    """The plug-in did not advertise a requested standard capability."""


class PluginCapabilityOutputError(PluginCapabilityExecutionError):
    """The plug-in returned a malformed or over-limit capability result."""


@dataclass(frozen=True, slots=True)
class PluginCapabilityLimits:
    """Core-owned ceilings independent of plug-in-provided request limits."""

    max_world_reads: int = 50_000
    max_change_items: int = 50_000
    max_correlation_outputs: int = 50_000
    max_consistency_outputs: int = 10_000
    max_topology_outputs: int = 100_000
    max_forwarding_outputs: int = 100_000
    max_diagnostics: int = 1_000
    max_evidence_per_output: int = 64
    max_resource_references: int = 4_096

    def __post_init__(self) -> None:
        for name, value in (
            ("max_world_reads", self.max_world_reads),
            ("max_change_items", self.max_change_items),
            ("max_correlation_outputs", self.max_correlation_outputs),
            ("max_consistency_outputs", self.max_consistency_outputs),
            ("max_topology_outputs", self.max_topology_outputs),
            ("max_forwarding_outputs", self.max_forwarding_outputs),
            ("max_diagnostics", self.max_diagnostics),
            ("max_evidence_per_output", self.max_evidence_per_output),
            ("max_resource_references", self.max_resource_references),
        ):
            if type(value) is not int or not 1 <= value <= 1_000_000:
                raise ValueError(f"{name} must be an integer between 1 and 1000000")


@dataclass(frozen=True, slots=True)
class CorrelationExecutionResult:
    causal_links: tuple[CausalLink, ...]
    relationship_mutations: tuple[RelationshipMutation, ...]
    clock_anchors: tuple[ClockAnchor, ...]
    diagnostics: tuple[PluginDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class ConsistencyExecutionResult:
    findings: tuple[ConsistencyFinding, ...]
    diagnostics: tuple[PluginDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class TopologyExecutionResult:
    records: tuple[TopologyProjectionRecord, ...]
    diagnostics: tuple[PluginDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class ForwardingProjectionExecutionResult:
    mutations: tuple[ForwardingMutation, ...]
    diagnostics: tuple[PluginDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class ForwardingStepExecutionResult:
    result: ForwardingStepResult | None
    diagnostics: tuple[PluginDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class _SchemaIndex:
    key_fields_by_kind: Mapping[str, tuple[str, ...]]
    property_roots_by_kind: Mapping[str, frozenset[str]]
    relationship_types: frozenset[str]
    causal_link_types: frozenset[str]
    perspectives: frozenset[str]
    topology_perspectives: Mapping[str, frozenset[str]]

    @classmethod
    def build(cls, schema: PluginSchema) -> _SchemaIndex:
        key_fields: dict[str, tuple[str, ...]] = {}
        property_roots: dict[str, frozenset[str]] = {}
        for resource_kind in schema.resource_kinds:
            key_fields[resource_kind.kind] = resource_kind.key_fields
            property_roots[resource_kind.kind] = frozenset(
                item.name.partition(".")[0]
                for item in resource_kind.properties
            )
        return cls(
            key_fields_by_kind=key_fields,
            property_roots_by_kind=property_roots,
            relationship_types=frozenset(
                descriptor.relation_type
                for descriptor in schema.relationship_types
            ),
            causal_link_types=frozenset(
                descriptor.link_type for descriptor in schema.causal_link_types
            ),
            perspectives=frozenset(
                descriptor.perspective_id
                for descriptor in schema.status_perspectives
            ),
            topology_perspectives={
                descriptor.projection_id: frozenset(
                    descriptor.supported_status_perspective_ids
                )
                for descriptor in schema.topology_projections
            },
        )


class _BoundedWorld:
    """Read-only world facade that charges every returned state or relation."""

    def __init__(
        self,
        world: ReadOnlyWorld,
        maximum_reads: int,
        capability: PluginCapability,
    ) -> None:
        self._world = world
        self._remaining = maximum_reads
        self._capability = capability

    @property
    def basis(self) -> WorldBasis:
        return self._world.basis

    @property
    def perspective_ref(self) -> StatusPerspectiveRef | None:
        return self._world.perspective_ref

    @property
    def remaining_reads(self) -> int:
        return self._remaining

    def _charge(self) -> None:
        if self._remaining <= 0:
            raise PluginCapabilityOutputError(
                "plug-in exceeded the configured world-read limit",
                capability=self._capability,
            )
        self._remaining -= 1

    def state_of(self, resource: ResourceKey) -> ResourceStateView | None:
        self._charge()
        return self._world.state_of(resource)

    def _bounded_iter[Item](
        self,
        producer: Callable[[int], Iterable[Item]],
        requested_limit: int | None,
    ) -> Iterator[Item]:
        if self._remaining <= 0:
            raise PluginCapabilityOutputError(
                "plug-in exceeded the configured world-read limit",
                capability=self._capability,
            )
        allowed = self._remaining
        if requested_limit is not None:
            if type(requested_limit) is not int or requested_limit < 0:
                raise ValueError("world read limit must be a non-negative integer")
            allowed = min(allowed, requested_limit)
        iterator = iter(producer(allowed))
        count = 0
        try:
            for item in iterator:
                if count >= allowed:
                    raise PluginCapabilityOutputError(
                        "world provider exceeded the bounded read request",
                        capability=self._capability,
                    )
                self._charge()
                count += 1
                yield item
        finally:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()

    def iter_states(
        self,
        layers: frozenset[str] | None = None,
        kinds: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[ResourceStateView]:
        return self._bounded_iter(
            lambda bounded: self._world.iter_states(
                layers=layers,
                kinds=kinds,
                limit=bounded,
            ),
            limit,
        )

    def related(
        self,
        resource: ResourceKey,
        direction: Any = None,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        if direction is None:
            from .plugin_api import RelationDirection

            direction = RelationDirection.OUTGOING
        return self._bounded_iter(
            lambda bounded: self._world.related(
                resource,
                direction=direction,
                relation_types=relation_types,
                limit=bounded,
            ),
            limit,
        )

    def iter_relationships(
        self,
        relation_types: frozenset[str] | None = None,
        layers: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        return self._bounded_iter(
            lambda bounded: self._world.iter_relationships(
                relation_types=relation_types,
                layers=layers,
                limit=bounded,
            ),
            limit,
        )


class _ValueBudget:
    def __init__(self) -> None:
        self.units = 0
        self.active: set[int] = set()


def _validate_value(
    value: Any,
    label: str,
    *,
    budget: _ValueBudget | None = None,
    depth: int = 0,
) -> None:
    """Validate one bounded Properties-compatible value without interpretation."""

    current = budget or _ValueBudget()
    current.units += 1
    if current.units > 4_096:
        raise ValueError(f"{label} exceeds 4096 value units")
    if depth > 16:
        raise ValueError(f"{label} exceeds 16 container levels")
    if value is None or type(value) is bool or isinstance(value, UUID):
        return
    if type(value) is int:
        if value.bit_length() > 4_096:
            raise ValueError(f"{label} contains an integer exceeding 4096 bits")
        return
    if type(value) is float:
        if not isfinite(value):
            raise ValueError(f"{label} contains a non-finite float")
        return
    if isinstance(value, (str, bytes)):
        if len(value) > 65_536:
            raise ValueError(f"{label} contains an atom exceeding 65536 units")
        return
    if isinstance(value, tuple):
        if len(value) > 1_024:
            raise ValueError(f"{label} contains a tuple exceeding 1024 items")
        identity = id(value)
        if identity in current.active:
            raise ValueError(f"{label} contains a reference cycle")
        current.active.add(identity)
        try:
            for item in value:
                _validate_value(
                    item,
                    label,
                    budget=current,
                    depth=depth + 1,
                )
        finally:
            current.active.remove(identity)
        return
    if isinstance(value, Mapping):
        if len(value) > 1_024:
            raise ValueError(f"{label} contains a mapping exceeding 1024 items")
        identity = id(value)
        if identity in current.active:
            raise ValueError(f"{label} contains a reference cycle")
        current.active.add(identity)
        try:
            for key, item in value.items():
                if not isinstance(key, str) or not key or len(key) > 256:
                    raise ValueError(
                        f"{label} mapping keys must contain 1 to 256 characters"
                    )
                _validate_value(
                    item,
                    label,
                    budget=current,
                    depth=depth + 1,
                )
        finally:
            current.active.remove(identity)
        return
    raise ValueError(f"{label} contains unsupported type {type(value).__name__}")


class PluginCapabilityExecutor:
    """Invoke optional analyzer hooks through one bounded validation boundary."""

    def __init__(
        self,
        plugin: AnalyzerPlugin,
        schema: PluginSchema | None = None,
        *,
        limits: PluginCapabilityLimits | None = None,
    ) -> None:
        manifest = getattr(plugin, "manifest", None)
        if not isinstance(manifest, PluginManifest):
            raise TypeError("capability executor requires a PluginManifest")
        selected_schema = plugin.describe() if schema is None else schema
        if type(selected_schema) is not PluginSchema:
            raise TypeError("capability executor requires an exact PluginSchema")
        self.plugin = plugin
        self.manifest = manifest
        self.schema = selected_schema
        self.limits = limits or PluginCapabilityLimits()
        self._schema = _SchemaIndex.build(selected_schema)

    def _error(
        self,
        capability: PluginCapability,
        message: str,
        *,
        diagnostics: tuple[PluginDiagnostic, ...] = (),
    ) -> PluginCapabilityOutputError:
        return PluginCapabilityOutputError(
            message,
            capability=capability,
            diagnostics=diagnostics,
        )

    def _require(self, capability: PluginCapability, hook_name: str) -> None:
        if not self.manifest.supports(capability):
            raise PluginCapabilityUnavailableError(
                f"plug-in does not advertise {capability.value!r}",
                capability=capability,
            )
        if not callable(getattr(self.plugin, hook_name, None)):
            raise PluginCapabilityUnavailableError(
                f"plug-in capability {capability.value!r} has no {hook_name}() hook",
                capability=capability,
            )

    def _resource(self, value: Any, label: str) -> ResourceKey:
        if type(value) is not ResourceKey:
            raise ValueError(f"{label} must be an exact ResourceKey")
        expected = self._schema.key_fields_by_kind.get(value.kind)
        if expected is None:
            raise ValueError(
                f"{label} references undeclared resource kind {value.kind!r}"
            )
        actual = tuple(name for name, _item in value.parts)
        if actual != expected:
            raise ValueError(
                f"{label} key fields do not match the declared order for "
                f"{value.kind!r}"
            )
        return value

    def _evidence(self, value: Any, label: str) -> Evidence:
        if type(value) is not Evidence:
            raise ValueError(f"{label} must be an exact Evidence")
        if not isinstance(value.artifact_id, UUID):
            raise TypeError(f"{label}.artifact_id must be a UUID")
        if (
            not isinstance(value.locator, str)
            or not value.locator
            or len(value.locator) > 4_096
        ):
            raise ValueError(f"{label}.locator must contain 1 to 4096 characters")
        self._optional_time(
            value.raw_timestamp_ns,
            f"{label}.raw_timestamp_ns",
        )
        if value.clock_domain is not None and (
            not isinstance(value.clock_domain, str)
            or not value.clock_domain
            or len(value.clock_domain) > 256
        ):
            raise ValueError(
                f"{label}.clock_domain must contain 1 to 256 characters or be None"
            )
        if value.excerpt_sha256 is not None and (
            not isinstance(value.excerpt_sha256, str)
            or len(value.excerpt_sha256) != 64
            or any(
                character not in "0123456789abcdefABCDEF"
                for character in value.excerpt_sha256
            )
        ):
            raise ValueError(f"{label}.excerpt_sha256 must be a 64-digit hex digest")
        return value

    def _evidence_tuple(self, value: Any, label: str) -> tuple[Evidence, ...]:
        if not isinstance(value, tuple):
            raise TypeError(f"{label} must be a tuple")
        if len(value) > self.limits.max_evidence_per_output:
            raise ValueError(f"{label} exceeds the configured evidence limit")
        for index, item in enumerate(value):
            self._evidence(item, f"{label}[{index}]")
        return cast(tuple[Evidence, ...], value)

    def _diagnostic(self, value: Any, label: str) -> PluginDiagnostic:
        diagnostic = validate_plugin_diagnostic(
            value,
            label=label,
            expected_origin=DiagnosticOrigin.PLUGIN,
            maximum_evidence_items=self.limits.max_evidence_per_output,
        )
        return diagnostic

    def _diagnostics(
        self,
        values: Any,
        capability: PluginCapability,
        label: str,
    ) -> tuple[PluginDiagnostic, ...]:
        if not isinstance(values, tuple):
            raise self._error(capability, f"{label} must be a tuple")
        if len(values) > self.limits.max_diagnostics:
            raise self._error(
                capability,
                f"{label} exceeds the configured diagnostic limit",
            )
        diagnostics: list[PluginDiagnostic] = []
        try:
            for index, value in enumerate(values):
                diagnostic = self._diagnostic(value, f"{label}[{index}]")
                diagnostics.append(diagnostic)
                if not diagnostic.recoverable:
                    raise self._error(
                        capability,
                        f"{label} failed: {diagnostic.code}: {diagnostic.message}",
                        diagnostics=tuple(diagnostics),
                    )
        except PluginCapabilityExecutionError:
            raise
        except (TypeError, ValueError) as error:
            raise self._error(capability, str(error)) from error
        return tuple(diagnostics)

    def _perspective(self, value: StatusPerspectiveRef | None, label: str) -> None:
        if value is None:
            return
        if type(value) is not StatusPerspectiveRef:
            raise ValueError(f"{label} must be an exact StatusPerspectiveRef")
        if value.perspective_id not in self._schema.perspectives:
            raise ValueError(
                f"{label} references undeclared perspective "
                f"{value.perspective_id!r}"
            )

    def _patch(
        self,
        value: Any,
        label: str,
        *,
        resource_kind: str | None = None,
    ) -> PropertyPatch:
        if type(value) is not PropertyPatch:
            raise ValueError(f"{label} must be an exact PropertyPatch")
        if len(value.set_values) > 1_024:
            raise ValueError(f"{label}.set_values exceeds 1024 entries")
        _validate_value(value.set_values, f"{label}.set_values")
        if not isinstance(value.remove_fields, tuple) or len(value.remove_fields) > 1_024:
            raise ValueError(f"{label}.remove_fields must be a bounded tuple")
        if not isinstance(value.unknown_fields, tuple) or len(value.unknown_fields) > 1_024:
            raise ValueError(f"{label}.unknown_fields must be a bounded tuple")
        mentioned = {
            *(str(name).split(".", 1)[0] for name in value.set_values),
            *(str(name).split(".", 1)[0] for name in value.remove_fields),
            *(
                str(unknown.name).split(".", 1)[0]
                for unknown in value.unknown_fields
            ),
        }
        if resource_kind is not None:
            allowed = self._schema.property_roots_by_kind[resource_kind]
            if unknown_roots := mentioned - allowed:
                raise ValueError(
                    f"{label} references undeclared properties: "
                    + ", ".join(sorted(unknown_roots))
                )
        for field_name in value.remove_fields:
            if not isinstance(field_name, str) or not field_name:
                raise ValueError(f"{label}.remove_fields contains an invalid name")
        for index, unknown_field in enumerate(value.unknown_fields):
            if type(unknown_field) is not UnknownField:
                raise ValueError(
                    f"{label}.unknown_fields[{index}] must be an exact UnknownField"
                )
            self._evidence_tuple(
                unknown_field.evidence,
                f"{label}.unknown_fields[{index}].evidence",
            )
        if type(value.complete) is not bool:
            raise ValueError(f"{label}.complete must be a boolean")
        return value

    @staticmethod
    def _enum(value: Any, enum_type: type[Enum], label: str) -> None:
        if not isinstance(value, enum_type):
            raise TypeError(f"{label} is invalid")

    @staticmethod
    def _optional_time(value: Any, label: str, *, nonnegative: bool = False) -> None:
        if value is None:
            return
        minimum = 0 if nonnegative else MIN_TIMESTAMP_NS
        if type(value) is not int or not minimum <= value <= MAX_TIMESTAMP_NS:
            qualifier = "a non-negative " if nonnegative else "a "
            raise ValueError(
                f"{label} must be {qualifier}signed 64-bit integer or None"
            )

    def _common_fact(
        self,
        *,
        provenance: Any,
        quality: Any,
        evidence: Any,
        label: str,
    ) -> None:
        self._enum(provenance, Provenance, f"{label}.provenance")
        self._enum(quality, Quality, f"{label}.quality")
        self._evidence_tuple(evidence, f"{label}.evidence")

    def _relationship_mutation(
        self,
        value: Any,
        label: str,
    ) -> RelationshipMutation:
        if type(value) is not RelationshipMutation:
            raise ValueError(f"{label} must be an exact RelationshipMutation")
        self._resource(value.source, f"{label}.source")
        self._resource(value.target, f"{label}.target")
        if value.relation_type not in self._schema.relationship_types:
            raise ValueError(
                f"{label} references undeclared relationship type "
                f"{value.relation_type!r}"
            )
        self._enum(value.operation, RelationshipOperation, f"{label}.operation")
        self._patch(value.attributes, f"{label}.attributes")
        self._optional_time(value.effective_time_ns, f"{label}.effective_time_ns")
        self._optional_time(
            value.time_uncertainty_ns,
            f"{label}.time_uncertainty_ns",
            nonnegative=True,
        )
        if value.cause_event_uid is not None:
            self._event_uid(value.cause_event_uid, f"{label}.cause_event_uid")
        self._common_fact(
            provenance=value.provenance,
            quality=value.quality,
            evidence=value.evidence,
            label=label,
        )
        self._perspective(value.perspective_ref, f"{label}.perspective_ref")
        return value

    @staticmethod
    def _event_uid(value: Any, label: str) -> bytes:
        if not isinstance(value, bytes) or not 1 <= len(value) <= 64:
            raise ValueError(f"{label} must contain 1 to 64 bytes")
        return value

    def _causal_link(self, value: Any, label: str) -> CausalLink:
        if type(value) is not CausalLink:
            raise ValueError(f"{label} must be an exact CausalLink")
        self._event_uid(value.source_event_uid, f"{label}.source_event_uid")
        self._event_uid(value.target_event_uid, f"{label}.target_event_uid")
        if value.link_type not in self._schema.causal_link_types:
            raise ValueError(
                f"{label} references undeclared causal link type "
                f"{value.link_type!r}"
            )
        if (
            isinstance(value.confidence, bool)
            or not isinstance(value.confidence, (int, float))
            or not isfinite(float(value.confidence))
            or not 0 <= float(value.confidence) <= 1
        ):
            raise ValueError(f"{label}.confidence must be finite and between 0 and 1")
        self._common_fact(
            provenance=value.provenance,
            quality=value.quality,
            evidence=value.evidence,
            label=label,
        )
        return value

    def _clock_anchor(self, value: Any, label: str) -> ClockAnchor:
        if type(value) is not ClockAnchor:
            raise ValueError(f"{label} must be an exact ClockAnchor")
        for field_name, clock_text in (
            ("left_clock_domain", value.left_clock_domain),
            ("right_clock_domain", value.right_clock_domain),
            ("method", value.method),
        ):
            if (
                not isinstance(clock_text, str)
                or not clock_text
                or len(clock_text) > 256
            ):
                raise ValueError(
                    f"{label}.{field_name} must contain 1 to 256 characters"
                )
        for field_name, clock_ns in (
            ("left_raw_ns", value.left_raw_ns),
            ("right_raw_ns", value.right_raw_ns),
        ):
            if type(clock_ns) is not int:
                raise ValueError(f"{label}.{field_name} must be an integer")
            self._optional_time(clock_ns, f"{label}.{field_name}")
        if type(value.uncertainty_ns) is not int:
            raise ValueError(f"{label}.uncertainty_ns must be non-negative")
        self._optional_time(
            value.uncertainty_ns,
            f"{label}.uncertainty_ns",
            nonnegative=True,
        )
        self._common_fact(
            provenance=value.provenance,
            quality=value.quality,
            evidence=value.evidence,
            label=label,
        )
        return value

    def _state_mutation(self, value: Any, label: str) -> StateMutation:
        if type(value) is not StateMutation:
            raise ValueError(f"{label} must be an exact StateMutation")
        resource = self._resource(value.resource, f"{label}.resource")
        self._enum(value.operation, MutationOperation, f"{label}.operation")
        if value.before is not None:
            self._patch(
                value.before,
                f"{label}.before",
                resource_kind=resource.kind,
            )
        if value.after is not None:
            self._patch(
                value.after,
                f"{label}.after",
                resource_kind=resource.kind,
            )
        self._optional_time(value.effective_time_ns, f"{label}.effective_time_ns")
        self._optional_time(
            value.time_uncertainty_ns,
            f"{label}.time_uncertainty_ns",
            nonnegative=True,
        )
        if value.cause_event_uid is not None:
            self._event_uid(value.cause_event_uid, f"{label}.cause_event_uid")
        self._common_fact(
            provenance=value.provenance,
            quality=value.quality,
            evidence=value.evidence,
            label=label,
        )
        _validate_value(value.condition, f"{label}.condition")
        self._perspective(value.perspective_ref, f"{label}.perspective_ref")
        return value

    def _unknown_change(self, value: Any, label: str) -> UnknownChange:
        if type(value) is not UnknownChange:
            raise ValueError(f"{label} must be an exact UnknownChange")
        for field_name, field_value, maximum in (
            ("change_kind", value.change_kind, 128),
            ("reason_code", value.reason_code, 128),
            ("message", value.message, 8_192),
        ):
            if (
                not isinstance(field_value, str)
                or not field_value
                or len(field_value) > maximum
            ):
                raise ValueError(
                    f"{label}.{field_name} must contain 1 to {maximum} characters"
                )
        if (
            not isinstance(value.affected_resources, tuple)
            or len(value.affected_resources) > self.limits.max_resource_references
        ):
            raise ValueError(f"{label}.affected_resources must be a bounded tuple")
        for index, resource in enumerate(value.affected_resources):
            self._resource(resource, f"{label}.affected_resources[{index}]")
        if not isinstance(value.affected_fields, tuple) or len(
            value.affected_fields
        ) > self.limits.max_resource_references:
            raise ValueError(f"{label}.affected_fields must be a bounded tuple")
        if (
            value.relation_type is not None
            and value.relation_type not in self._schema.relationship_types
        ):
            raise ValueError(
                f"{label} references undeclared relationship type "
                f"{value.relation_type!r}"
            )
        self._evidence_tuple(value.evidence, f"{label}.evidence")
        return value

    def _coverage(self, value: Any, label: str) -> ReconstructionCoverage:
        if type(value) is not ReconstructionCoverage:
            raise ValueError(f"{label} must be an exact ReconstructionCoverage")
        if (
            not isinstance(value.scope, str)
            or not value.scope
            or len(value.scope) > 256
        ):
            raise ValueError(f"{label}.scope must contain 1 to 256 characters")
        for field_name in (
            "exact_outputs",
            "best_effort_outputs",
            "ambiguous_outputs",
            "unknown_outputs",
        ):
            field_value = getattr(value, field_name)
            if type(field_value) is not int or not 0 <= field_value <= 2**63 - 1:
                raise ValueError(f"{label}.{field_name} must be non-negative")
        return value

    def _change_set(
        self,
        value: Any,
        capability: PluginCapability,
    ) -> ChangeSet:
        if type(value) is not ChangeSet:
            raise self._error(capability, "hook must return an exact ChangeSet")
        collections: tuple[tuple[str, Any, type[Any], Callable[[Any, str], Any]], ...] = (
            ("state", value.state, StateMutation, self._state_mutation),
            (
                "relationships",
                value.relationships,
                RelationshipMutation,
                self._relationship_mutation,
            ),
            ("causal_links", value.causal_links, CausalLink, self._causal_link),
            ("unknowns", value.unknowns, UnknownChange, self._unknown_change),
            (
                "coverage",
                value.coverage,
                ReconstructionCoverage,
                self._coverage,
            ),
        )
        total = len(value.diagnostics) if isinstance(value.diagnostics, tuple) else 0
        try:
            for name, items, item_type, validator in collections:
                if not isinstance(items, tuple):
                    raise TypeError(f"ChangeSet.{name} must be a tuple")
                total += len(items)
                if any(type(item) is not item_type for item in items):
                    raise ValueError(
                        f"ChangeSet.{name} contains an unsupported output"
                    )
                for index, item in enumerate(items):
                    validator(item, f"ChangeSet.{name}[{index}]")
            if total > self.limits.max_change_items:
                raise ValueError("ChangeSet exceeds the configured item limit")
            self._diagnostics(
                value.diagnostics,
                capability,
                "ChangeSet.diagnostics",
            )
        except PluginCapabilityExecutionError:
            raise
        except (TypeError, ValueError) as error:
            raise self._error(capability, str(error)) from error
        return value

    def _event(self, value: Any, label: str) -> DomainEvent:
        if type(value) is not DomainEvent:
            raise ValueError(f"{label} must be an exact DomainEvent")
        self._event_uid(value.event_uid, f"{label}.event_uid")
        _validate_value(value.attributes, f"{label}.attributes")
        if (
            not isinstance(value.subjects, tuple)
            or len(value.subjects) > self.limits.max_resource_references
        ):
            raise ValueError(f"{label}.subjects must be a bounded tuple")
        for index, resource in enumerate(value.subjects):
            self._resource(resource, f"{label}.subjects[{index}]")
        self._evidence(value.evidence, f"{label}.evidence")
        return value

    def apply(self, event: DomainEvent, world: ReadOnlyWorld) -> ChangeSet:
        capability = PluginCapability.EVENT_REDUCTION
        self._require(capability, "apply")
        try:
            self._event(event, "event")
            result = self.plugin.apply(
                event,
                cast(
                    ReadOnlyWorld,
                    _BoundedWorld(
                        world,
                        self.limits.max_world_reads,
                        capability,
                    ),
                ),
            )
        except PluginCapabilityExecutionError:
            raise
        except Exception as error:
            raise self._error(capability, f"apply() failed: {error}") from error
        return self._change_set(result, capability)

    def revert(
        self,
        event: DomainEvent,
        world_after: ReadOnlyWorld,
    ) -> ChangeSet:
        capability = PluginCapability.EVENT_REVERSION
        self._require(capability, "revert")
        try:
            self._event(event, "event")
            result = self.plugin.revert(
                event,
                cast(
                    ReadOnlyWorld,
                    _BoundedWorld(
                        world_after,
                        self.limits.max_world_reads,
                        capability,
                    ),
                ),
            )
        except PluginCapabilityExecutionError:
            raise
        except Exception as error:
            raise self._error(capability, f"revert() failed: {error}") from error
        return self._change_set(result, capability)

    def _consume(
        self,
        capability: PluginCapability,
        outputs: Iterable[Any],
        *,
        maximum: int,
        allowed: tuple[type[Any], ...],
        validator: Callable[[Any, str], None],
    ) -> tuple[tuple[Any, ...], tuple[PluginDiagnostic, ...]]:
        values: list[Any] = []
        diagnostics: list[PluginDiagnostic] = []
        try:
            iterator = iter(outputs)
        except TypeError as error:
            raise self._error(
                capability,
                "capability hook must return an iterable",
            ) from error
        try:
            for index, output in enumerate(iterator):
                if index >= maximum:
                    raise self._error(
                        capability,
                        "capability output exceeded the configured limit",
                        diagnostics=tuple(diagnostics),
                    )
                if type(output) is PluginDiagnostic:
                    try:
                        diagnostic = self._diagnostic(
                            output,
                            f"{capability.value}[{index}]",
                        )
                    except (TypeError, ValueError) as error:
                        raise self._error(capability, str(error)) from error
                    diagnostics.append(diagnostic)
                    if len(diagnostics) > self.limits.max_diagnostics:
                        raise self._error(
                            capability,
                            "capability output exceeded the diagnostic limit",
                            diagnostics=tuple(diagnostics),
                        )
                    if not diagnostic.recoverable:
                        raise self._error(
                            capability,
                            f"{capability.value} failed: {diagnostic.code}: "
                            f"{diagnostic.message}",
                            diagnostics=tuple(diagnostics),
                        )
                    continue
                if type(output) not in allowed:
                    raise self._error(
                        capability,
                        f"capability emitted unsupported {type(output).__name__}",
                        diagnostics=tuple(diagnostics),
                    )
                try:
                    validator(output, f"{capability.value}[{index}]")
                except (TypeError, ValueError) as error:
                    raise self._error(
                        capability,
                        str(error),
                        diagnostics=tuple(diagnostics),
                    ) from error
                values.append(output)
        finally:
            close = getattr(iterator, "close", None)
            if callable(close):
                close()
        return tuple(values), tuple(diagnostics)

    def correlate(
        self,
        reader: CorrelationReader,
        window: CorrelationWindow,
    ) -> CorrelationExecutionResult:
        capability = PluginCapability.CORRELATION
        self._require(capability, "correlate")
        if type(window) is not CorrelationWindow:
            raise self._error(capability, "window must be an exact CorrelationWindow")
        try:
            self._optional_time(window.start_ns, "window.start_ns")
            self._optional_time(window.end_ns, "window.end_ns")
        except ValueError as error:
            raise self._error(capability, str(error)) from error
        if (
            window.start_ns is not None
            and window.end_ns is not None
            and window.start_ns > window.end_ns
        ):
            raise self._error(capability, "window time bounds are reversed")
        if (
            type(window.max_events) is not int
            or not 1 <= window.max_events <= self.limits.max_correlation_outputs
        ):
            raise self._error(capability, "window max_events is outside core bounds")
        if (
            type(window.max_world_reads) is not int
            or not 1 <= window.max_world_reads <= self.limits.max_world_reads
        ):
            raise self._error(
                capability,
                "window max_world_reads is outside core bounds",
            )
        maximum = min(window.max_events, self.limits.max_correlation_outputs)
        try:
            outputs = self.plugin.correlate(reader, window)
            values, diagnostics = self._consume(
                capability,
                outputs,
                maximum=maximum,
                allowed=(CausalLink, RelationshipMutation, ClockAnchor),
                validator=self._validate_correlation_output,
            )
        except PluginCapabilityExecutionError:
            raise
        except Exception as error:
            raise self._error(capability, f"correlate() failed: {error}") from error
        return CorrelationExecutionResult(
            causal_links=tuple(
                item for item in values if type(item) is CausalLink
            ),
            relationship_mutations=tuple(
                item for item in values if type(item) is RelationshipMutation
            ),
            clock_anchors=tuple(
                item for item in values if type(item) is ClockAnchor
            ),
            diagnostics=diagnostics,
        )

    def _validate_correlation_output(self, value: Any, label: str) -> None:
        if type(value) is CausalLink:
            self._causal_link(value, label)
        elif type(value) is RelationshipMutation:
            self._relationship_mutation(value, label)
        else:
            self._clock_anchor(value, label)

    def _world_basis(self, value: Any, label: str) -> WorldBasis:
        if type(value) is not WorldBasis:
            raise ValueError(f"{label} must be an exact WorldBasis")
        self._enum(value.kind, WorldBasisKind, f"{label}.kind")
        self._enum(value.provenance, Provenance, f"{label}.provenance")
        self._enum(value.quality, Quality, f"{label}.quality")
        for field_name in (
            "requested_time_ns",
            "resolved_at_min_ns",
            "resolved_at_max_ns",
        ):
            self._optional_time(getattr(value, field_name), f"{label}.{field_name}")
        if (
            value.resolved_at_min_ns is not None
            and value.resolved_at_max_ns is not None
            and value.resolved_at_min_ns > value.resolved_at_max_ns
        ):
            raise ValueError(f"{label} resolved bounds are reversed")
        if not isinstance(value.capture_ranges, tuple) or len(
            value.capture_ranges
        ) > 1_024:
            raise ValueError(f"{label}.capture_ranges must be a bounded tuple")
        for index, item in enumerate(value.capture_ranges):
            if type(item) is not CaptureRange:
                raise ValueError(
                    f"{label}.capture_ranges[{index}] must be an exact CaptureRange"
                )
            self._optional_time(
                item.observed_at_min_ns,
                f"{label}.capture_ranges[{index}].observed_at_min_ns",
            )
            self._optional_time(
                item.observed_at_max_ns,
                f"{label}.capture_ranges[{index}].observed_at_max_ns",
            )
            if (
                item.observed_at_min_ns is not None
                and item.observed_at_max_ns is not None
                and item.observed_at_min_ns > item.observed_at_max_ns
            ):
                raise ValueError(
                    f"{label}.capture_ranges[{index}] bounds are reversed"
                )
            self._evidence_tuple(
                item.evidence,
                f"{label}.capture_ranges[{index}].evidence",
            )
        selector = value.selector
        if selector is not None:
            if type(selector) is AbsoluteTimeSelector:
                self._optional_time(
                    selector.time_ns,
                    f"{label}.selector.time_ns",
                )
            elif type(selector) is RelativeToWatermarkSelector:
                self._optional_time(
                    selector.offset_ns,
                    f"{label}.selector.offset_ns",
                )
                if selector.offset_ns > 0:
                    raise ValueError(
                        f"{label}.selector.offset_ns must be zero or negative"
                    )
            else:
                raise ValueError(f"{label}.selector is invalid")
        if not isinstance(value.node_resolutions, tuple):
            raise ValueError(f"{label}.node_resolutions must be a tuple")
        for index, resolution in enumerate(value.node_resolutions):
            if type(resolution) is not ResolvedNodeBasis:
                raise ValueError(
                    f"{label}.node_resolutions[{index}] must be an exact "
                    "ResolvedNodeBasis"
                )
            for field_name in (
                "local_min_ns",
                "local_max_ns",
                "absolute_min_ns",
                "absolute_max_ns",
            ):
                self._optional_time(
                    getattr(resolution, field_name),
                    f"{label}.node_resolutions[{index}].{field_name}",
                )
        watermark = value.watermark
        if watermark is not None:
            if type(watermark) is not ReconstructionWatermark:
                raise ValueError(
                    f"{label}.watermark must be an exact ReconstructionWatermark"
                )
            self._optional_time(
                watermark.local_time_ns,
                f"{label}.watermark.local_time_ns",
            )
            self._optional_time(
                watermark.absolute_min_ns,
                f"{label}.watermark.absolute_min_ns",
            )
            self._optional_time(
                watermark.absolute_max_ns,
                f"{label}.watermark.absolute_max_ns",
            )
        return value

    def _finding(self, value: Any, label: str) -> None:
        if type(value) is not ConsistencyFinding:
            raise ValueError(f"{label} must be an exact ConsistencyFinding")
        if (
            not isinstance(value.rule_id, str)
            or not value.rule_id
            or len(value.rule_id) > 256
        ):
            raise ValueError(f"{label}.rule_id must contain 1 to 256 characters")
        self._enum(value.severity, DiagnosticSeverity, f"{label}.severity")
        self._enum(value.result, FindingResult, f"{label}.result")
        if (
            not isinstance(value.summary, str)
            or not value.summary
            or len(value.summary) > 8_192
        ):
            raise ValueError(f"{label}.summary must contain 1 to 8192 characters")
        if (
            not isinstance(value.resources, tuple)
            or len(value.resources) > self.limits.max_resource_references
        ):
            raise ValueError(f"{label}.resources must be a bounded tuple")
        for index, resource in enumerate(value.resources):
            self._resource(resource, f"{label}.resources[{index}]")
        self._common_fact(
            provenance=value.provenance,
            quality=value.quality,
            evidence=value.evidence,
            label=label,
        )
        self._world_basis(value.basis, f"{label}.basis")
        _validate_value(value.details, f"{label}.details")

    def check_consistency(
        self,
        world: ReadOnlyWorld,
    ) -> ConsistencyExecutionResult:
        capability = PluginCapability.CONSISTENCY_CHECK
        self._require(capability, "check_consistency")
        try:
            outputs = self.plugin.check_consistency(
                cast(
                    ReadOnlyWorld,
                    _BoundedWorld(
                        world,
                        self.limits.max_world_reads,
                        capability,
                    ),
                )
            )
            values, diagnostics = self._consume(
                capability,
                outputs,
                maximum=self.limits.max_consistency_outputs,
                allowed=(ConsistencyFinding,),
                validator=self._finding,
            )
        except PluginCapabilityExecutionError:
            raise
        except Exception as error:
            raise self._error(
                capability,
                f"check_consistency() failed: {error}",
            ) from error
        return ConsistencyExecutionResult(
            findings=cast(tuple[ConsistencyFinding, ...], values),
            diagnostics=diagnostics,
        )

    def _topology_reference(
        self,
        value: Any,
        label: str,
    ) -> TopologyEndpointReference:
        if type(value) is not TopologyEndpointReference:
            raise ValueError(f"{label} must be an exact TopologyEndpointReference")
        if value.resource is not None:
            self._resource(value.resource, f"{label}.resource")
        else:
            assert value.match is not None
            _validate_value(value.match.arguments, f"{label}.match.arguments")
            if len(value.match.resolved_candidates) > self.limits.max_resource_references:
                raise ValueError(
                    f"{label}.match.resolved_candidates exceeds the reference limit"
                )
            for index, resource in enumerate(value.match.resolved_candidates):
                self._resource(
                    resource,
                    f"{label}.match.resolved_candidates[{index}]",
                )
        return value

    def _topology_record(
        self,
        request: TopologyProjectionRequest,
        value: Any,
        label: str,
    ) -> None:
        if type(value) is not TopologyProjectionRecord:
            raise ValueError(f"{label} must be an exact TopologyProjectionRecord")
        if value.projection_id != request.projection_id:
            raise ValueError(f"{label}.projection_id does not match the request")
        if value.status_perspective_id != request.status_perspective_id:
            raise ValueError(
                f"{label}.status_perspective_id does not match the request"
            )
        self._enum(value.usability, TopologyUsability, f"{label}.usability")
        self._enum(value.provenance, Provenance, f"{label}.provenance")
        self._enum(value.quality, Quality, f"{label}.quality")
        if value.exists is not None and type(value.exists) is not bool:
            raise ValueError(f"{label}.exists must be a boolean or None")
        if (
            not isinstance(value.source_resources, tuple)
            or len(value.source_resources) > self.limits.max_resource_references
        ):
            raise ValueError(f"{label}.source_resources must be a bounded tuple")
        for index, resource in enumerate(value.source_resources):
            self._resource(resource, f"{label}.source_resources[{index}]")
        payload = value.payload
        if type(payload) is TopologyResourceRecord:
            self._resource(payload.resource, f"{label}.payload.resource")
        elif type(payload) is TopologyEndpointRecord:
            self._topology_reference(payload.target, f"{label}.payload.target")
        elif type(payload) is TopologyLinkRecord:
            self._topology_reference(payload.source, f"{label}.payload.source")
            self._topology_reference(payload.target, f"{label}.payload.target")
        else:
            raise ValueError(f"{label}.payload is unsupported")
        _validate_value(value.properties, f"{label}.properties")
        if not isinstance(value.unknown_fields, tuple) or len(
            value.unknown_fields
        ) > 1_024:
            raise ValueError(f"{label}.unknown_fields must be a bounded tuple")
        self._optional_time(value.valid_from_ns, f"{label}.valid_from_ns")
        self._optional_time(value.valid_to_ns, f"{label}.valid_to_ns")
        if (
            value.valid_from_ns is not None
            and value.valid_to_ns is not None
            and value.valid_from_ns > value.valid_to_ns
        ):
            raise ValueError(f"{label} validity bounds are reversed")
        self._evidence_tuple(value.evidence, f"{label}.evidence")

    def project_topology(
        self,
        request: TopologyProjectionRequest,
        world: ReadOnlyWorld,
    ) -> TopologyExecutionResult:
        capability = PluginCapability.TOPOLOGY_PROJECTION
        self._require(capability, "project_topology")
        if type(request) is not TopologyProjectionRequest:
            raise self._error(
                capability,
                "request must be an exact TopologyProjectionRequest",
            )
        supported = self._schema.topology_perspectives.get(request.projection_id)
        if supported is None:
            raise self._error(
                capability,
                f"projection {request.projection_id!r} is not declared",
            )
        if request.status_perspective_id not in supported:
            raise self._error(
                capability,
                "requested status perspective is not supported by the projection",
            )
        try:
            for index, resource in enumerate(request.seed_resources):
                self._resource(resource, f"request.seed_resources[{index}]")
        except ValueError as error:
            raise self._error(capability, str(error)) from error
        maximum = min(request.max_records, self.limits.max_topology_outputs)
        try:
            outputs = self.plugin.project_topology(
                request,
                cast(
                    ReadOnlyWorld,
                    _BoundedWorld(
                        world,
                        min(request.max_world_reads, self.limits.max_world_reads),
                        capability,
                    ),
                ),
            )
            values, diagnostics = self._consume(
                capability,
                outputs,
                maximum=maximum,
                allowed=(TopologyProjectionRecord,),
                validator=lambda value, label: self._topology_record(
                    request,
                    value,
                    label,
                ),
            )
        except PluginCapabilityExecutionError:
            raise
        except Exception as error:
            raise self._error(
                capability,
                f"project_topology() failed: {error}",
            ) from error
        return TopologyExecutionResult(
            records=cast(tuple[TopologyProjectionRecord, ...], values),
            diagnostics=diagnostics,
        )

    def _supported_ir(
        self,
        capability: PluginCapability,
        ir_version: Any,
    ) -> str:
        if not isinstance(ir_version, str) or not ir_version:
            raise self._error(capability, "forwarding IR version must be a string")
        if ir_version not in self.manifest.forwarding_ir_versions:
            raise self._error(
                capability,
                f"forwarding IR {ir_version!r} is not declared by the plug-in",
            )
        return ir_version

    def _nested_contract(
        self,
        value: Any,
        label: str,
        *,
        depth: int = 0,
        units: list[int] | None = None,
    ) -> None:
        """Walk typed forwarding records to validate every embedded ResourceKey."""

        budget = units or [0]
        budget[0] += 1
        if budget[0] > 20_000 or depth > 24:
            raise ValueError(f"{label} exceeds the nested contract limit")
        if type(value) is ResourceKey:
            self._resource(value, label)
            return
        if type(value) is Evidence:
            self._evidence(value, label)
            return
        if value is None or isinstance(value, (str, bytes, UUID, Enum)):
            return
        if type(value) in (bool, int):
            return
        if type(value) is float:
            if not isfinite(value):
                raise ValueError(f"{label} contains a non-finite float")
            return
        if isinstance(value, Mapping):
            _validate_value(value, label)
            return
        if isinstance(value, tuple):
            if len(value) > 4_096:
                raise ValueError(f"{label} exceeds 4096 items")
            for index, item in enumerate(value):
                self._nested_contract(
                    item,
                    f"{label}[{index}]",
                    depth=depth + 1,
                    units=budget,
                )
            return
        if is_dataclass(value):
            for contract_field in fields(value):
                self._nested_contract(
                    getattr(value, contract_field.name),
                    f"{label}.{contract_field.name}",
                    depth=depth + 1,
                    units=budget,
                )
            return
        raise ValueError(f"{label} contains unsupported type {type(value).__name__}")

    def _forwarding_mutation(
        self,
        request: ForwardingProjectionRequest,
        value: Any,
        label: str,
    ) -> None:
        if type(value) is not ForwardingMutation:
            raise ValueError(f"{label} must be an exact ForwardingMutation")
        self._enum(value.operation, ForwardingOperation, f"{label}.operation")
        self._resource(value.key, f"{label}.key")
        record_types = (
            FibEntry,
            NextHopGroup,
            NextHop,
            FailoverGroup,
            Adjacency,
            TunnelAction,
            InterfaceForwardingState,
            VrfForwardingState,
        )
        if value.operation is ForwardingOperation.UPSERT:
            if type(value.record) not in record_types:
                raise ValueError(f"{label}.record is not a supported forwarding record")
            assert value.record is not None
            if value.record.key != value.key:
                raise ValueError(f"{label}.record key does not match mutation key")
            self._nested_contract(value.record, f"{label}.record")
        elif value.record is not None:
            raise ValueError(f"{label} delete must not include a record")
        self._optional_time(value.effective_time_ns, f"{label}.effective_time_ns")
        self._optional_time(
            value.time_uncertainty_ns,
            f"{label}.time_uncertainty_ns",
            nonnegative=True,
        )
        if value.cause_event_uid is not None:
            self._event_uid(value.cause_event_uid, f"{label}.cause_event_uid")
        self._enum(value.provenance, Provenance, f"{label}.provenance")
        self._enum(value.quality, Quality, f"{label}.quality")
        self._world_basis(value.basis, f"{label}.basis")
        self._evidence_tuple(value.evidence, f"{label}.evidence")
        if value.ir_version != request.ir_version:
            raise ValueError(f"{label}.ir_version does not match the request")

    def project_forwarding(
        self,
        request: ForwardingProjectionRequest,
        world: ReadOnlyWorld,
    ) -> ForwardingProjectionExecutionResult:
        capability = PluginCapability.FORWARDING_PROJECTION
        self._require(capability, "project_forwarding")
        if type(request) is not ForwardingProjectionRequest:
            raise self._error(
                capability,
                "request must be an exact ForwardingProjectionRequest",
            )
        self._supported_ir(capability, request.ir_version)
        try:
            self._perspective(
                request.status_perspective,
                "request.status_perspective",
            )
        except ValueError as error:
            raise self._error(capability, str(error)) from error
        if request.changes is not None:
            self._change_set(request.changes, capability)
        maximum = min(request.max_records, self.limits.max_forwarding_outputs)
        try:
            outputs = self.plugin.project_forwarding(
                request,
                cast(
                    ReadOnlyWorld,
                    _BoundedWorld(
                        world,
                        min(request.max_world_reads, self.limits.max_world_reads),
                        capability,
                    ),
                ),
            )
            values, diagnostics = self._consume(
                capability,
                outputs,
                maximum=maximum,
                allowed=(ForwardingMutation,),
                validator=lambda value, label: self._forwarding_mutation(
                    request,
                    value,
                    label,
                ),
            )
        except PluginCapabilityExecutionError:
            raise
        except Exception as error:
            raise self._error(
                capability,
                f"project_forwarding() failed: {error}",
            ) from error
        return ForwardingProjectionExecutionResult(
            mutations=cast(tuple[ForwardingMutation, ...], values),
            diagnostics=diagnostics,
        )

    def _forwarding_step_result(
        self,
        request: ForwardingStepRequest,
        value: Any,
    ) -> ForwardingStepResult:
        if type(value) is not ForwardingStepResult:
            raise ValueError(
                "resolve_forwarding_step() must return an exact "
                "ForwardingStepResult or PluginDiagnostic"
            )
        if value.step_id != request.step_id:
            raise ValueError("forwarding step result step_id does not match request")
        if value.transition.before != request.packet_state:
            raise ValueError(
                "forwarding step transition before-state does not match request"
            )
        self._resource(request.forwarding_object, "request.forwarding_object")
        if request.ingress_resource is not None:
            self._resource(request.ingress_resource, "request.ingress_resource")
        for label, resource in (
            ("selected_candidate", value.selected_candidate),
            ("next_forwarding_object", value.next_forwarding_object),
        ):
            if resource is not None:
                self._resource(resource, f"forwarding step result.{label}")
        self._nested_contract(value.transition, "forwarding step result.transition")
        if (
            value.transition.origin is ForwardingTransitionOrigin.USER_FORCED
            and not any(
                rule.rule_id == value.transition.forced_rule_id
                and rule.target_step_id == request.step_id
                for rule in request.steering_rules
            )
        ):
            raise ValueError(
                "user-forced forwarding transition does not match a request rule"
            )
        self._enum(value.quality, Quality, "forwarding step result.quality")
        return value

    def resolve_forwarding_step(
        self,
        request: ForwardingStepRequest,
        world: ReadOnlyWorld,
    ) -> ForwardingStepExecutionResult:
        capability = PluginCapability.FORWARDING_TRACE
        self._require(capability, "resolve_forwarding_step")
        if type(request) is not ForwardingStepRequest:
            raise self._error(
                capability,
                "request must be an exact ForwardingStepRequest",
            )
        self._supported_ir(capability, request.ir_version)
        try:
            self._perspective(
                request.status_perspective,
                "request.status_perspective",
            )
            self._resource(
                request.forwarding_object,
                "request.forwarding_object",
            )
            if request.ingress_resource is not None:
                self._resource(
                    request.ingress_resource,
                    "request.ingress_resource",
                )
            for index, rule in enumerate(request.steering_rules):
                if rule.selected_candidate is not None:
                    self._resource(
                        rule.selected_candidate,
                        f"request.steering_rules[{index}].selected_candidate",
                    )
        except ValueError as error:
            raise self._error(capability, str(error)) from error
        try:
            output = self.plugin.resolve_forwarding_step(
                request,
                cast(
                    ReadOnlyWorld,
                    _BoundedWorld(
                        world,
                        self.limits.max_world_reads,
                        capability,
                    ),
                ),
            )
            if type(output) is PluginDiagnostic:
                diagnostic = self._diagnostic(output, "forwarding_trace")
                diagnostics = (diagnostic,)
                if not diagnostic.recoverable:
                    raise self._error(
                        capability,
                        f"forwarding_trace failed: {diagnostic.code}: "
                        f"{diagnostic.message}",
                        diagnostics=diagnostics,
                    )
                return ForwardingStepExecutionResult(
                    result=None,
                    diagnostics=diagnostics,
                )
            result = self._forwarding_step_result(request, output)
        except PluginCapabilityExecutionError:
            raise
        except Exception as error:
            raise self._error(
                capability,
                f"resolve_forwarding_step() failed: {error}",
            ) from error
        return ForwardingStepExecutionResult(result=result, diagnostics=())


__all__ = [
    "ConsistencyExecutionResult",
    "CorrelationExecutionResult",
    "ForwardingProjectionExecutionResult",
    "ForwardingStepExecutionResult",
    "PluginCapabilityExecutionError",
    "PluginCapabilityExecutor",
    "PluginCapabilityLimits",
    "PluginCapabilityOutputError",
    "PluginCapabilityUnavailableError",
    "TopologyExecutionResult",
]
