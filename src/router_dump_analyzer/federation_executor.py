"""Bounded execution boundary for cross-member connector federation.

Node analyzers produce only normalized, node-local connector claims.  This
module is the coordinator-owned boundary that either exact-matches those
claims or dispatches them to an explicitly allowlisted federation linker.  A
linker receives no artifact reader and no world view: its complete authority
is the frozen :class:`FederationLinkRequest` passed to ``link()``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, cast
from uuid import UUID

from .corroboration import (
    CorroborationError,
    ExactMatchClaim,
    MatcherId,
    exact_match_claims,
)
from .plugin_api import (
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
    ConnectorClaim,
    ConnectorMatchPolicyDescriptor,
    ConnectorMatchPolicyKind,
    DiagnosticOrigin,
    Evidence,
    FederatedConnectorClaim,
    FederationLinkerPlugin,
    FederationLinkRequest,
    FederationLinkResult,
    FederationMatchCandidate,
    FederationMatchState,
    GlobalResourceRef,
    InterNodeLinkPresentation,
    InterNodeRouteTraceRole,
    KeyAtom,
    PluginDiagnostic,
    Provenance,
    Quality,
    ResourceKey,
    StatusPerspectiveRef,
    validate_plugin_diagnostic,
)
from .process_control import PROCESS_CONTROL_EXCEPTIONS

_LINKER_ID_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_MAX_IDENTIFIER_CHARACTERS = 128
_MAX_OPAQUE_IDENTIFIER_CHARACTERS = 256
_MAX_EVIDENCE_LOCATOR_CHARACTERS = 4_096
_MAX_EVIDENCE_CLOCK_CHARACTERS = 256
_MAX_PROPERTY_DEPTH = 8
_MAX_PROPERTY_CONTAINER_ITEMS = 64
_MAX_PROPERTY_UNITS = 4_096
_MAX_PROPERTY_ATOM_UNITS = 4_096
_MAX_PROPERTY_INTEGER_BITS = 4_096


class FederationExecutionError(RuntimeError):
    """A federation request could not produce a trusted bounded result."""

    def __init__(
        self,
        message: str,
        *,
        linker_identity: FederationLinkerIdentity | None = None,
        diagnostics: tuple[PluginDiagnostic, ...] = (),
    ) -> None:
        super().__init__(message)
        self.linker_identity: FederationLinkerIdentity | None = linker_identity
        self.diagnostics: tuple[PluginDiagnostic, ...] = diagnostics


class FederationRegistrationError(FederationExecutionError):
    """An allowlisted linker has an invalid or ambiguous declaration."""


class FederationPolicyError(FederationExecutionError):
    """A caller supplied an undeclared or malformed federation policy/input."""


class FederationLinkExecutionError(FederationExecutionError):
    """An allowlisted linker's ``link()`` hook failed."""


class FederationLinkOutputError(FederationLinkExecutionError):
    """A linker returned an invalid, over-limit, or out-of-scope output."""


class FederationExecutionProvenance(StrEnum):
    """The authority that produced a federation execution result."""

    CORE_EXACT_TOKEN = "core_exact_token"
    LINKER_PLUGIN = "linker_plugin"


@dataclass(frozen=True, slots=True, order=True)
class FederationLinkerIdentity:
    """Frozen identity recorded for one selected allowlisted linker."""

    plugin_id: str
    plugin_version: str

    def __post_init__(self) -> None:
        _linker_id(self.plugin_id, "linker plugin_id")
        _opaque_text(self.plugin_version, "linker plugin_version", maximum=128)


@dataclass(frozen=True, slots=True)
class FederationLinkerLimits:
    """Core-owned size ceilings for trusted inline linker execution."""

    max_linkers: int = 128
    max_policies_per_linker: int = 1_024
    max_claims: int = 100_000
    max_results: int = 10_000
    max_candidates_per_result: int = 64
    max_diagnostics: int = 1_000
    max_evidence_per_output: int = 64

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("max_linkers", self.max_linkers, 1_000),
            ("max_policies_per_linker", self.max_policies_per_linker, 10_000),
            ("max_claims", self.max_claims, 100_000),
            ("max_results", self.max_results, 100_000),
            ("max_candidates_per_result", self.max_candidates_per_result, 64),
            ("max_diagnostics", self.max_diagnostics, 10_000),
            ("max_evidence_per_output", self.max_evidence_per_output, 64),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(
                    f"{name} must be an integer between 1 and {maximum}"
                )


@dataclass(frozen=True, slots=True)
class FederationExecutionResult:
    """Detached deterministic outputs from one federation policy execution."""

    results: tuple[FederationLinkResult, ...]
    diagnostics: tuple[PluginDiagnostic, ...]
    complete: bool
    truncated: bool
    provenance: FederationExecutionProvenance
    linker_identity: FederationLinkerIdentity | None

    def __post_init__(self) -> None:
        if type(self.results) is not tuple or any(
            type(item) is not FederationLinkResult for item in self.results
        ):
            raise ValueError("federation execution results must be an exact tuple")
        if type(self.diagnostics) is not tuple or any(
            type(item) is not PluginDiagnostic for item in self.diagnostics
        ):
            raise ValueError(
                "federation execution diagnostics must be an exact tuple"
            )
        if type(self.complete) is not bool or type(self.truncated) is not bool:
            raise ValueError("federation execution completeness flags must be boolean")
        try:
            provenance = FederationExecutionProvenance(self.provenance)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported federation execution provenance") from error
        object.__setattr__(self, "provenance", provenance)
        if self.linker_identity is not None and type(
            self.linker_identity
        ) is not FederationLinkerIdentity:
            raise ValueError(
                "federation execution linker_identity must be frozen linker identity"
            )
        if (
            provenance is FederationExecutionProvenance.CORE_EXACT_TOKEN
            and self.linker_identity is not None
        ):
            raise ValueError("core exact-token execution must not name a linker")
        if (
            provenance is FederationExecutionProvenance.LINKER_PLUGIN
            and self.linker_identity is None
        ):
            raise ValueError("linker execution must retain its frozen identity")
        if self.complete and self.truncated:
            raise ValueError("a truncated federation execution cannot be complete")


@dataclass(frozen=True, slots=True)
class _Registration:
    identity: FederationLinkerIdentity
    plugin: FederationLinkerPlugin
    link_hook: Callable[[FederationLinkRequest], Iterable[object]]
    policies: tuple[ConnectorMatchPolicyDescriptor, ...]


def _linker_id(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_IDENTIFIER_CHARACTERS
        or _LINKER_ID_PATTERN.fullmatch(value) is None
    ):
        raise ValueError(
            f"{label} must be a lowercase dotted, dashed, or underscored identifier"
        )
    return value


def _opaque_text(value: object, label: str, *, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(character.isspace() or ord(character) < 0x20 for character in value)
        or "\x7f" in value
    ):
        raise ValueError(
            f"{label} must be a non-empty opaque identifier of at most "
            f"{maximum} characters without whitespace or controls"
        )
    return value


def _exact_text(value: object, label: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if type(value) is not str:
        raise ValueError(f"{label} must be an exact string")
    return value


def _attribute(value: object, name: str) -> object:
    """Resolve an untrusted protocol attribute inside the caller's boundary."""

    try:
        return getattr(value, name)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise RuntimeError(
            "federation linker attribute could not be resolved"
        ) from error


def _live_linker_identity(plugin: object) -> FederationLinkerIdentity:
    """Read and validate one linker's current public identity."""

    return FederationLinkerIdentity(
        _linker_id(
            _attribute(plugin, "linker_plugin_id"),
            "linker plugin_id",
        ),
        _opaque_text(
            _attribute(plugin, "linker_plugin_version"),
            "linker plugin_version",
            maximum=128,
        ),
    )


def _snapshot_policy(
    value: object,
    *,
    require_kind: ConnectorMatchPolicyKind | None = None,
) -> ConnectorMatchPolicyDescriptor:
    if type(value) is not ConnectorMatchPolicyDescriptor:
        raise ValueError(
            "federation policy must be an exact ConnectorMatchPolicyDescriptor"
        )
    try:
        if type(value.kind) not in {str, ConnectorMatchPolicyKind}:
            raise ValueError("connector match policy kind has an invalid type")
        kind = ConnectorMatchPolicyKind(value.kind)
        policy_id = _exact_text(value.policy_id, "connector match policy_id")
        claim_contract_id = _exact_text(
            value.claim_contract_id,
            "connector claim_contract_id",
        )
        linker_plugin_id = _exact_text(
            value.linker_plugin_id,
            "connector linker_plugin_id",
            optional=True,
        )
        assert policy_id is not None and claim_contract_id is not None
        argument_names = value.argument_names
        if type(argument_names) is not tuple or any(
            type(name) is not str for name in argument_names
        ):
            raise ValueError("connector match argument_names must be an exact tuple")
        snapshot = ConnectorMatchPolicyDescriptor(
            policy_id=policy_id,
            claim_contract_id=claim_contract_id,
            kind=kind,
            argument_names=tuple(argument_names),
            linker_plugin_id=linker_plugin_id,
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except (TypeError, ValueError) as error:
        raise ValueError("federation policy is malformed") from error
    if require_kind is not None and kind is not require_kind:
        raise ValueError(f"federation policy must have kind {require_kind.value!r}")
    return snapshot


def _snapshot_key_value(value: object, *, depth: int = 0) -> Any:
    if depth > 4:
        raise ValueError("connector claim arguments exceed four tuple levels")
    value_type = type(value)
    if value_type is bool:
        raise ValueError("Boolean connector claim arguments are forbidden")
    if value_type is int:
        if cast(int, value).bit_length() > 4_096:
            raise ValueError("connector claim integer arguments exceed 4096 bits")
        return value
    if value_type is str:
        if len(cast(str, value)) > 4_096:
            raise ValueError("connector claim argument exceeds 4096 units")
        return value
    if value_type is bytes:
        if len(cast(bytes, value)) > 4_096:
            raise ValueError("connector claim argument exceeds 4096 units")
        return bytes(cast(bytes, value))
    if value_type is UUID:
        return UUID(bytes=cast(UUID, value).bytes)
    if value_type is KeyAtom:
        atom = cast(KeyAtom, value)
        type_tag = _exact_text(atom.type_tag, "connector key atom type_tag")
        assert type_tag is not None
        return KeyAtom(type_tag, _snapshot_key_value(atom.value, depth=depth))
    if value_type is tuple:
        nested = cast(tuple[object, ...], value)
        if len(nested) > 32:
            raise ValueError("connector claim argument tuples exceed 32 values")
        return tuple(
            _snapshot_key_value(item, depth=depth + 1) for item in nested
        )
    raise ValueError("connector claim argument contains an unsupported type")


def _snapshot_resource(value: object) -> ResourceKey:
    if type(value) is not ResourceKey:
        raise ValueError("connector endpoint must be an exact ResourceKey")
    if type(value.parts) is not tuple:
        raise ValueError("connector endpoint parts must be an exact tuple")
    parts: list[tuple[str, Any]] = []
    for part in value.parts:
        if (
            type(part) is not tuple
            or len(part) != 2
            or type(part[0]) is not str
        ):
            raise ValueError("connector endpoint parts are malformed")
        parts.append((part[0], _snapshot_key_value(part[1])))
    namespace = _exact_text(value.namespace, "connector endpoint namespace")
    node = _exact_text(value.node, "connector endpoint node")
    layer = _exact_text(value.layer, "connector endpoint layer")
    kind = _exact_text(value.kind, "connector endpoint kind")
    assert namespace is not None and node is not None
    assert layer is not None and kind is not None
    return ResourceKey(
        namespace=namespace,
        node=node,
        layer=layer,
        kind=kind,
        parts=tuple(parts),
    )


def _snapshot_evidence(value: object, label: str) -> Evidence:
    if type(value) is not Evidence:
        raise ValueError(f"{label} must be an exact Evidence")
    if type(value.artifact_id) is not UUID:
        raise ValueError(f"{label}.artifact_id must be a UUID")
    if (
        type(value.locator) is not str
        or not value.locator
        or len(value.locator) > _MAX_EVIDENCE_LOCATOR_CHARACTERS
        or "\x00" in value.locator
    ):
        raise ValueError(f"{label}.locator is invalid")
    if value.raw_timestamp_ns is not None and (
        type(value.raw_timestamp_ns) is not int
        or not MIN_TIMESTAMP_NS <= value.raw_timestamp_ns <= MAX_TIMESTAMP_NS
    ):
        raise ValueError(f"{label}.raw_timestamp_ns is invalid")
    if value.clock_domain is not None and (
        type(value.clock_domain) is not str
        or not value.clock_domain
        or len(value.clock_domain) > _MAX_EVIDENCE_CLOCK_CHARACTERS
        or "\x00" in value.clock_domain
    ):
        raise ValueError(f"{label}.clock_domain is invalid")
    if value.excerpt_sha256 is not None and (
        type(value.excerpt_sha256) is not str
        or len(value.excerpt_sha256) != 64
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in value.excerpt_sha256
        )
    ):
        raise ValueError(f"{label}.excerpt_sha256 is invalid")
    return Evidence(
        artifact_id=UUID(bytes=value.artifact_id.bytes),
        locator=value.locator,
        raw_timestamp_ns=value.raw_timestamp_ns,
        clock_domain=value.clock_domain,
        excerpt_sha256=value.excerpt_sha256,
    )


def _snapshot_evidence_tuple(
    value: object,
    label: str,
    *,
    maximum: int,
) -> tuple[Evidence, ...]:
    if type(value) is not tuple:
        raise ValueError(f"{label} must be an exact tuple")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds the configured evidence limit")
    return tuple(
        _snapshot_evidence(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    )


def _snapshot_perspective(value: object) -> StatusPerspectiveRef | None:
    if value is None:
        return None
    if type(value) is not StatusPerspectiveRef:
        raise ValueError(
            "connector claim status_perspective must be exact StatusPerspectiveRef"
        )
    perspective_id = _exact_text(
        value.perspective_id,
        "connector claim perspective_id",
    )
    plugin_instance_id = _exact_text(
        value.plugin_instance_id,
        "connector claim perspective plugin_instance_id",
        optional=True,
    )
    schema_digest = _exact_text(
        value.schema_digest,
        "connector claim perspective schema_digest",
        optional=True,
    )
    assert perspective_id is not None
    return StatusPerspectiveRef(
        perspective_id=perspective_id,
        plugin_instance_id=plugin_instance_id,
        schema_digest=schema_digest,
    )


def _snapshot_claim(
    value: object,
    *,
    maximum_evidence: int,
) -> FederatedConnectorClaim:
    if type(value) is not FederatedConnectorClaim:
        raise ValueError("claims must contain exact FederatedConnectorClaim values")
    if type(value.endpoint) is not GlobalResourceRef:
        raise ValueError("federated connector endpoint is malformed")
    if type(value.claim) is not ConnectorClaim:
        raise ValueError("federated connector local claim is malformed")
    local = value.claim
    if type(local.provenance) not in {str, Provenance}:
        raise ValueError("connector claim provenance has an invalid type")
    if type(local.quality) not in {str, Quality}:
        raise ValueError("connector claim quality has an invalid type")
    claim_id = _exact_text(local.claim_id, "connector claim_id")
    claim_contract_id = _exact_text(
        local.claim_contract_id,
        "connector claim_contract_id",
    )
    match_policy_id = _exact_text(
        local.match_policy_id,
        "connector match_policy_id",
    )
    link_type = _exact_text(local.link_type, "connector claim link_type")
    role = _exact_text(local.role, "connector claim role", optional=True)
    member_id = _exact_text(value.endpoint.member_id, "federated member_id")
    revision_id = _exact_text(value.endpoint.revision_id, "federated revision_id")
    plugin_instance_id = _exact_text(
        value.endpoint.plugin_instance_id,
        "federated plugin_instance_id",
    )
    assert claim_id is not None and claim_contract_id is not None
    assert match_policy_id is not None and member_id is not None
    assert revision_id is not None and plugin_instance_id is not None
    assert link_type is not None
    if type(local.presentation) is not InterNodeLinkPresentation:
        raise ValueError(
            "connector claim presentation must be an exact "
            "InterNodeLinkPresentation"
        )
    if type(local.presentation.route_trace) not in {
        str,
        InterNodeRouteTraceRole,
    }:
        raise ValueError(
            "connector claim presentation route_trace has an invalid type"
        )
    presentation = InterNodeLinkPresentation(
        route_trace=InterNodeRouteTraceRole(local.presentation.route_trace)
    )
    if type(local.arguments) is not tuple:
        raise ValueError("connector claim arguments must be an exact tuple")
    arguments: list[tuple[str, Any]] = []
    for argument in local.arguments:
        if (
            type(argument) is not tuple
            or len(argument) != 2
            or type(argument[0]) is not str
        ):
            raise ValueError("connector claim arguments are malformed")
        arguments.append((argument[0], _snapshot_key_value(argument[1])))
    resource = _snapshot_resource(value.endpoint.resource)
    local_resource = _snapshot_resource(local.endpoint)
    local_snapshot = ConnectorClaim(
        claim_id=claim_id,
        endpoint=local_resource,
        claim_contract_id=claim_contract_id,
        match_policy_id=match_policy_id,
        arguments=tuple(arguments),
        provenance=Provenance(local.provenance),
        quality=Quality(local.quality),
        link_type=link_type,
        presentation=presentation,
        status_perspective=_snapshot_perspective(local.status_perspective),
        role=role,
        valid_from_ns=local.valid_from_ns,
        valid_to_ns=local.valid_to_ns,
        evidence=_snapshot_evidence_tuple(
            local.evidence,
            "connector claim evidence",
            maximum=maximum_evidence,
        ),
    )
    endpoint_snapshot = GlobalResourceRef(
        member_id=member_id,
        revision_id=revision_id,
        plugin_instance_id=plugin_instance_id,
        resource=resource,
    )
    return FederatedConnectorClaim(
        endpoint=endpoint_snapshot,
        claim=local_snapshot,
    )


def _claim_identity(claim: FederatedConnectorClaim) -> tuple[str, str, str, str]:
    return (
        claim.endpoint.member_id,
        claim.endpoint.revision_id,
        claim.endpoint.plugin_instance_id,
        claim.claim.claim_id,
    )


def _snapshot_claims(
    values: object,
    policy: ConnectorMatchPolicyDescriptor,
    *,
    limits: FederationLinkerLimits,
) -> tuple[FederatedConnectorClaim, ...]:
    if type(values) is not tuple:
        raise ValueError("federation claims must be an exact tuple")
    if len(values) > limits.max_claims:
        raise ValueError("federation claims exceed the configured claim limit")
    claims = tuple(
        _snapshot_claim(item, maximum_evidence=limits.max_evidence_per_output)
        for item in values
    )
    identities: set[tuple[str, str, str, str]] = set()
    for claim in claims:
        identity = _claim_identity(claim)
        if identity in identities:
            raise ValueError("federation claims contain a duplicate qualified identity")
        identities.add(identity)
        if claim.claim.match_policy_id != policy.policy_id:
            raise ValueError("federation claim references a different match policy")
        if claim.claim.claim_contract_id != policy.claim_contract_id:
            raise ValueError("federation claim uses a different claim contract")
        if tuple(name for name, _item in claim.claim.arguments) != policy.argument_names:
            raise ValueError("federation claim arguments do not match policy order")
    return tuple(sorted(claims, key=_claim_identity))


class _PropertyBudget:
    def __init__(self) -> None:
        self.units = 0
        self.active: set[int] = set()


def _snapshot_property_value(
    value: object,
    label: str,
    *,
    budget: _PropertyBudget,
    depth: int = 0,
) -> Any:
    if depth > _MAX_PROPERTY_DEPTH:
        raise ValueError(f"{label} exceeds the property depth limit")
    budget.units += 1
    if budget.units > _MAX_PROPERTY_UNITS:
        raise ValueError(f"{label} exceeds the property value-unit limit")
    value_type = type(value)
    if value is None or value_type is bool:
        return value
    if value_type is int:
        if cast(int, value).bit_length() > _MAX_PROPERTY_INTEGER_BITS:
            raise ValueError(f"{label} contains an over-limit integer")
        return value
    if value_type is float:
        if not math.isfinite(cast(float, value)):
            raise ValueError(f"{label} contains a non-finite float")
        return value
    if value_type in {str, bytes}:
        if len(cast(str | bytes, value)) > _MAX_PROPERTY_ATOM_UNITS:
            raise ValueError(f"{label} contains an over-limit atom")
        return value if value_type is str else bytes(cast(bytes, value))
    if value_type is UUID:
        return UUID(bytes=cast(UUID, value).bytes)
    if value_type is tuple:
        nested_tuple = cast(tuple[object, ...], value)
        if len(nested_tuple) > _MAX_PROPERTY_CONTAINER_ITEMS:
            raise ValueError(f"{label} contains an over-limit tuple")
        identity = id(value)
        if identity in budget.active:
            raise ValueError(f"{label} contains a reference cycle")
        budget.active.add(identity)
        try:
            return tuple(
                _snapshot_property_value(
                    item,
                    label,
                    budget=budget,
                    depth=depth + 1,
                )
                for item in nested_tuple
            )
        finally:
            budget.active.remove(identity)
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in budget.active:
            raise ValueError(f"{label} contains a reference cycle")
        budget.active.add(identity)
        result: dict[str, Any] = {}
        try:
            for index, (key, item) in enumerate(value.items()):
                if index >= _MAX_PROPERTY_CONTAINER_ITEMS:
                    raise ValueError(f"{label} contains an over-limit mapping")
                if (
                    type(key) is not str
                    or not key
                    or len(key) > _MAX_PROPERTY_ATOM_UNITS
                ):
                    raise ValueError(f"{label} contains an invalid mapping key")
                result[key] = _snapshot_property_value(
                    item,
                    label,
                    budget=budget,
                    depth=depth + 1,
                )
        finally:
            budget.active.remove(identity)
        return MappingProxyType(result)
    raise ValueError(f"{label} contains an unsupported property value")


def _snapshot_properties(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a mapping")
    snapshot = _snapshot_property_value(value, label, budget=_PropertyBudget())
    assert isinstance(snapshot, Mapping)
    return snapshot


def _snapshot_diagnostic(
    value: object,
    label: str,
    *,
    maximum_evidence: int,
) -> PluginDiagnostic:
    validated = validate_plugin_diagnostic(
        value,
        label=label,
        expected_origin=DiagnosticOrigin.PLUGIN,
        maximum_evidence_items=maximum_evidence,
    )
    snapshot = PluginDiagnostic(
        stage=validated.stage,
        severity=validated.severity,
        code=validated.code,
        message=validated.message,
        recoverable=validated.recoverable,
        evidence=_snapshot_evidence_tuple(
            validated.evidence,
            f"{label}.evidence",
            maximum=maximum_evidence,
        ),
        details=_snapshot_properties(validated.details, f"{label}.details"),
        origin=validated.origin,
    )
    validate_plugin_diagnostic(
        snapshot,
        label=label,
        expected_origin=DiagnosticOrigin.PLUGIN,
        maximum_evidence_items=maximum_evidence,
    )
    return snapshot


def _snapshot_candidate(
    value: object,
    *,
    supplied: Mapping[tuple[str, str, str, str], FederatedConnectorClaim],
    maximum_evidence: int,
) -> FederationMatchCandidate:
    if type(value) is not FederationMatchCandidate:
        raise ValueError(
            "federation result candidates must be exact FederationMatchCandidate values"
        )
    if type(value.endpoint) is not GlobalResourceRef:
        raise ValueError("federation candidate endpoint is malformed")
    claim_id = _exact_text(value.claim_id, "federation candidate claim_id")
    member_id = _exact_text(
        value.endpoint.member_id,
        "federation candidate member_id",
    )
    revision_id = _exact_text(
        value.endpoint.revision_id,
        "federation candidate revision_id",
    )
    plugin_instance_id = _exact_text(
        value.endpoint.plugin_instance_id,
        "federation candidate plugin_instance_id",
    )
    assert claim_id is not None and member_id is not None
    assert revision_id is not None and plugin_instance_id is not None
    endpoint = GlobalResourceRef(
        member_id=member_id,
        revision_id=revision_id,
        plugin_instance_id=plugin_instance_id,
        resource=_snapshot_resource(value.endpoint.resource),
    )
    identity = (
        endpoint.member_id,
        endpoint.revision_id,
        endpoint.plugin_instance_id,
        claim_id,
    )
    referenced = supplied.get(identity)
    if referenced is None or endpoint != referenced.endpoint:
        raise ValueError("federation candidate references a claim outside its request")
    confidence = value.confidence
    if confidence is not None and type(confidence) not in {int, float}:
        raise ValueError("federation candidate confidence must be an exact number")
    if type(value.quality) not in {str, Quality}:
        raise ValueError("federation candidate quality has an invalid type")
    return FederationMatchCandidate(
        claim_id=claim_id,
        endpoint=endpoint,
        quality=Quality(value.quality),
        confidence=confidence,
        evidence=_snapshot_evidence_tuple(
            value.evidence,
            "federation candidate evidence",
            maximum=maximum_evidence,
        ),
    )


def _snapshot_link_result(
    value: object,
    *,
    policy: ConnectorMatchPolicyDescriptor,
    supplied: Mapping[tuple[str, str, str, str], FederatedConnectorClaim],
    limits: FederationLinkerLimits,
    max_candidates: int,
) -> FederationLinkResult:
    if type(value) is not FederationLinkResult:
        raise ValueError("linker outputs must be exact FederationLinkResult values")
    result_id = _exact_text(value.result_id, "federation result_id")
    match_policy_id = _exact_text(
        value.match_policy_id,
        "federation result match_policy_id",
    )
    link_type = _exact_text(
        value.link_type,
        "federation result link_type",
        optional=True,
    )
    assert result_id is not None and match_policy_id is not None
    if match_policy_id != policy.policy_id:
        raise ValueError("federation result references a different match policy")
    source = _snapshot_claim(
        value.source,
        maximum_evidence=limits.max_evidence_per_output,
    )
    supplied_source = supplied.get(_claim_identity(source))
    if supplied_source is None or source != supplied_source:
        raise ValueError("federation result source is outside its request")
    if type(value.candidates) is not tuple:
        raise ValueError("federation result candidates must be an exact tuple")
    if len(value.candidates) > max_candidates:
        raise ValueError("federation result exceeds its candidate limit")
    candidates = tuple(
        sorted(
            (
                _snapshot_candidate(
                    item,
                    supplied=supplied,
                    maximum_evidence=limits.max_evidence_per_output,
                )
                for item in value.candidates
            ),
            key=lambda candidate: (
                candidate.endpoint.member_id,
                candidate.endpoint.revision_id,
                candidate.endpoint.plugin_instance_id,
                candidate.claim_id,
            ),
        )
    )
    if type(value.state) not in {str, FederationMatchState}:
        raise ValueError("federation result state has an invalid type")
    if type(value.provenance) not in {str, Provenance}:
        raise ValueError("federation result provenance has an invalid type")
    if type(value.quality) not in {str, Quality}:
        raise ValueError("federation result quality has an invalid type")
    return FederationLinkResult(
        result_id=result_id,
        match_policy_id=match_policy_id,
        source=source,
        state=FederationMatchState(value.state),
        candidates=candidates,
        provenance=Provenance(value.provenance),
        quality=Quality(value.quality),
        link_type=link_type,
        directed=value.directed,
        properties=_snapshot_properties(
            value.properties,
            "federation result properties",
        ),
        evidence=_snapshot_evidence_tuple(
            value.evidence,
            "federation result evidence",
            maximum=limits.max_evidence_per_output,
        ),
    )


class FederationLinkerRegistry:
    """Deterministic registry of explicitly trusted inline linkers."""

    def __init__(
        self,
        linkers: tuple[FederationLinkerPlugin, ...] = (),
        *,
        limits: FederationLinkerLimits | None = None,
    ) -> None:
        if type(linkers) is not tuple:
            raise TypeError("federation linker allowlist must be an exact tuple")
        self.limits: FederationLinkerLimits = limits or FederationLinkerLimits()
        if type(self.limits) is not FederationLinkerLimits:
            raise TypeError("limits must be an exact FederationLinkerLimits")
        if len(linkers) > self.limits.max_linkers:
            raise FederationRegistrationError(
                "federation linker allowlist exceeds the configured limit"
            )

        registrations: list[_Registration] = []
        for plugin in linkers:
            try:
                registration = self._inspect(plugin)
            except FederationExecutionError:
                raise
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise FederationRegistrationError(
                    "allowlisted federation linker declaration is invalid"
                ) from error
            registrations.append(registration)

        registrations.sort(key=lambda item: item.identity)
        by_plugin_id: dict[str, _Registration] = {}
        policies: list[ConnectorMatchPolicyDescriptor] = []
        for registration in registrations:
            plugin_id = registration.identity.plugin_id
            if plugin_id in by_plugin_id:
                raise FederationRegistrationError(
                    "federation linker allowlist contains a duplicate plugin_id"
                )
            by_plugin_id[plugin_id] = registration
            policies.extend(registration.policies)
        self._registrations = tuple(registrations)
        self._by_plugin_id = MappingProxyType(by_plugin_id)
        self._identities = tuple(item.identity for item in registrations)
        self._policies = tuple(
            sorted(
                policies,
                key=lambda policy: (
                    cast(str, policy.linker_plugin_id),
                    policy.policy_id,
                    policy.claim_contract_id,
                    policy.argument_names,
                ),
            )
        )

    def _inspect(self, plugin: FederationLinkerPlugin) -> _Registration:
        identity = _live_linker_identity(plugin)
        plugin_id = identity.plugin_id
        describe = _attribute(plugin, "describe_match_policies")
        link_hook = _attribute(plugin, "link")
        if not callable(describe) or not callable(link_hook):
            raise TypeError("federation linker hooks must be callable")
        try:
            raw_policies = describe()
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise RuntimeError(
                "federation linker policy declaration failed"
            ) from error
        if type(raw_policies) is not tuple:
            raise ValueError("linker match policies must be an exact tuple")
        if len(raw_policies) > self.limits.max_policies_per_linker:
            raise ValueError("linker match policies exceed the configured limit")
        policies = tuple(
            _snapshot_policy(item, require_kind=ConnectorMatchPolicyKind.LINKER)
            for item in raw_policies
        )
        policy_ids: set[str] = set()
        for policy in policies:
            if policy.linker_plugin_id != plugin_id:
                raise ValueError("linker declared a policy owned by another plugin")
            if policy.policy_id in policy_ids:
                raise ValueError("linker declared a duplicate policy_id")
            policy_ids.add(policy.policy_id)
        ordered = tuple(
            sorted(
                policies,
                key=lambda policy: (
                    policy.policy_id,
                    policy.claim_contract_id,
                    policy.argument_names,
                ),
            )
        )
        if _live_linker_identity(plugin) != identity:
            raise ValueError(
                "federation linker identity changed during registration"
            )
        return _Registration(
            identity=identity,
            plugin=plugin,
            link_hook=cast(
                Callable[[FederationLinkRequest], Iterable[object]],
                link_hook,
            ),
            policies=ordered,
        )

    @property
    def identities(self) -> tuple[FederationLinkerIdentity, ...]:
        return tuple(
            FederationLinkerIdentity(item.plugin_id, item.plugin_version)
            for item in self._identities
        )

    @property
    def policies(self) -> tuple[ConnectorMatchPolicyDescriptor, ...]:
        return tuple(_snapshot_policy(item) for item in self._policies)

    def select(
        self,
        policy: ConnectorMatchPolicyDescriptor,
    ) -> FederationLinkerIdentity | None:
        """Validate one policy and return its frozen linker identity, if any."""

        try:
            snapshot = _snapshot_policy(policy)
            registration = self._registration_for(snapshot)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except FederationPolicyError:
            raise
        except (TypeError, ValueError) as error:
            raise FederationPolicyError(str(error)) from error
        if registration is None:
            return None
        return FederationLinkerIdentity(
            registration.identity.plugin_id,
            registration.identity.plugin_version,
        )

    def _registration_for(
        self,
        policy: ConnectorMatchPolicyDescriptor,
    ) -> _Registration | None:
        if ConnectorMatchPolicyKind(policy.kind) is ConnectorMatchPolicyKind.EXACT_TOKEN:
            return None
        assert policy.linker_plugin_id is not None
        registration = self._by_plugin_id.get(policy.linker_plugin_id)
        if registration is None:
            raise FederationPolicyError(
                "federation policy names a linker outside the allowlist"
            )
        declared = tuple(
            item for item in registration.policies if item.policy_id == policy.policy_id
        )
        if len(declared) != 1 or declared[0] != policy:
            raise FederationPolicyError(
                "federation policy does not match the linker's frozen declaration",
                linker_identity=registration.identity,
            )
        return registration


class FederationLinkExecutor:
    """Resolve exact-token and trusted inline linker policies through one API."""

    def __init__(
        self,
        registry: FederationLinkerRegistry | None = None,
        *,
        limits: FederationLinkerLimits | None = None,
    ) -> None:
        if registry is not None and type(registry) is not FederationLinkerRegistry:
            raise TypeError("registry must be an exact FederationLinkerRegistry")
        if limits is not None and type(limits) is not FederationLinkerLimits:
            raise TypeError("limits must be an exact FederationLinkerLimits")
        if registry is None:
            selected_limits = limits or FederationLinkerLimits()
            registry = FederationLinkerRegistry((), limits=selected_limits)
        else:
            selected_limits = limits or registry.limits
        self.registry: FederationLinkerRegistry = registry
        self.limits: FederationLinkerLimits = selected_limits

    def resolve(
        self,
        policy: ConnectorMatchPolicyDescriptor,
        claims: tuple[FederatedConnectorClaim, ...],
        *,
        max_results: int | None = None,
        max_candidates_per_result: int | None = None,
    ) -> FederationExecutionResult:
        """Resolve normalized claims without exposing node worlds or artifacts."""

        selected_max_results = self._request_limit(
            max_results,
            default=self.limits.max_results,
            maximum=self.limits.max_results,
            label="max_results",
        )
        selected_max_candidates = self._request_limit(
            max_candidates_per_result,
            default=self.limits.max_candidates_per_result,
            maximum=self.limits.max_candidates_per_result,
            label="max_candidates_per_result",
        )
        try:
            policy_snapshot = _snapshot_policy(policy)
            claim_snapshots = _snapshot_claims(
                claims,
                policy_snapshot,
                limits=self.limits,
            )
            registration = self.registry._registration_for(policy_snapshot)
        except FederationPolicyError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except (TypeError, ValueError) as error:
            raise FederationPolicyError(str(error)) from error
        except BaseException as error:
            raise FederationPolicyError(
                "federation request could not be validated"
            ) from error

        if registration is None:
            return self._resolve_exact(
                policy_snapshot,
                claim_snapshots,
                max_results=selected_max_results,
                max_candidates=selected_max_candidates,
            )
        request = FederationLinkRequest(
            policy=policy_snapshot,
            claims=claim_snapshots,
            max_results=selected_max_results,
            max_candidates_per_result=selected_max_candidates,
        )
        return self._resolve_linker(registration, request)

    @staticmethod
    def _request_limit(
        value: int | None,
        *,
        default: int,
        minimum: int = 1,
        maximum: int,
        label: str,
    ) -> int:
        selected = default if value is None else value
        if type(selected) is not int or not minimum <= selected <= maximum:
            raise FederationPolicyError(
                f"{label} must be an integer between {minimum} and {maximum}"
            )
        return selected

    def _resolve_exact(
        self,
        policy: ConnectorMatchPolicyDescriptor,
        claims: tuple[FederatedConnectorClaim, ...],
        *,
        max_results: int,
        max_candidates: int,
    ) -> FederationExecutionResult:
        internal_to_claim: dict[str, FederatedConnectorClaim] = {}
        exact_claims: list[ExactMatchClaim] = []
        for index, claim in enumerate(claims):
            internal_id = f"claim-{index:06d}"
            internal_to_claim[internal_id] = claim
            exact_claims.append(
                ExactMatchClaim(
                    claim_id=internal_id,
                    partition_id=claim.endpoint.member_id,
                    matcher_id=MatcherId(policy.policy_id),
                    match_key=claim.claim.arguments,
                )
            )
        try:
            matched = exact_match_claims(
                exact_claims,
                max_candidates=0,
                max_claims=self.limits.max_claims,
            )
        except CorroborationError as error:
            raise FederationPolicyError("exact-token federation claims are invalid") from error

        group_by_internal_id: dict[
            str,
            tuple[
                tuple[tuple[str, tuple[FederatedConnectorClaim, ...]], ...],
                int,
            ],
        ] = {}
        for group in matched.groups:
            by_member: dict[str, list[FederatedConnectorClaim]] = {}
            for item in group.claims:
                claim = internal_to_claim[item.claim_id]
                by_member.setdefault(claim.endpoint.member_id, []).append(claim)
            member_groups = tuple(
                (member_id, tuple(member_claims))
                for member_id, member_claims in sorted(by_member.items())
            )
            view = (member_groups, len(group.claims))
            for item in group.claims:
                group_by_internal_id[item.claim_id] = view

        results: list[FederationLinkResult] = []
        candidates_truncated = False
        for index, source in enumerate(claims[:max_results]):
            internal_id = f"claim-{index:06d}"
            member_groups, group_size = group_by_internal_id[internal_id]
            own_member_count = next(
                len(member_claims)
                for member_id, member_claims in member_groups
                if member_id == source.endpoint.member_id
            )
            remote_count = group_size - own_member_count
            selected_remote_list: list[FederatedConnectorClaim] = []
            for member_id, member_claims in member_groups:
                if member_id == source.endpoint.member_id:
                    continue
                remaining = max_candidates - len(selected_remote_list)
                if remaining <= 0:
                    break
                selected_remote_list.extend(member_claims[:remaining])
            selected_remote = tuple(selected_remote_list)
            if remote_count == 0:
                state = FederationMatchState.UNRESOLVED
            elif remote_count == 1:
                state = FederationMatchState.MATCHED
            else:
                state = FederationMatchState.AMBIGUOUS
                if max_candidates < 2:
                    raise FederationPolicyError(
                        "exact-token ambiguity requires a candidate limit of at "
                        "least two"
                    )
            link_type: str | None = None
            properties: Mapping[str, Any] = MappingProxyType({})
            if remote_count == 1:
                state, link_type, properties = self._exact_pair_contract(
                    source,
                    selected_remote[0],
                )
            candidates_truncated = (
                candidates_truncated or remote_count > len(selected_remote)
            )
            candidates = tuple(
                FederationMatchCandidate(
                    claim_id=item.claim.claim_id,
                    endpoint=item.endpoint,
                    quality=item.claim.quality,
                    evidence=item.claim.evidence,
                )
                for item in selected_remote
            )
            identity = _claim_identity(source)
            digest = hashlib.sha256(
                json.dumps(
                    [policy.policy_id, *identity],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            results.append(
                FederationLinkResult(
                    result_id=f"core-exact-{digest}",
                    match_policy_id=policy.policy_id,
                    source=source,
                    state=state,
                    candidates=candidates,
                    provenance=Provenance.CORRELATED,
                    quality=self._exact_quality(source, selected_remote, state),
                    link_type=link_type,
                    properties=properties,
                )
            )

        results_truncated = len(claims) > max_results
        truncated = results_truncated or candidates_truncated
        return FederationExecutionResult(
            results=tuple(results),
            diagnostics=(),
            complete=not truncated and len(results) == len(claims),
            truncated=truncated,
            provenance=FederationExecutionProvenance.CORE_EXACT_TOKEN,
            linker_identity=None,
        )

    @staticmethod
    def _exact_pair_contract(
        source: FederatedConnectorClaim,
        candidate: FederatedConnectorClaim,
    ) -> tuple[FederationMatchState, str, Mapping[str, Any]]:
        """Fail closed when two otherwise exact claims disagree semantically."""

        claimed_link_types = tuple(
            sorted({source.claim.link_type, candidate.claim.link_type})
        )
        source_role = source.claim.presentation.route_trace
        candidate_role = candidate.claim.presentation.route_trace
        role_conflict = source_role is not candidate_role
        link_type_conflict = len(claimed_link_types) != 1
        route_trace = (
            InterNodeRouteTraceRole.CONFLICT
            if role_conflict
            else source_role
        )
        projection_role = (
            "presentation_conflict"
            if role_conflict
            else "presentation_overlay"
            if route_trace is InterNodeRouteTraceRole.OVERLAY
            else "route_trace_compatibility"
        )
        properties: dict[str, Any] = {
            "claimed_link_types": claimed_link_types,
            "presentation": MappingProxyType(
                {"route_trace": route_trace.value}
            ),
            "projection_role": projection_role,
        }
        if link_type_conflict:
            properties["reason"] = "plugin_link_type_mismatch"
        elif role_conflict:
            properties["reason"] = "plugin_route_trace_role_mismatch"
        return (
            FederationMatchState.CONFLICT
            if link_type_conflict or role_conflict
            else FederationMatchState.MATCHED,
            "unknown" if link_type_conflict else claimed_link_types[0],
            MappingProxyType(properties),
        )

    @staticmethod
    def _exact_quality(
        source: FederatedConnectorClaim,
        candidates: tuple[FederatedConnectorClaim, ...],
        state: FederationMatchState,
    ) -> Quality:
        if state is FederationMatchState.UNRESOLVED:
            return Quality.UNKNOWN
        if state in {
            FederationMatchState.AMBIGUOUS,
            FederationMatchState.CONFLICT,
        }:
            return Quality.AMBIGUOUS
        qualities = (source.claim.quality,) + tuple(
            item.claim.quality for item in candidates
        )
        if Quality.UNKNOWN in qualities:
            return Quality.UNKNOWN
        if Quality.AMBIGUOUS in qualities:
            return Quality.AMBIGUOUS
        if Quality.BEST_EFFORT in qualities:
            return Quality.BEST_EFFORT
        return Quality.EXACT

    def _resolve_linker(
        self,
        registration: _Registration,
        request: FederationLinkRequest,
    ) -> FederationExecutionResult:
        identity = FederationLinkerIdentity(
            registration.identity.plugin_id,
            registration.identity.plugin_version,
        )
        authoritative_policy = _snapshot_policy(request.policy)
        authoritative_claims = tuple(
            _snapshot_claim(
                claim,
                maximum_evidence=self.limits.max_evidence_per_output,
            )
            for claim in request.claims
        )
        supplied = MappingProxyType(
            {_claim_identity(claim): claim for claim in authoritative_claims}
        )
        request_max_results = request.max_results
        request_max_candidates = request.max_candidates_per_result

        def invoke() -> tuple[
            tuple[FederationLinkResult, ...], tuple[PluginDiagnostic, ...]
        ]:
            try:
                live_identity = _live_linker_identity(registration.plugin)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise _LinkerOutputFailure(
                    "federation linker identity could not be validated",
                    (),
                ) from error
            if live_identity != identity:
                raise _LinkerOutputFailure(
                    "federation linker identity changed after registration",
                    (),
                )
            try:
                outputs = registration.link_hook(request)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise _LinkerHookFailure(()) from error
            results, diagnostics = self._consume_linker_outputs(
                outputs,
                policy=authoritative_policy,
                max_results=request_max_results,
                max_candidates=request_max_candidates,
                supplied=supplied,
            )
            try:
                live_identity = _live_linker_identity(registration.plugin)
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise _LinkerOutputFailure(
                    "federation linker identity could not be validated after link()",
                    diagnostics,
                ) from error
            if live_identity != identity:
                raise _LinkerOutputFailure(
                    "federation linker identity changed during link()",
                    diagnostics,
                )
            return results, diagnostics

        try:
            results, diagnostics = invoke()
        except FederationExecutionError:
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except _NonRecoverableDiagnostic as error:
            raise FederationLinkExecutionError(
                f"linker failed: {error.diagnostic.code}: "
                f"{error.diagnostic.message}",
                linker_identity=identity,
                diagnostics=error.diagnostics,
            ) from error
        except _LinkerOutputFailure as error:
            raise FederationLinkOutputError(
                str(error),
                linker_identity=identity,
                diagnostics=error.diagnostics,
            ) from error
        except _LinkerHookFailure as error:
            raise FederationLinkExecutionError(
                "link() failed inside the federation linker",
                linker_identity=identity,
                diagnostics=error.diagnostics,
            ) from error
        except (TypeError, ValueError) as error:
            raise FederationLinkOutputError(
                str(error),
                linker_identity=identity,
            ) from error
        except BaseException as error:
            raise FederationLinkExecutionError(
                "link() failed inside the federation linker",
                linker_identity=identity,
            ) from error

        covered = {_claim_identity(item.source) for item in results}
        incomplete = len(covered) != len(authoritative_claims)
        truncated = incomplete and len(results) == request_max_results
        return FederationExecutionResult(
            results=results,
            diagnostics=diagnostics,
            complete=not incomplete and not truncated,
            truncated=truncated,
            provenance=FederationExecutionProvenance.LINKER_PLUGIN,
            linker_identity=identity,
        )

    def _consume_linker_outputs(
        self,
        outputs: object,
        *,
        policy: ConnectorMatchPolicyDescriptor,
        max_results: int,
        max_candidates: int,
        supplied: Mapping[
            tuple[str, str, str, str], FederatedConnectorClaim
        ],
    ) -> tuple[tuple[FederationLinkResult, ...], tuple[PluginDiagnostic, ...]]:
        try:
            iterator = iter(cast(Iterable[object], outputs))
        except TypeError as error:
            raise _LinkerOutputFailure("link() must return an iterable", ()) from error
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise _LinkerHookFailure(()) from error
        results: list[FederationLinkResult] = []
        diagnostics: list[PluginDiagnostic] = []
        result_ids: set[str] = set()
        source_ids: set[tuple[str, str, str, str]] = set()
        try:
            while True:
                try:
                    output = next(iterator)
                except StopIteration:
                    break
                except PROCESS_CONTROL_EXCEPTIONS:
                    raise
                except BaseException as error:
                    raise _LinkerHookFailure(tuple(diagnostics)) from error
                if type(output) is PluginDiagnostic:
                    if len(diagnostics) >= self.limits.max_diagnostics:
                        raise ValueError("linker output exceeded the diagnostic limit")
                    diagnostic = _snapshot_diagnostic(
                        output,
                        f"link[{len(results) + len(diagnostics)}]",
                        maximum_evidence=self.limits.max_evidence_per_output,
                    )
                    diagnostics.append(diagnostic)
                    if not diagnostic.recoverable:
                        raise _NonRecoverableDiagnostic(
                            diagnostic,
                            tuple(diagnostics),
                        )
                    continue
                if type(output) is not FederationLinkResult:
                    raise ValueError("linker emitted an unsupported output type")
                if len(results) >= max_results:
                    raise ValueError("linker output exceeded the result limit")
                result = _snapshot_link_result(
                    output,
                    policy=policy,
                    supplied=supplied,
                    limits=self.limits,
                    max_candidates=max_candidates,
                )
                if result.result_id in result_ids:
                    raise ValueError("linker emitted a duplicate result_id")
                source_identity = _claim_identity(result.source)
                if source_identity in source_ids:
                    raise ValueError("linker emitted multiple results for one source")
                result_ids.add(result.result_id)
                source_ids.add(source_identity)
                results.append(result)
        except (_LinkerHookFailure, _NonRecoverableDiagnostic):
            raise
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except (TypeError, ValueError) as error:
            raise _LinkerOutputFailure(
                str(error),
                tuple(diagnostics),
            ) from error
        finally:
            try:
                close = getattr(iterator, "close", None)
                if callable(close):
                    close()
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except BaseException as error:
                raise _LinkerHookFailure(tuple(diagnostics)) from error
        results.sort(key=lambda item: (_claim_identity(item.source), item.result_id))
        return tuple(results), tuple(diagnostics)


class _NonRecoverableDiagnostic(Exception):
    def __init__(
        self,
        diagnostic: PluginDiagnostic,
        diagnostics: tuple[PluginDiagnostic, ...],
    ) -> None:
        super().__init__(diagnostic.code)
        self.diagnostic = diagnostic
        self.diagnostics = diagnostics


class _LinkerOutputFailure(ValueError):
    def __init__(
        self,
        message: str,
        diagnostics: tuple[PluginDiagnostic, ...],
    ) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics


class _LinkerHookFailure(Exception):
    def __init__(self, diagnostics: tuple[PluginDiagnostic, ...]) -> None:
        super().__init__("federation linker hook failed")
        self.diagnostics = diagnostics


__all__ = [
    "FederationExecutionError",
    "FederationExecutionProvenance",
    "FederationExecutionResult",
    "FederationLinkExecutionError",
    "FederationLinkExecutor",
    "FederationLinkOutputError",
    "FederationLinkerIdentity",
    "FederationLinkerLimits",
    "FederationLinkerRegistry",
    "FederationPolicyError",
    "FederationRegistrationError",
]
