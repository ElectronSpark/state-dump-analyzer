"""Typed, fail-closed disclosure policy for private workspace analysis.

The policy answers one narrow question: may one already-authorized private
analysis run receive evidence in a declared disclosure class over a declared
local transport?  It does not grant workspace access, invoke a model, inspect
payloads, or override evidence-level ``never_assistant`` declarations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from ..canonical import strict_canonical_json_sha256
from ..public_text import (
    contains_filesystem_identity_path,
    contains_unsafe_identifier_text,
    has_visible_identity_anchor,
)
from ._wire import SealedContractValue, exact_json_object, strict_string_enum
from .policy import PrivateAnalysisPolicy, PrivateAnalysisTransport

WORKSPACE_DISCLOSURE_POLICY_VERSION: Final = (
    "router_dump_analyzer.workspace_disclosure_policy.v1"
)
DISCLOSURE_SCOPE_VERSION: Final = (
    "router_dump_analyzer.private_analysis.disclosure_scope.v1"
)
_MAX_SCOPE_IDENTIFIER_CHARACTERS: Final = 256


class PrivateAnalysisDisclosureMode(StrEnum):
    """The complete set of workspace disclosure tiers."""

    DISABLED = "disabled"
    CLIENT_SAFE = "client_safe"
    FULL_FIDELITY = "full_fidelity"


class PrivateAnalysisEvidenceClass(StrEnum):
    """Core-owned disclosure classes assigned before evidence retrieval."""

    PUBLIC_METADATA = "public_metadata"
    CLIENT_SAFE = "client_safe"
    PROPRIETARY = "proprietary"
    NEVER_ASSISTANT = "never_assistant"


class DisclosureDecisionReason(StrEnum):
    """Closed reasons recorded without copying the evaluated payload."""

    ALLOWED = "allowed"
    WORKSPACE_DISABLED = "workspace_disabled"
    TRANSPORT_NOT_APPROVED = "transport_not_approved"
    RUNNER_FULL_FIDELITY_NOT_APPROVED = "runner_full_fidelity_not_approved"
    EVIDENCE_CLASS_NOT_APPROVED = "evidence_class_not_approved"
    NEVER_ASSISTANT = "never_assistant"


_CLIENT_SAFE_CLASSES: Final = frozenset(
    {
        PrivateAnalysisEvidenceClass.PUBLIC_METADATA,
        PrivateAnalysisEvidenceClass.CLIENT_SAFE,
    }
)
_FULL_FIDELITY_CLASSES: Final = frozenset(
    {
        *_CLIENT_SAFE_CLASSES,
        PrivateAnalysisEvidenceClass.PROPRIETARY,
    }
)


@dataclass(frozen=True, slots=True)
class WorkspaceDisclosurePolicy(SealedContractValue):
    """One detached policy value later bound to an exact workspace.

    Transport entries must be in canonical wire order.  Requiring canonical
    construction prevents two semantically identical policies from acquiring
    different digests or optimistic versions.
    """

    mode: PrivateAnalysisDisclosureMode
    transports: tuple[PrivateAnalysisTransport, ...] = ()

    def __post_init__(self) -> None:
        if type(self.mode) is not PrivateAnalysisDisclosureMode:
            raise TypeError("disclosure mode must be PrivateAnalysisDisclosureMode")
        if type(self.transports) is not tuple:
            raise TypeError("disclosure transports must be a tuple")
        if len(self.transports) > len(PrivateAnalysisTransport):
            raise ValueError("too many disclosure transports")
        if any(
            type(transport) is not PrivateAnalysisTransport
            for transport in self.transports
        ):
            raise TypeError(
                "disclosure transports must contain PrivateAnalysisTransport values"
            )
        canonical = tuple(sorted(set(self.transports), key=lambda item: item.value))
        if self.transports != canonical:
            raise ValueError(
                "disclosure transports must be unique and in canonical order"
            )
        if self.mode is PrivateAnalysisDisclosureMode.DISABLED:
            if self.transports:
                raise ValueError("disabled disclosure cannot approve a transport")
        elif not self.transports:
            raise ValueError("enabled disclosure must approve at least one transport")

    @classmethod
    def disabled(cls) -> WorkspaceDisclosurePolicy:
        """Return the explicit fail-closed policy used for unconfigured workspaces."""

        return cls(PrivateAnalysisDisclosureMode.DISABLED)

    @property
    def digest(self) -> str:
        return workspace_disclosure_policy_digest(self)


@dataclass(frozen=True, slots=True)
class DisclosureDecision(SealedContractValue):
    """Payload-free result of evaluating one evidence disclosure."""

    policy_digest: str
    scope_digest: str
    transport: PrivateAnalysisTransport
    evidence_class: PrivateAnalysisEvidenceClass
    allowed: bool
    reason: DisclosureDecisionReason

    def __post_init__(self) -> None:
        if type(self.policy_digest) is not str or len(self.policy_digest) != 64:
            raise ValueError("policy_digest must be a lowercase SHA-256 digest")
        if any(character not in "0123456789abcdef" for character in self.policy_digest):
            raise ValueError("policy_digest must be a lowercase SHA-256 digest")
        if type(self.scope_digest) is not str or len(self.scope_digest) != 64:
            raise ValueError("scope_digest must be a lowercase SHA-256 digest")
        if any(character not in "0123456789abcdef" for character in self.scope_digest):
            raise ValueError("scope_digest must be a lowercase SHA-256 digest")
        if type(self.transport) is not PrivateAnalysisTransport:
            raise TypeError("decision transport must be PrivateAnalysisTransport")
        if type(self.evidence_class) is not PrivateAnalysisEvidenceClass:
            raise TypeError(
                "decision evidence_class must be PrivateAnalysisEvidenceClass"
            )
        if type(self.allowed) is not bool:
            raise TypeError("decision allowed must be a boolean")
        if type(self.reason) is not DisclosureDecisionReason:
            raise TypeError("decision reason must be DisclosureDecisionReason")
        if self.allowed is not (self.reason is DisclosureDecisionReason.ALLOWED):
            raise ValueError("decision allowed flag and reason disagree")

    @property
    def digest(self) -> str:
        return strict_canonical_json_sha256(disclosure_decision_dict(self))


def workspace_disclosure_policy_dict(
    policy: WorkspaceDisclosurePolicy,
) -> dict[str, object]:
    """Project one policy to its exact versioned canonical wire object."""

    policy = _revalidated_workspace_disclosure_policy(policy)
    return {
        "policy_version": WORKSPACE_DISCLOSURE_POLICY_VERSION,
        "mode": policy.mode.value,
        "transports": [transport.value for transport in policy.transports],
    }


def workspace_disclosure_policy_from_dict(
    value: dict[str, Any],
) -> WorkspaceDisclosurePolicy:
    """Parse one exact policy object and reject missing or unknown fields."""

    expected = {"policy_version", "mode", "transports"}
    item = exact_json_object(value, "workspace disclosure policy fields", expected)
    if (
        type(item["policy_version"]) is not str
        or item["policy_version"] != WORKSPACE_DISCLOSURE_POLICY_VERSION
    ):
        raise ValueError("workspace disclosure policy version is unsupported")
    mode_value = item["mode"]
    if type(mode_value) is not str:
        raise TypeError("workspace disclosure policy mode must be a string")
    mode = strict_string_enum(
        PrivateAnalysisDisclosureMode,
        mode_value,
        "workspace disclosure policy mode",
    )
    raw_transports = item["transports"]
    if type(raw_transports) is not list:
        raise TypeError("workspace disclosure policy transports must be a list")
    if len(raw_transports) > len(PrivateAnalysisTransport):
        raise ValueError("too many workspace disclosure policy transports")
    transports: list[PrivateAnalysisTransport] = []
    for raw_transport in raw_transports:
        if type(raw_transport) is not str:
            raise TypeError("workspace disclosure policy transport must be a string")
        transports.append(
            strict_string_enum(
                PrivateAnalysisTransport,
                raw_transport,
                "workspace disclosure policy transport",
            )
        )
    return WorkspaceDisclosurePolicy(mode, tuple(transports))


def workspace_disclosure_policy_digest(policy: WorkspaceDisclosurePolicy) -> str:
    """Return the type-preserving digest used by storage and future ledgers."""

    return strict_canonical_json_sha256(workspace_disclosure_policy_dict(policy))


def _revalidated_workspace_disclosure_policy(
    policy: object,
) -> WorkspaceDisclosurePolicy:
    """Return a detached policy after rechecking every authority-bearing field."""

    if type(policy) is not WorkspaceDisclosurePolicy:
        raise TypeError("policy must be WorkspaceDisclosurePolicy")
    return WorkspaceDisclosurePolicy(
        mode=policy.mode,
        transports=policy.transports,
    )


def _revalidated_private_analysis_policy(
    policy: object,
) -> PrivateAnalysisPolicy:
    """Return a detached runner ceiling instead of trusting a frozen instance."""

    if type(policy) is not PrivateAnalysisPolicy:
        raise TypeError("runner_policy must be PrivateAnalysisPolicy")
    return PrivateAnalysisPolicy(
        transport=policy.transport,
        full_fidelity_workspace_data=policy.full_fidelity_workspace_data,
    )


def _revalidated_disclosure_decision(
    decision: object,
) -> DisclosureDecision:
    """Return a detached decision after rechecking its closed invariants."""

    if type(decision) is not DisclosureDecision:
        raise TypeError("disclosure_decision must be DisclosureDecision")
    return DisclosureDecision(
        policy_digest=decision.policy_digest,
        scope_digest=decision.scope_digest,
        transport=decision.transport,
        evidence_class=decision.evidence_class,
        allowed=decision.allowed,
        reason=decision.reason,
    )


def _scope_identifier(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_SCOPE_IDENTIFIER_CHARACTERS
        or value != value.strip()
        or contains_filesystem_identity_path(value)
        or contains_unsafe_identifier_text(value)
        or not has_visible_identity_anchor(value)
    ):
        raise ValueError(f"{label} is not a safe bounded identifier")
    return value


def disclosure_scope_digest(
    *,
    tenant_id: str,
    project_id: str,
    workspace_id: str,
) -> str:
    """Bind a decision to one exact authorization scope without echoing IDs."""

    return strict_canonical_json_sha256(
        {
            "contract_version": DISCLOSURE_SCOPE_VERSION,
            "tenant_id": _scope_identifier(tenant_id, "tenant_id"),
            "project_id": _scope_identifier(project_id, "project_id"),
            "workspace_id": _scope_identifier(workspace_id, "workspace_id"),
        }
    )


def evaluate_workspace_disclosure(
    policy: WorkspaceDisclosurePolicy,
    *,
    tenant_id: str,
    project_id: str,
    workspace_id: str,
    runner_policy: PrivateAnalysisPolicy,
    evidence_class: PrivateAnalysisEvidenceClass,
) -> DisclosureDecision:
    """Evaluate one class without accepting or observing the evidence payload."""

    policy = _revalidated_workspace_disclosure_policy(policy)
    runner_policy = _revalidated_private_analysis_policy(runner_policy)
    if type(evidence_class) is not PrivateAnalysisEvidenceClass:
        raise TypeError("evidence_class must be PrivateAnalysisEvidenceClass")
    transport = runner_policy.transport
    if evidence_class is PrivateAnalysisEvidenceClass.NEVER_ASSISTANT:
        allowed = False
        reason = DisclosureDecisionReason.NEVER_ASSISTANT
    elif policy.mode is PrivateAnalysisDisclosureMode.DISABLED:
        allowed = False
        reason = DisclosureDecisionReason.WORKSPACE_DISABLED
    elif transport not in policy.transports:
        allowed = False
        reason = DisclosureDecisionReason.TRANSPORT_NOT_APPROVED
    elif policy.mode is PrivateAnalysisDisclosureMode.CLIENT_SAFE:
        approved_classes = _CLIENT_SAFE_CLASSES
        allowed = evidence_class in approved_classes
        reason = (
            DisclosureDecisionReason.ALLOWED
            if allowed
            else DisclosureDecisionReason.EVIDENCE_CLASS_NOT_APPROVED
        )
    elif policy.mode is PrivateAnalysisDisclosureMode.FULL_FIDELITY:
        approved_classes = _FULL_FIDELITY_CLASSES
        allowed = evidence_class in approved_classes
        if not allowed:
            reason = DisclosureDecisionReason.EVIDENCE_CLASS_NOT_APPROVED
        elif (
            evidence_class is PrivateAnalysisEvidenceClass.PROPRIETARY
            and not runner_policy.full_fidelity_workspace_data
        ):
            allowed = False
            reason = DisclosureDecisionReason.RUNNER_FULL_FIDELITY_NOT_APPROVED
        else:
            reason = DisclosureDecisionReason.ALLOWED
    else:  # pragma: no cover - constructor and enum make this unreachable
        allowed = False
        reason = DisclosureDecisionReason.EVIDENCE_CLASS_NOT_APPROVED
    return DisclosureDecision(
        policy_digest=policy.digest,
        scope_digest=disclosure_scope_digest(
            tenant_id=tenant_id,
            project_id=project_id,
            workspace_id=workspace_id,
        ),
        transport=transport,
        evidence_class=evidence_class,
        allowed=allowed,
        reason=reason,
    )


def disclosure_decision_dict(decision: DisclosureDecision) -> dict[str, object]:
    """Project a decision without any payload, identifier, or free-form text."""

    decision = _revalidated_disclosure_decision(decision)
    return {
        "policy_digest": decision.policy_digest,
        "scope_digest": decision.scope_digest,
        "transport": decision.transport.value,
        "evidence_class": decision.evidence_class.value,
        "allowed": decision.allowed,
        "reason": decision.reason.value,
    }


def disclosure_decision_from_dict(
    value: dict[str, Any],
) -> DisclosureDecision:
    """Parse the exact payload-free decision used by evidence envelopes."""

    expected = {
        "policy_digest",
        "scope_digest",
        "transport",
        "evidence_class",
        "allowed",
        "reason",
    }
    item = exact_json_object(value, "disclosure decision fields", expected)
    transport_value = item["transport"]
    evidence_class_value = item["evidence_class"]
    reason_value = item["reason"]
    if type(transport_value) is not str:
        raise TypeError("disclosure decision transport must be a string")
    if type(evidence_class_value) is not str:
        raise TypeError("disclosure decision evidence_class must be a string")
    if type(reason_value) is not str:
        raise TypeError("disclosure decision reason must be a string")
    if type(item["allowed"]) is not bool:
        raise TypeError("disclosure decision allowed must be a boolean")
    policy_digest = item["policy_digest"]
    scope_digest = item["scope_digest"]
    if type(policy_digest) is not str:
        raise TypeError("disclosure decision policy_digest must be a string")
    if type(scope_digest) is not str:
        raise TypeError("disclosure decision scope_digest must be a string")
    transport = strict_string_enum(
        PrivateAnalysisTransport,
        transport_value,
        "disclosure decision transport",
    )
    evidence_class = strict_string_enum(
        PrivateAnalysisEvidenceClass,
        evidence_class_value,
        "disclosure decision evidence_class",
    )
    reason = strict_string_enum(
        DisclosureDecisionReason,
        reason_value,
        "disclosure decision reason",
    )
    return DisclosureDecision(
        policy_digest=policy_digest,
        scope_digest=scope_digest,
        transport=transport,
        evidence_class=evidence_class,
        allowed=item["allowed"],
        reason=reason,
    )


__all__ = [
    "DISCLOSURE_SCOPE_VERSION",
    "WORKSPACE_DISCLOSURE_POLICY_VERSION",
    "DisclosureDecision",
    "DisclosureDecisionReason",
    "PrivateAnalysisDisclosureMode",
    "PrivateAnalysisEvidenceClass",
    "WorkspaceDisclosurePolicy",
    "disclosure_decision_dict",
    "disclosure_decision_from_dict",
    "disclosure_scope_digest",
    "evaluate_workspace_disclosure",
    "workspace_disclosure_policy_dict",
    "workspace_disclosure_policy_digest",
    "workspace_disclosure_policy_from_dict",
]
