"""Immutable deployment policy for composing one revision's plug-in plan.

The primary parser is still selected by the durable probe/selection workflow.
This module lets an operator attach additional, exactly registered capability
providers to that primary interpretation.  It contains identities and roles
only: no plug-in objects, callbacks, configuration values, or device matching
logic cross this boundary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from .canonical import strict_canonical_json_sha256
from .public_text import contains_unsafe_identifier_text, has_visible_identity_anchor

PLUGIN_COMPOSITION_POLICY_VERSION: Final = (
    "router_dump_analyzer.plugin_composition_policy.v1"
)
REVISION_CONSISTENCY_ROLE: Final = "revision_consistency"
MAX_PLUGIN_COMPOSITION_RULES: Final = 256
MAX_PLUGIN_COMPOSITION_AUXILIARIES: Final = 127

_TOKEN = re.compile(r"^[^\s\x00-\x1f\x7f]+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _token(value: object, label: str, *, maximum: int = 256) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip()
        or _TOKEN.fullmatch(value) is None
        or contains_unsafe_identifier_text(value)
        or not has_visible_identity_anchor(value)
    ):
        raise ValueError(f"{label} must be a safe bounded opaque token")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a sha256-prefixed lowercase digest")
    return value


def _roles(value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError("roles must be an exact tuple")
    if not 1 <= len(value) <= 32:
        raise ValueError("roles must contain 1 to 32 values")
    roles = tuple(_token(item, "role", maximum=128) for item in value)
    if roles != tuple(sorted(set(roles))):
        raise ValueError("roles must be unique and canonically ordered")
    if "primary_parser" in roles:
        raise ValueError("auxiliary selections cannot claim primary_parser")
    return roles


@dataclass(frozen=True, slots=True)
class PluginParticipationSelection:
    """One exact auxiliary provider selected by deployment policy."""

    instance_id: str
    registered_execution_identity: str
    roles: tuple[str, ...]

    def __post_init__(self) -> None:
        _token(self.instance_id, "instance_id")
        _digest(
            self.registered_execution_identity,
            "registered_execution_identity",
        )
        object.__setattr__(self, "roles", _roles(self.roles))


def _selection_dict(value: PluginParticipationSelection) -> dict[str, object]:
    if type(value) is not PluginParticipationSelection:
        raise TypeError("auxiliaries must contain PluginParticipationSelection")
    detached = PluginParticipationSelection(
        instance_id=value.instance_id,
        registered_execution_identity=value.registered_execution_identity,
        roles=value.roles,
    )
    return {
        "instance_id": detached.instance_id,
        "registered_execution_identity": detached.registered_execution_identity,
        "roles": list(detached.roles),
    }


@dataclass(frozen=True, slots=True)
class PluginCompositionRule:
    """Auxiliary plan pins applied to one exact primary execution identity."""

    primary_instance_id: str
    primary_registered_execution_identity: str
    auxiliaries: tuple[PluginParticipationSelection, ...]

    def __post_init__(self) -> None:
        _token(self.primary_instance_id, "primary_instance_id")
        _digest(
            self.primary_registered_execution_identity,
            "primary_registered_execution_identity",
        )
        if type(self.auxiliaries) is not tuple:
            raise TypeError("auxiliaries must be an exact tuple")
        if len(self.auxiliaries) > MAX_PLUGIN_COMPOSITION_AUXILIARIES:
            raise ValueError("too many auxiliary plug-in selections")
        detached = tuple(
            PluginParticipationSelection(
                instance_id=item.instance_id,
                registered_execution_identity=item.registered_execution_identity,
                roles=item.roles,
            )
            if type(item) is PluginParticipationSelection
            else _selection_type_error()
            for item in self.auxiliaries
        )
        canonical = tuple(
            sorted(
                detached,
                key=lambda item: (
                    item.instance_id,
                    item.registered_execution_identity,
                    item.roles,
                ),
            )
        )
        if detached != canonical:
            raise ValueError("auxiliaries must use canonical identity order")
        instance_ids = tuple(item.instance_id for item in detached)
        if len(instance_ids) != len(set(instance_ids)):
            raise ValueError("auxiliary instance IDs must be unique")
        if self.primary_instance_id in instance_ids:
            raise ValueError("primary instance cannot also be an auxiliary")
        object.__setattr__(self, "auxiliaries", detached)


def _selection_type_error() -> PluginParticipationSelection:
    raise TypeError("auxiliaries must contain PluginParticipationSelection")


def _rule_dict(value: PluginCompositionRule) -> dict[str, object]:
    if type(value) is not PluginCompositionRule:
        raise TypeError("rules must contain PluginCompositionRule")
    return {
        "primary_instance_id": value.primary_instance_id,
        "primary_registered_execution_identity": (
            value.primary_registered_execution_identity
        ),
        "auxiliaries": [_selection_dict(item) for item in value.auxiliaries],
    }


@dataclass(frozen=True, slots=True)
class PluginCompositionPolicy:
    """Canonical exact-primary-to-auxiliary composition policy."""

    rules: tuple[PluginCompositionRule, ...] = ()
    contract_version: str = PLUGIN_COMPOSITION_POLICY_VERSION
    policy_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.contract_version) is not str:
            raise TypeError("contract_version must be an exact string")
        if self.contract_version != PLUGIN_COMPOSITION_POLICY_VERSION:
            raise ValueError("plug-in composition policy version is unsupported")
        if type(self.policy_digest) is not str:
            raise TypeError("policy_digest must be an exact string")
        if type(self.rules) is not tuple:
            raise TypeError("rules must be an exact tuple")
        if len(self.rules) > MAX_PLUGIN_COMPOSITION_RULES:
            raise ValueError("too many plug-in composition rules")
        rules = tuple(
            PluginCompositionRule(
                primary_instance_id=item.primary_instance_id,
                primary_registered_execution_identity=(
                    item.primary_registered_execution_identity
                ),
                auxiliaries=item.auxiliaries,
            )
            if type(item) is PluginCompositionRule
            else _rule_type_error()
            for item in self.rules
        )
        canonical = tuple(
            sorted(
                rules,
                key=lambda item: (
                    item.primary_instance_id,
                    item.primary_registered_execution_identity,
                ),
            )
        )
        if rules != canonical:
            raise ValueError("composition rules must use canonical primary order")
        keys = tuple(
            (
                item.primary_instance_id,
                item.primary_registered_execution_identity,
            )
            for item in rules
        )
        if len(keys) != len(set(keys)):
            raise ValueError("composition primary identities must be unique")
        object.__setattr__(self, "rules", rules)
        payload = {
            "contract_version": self.contract_version,
            "rules": [_rule_dict(item) for item in rules],
        }
        expected = "sha256:" + strict_canonical_json_sha256(payload)
        if self.policy_digest != "":
            _digest(self.policy_digest, "policy_digest")
            if self.policy_digest != expected:
                raise ValueError("plug-in composition policy digest does not match")
        else:
            object.__setattr__(self, "policy_digest", expected)

    def auxiliaries_for(
        self,
        *,
        primary_instance_id: str,
        primary_registered_execution_identity: str,
    ) -> tuple[PluginParticipationSelection, ...]:
        """Return the one exact rule or an empty immutable selection."""

        key = (
            _token(primary_instance_id, "primary_instance_id"),
            _digest(
                primary_registered_execution_identity,
                "primary_registered_execution_identity",
            ),
        )
        for rule in self.rules:
            if (
                rule.primary_instance_id,
                rule.primary_registered_execution_identity,
            ) == key:
                return rule.auxiliaries
        return ()


def _rule_type_error() -> PluginCompositionRule:
    raise TypeError("rules must contain PluginCompositionRule")


DEFAULT_PLUGIN_COMPOSITION_POLICY_DIGEST: Final[str] = (
    PluginCompositionPolicy().policy_digest
)


__all__ = [
    "DEFAULT_PLUGIN_COMPOSITION_POLICY_DIGEST",
    "MAX_PLUGIN_COMPOSITION_AUXILIARIES",
    "MAX_PLUGIN_COMPOSITION_RULES",
    "PLUGIN_COMPOSITION_POLICY_VERSION",
    "REVISION_CONSISTENCY_ROLE",
    "PluginCompositionPolicy",
    "PluginCompositionRule",
    "PluginParticipationSelection",
]
