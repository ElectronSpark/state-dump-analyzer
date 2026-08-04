"""Immutable, replayable plug-in execution-plan identities.

The core records *which executable interpretation* produced a node revision.
It does not persist plug-in configuration values here: only their digest is
allowed.  The ordered tuple of pins is deliberately not a synthetic plug-in;
each producer retains its own identity for later routing and provenance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from .canonical import strict_canonical_json_sha256
from .contract_validation import bounded_string
from .public_text import contains_unsafe_identifier_text, has_visible_identity_anchor

PLUGIN_EXECUTION_PLAN_VERSION: Final = (
    "router_dump_analyzer.plugin_execution_plan.v1"
)
_MAX_PLUGINS = 128
_OPAQUE_PATTERN = re.compile(r"^[^\s\x00-\x1f\x7f]+$")
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_PACKAGE_DIGEST_PATTERN = re.compile(
    r"^(?:(?:manifest|module|package)-sha256|sha256):[0-9a-f]{64}$"
)


def _opaque(value: object, label: str, *, maximum: int = 256) -> str:
    if type(value) is not str:
        raise TypeError(f"{label} must be an exact string")
    result = bounded_string(value, label, maximum=maximum)
    if (
        result != result.strip()
        or _OPAQUE_PATTERN.fullmatch(result) is None
        or contains_unsafe_identifier_text(result)
        or not has_visible_identity_anchor(result)
    ):
        raise ValueError(f"{label} must be an opaque identifier")
    return result


def _digest(value: object, label: str, *, package: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(f"{label} must be an exact string")
    result = bounded_string(value, label, maximum=80)
    pattern = _PACKAGE_DIGEST_PATTERN if package else _SHA256_PATTERN
    if pattern.fullmatch(result) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return result


def _string_tuple(
    value: object,
    label: str,
    *,
    maximum_items: int = 128,
) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be a tuple")
    if len(value) > maximum_items:
        raise ValueError(f"{label} supports at most {maximum_items} items")
    result = tuple(_opaque(item, f"{label}[{index}]") for index, item in enumerate(value))
    if len(result) != len(set(result)):
        raise ValueError(f"{label} must not contain duplicates")
    return result


@dataclass(frozen=True, slots=True)
class PluginArtifactIdentity:
    """Installed distribution and executable package identity for one pin."""

    distribution_name: str
    distribution_version: str
    package_hash: str
    entry_point_name: str
    module_target: str

    def __post_init__(self) -> None:
        _opaque(self.distribution_name, "distribution_name")
        _opaque(self.distribution_version, "distribution_version", maximum=128)
        _digest(self.package_hash, "package_hash", package=True)
        _opaque(self.entry_point_name, "entry_point_name")
        _opaque(self.module_target, "module_target", maximum=512)


def _snapshot_artifact_identity(
    artifact: PluginArtifactIdentity,
) -> PluginArtifactIdentity:
    if type(artifact) is not PluginArtifactIdentity:
        raise TypeError("artifact must be PluginArtifactIdentity")
    return PluginArtifactIdentity(
        distribution_name=artifact.distribution_name,
        distribution_version=artifact.distribution_version,
        package_hash=artifact.package_hash,
        entry_point_name=artifact.entry_point_name,
        module_target=artifact.module_target,
    )


@dataclass(frozen=True, slots=True)
class DecoderIdentity:
    """Core- or deployment-owned decoder executable selected for the run."""

    decoder_id: str
    decoder_version: str
    executable_digest: str

    def __post_init__(self) -> None:
        _opaque(self.decoder_id, "decoder_id")
        _opaque(self.decoder_version, "decoder_version", maximum=128)
        _digest(self.executable_digest, "executable_digest")


def _snapshot_decoder_identity(decoder: DecoderIdentity) -> DecoderIdentity:
    if type(decoder) is not DecoderIdentity:
        raise TypeError("decoder must be DecoderIdentity")
    return DecoderIdentity(
        decoder_id=decoder.decoder_id,
        decoder_version=decoder.decoder_version,
        executable_digest=decoder.executable_digest,
    )


@dataclass(frozen=True, slots=True)
class PluginExecutionPin:
    """One configured plug-in instance; contains digests, never secret values."""

    instance_id: str
    plugin_id: str
    plugin_version: str
    core_api_version: str
    artifact: PluginArtifactIdentity
    configuration_digest: str
    schema_digest: str
    schema_versions: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _opaque(self.instance_id, "instance_id")
        _opaque(self.plugin_id, "plugin_id")
        _opaque(self.plugin_version, "plugin_version", maximum=128)
        _opaque(self.core_api_version, "core_api_version", maximum=128)
        object.__setattr__(
            self,
            "artifact",
            _snapshot_artifact_identity(self.artifact),
        )
        _digest(self.configuration_digest, "configuration_digest")
        _digest(self.schema_digest, "schema_digest")
        object.__setattr__(
            self,
            "schema_versions",
            _string_tuple(self.schema_versions, "schema_versions"),
        )
        object.__setattr__(
            self,
            "capabilities",
            _string_tuple(self.capabilities, "capabilities"),
        )
        object.__setattr__(
            self,
            "roles",
            _string_tuple(self.roles, "roles"),
        )


def _snapshot_execution_pin(pin: PluginExecutionPin) -> PluginExecutionPin:
    if type(pin) is not PluginExecutionPin:
        raise TypeError("pin must be PluginExecutionPin")
    return PluginExecutionPin(
        instance_id=pin.instance_id,
        plugin_id=pin.plugin_id,
        plugin_version=pin.plugin_version,
        core_api_version=pin.core_api_version,
        artifact=pin.artifact,
        configuration_digest=pin.configuration_digest,
        schema_digest=pin.schema_digest,
        schema_versions=pin.schema_versions,
        capabilities=pin.capabilities,
        roles=pin.roles,
    )


def plugin_execution_pin_dict(pin: PluginExecutionPin) -> dict[str, Any]:
    pin = _snapshot_execution_pin(pin)
    artifact = pin.artifact
    return {
        "instance_id": pin.instance_id,
        "plugin_id": pin.plugin_id,
        "plugin_version": pin.plugin_version,
        "core_api_version": pin.core_api_version,
        "artifact": {
            "distribution_name": artifact.distribution_name,
            "distribution_version": artifact.distribution_version,
            "package_hash": artifact.package_hash,
            "entry_point_name": artifact.entry_point_name,
            "module_target": artifact.module_target,
        },
        "configuration_digest": pin.configuration_digest,
        "schema_digest": pin.schema_digest,
        "schema_versions": list(pin.schema_versions),
        "capabilities": list(pin.capabilities),
        "roles": list(pin.roles),
    }


def _plan_payload(plan: PluginExecutionPlan) -> dict[str, Any]:
    return {
        "contract_version": plan.contract_version,
        "node_id": plan.node_id,
        "basis_revision_id": plan.basis_revision_id,
        "plugins": [plugin_execution_pin_dict(pin) for pin in plan.plugins],
        "decoder": (
            {
                "decoder_id": plan.decoder.decoder_id,
                "decoder_version": plan.decoder.decoder_version,
                "executable_digest": plan.decoder.executable_digest,
            }
            if plan.decoder is not None
            else None
        ),
    }


def _unchecked_plugin_execution_plan_digest(plan: PluginExecutionPlan) -> str:
    if type(plan) is not PluginExecutionPlan:
        raise TypeError("plan must be PluginExecutionPlan")
    return f"sha256:{strict_canonical_json_sha256(_plan_payload(plan))}"


@dataclass(frozen=True, slots=True)
class PluginExecutionPlan:
    """Ordered producer pins used to interpret one node revision basis."""

    node_id: str
    basis_revision_id: str
    plugins: tuple[PluginExecutionPin, ...]
    decoder: DecoderIdentity | None = None
    contract_version: str = PLUGIN_EXECUTION_PLAN_VERSION
    plan_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.contract_version) is not str:
            raise TypeError("contract_version must be an exact string")
        if self.contract_version != PLUGIN_EXECUTION_PLAN_VERSION:
            raise ValueError("unsupported plug-in execution-plan version")
        _opaque(self.node_id, "node_id")
        _opaque(self.basis_revision_id, "basis_revision_id")
        if type(self.plugins) is not tuple:
            raise TypeError("plugins must be a tuple")
        if not 1 <= len(self.plugins) <= _MAX_PLUGINS:
            raise ValueError("plugins must contain 1 to 128 pins")
        pins = tuple(_snapshot_execution_pin(pin) for pin in self.plugins)
        object.__setattr__(self, "plugins", pins)
        instance_ids = tuple(pin.instance_id for pin in self.plugins)
        if len(instance_ids) != len(set(instance_ids)):
            raise ValueError("plug-in instance IDs must be unique")
        if self.decoder is not None:
            object.__setattr__(
                self,
                "decoder",
                _snapshot_decoder_identity(self.decoder),
            )
        if type(self.plan_digest) is not str:
            raise TypeError("plan_digest must be an exact string")
        expected = _unchecked_plugin_execution_plan_digest(self)
        if self.plan_digest:
            _digest(self.plan_digest, "plan_digest")
            if self.plan_digest != expected:
                raise ValueError("plug-in execution-plan digest does not match")
        else:
            object.__setattr__(self, "plan_digest", expected)


def _snapshot_execution_plan(plan: PluginExecutionPlan) -> PluginExecutionPlan:
    if type(plan) is not PluginExecutionPlan:
        raise TypeError("plan must be PluginExecutionPlan")
    if type(plan.plan_digest) is not str or not plan.plan_digest:
        raise ValueError("plan_digest must contain the immutable plan digest")
    return PluginExecutionPlan(
        node_id=plan.node_id,
        basis_revision_id=plan.basis_revision_id,
        plugins=plan.plugins,
        decoder=plan.decoder,
        contract_version=plan.contract_version,
        plan_digest=plan.plan_digest,
    )


def snapshot_plugin_execution_plan(plan: PluginExecutionPlan) -> PluginExecutionPlan:
    """Return a detached, digest-verified copy of one immutable plan."""

    return _snapshot_execution_plan(plan)


def plugin_execution_plan_digest(plan: PluginExecutionPlan) -> str:
    return _snapshot_execution_plan(plan).plan_digest


def plugin_execution_plan_dict(plan: PluginExecutionPlan) -> dict[str, Any]:
    plan = _snapshot_execution_plan(plan)
    payload = _plan_payload(plan)
    payload["plan_digest"] = plan.plan_digest
    return payload


def _exact_mapping(value: object, label: str, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{label} must contain exactly {sorted(keys)}")
    actual_keys = tuple(value)
    if (
        any(type(key) is not str for key in actual_keys)
        or set(actual_keys) != keys
    ):
        raise ValueError(f"{label} must contain exactly {sorted(keys)}")
    return value


def plugin_execution_plan_from_dict(value: object) -> PluginExecutionPlan:
    """Strictly parse one wire projection and revalidate its content digest."""

    plan = _exact_mapping(
        value,
        "execution plan",
        {"contract_version", "node_id", "basis_revision_id", "plugins", "decoder", "plan_digest"},
    )
    _digest(plan["plan_digest"], "plan_digest")
    raw_plugins = plan["plugins"]
    if type(raw_plugins) is not list:
        raise TypeError("execution plan plugins must be a list")
    pins: list[PluginExecutionPin] = []
    pin_keys = {
        "instance_id", "plugin_id", "plugin_version", "core_api_version", "artifact",
        "configuration_digest", "schema_digest", "schema_versions", "capabilities", "roles",
    }
    artifact_keys = {
        "distribution_name", "distribution_version", "package_hash", "entry_point_name", "module_target",
    }
    for index, raw_pin in enumerate(raw_plugins):
        parsed = _exact_mapping(raw_pin, f"plugins[{index}]", pin_keys)
        artifact = _exact_mapping(parsed["artifact"], f"plugins[{index}].artifact", artifact_keys)
        pins.append(
            PluginExecutionPin(
                instance_id=parsed["instance_id"],
                plugin_id=parsed["plugin_id"],
                plugin_version=parsed["plugin_version"],
                core_api_version=parsed["core_api_version"],
                artifact=PluginArtifactIdentity(**artifact),
                configuration_digest=parsed["configuration_digest"],
                schema_digest=parsed["schema_digest"],
                schema_versions=_wire_tuple(parsed["schema_versions"], "schema_versions"),
                capabilities=_wire_tuple(parsed["capabilities"], "capabilities"),
                roles=_wire_tuple(parsed["roles"], "roles"),
            )
        )
    raw_decoder = plan["decoder"]
    decoder = None
    if raw_decoder is not None:
        decoder_map = _exact_mapping(
            raw_decoder,
            "decoder",
            {"decoder_id", "decoder_version", "executable_digest"},
        )
        decoder = DecoderIdentity(**decoder_map)
    return PluginExecutionPlan(
        contract_version=plan["contract_version"],
        node_id=plan["node_id"],
        basis_revision_id=plan["basis_revision_id"],
        plugins=tuple(pins),
        decoder=decoder,
        plan_digest=plan["plan_digest"],
    )


def _wire_tuple(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise TypeError(f"{label} must be a list")
    if any(type(item) is not str for item in value):
        raise TypeError(f"{label} must contain strings")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class RevisionExecutionPlanRef:
    node_id: str
    revision_id: str
    plan_digest: str

    def __post_init__(self) -> None:
        _opaque(self.node_id, "node_id")
        _opaque(self.revision_id, "revision_id")
        _digest(self.plan_digest, "plan_digest")


__all__ = [
    "PLUGIN_EXECUTION_PLAN_VERSION",
    "DecoderIdentity",
    "PluginArtifactIdentity",
    "PluginExecutionPin",
    "PluginExecutionPlan",
    "RevisionExecutionPlanRef",
    "plugin_execution_pin_dict",
    "plugin_execution_plan_dict",
    "plugin_execution_plan_digest",
    "plugin_execution_plan_from_dict",
    "snapshot_plugin_execution_plan",
]
