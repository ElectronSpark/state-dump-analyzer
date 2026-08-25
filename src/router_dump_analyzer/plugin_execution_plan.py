"""Immutable, replayable plug-in execution-plan identities.

The core records *which executable interpretation* produced a node revision.
It does not persist plug-in configuration values here: only their digest is
allowed.  The ordered tuple of pins is deliberately not a synthetic plug-in;
each producer retains its own identity for later routing and provenance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from .canonical import strict_canonical_json_bytes, strict_canonical_json_sha256
from .contract_validation import bounded_string
from .plugin_composition import DEFAULT_PLUGIN_COMPOSITION_POLICY_DIGEST
from .public_text import contains_unsafe_identifier_text, has_visible_identity_anchor

PLUGIN_EXECUTION_PLAN_VERSION_V1: Final = (
    "router_dump_analyzer.plugin_execution_plan.v1"
)
PLUGIN_EXECUTION_PLAN_VERSION_V2: Final = (
    "router_dump_analyzer.plugin_execution_plan.v2"
)
PLUGIN_EXECUTION_PLAN_VERSION_V3: Final = (
    "router_dump_analyzer.plugin_execution_plan.v3"
)
PLUGIN_EXECUTION_PLAN_VERSION: Final = "router_dump_analyzer.plugin_execution_plan.v4"
_LEGACY_REGISTERED_EXECUTION_IDENTITY: Final = "sha256:" + "0" * 64
_LEGACY_COMPOSITION_POLICY_DIGEST: Final = "sha256:" + "0" * 64
_MAX_PLUGINS = 128
MAX_EXECUTION_IDENTITY_LENGTH: Final[int] = 256
MAX_PLUGIN_EXECUTION_PLAN_WIRE_BYTES: Final[int] = 512 * 1024
_OPAQUE_PATTERN = re.compile(r"^[^\s\x00-\x1f\x7f]+$")
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_PACKAGE_DIGEST_PATTERN = re.compile(
    r"^(?:(?:manifest|module|package)-sha256|sha256):[0-9a-f]{64}$"
)


class PluginExecutionPlanAuthority(StrEnum):
    """Weakest publication authority bound across one complete plan.

    ``PROCESS`` means the primary parser ran behind the child-process boundary
    and every pin was PROCESS-capable. Scheduled revision relationship
    projection and consistency materialization also run synchronously inside
    that killable ingestion child. The value does not claim that every later
    on-demand capability hook is subprocess isolated; those hooks follow their
    owning coordinator's execution policy.
    """

    LEGACY_UNRECORDED = "legacy_unrecorded"
    PROCESS = "process"
    TRUSTED_INLINE_ATTESTED = "trusted_inline_attested"
    TRUSTED_INLINE_MANIFEST = "trusted_inline_manifest"


def validate_execution_identity(
    value: object,
    label: str,
    *,
    maximum: int = MAX_EXECUTION_IDENTITY_LENGTH,
) -> str:
    """Validate one opaque identifier used by an executable revision plan."""

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


def _opaque(
    value: object,
    label: str,
    *,
    maximum: int = MAX_EXECUTION_IDENTITY_LENGTH,
) -> str:
    return validate_execution_identity(value, label, maximum=maximum)


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
    result = tuple(
        _opaque(item, f"{label}[{index}]") for index, item in enumerate(value)
    )
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
    registered_execution_identity: str = _LEGACY_REGISTERED_EXECUTION_IDENTITY
    schema_versions: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    process_bootstrap_digest: str | None = None

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
        _digest(
            self.registered_execution_identity,
            "registered_execution_identity",
        )
        if self.process_bootstrap_digest is not None:
            _digest(self.process_bootstrap_digest, "process_bootstrap_digest")
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
        registered_execution_identity=pin.registered_execution_identity,
        process_bootstrap_digest=pin.process_bootstrap_digest,
        schema_versions=pin.schema_versions,
        capabilities=pin.capabilities,
        roles=pin.roles,
    )


def snapshot_plugin_execution_pin(pin: PluginExecutionPin) -> PluginExecutionPin:
    """Return a detached, validated copy of one execution pin."""

    return _snapshot_execution_pin(pin)


def plugin_execution_pin_uses_legacy_identity(pin: PluginExecutionPin) -> bool:
    """Return whether *pin* was decoded from the retained V1 contract.

    V2-and-later plans reject the reserved all-zero identity, so skipping the
    added identity comparison for this sentinel cannot weaken their matching.
    """

    if type(pin) is not PluginExecutionPin:
        raise TypeError("pin must be an exact PluginExecutionPin")
    return pin.registered_execution_identity == _LEGACY_REGISTERED_EXECUTION_IDENTITY


def plugin_execution_plan_plugin_ids(
    plan: PluginExecutionPlan,
) -> tuple[str, ...]:
    """Return the ordered, distinct producer IDs represented by ``plan``."""

    if type(plan) is not PluginExecutionPlan:
        raise TypeError("plan must be an exact PluginExecutionPlan")
    return tuple(dict.fromkeys(pin.plugin_id for pin in plan.plugins))


def _plugin_execution_pin_payload(
    pin: PluginExecutionPin,
    *,
    include_registered_execution_identity: bool,
    include_process_bootstrap_digest: bool,
) -> dict[str, Any]:
    pin = _snapshot_execution_pin(pin)
    artifact = pin.artifact
    result: dict[str, Any] = {
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
    if include_registered_execution_identity:
        result["registered_execution_identity"] = pin.registered_execution_identity
    if include_process_bootstrap_digest:
        result["process_bootstrap_digest"] = pin.process_bootstrap_digest
    return result


def plugin_execution_pin_dict(pin: PluginExecutionPin) -> dict[str, Any]:
    return _plugin_execution_pin_payload(
        pin,
        include_registered_execution_identity=True,
        include_process_bootstrap_digest=True,
    )


def _plan_payload(plan: PluginExecutionPlan) -> dict[str, Any]:
    payload = {
        "contract_version": plan.contract_version,
        "node_id": plan.node_id,
        "basis_revision_id": plan.basis_revision_id,
        "plugins": [
            _plugin_execution_pin_payload(
                pin,
                include_registered_execution_identity=(
                    plan.contract_version != PLUGIN_EXECUTION_PLAN_VERSION_V1
                ),
                include_process_bootstrap_digest=(
                    plan.contract_version == PLUGIN_EXECUTION_PLAN_VERSION
                ),
            )
            for pin in plan.plugins
        ],
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
    if plan.contract_version != PLUGIN_EXECUTION_PLAN_VERSION_V1:
        payload["composition_policy_digest"] = plan.composition_policy_digest
    if plan.contract_version in (
        PLUGIN_EXECUTION_PLAN_VERSION_V3,
        PLUGIN_EXECUTION_PLAN_VERSION,
    ):
        payload["execution_plan_authority"] = plan.execution_plan_authority.value
    return payload


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
    composition_policy_digest: str = ""
    execution_plan_authority: PluginExecutionPlanAuthority = (
        PluginExecutionPlanAuthority.PROCESS
    )
    plan_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.contract_version) is not str:
            raise TypeError("contract_version must be an exact string")
        if self.contract_version not in (
            PLUGIN_EXECUTION_PLAN_VERSION_V1,
            PLUGIN_EXECUTION_PLAN_VERSION_V2,
            PLUGIN_EXECUTION_PLAN_VERSION_V3,
            PLUGIN_EXECUTION_PLAN_VERSION,
        ):
            raise ValueError("unsupported plug-in execution-plan version")
        if type(self.execution_plan_authority) is not PluginExecutionPlanAuthority:
            raise TypeError(
                "execution_plan_authority must be an exact PluginExecutionPlanAuthority"
            )
        if self.contract_version not in (
            PLUGIN_EXECUTION_PLAN_VERSION_V3,
            PLUGIN_EXECUTION_PLAN_VERSION,
        ):
            if self.execution_plan_authority not in (
                PluginExecutionPlanAuthority.PROCESS,
                PluginExecutionPlanAuthority.LEGACY_UNRECORDED,
            ):
                raise ValueError(
                    "legacy plug-in execution plans cannot carry trusted-inline "
                    "ingestion authority"
                )
            object.__setattr__(
                self,
                "execution_plan_authority",
                PluginExecutionPlanAuthority.LEGACY_UNRECORDED,
            )
        elif (
            self.execution_plan_authority
            is PluginExecutionPlanAuthority.LEGACY_UNRECORDED
        ):
            raise ValueError(
                "v3-v4 plug-in execution plans require recorded plan authority"
            )
        if type(self.composition_policy_digest) is not str:
            raise TypeError("composition_policy_digest must be an exact string")
        if self.contract_version == PLUGIN_EXECUTION_PLAN_VERSION_V1:
            if self.composition_policy_digest not in (
                "",
                _LEGACY_COMPOSITION_POLICY_DIGEST,
            ):
                raise ValueError(
                    "v1 plug-in execution plans cannot carry a composition "
                    "policy digest"
                )
            object.__setattr__(
                self,
                "composition_policy_digest",
                _LEGACY_COMPOSITION_POLICY_DIGEST,
            )
        else:
            selected_policy_digest = (
                DEFAULT_PLUGIN_COMPOSITION_POLICY_DIGEST
                if self.composition_policy_digest == ""
                else self.composition_policy_digest
            )
            _digest(selected_policy_digest, "composition_policy_digest")
            if selected_policy_digest == _LEGACY_COMPOSITION_POLICY_DIGEST:
                raise ValueError(
                    "current plug-in execution plans require a non-legacy "
                    "composition policy digest"
                )
            object.__setattr__(
                self,
                "composition_policy_digest",
                selected_policy_digest,
            )
        _opaque(self.node_id, "node_id")
        _opaque(self.basis_revision_id, "basis_revision_id")
        if type(self.plugins) is not tuple:
            raise TypeError("plugins must be a tuple")
        if not 1 <= len(self.plugins) <= _MAX_PLUGINS:
            raise ValueError("plugins must contain 1 to 128 pins")
        pins = tuple(_snapshot_execution_pin(pin) for pin in self.plugins)
        object.__setattr__(self, "plugins", pins)
        if self.contract_version != PLUGIN_EXECUTION_PLAN_VERSION_V1 and any(
            pin.registered_execution_identity == _LEGACY_REGISTERED_EXECUTION_IDENTITY
            for pin in pins
        ):
            raise ValueError(
                "executable plug-in execution pins require registered execution "
                "identities"
            )
        if self.contract_version == PLUGIN_EXECUTION_PLAN_VERSION_V1 and any(
            pin.registered_execution_identity != _LEGACY_REGISTERED_EXECUTION_IDENTITY
            for pin in pins
        ):
            raise ValueError(
                "v1 plug-in execution pins cannot carry registered execution identities"
            )
        instance_ids = tuple(pin.instance_id for pin in self.plugins)
        if len(instance_ids) != len(set(instance_ids)):
            raise ValueError("plug-in instance IDs must be unique")
        if sum("primary_parser" in pin.roles for pin in self.plugins) != 1:
            raise ValueError(
                "plug-in execution plan must contain exactly one primary_parser pin"
            )
        if self.contract_version in (
            PLUGIN_EXECUTION_PLAN_VERSION_V3,
            PLUGIN_EXECUTION_PLAN_VERSION,
        ):
            contains_manifest_identity = any(
                pin.artifact.package_hash.startswith("manifest-sha256:")
                for pin in self.plugins
            )
            if contains_manifest_identity != (
                self.execution_plan_authority
                is PluginExecutionPlanAuthority.TRUSTED_INLINE_MANIFEST
            ):
                raise ValueError(
                    "current plug-in execution-plan authority contradicts its "
                    "artifact identities"
                )
        if self.contract_version == PLUGIN_EXECUTION_PLAN_VERSION:
            process_plan = (
                self.execution_plan_authority is PluginExecutionPlanAuthority.PROCESS
            )
            if any(
                (pin.process_bootstrap_digest is not None) != process_plan
                for pin in pins
            ):
                raise ValueError(
                    "v4 PROCESS plans require one process bootstrap digest per pin, "
                    "and trusted-inline plans forbid them"
                )
        elif any(pin.process_bootstrap_digest is not None for pin in pins):
            raise ValueError(
                "v1-v3 plug-in execution plans cannot carry process bootstrap digests"
            )
        if self.decoder is not None:
            object.__setattr__(
                self,
                "decoder",
                _snapshot_decoder_identity(self.decoder),
            )
        if (
            len(strict_canonical_json_bytes(_plan_payload(self)))
            > MAX_PLUGIN_EXECUTION_PLAN_WIRE_BYTES
        ):
            raise ValueError(
                "plug-in execution plan exceeds the canonical wire-size limit"
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
        composition_policy_digest=plan.composition_policy_digest,
        execution_plan_authority=plan.execution_plan_authority,
        plan_digest=plan.plan_digest,
    )


def snapshot_plugin_execution_plan(plan: PluginExecutionPlan) -> PluginExecutionPlan:
    """Return a detached, digest-verified copy of one immutable plan."""

    return _snapshot_execution_plan(plan)


def plugin_execution_plan_is_executable(plan: PluginExecutionPlan) -> bool:
    """Return whether *plan* carries the current executable identity contract.

    Retained V1 plans remain valid passive catalog values, but they predate
    both registered execution identities and composition-policy binding.  No
    live provider or private evidence producer may be selected from them.
    """

    detached = _snapshot_execution_plan(plan)
    return detached.contract_version in (
        PLUGIN_EXECUTION_PLAN_VERSION_V2,
        PLUGIN_EXECUTION_PLAN_VERSION_V3,
        PLUGIN_EXECUTION_PLAN_VERSION,
    )


def plugin_execution_plan_digest(plan: PluginExecutionPlan) -> str:
    return _snapshot_execution_plan(plan).plan_digest


def primary_parser_execution_pin(
    plan: PluginExecutionPlan,
) -> PluginExecutionPin:
    """Return the unique plan pin assigned the core ``primary_parser`` role."""

    detached = _snapshot_execution_plan(plan)
    matches = tuple(pin for pin in detached.plugins if "primary_parser" in pin.roles)
    if len(matches) != 1:
        raise ValueError(
            "plug-in execution plan must contain exactly one primary_parser pin"
        )
    return _snapshot_execution_pin(matches[0])


def plugin_execution_plan_dict(plan: PluginExecutionPlan) -> dict[str, Any]:
    plan = _snapshot_execution_plan(plan)
    payload = _plan_payload(plan)
    payload["plan_digest"] = plan.plan_digest
    return payload


def _exact_mapping(value: object, label: str, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{label} must contain exactly {sorted(keys)}")
    actual_keys = tuple(value)
    if any(type(key) is not str for key in actual_keys) or set(actual_keys) != keys:
        raise ValueError(f"{label} must contain exactly {sorted(keys)}")
    return value


def plugin_execution_plan_from_dict(value: object) -> PluginExecutionPlan:
    """Strictly parse one wire projection and revalidate its content digest."""

    if type(value) is not dict:
        raise ValueError("execution plan must contain an exact object")
    contract_version = value.get("contract_version")
    if contract_version not in (
        PLUGIN_EXECUTION_PLAN_VERSION_V1,
        PLUGIN_EXECUTION_PLAN_VERSION_V2,
        PLUGIN_EXECUTION_PLAN_VERSION_V3,
        PLUGIN_EXECUTION_PLAN_VERSION,
    ):
        raise ValueError("unsupported plug-in execution-plan version")
    plan_keys = {
        "contract_version",
        "node_id",
        "basis_revision_id",
        "plugins",
        "decoder",
        "plan_digest",
    }
    if contract_version != PLUGIN_EXECUTION_PLAN_VERSION_V1:
        plan_keys.add("composition_policy_digest")
    if contract_version in (
        PLUGIN_EXECUTION_PLAN_VERSION_V3,
        PLUGIN_EXECUTION_PLAN_VERSION,
    ):
        plan_keys.add("execution_plan_authority")
    plan = _exact_mapping(value, "execution plan", plan_keys)
    _digest(plan["plan_digest"], "plan_digest")
    raw_plugins = plan["plugins"]
    if type(raw_plugins) is not list:
        raise TypeError("execution plan plugins must be a list")
    pins: list[PluginExecutionPin] = []
    pin_keys = {
        "instance_id",
        "plugin_id",
        "plugin_version",
        "core_api_version",
        "artifact",
        "configuration_digest",
        "schema_digest",
        "schema_versions",
        "capabilities",
        "roles",
    }
    if contract_version != PLUGIN_EXECUTION_PLAN_VERSION_V1:
        pin_keys.add("registered_execution_identity")
    if contract_version == PLUGIN_EXECUTION_PLAN_VERSION:
        pin_keys.add("process_bootstrap_digest")
    artifact_keys = {
        "distribution_name",
        "distribution_version",
        "package_hash",
        "entry_point_name",
        "module_target",
    }
    for index, raw_pin in enumerate(raw_plugins):
        parsed = _exact_mapping(raw_pin, f"plugins[{index}]", pin_keys)
        artifact = _exact_mapping(
            parsed["artifact"], f"plugins[{index}].artifact", artifact_keys
        )
        pins.append(
            PluginExecutionPin(
                instance_id=parsed["instance_id"],
                plugin_id=parsed["plugin_id"],
                plugin_version=parsed["plugin_version"],
                core_api_version=parsed["core_api_version"],
                artifact=PluginArtifactIdentity(**artifact),
                configuration_digest=parsed["configuration_digest"],
                schema_digest=parsed["schema_digest"],
                registered_execution_identity=(
                    parsed["registered_execution_identity"]
                    if contract_version != PLUGIN_EXECUTION_PLAN_VERSION_V1
                    else _LEGACY_REGISTERED_EXECUTION_IDENTITY
                ),
                process_bootstrap_digest=(
                    parsed["process_bootstrap_digest"]
                    if contract_version == PLUGIN_EXECUTION_PLAN_VERSION
                    else None
                ),
                schema_versions=_wire_tuple(
                    parsed["schema_versions"], "schema_versions"
                ),
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
        contract_version=contract_version,
        node_id=plan["node_id"],
        basis_revision_id=plan["basis_revision_id"],
        plugins=tuple(pins),
        decoder=decoder,
        composition_policy_digest=(
            plan["composition_policy_digest"]
            if contract_version != PLUGIN_EXECUTION_PLAN_VERSION_V1
            else _LEGACY_COMPOSITION_POLICY_DIGEST
        ),
        execution_plan_authority=(
            PluginExecutionPlanAuthority(plan["execution_plan_authority"])
            if contract_version
            in (
                PLUGIN_EXECUTION_PLAN_VERSION_V3,
                PLUGIN_EXECUTION_PLAN_VERSION,
            )
            else PluginExecutionPlanAuthority.LEGACY_UNRECORDED
        ),
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
    "MAX_EXECUTION_IDENTITY_LENGTH",
    "MAX_PLUGIN_EXECUTION_PLAN_WIRE_BYTES",
    "PLUGIN_EXECUTION_PLAN_VERSION",
    "PLUGIN_EXECUTION_PLAN_VERSION_V1",
    "PLUGIN_EXECUTION_PLAN_VERSION_V2",
    "PLUGIN_EXECUTION_PLAN_VERSION_V3",
    "DecoderIdentity",
    "PluginArtifactIdentity",
    "PluginExecutionPin",
    "PluginExecutionPlan",
    "PluginExecutionPlanAuthority",
    "RevisionExecutionPlanRef",
    "plugin_execution_pin_dict",
    "plugin_execution_pin_uses_legacy_identity",
    "plugin_execution_plan_dict",
    "plugin_execution_plan_digest",
    "plugin_execution_plan_from_dict",
    "plugin_execution_plan_is_executable",
    "plugin_execution_plan_plugin_ids",
    "primary_parser_execution_pin",
    "snapshot_plugin_execution_pin",
    "snapshot_plugin_execution_plan",
]
