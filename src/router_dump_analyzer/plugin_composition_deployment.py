"""Trusted deployment contract for deterministic plug-in composition.

The descriptor binds the primary parser allowlist, the complete capability
provider directory, and the exact composition policy as one validated unit.
It contains no device-selection heuristics and performs no fallback routing.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .canonical import strict_canonical_json_sha256
from .capability_router import (
    CapabilityProviderRegistry,
    CapabilityRouteStaleError,
)
from .ingestion_pipeline import (
    PluginRegistry,
    RegisteredPlugin,
    _require_no_inline_only_plugin_compatibility,
)
from .plugin_composition import PluginCompositionPolicy
from .process_control import PROCESS_CONTROL_EXCEPTIONS

PLUGIN_COMPOSITION_DEPLOYMENT_VERSION: Final = (
    "router_dump_analyzer.plugin_composition_deployment.v1"
)

_PATH_TYPE: Final = type(Path())
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class PluginCompositionDeploymentLoadError(RuntimeError):
    """A trusted deployment target could not produce a valid descriptor."""


@dataclass(frozen=True, slots=True)
class PluginCompositionDeploymentContext:
    """The sole core-owned value disclosed to a deployment factory."""

    state_dir: Path

    def __post_init__(self) -> None:
        if type(self.state_dir) not in (str, _PATH_TYPE):
            raise TypeError("state_dir must be a string or platform Path")
        try:
            resolved = Path(self.state_dir).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError) as error:
            raise ValueError("state_dir could not be resolved safely") from error
        if not resolved.is_absolute():  # pragma: no cover - resolve guarantees it.
            raise ValueError("state_dir must resolve to an absolute path")
        object.__setattr__(self, "state_dir", resolved)


def _execution_coordinate(record: RegisteredPlugin) -> str:
    if type(record) is not RegisteredPlugin:
        raise TypeError("deployment registries must contain registered plug-ins")
    if (
        not record.verify_package_bytes
        or record._registered_execution_identity_snapshot is None
    ):
        raise ValueError("deployment plug-ins require executable identities")
    try:
        PluginRegistry.revalidate_registered_identity(record)
        identity = record.registered_execution_identity
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - plug-in properties are extension code.
        raise ValueError(
            "deployment plug-in executable identity is invalid"
        ) from None
    if _DIGEST.fullmatch(identity) is None:
        raise ValueError("deployment plug-in execution identity is invalid")
    return identity


def _deployment_digest(
    primary_records: tuple[RegisteredPlugin, ...],
    provider_records: tuple[RegisteredPlugin, ...],
    policy: PluginCompositionPolicy,
) -> str:
    # Registered execution identities are already content-addressed projections
    # of exact configured instances.  Hashing only those opaque coordinates
    # avoids copying plug-in objects, configuration values, or proprietary
    # labels into this deployment-level identity document.
    payload = {
        "contract_version": PLUGIN_COMPOSITION_DEPLOYMENT_VERSION,
        "primary_execution_identities": sorted(
            _execution_coordinate(record) for record in primary_records
        ),
        "provider_execution_identities": sorted(
            _execution_coordinate(record) for record in provider_records
        ),
        "policy_digest": policy.policy_digest,
    }
    return "sha256:" + strict_canonical_json_sha256(payload)


@dataclass(frozen=True, slots=True)
class PluginCompositionDeployment:
    """One validated primary/provider/policy deployment composition."""

    primary_registry: PluginRegistry
    capability_providers: CapabilityProviderRegistry
    policy: PluginCompositionPolicy
    deployment_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.primary_registry) is not PluginRegistry:
            raise TypeError("primary_registry must be an exact PluginRegistry")
        if type(self.capability_providers) is not CapabilityProviderRegistry:
            raise TypeError(
                "capability_providers must be an exact CapabilityProviderRegistry"
            )
        if type(self.policy) is not PluginCompositionPolicy:
            raise TypeError("policy must be an exact PluginCompositionPolicy")
        if type(self.deployment_digest) is not str:
            raise TypeError("deployment_digest must be an exact string")

        authority_primary_registry = self.primary_registry._sealed_snapshot()
        authority_capability_providers = (
            self.capability_providers._sealed_snapshot()
        )
        object.__setattr__(
            self,
            "primary_registry",
            authority_primary_registry,
        )
        object.__setattr__(
            self,
            "capability_providers",
            authority_capability_providers,
        )

        primary_records = authority_primary_registry.records()
        provider_records = authority_capability_providers.records()
        if not primary_records:
            raise ValueError("deployment requires at least one primary plug-in")
        _require_no_inline_only_plugin_compatibility(
            (*primary_records, *provider_records),
            boundary="plug-in composition deployment requires PROCESS-capable plug-ins",
        )

        primary_by_coordinate: dict[tuple[str, str], RegisteredPlugin] = {}
        for primary in primary_records:
            identity = _execution_coordinate(primary)
            coordinate = (primary.instance_id, identity)
            if coordinate in primary_by_coordinate:
                raise ValueError("primary execution coordinates must be unique")
            primary_by_coordinate[coordinate] = primary
            try:
                provider = authority_capability_providers.get_by_execution_identity(
                    *coordinate
                )
            except PROCESS_CONTROL_EXCEPTIONS:
                raise
            except (CapabilityRouteStaleError, TypeError, ValueError) as error:
                raise ValueError(
                    "every primary plug-in must be present in capability providers"
                ) from error
            if provider is not primary:
                raise ValueError(
                    "capability providers must contain the exact primary record"
                )

        used_primary_coordinates: set[tuple[str, str]] = set()
        for rule in self.policy.rules:
            primary_coordinate = (
                rule.primary_instance_id,
                rule.primary_registered_execution_identity,
            )
            if primary_coordinate not in primary_by_coordinate:
                raise ValueError(
                    "every composition rule must select an exact primary plug-in"
                )
            used_primary_coordinates.add(primary_coordinate)
            for selection in rule.auxiliaries:
                try:
                    authority_capability_providers.get_by_execution_identity(
                        selection.instance_id,
                        selection.registered_execution_identity,
                    )
                except PROCESS_CONTROL_EXCEPTIONS:
                    raise
                except (CapabilityRouteStaleError, TypeError, ValueError) as error:
                    raise ValueError(
                        "every auxiliary selection must resolve an exact provider"
                    ) from error
        if len(used_primary_coordinates) != len(self.policy.rules):
            raise ValueError("composition policy contains an unused rule")

        expected = _deployment_digest(primary_records, provider_records, self.policy)
        if self.deployment_digest:
            if (
                _DIGEST.fullmatch(self.deployment_digest) is None
                or self.deployment_digest != expected
            ):
                raise ValueError("plug-in composition deployment digest does not match")
        else:
            object.__setattr__(self, "deployment_digest", expected)


def _deployment_target(value: object) -> tuple[str, str]:
    if type(value) is not str:
        raise TypeError("deployment target must be a string")
    if not value or value != value.strip() or len(value) > 512:
        raise ValueError("deployment target must use 'package.module:attribute' syntax")
    module_name, separator, attribute = value.partition(":")
    if (
        not separator
        or not module_name
        or not attribute
        or ":" in attribute
        or len(module_name) > 255
        or len(attribute) > 128
        or any(not part.isidentifier() for part in module_name.split("."))
        or not attribute.isidentifier()
    ):
        raise ValueError("deployment target must use 'package.module:attribute' syntax")
    return module_name, attribute


def _detached_context(
    context: PluginCompositionDeploymentContext,
) -> PluginCompositionDeploymentContext:
    if type(context) is not PluginCompositionDeploymentContext:
        raise TypeError("context must be PluginCompositionDeploymentContext")
    return PluginCompositionDeploymentContext(state_dir=context.state_dir)


def _validated_deployment(value: object) -> PluginCompositionDeployment:
    if type(value) is not PluginCompositionDeployment:
        raise TypeError("deployment target must return PluginCompositionDeployment")
    # Reconstruct the immutable shell. Its constructor takes fresh sealed
    # registry snapshots while retaining the exact registered plug-in records.
    return PluginCompositionDeployment(
        primary_registry=value.primary_registry,
        capability_providers=value.capability_providers,
        policy=value.policy,
        deployment_digest=value.deployment_digest,
    )


def load_plugin_composition_deployment(
    target: str,
    *,
    context: PluginCompositionDeploymentContext,
) -> PluginCompositionDeployment:
    """Load an exact descriptor or call one trusted factory exactly once."""

    module_name, attribute = _deployment_target(target)
    private_context = _detached_context(context)
    try:
        module = importlib.import_module(module_name)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - trusted module initialization is code.
        raise PluginCompositionDeploymentLoadError(
            "plug-in composition deployment module could not be imported"
        ) from None
    try:
        candidate = getattr(module, attribute)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - module attributes may be dynamic.
        raise PluginCompositionDeploymentLoadError(
            "plug-in composition deployment target could not be resolved"
        ) from None

    if type(candidate) is PluginCompositionDeployment:
        produced: object = candidate
    elif callable(candidate):
        try:
            produced = candidate(private_context)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - factories are trusted process code.
            raise PluginCompositionDeploymentLoadError(
                "plug-in composition deployment factory failed"
            ) from None
    else:
        raise PluginCompositionDeploymentLoadError(
            "plug-in composition deployment target must be a descriptor or factory"
        )

    try:
        return _validated_deployment(produced)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - in-process descriptors may be tampered.
        raise PluginCompositionDeploymentLoadError(
            "plug-in composition deployment descriptor is invalid"
        ) from None


__all__ = [
    "PLUGIN_COMPOSITION_DEPLOYMENT_VERSION",
    "PluginCompositionDeployment",
    "PluginCompositionDeploymentContext",
    "PluginCompositionDeploymentLoadError",
    "load_plugin_composition_deployment",
]
