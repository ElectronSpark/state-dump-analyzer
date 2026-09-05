"""Shared provider provenance fields for revision materialization records."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .capability_router import CapabilityProviderRef


def materialization_provider_projection(provider: CapabilityProviderRef) -> dict[str, Any]:
    pin = provider.pin
    return {
        "member_id": provider.member_id,
        "node_id": provider.node_id,
        "basis_revision_id": provider.basis_revision_id,
        "plan_digest": provider.plan_digest,
        "instance_id": pin.instance_id,
        "plugin_id": pin.plugin_id,
        "plugin_version": pin.plugin_version,
        "registered_execution_identity": pin.registered_execution_identity,
        "configuration_digest": pin.configuration_digest,
        "schema_digest": pin.schema_digest,
        "package_hash": pin.artifact.package_hash,
        "capability": provider.capability.value,
        "roles": list(pin.roles),
    }
