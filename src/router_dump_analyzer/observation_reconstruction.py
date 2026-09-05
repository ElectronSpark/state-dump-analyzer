"""Shared identity, ordering, and patch rules for observed revision views.

The durable JSON projection and immutable plug-in world intentionally use
different value representations. They share these domain-neutral operations
so neither can invent a different observation history or relationship key.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import replace
from hashlib import sha256
from typing import Any

from .canonical import canonical_json, opaque_value_json
from .plugin_api import (
    KeyAtom,
    PropertyPatch,
    Provenance,
    Quality,
    RelationshipCollectionObservation,
    RelationshipObservation,
    ResourceKey,
    SnapshotObservation,
    StatusPerspectiveRef,
)

type SnapshotIdentity = tuple[ResourceKey, StatusPerspectiveRef | None]
type RelationshipIdentity = tuple[
    ResourceKey, ResourceKey, str, StatusPerspectiveRef | None
]


def canonical_resource_identity(resource: ResourceKey) -> tuple[str, dict[str, Any]]:
    """Preserve the durable ASCII-escaped identity profile, including key types."""
    identity = {
        "namespace": resource.namespace,
        "node": resource.node,
        "layer": resource.layer,
        "kind": resource.kind,
        "parts": [
            {"name": name, "value": opaque_value_json(value, key_atom_type=KeyAtom)}
            for name, value in resource.parts
        ],
    }
    digest = sha256(canonical_json(identity).encode("utf-8")).hexdigest()[:32]
    return (
        f"{resource.namespace}/{resource.node}/{resource.layer}/{resource.kind}/{digest}",
        identity,
    )


def resource_order_key(resource: ResourceKey) -> tuple[str]:
    return (canonical_resource_identity(resource)[0],)


def perspective_order_key(
    perspective: StatusPerspectiveRef | None,
) -> tuple[str, str, str]:
    if perspective is None:
        return ("", "", "")
    return (
        perspective.perspective_id,
        perspective.plugin_instance_id or "",
        perspective.schema_digest or "",
    )


def bind_primary_perspective(
    perspective: StatusPerspectiveRef | None,
    *,
    plugin_instance_id: str | None,
    schema_digest: str | None,
) -> StatusPerspectiveRef | None:
    if perspective is None or plugin_instance_id is None or schema_digest is None:
        return perspective
    if perspective.plugin_instance_id not in (None, plugin_instance_id):
        raise ValueError("perspective belongs to a different plug-in instance")
    if perspective.schema_digest not in (None, schema_digest):
        raise ValueError("perspective belongs to a different schema")
    return StatusPerspectiveRef(
        perspective.perspective_id, plugin_instance_id, schema_digest
    )


def bind_observation_perspectives[
    Observation: SnapshotObservation
    | RelationshipObservation
    | RelationshipCollectionObservation
](
    observations: Iterable[Observation],
    *,
    plugin_instance_id: str | None,
    schema_digest: str | None,
) -> tuple[Observation, ...]:
    """Qualify each observation before identity grouping or JSON projection."""
    if (plugin_instance_id is None) != (schema_digest is None):
        raise ValueError("primary perspective authority requires instance and schema")
    if plugin_instance_id is None:
        return tuple(observations)
    return tuple(
        replace(
            item,
            perspective_ref=bind_primary_perspective(
                item.perspective_ref,
                plugin_instance_id=plugin_instance_id,
                schema_digest=schema_digest,
            ),
        )
        for item in observations
    )


def canonical_relationship_endpoints(
    source: ResourceKey,
    target: ResourceKey,
    relation_type: str,
    undirected_relationship_types: frozenset[str],
) -> tuple[ResourceKey, ResourceKey]:
    if relation_type in undirected_relationship_types and resource_order_key(
        target
    ) < resource_order_key(source):
        return target, source
    return source, target


def relationship_order_key(key: RelationshipIdentity) -> tuple[Any, ...]:
    return (
        resource_order_key(key[0]),
        resource_order_key(key[1]),
        key[2],
        perspective_order_key(key[3]),
    )


def _ordered_groups[Observation: SnapshotObservation | RelationshipObservation, Key](
    observations: Iterable[Observation],
    identity: Callable[[Observation], Key],
    order: Callable[[Key], Any],
) -> dict[Key, tuple[Observation, ...]]:
    grouped: dict[Key, list[Observation]] = defaultdict(list)
    for observation in observations:
        grouped[identity(observation)].append(observation)
    # Python's stable sort retains parser order for equal time/evidence keys.
    return {
        key: tuple(
            sorted(
                grouped[key],
                key=lambda item: (
                    item.observed_at_min_ns is None,
                    item.observed_at_min_ns or 0,
                    item.observed_at_max_ns is None,
                    item.observed_at_max_ns or 0,
                    item.evidence.artifact_id.bytes,
                    item.evidence.locator,
                ),
            )
        )
        for key in sorted(grouped, key=order)
    }


def snapshot_observation_groups(
    observations: Iterable[SnapshotObservation],
    *,
    plugin_instance_id: str | None = None,
    schema_digest: str | None = None,
) -> dict[SnapshotIdentity, tuple[SnapshotObservation, ...]]:
    return _ordered_groups(
        observations,
        lambda item: (
            item.resource,
            bind_primary_perspective(
                item.perspective_ref,
                plugin_instance_id=plugin_instance_id,
                schema_digest=schema_digest,
            ),
        ),
        lambda key: (resource_order_key(key[0]), perspective_order_key(key[1])),
    )


def relationship_observation_groups(
    observations: Iterable[RelationshipObservation],
    undirected_relationship_types: frozenset[str],
    *,
    plugin_instance_id: str | None = None,
    schema_digest: str | None = None,
) -> dict[RelationshipIdentity, tuple[RelationshipObservation, ...]]:
    return _ordered_groups(
        observations,
        lambda item: (
            *canonical_relationship_endpoints(
                item.source,
                item.target,
                item.relation_type,
                undirected_relationship_types,
            ),
            item.relation_type,
            bind_primary_perspective(
                item.perspective_ref,
                plugin_instance_id=plugin_instance_id,
                schema_digest=schema_digest,
            ),
        ),
        relationship_order_key,
    )


def apply_property_patch(
    properties: dict[str, Any],
    unknown_fields: dict[str, Any],
    field_quality: dict[str, Any],
    field_provenance: dict[str, Any] | None,
    patch: PropertyPatch,
    *,
    default_quality: Quality,
    default_provenance: Provenance,
    project_value: Callable[[Any], Any],
    project_unknown: Callable[[Any], Any],
    project_quality: Callable[[Quality], Any],
    project_provenance: Callable[[Provenance], Any],
) -> None:
    """Apply validated known/removed/unknown operations in either representation."""
    containers = [properties, unknown_fields, field_quality]
    if field_provenance is not None:
        containers.append(field_provenance)
    if patch.complete:
        for container in containers:
            container.clear()
    for name in patch.remove_fields:
        for container in containers:
            container.pop(name, None)
    for name, value in patch.set_values.items():
        properties[name] = project_value(value)
        unknown_fields.pop(name, None)
    for item in patch.unknown_fields:
        properties.pop(item.name, None)
        unknown_fields[item.name] = project_unknown(item)
    mentioned = {
        *patch.set_values,
        *patch.remove_fields,
        *(item.name for item in patch.unknown_fields),
    }
    for name in mentioned:
        field_quality[name] = project_quality(
            patch.field_quality.get(name, default_quality)
        )
        if field_provenance is not None:
            field_provenance[name] = project_provenance(
                patch.field_provenance.get(name, default_provenance)
            )
