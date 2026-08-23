"""Canonical, bounded identity projection for plug-in schemas.

Ingestion and later capability execution must name the same immutable schema.
Keeping the projection here prevents the two trust boundaries from acquiring
different hashing rules while still treating every plug-in vocabulary item as
opaque data.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from hashlib import sha256
from math import isfinite
from typing import Any
from uuid import UUID

from .canonical import canonical_json
from .plugin_api import PluginSchema

_MAX_DEPTH = 16
_MAX_CONTAINER_ITEMS = 1_024
_MAX_UNITS = 4_096
_MAX_ATOM_UNITS = 65_536
_MAX_INTEGER_BITS = 4_096


class PluginSchemaIdentityError(ValueError):
    """A schema cannot be projected into its bounded immutable identity."""


def _json_value(
    value: Any,
    *,
    depth: int = 0,
    units: list[int] | None = None,
    active: set[int] | None = None,
) -> Any:
    if units is None:
        units = [0]
    if active is None:
        active = set()
    if depth > _MAX_DEPTH:
        raise PluginSchemaIdentityError("plug-in schema exceeds 16 container levels")
    units[0] += 1
    if units[0] > _MAX_UNITS:
        raise PluginSchemaIdentityError("plug-in schema exceeds 4096 value units")
    if value is None or type(value) is bool:
        return value
    if isinstance(value, Enum):
        return _json_value(value.value, depth=depth, units=units, active=active)
    if type(value) is int:
        if value.bit_length() > _MAX_INTEGER_BITS:
            raise PluginSchemaIdentityError("plug-in schema contains an oversized integer")
        return value
    if type(value) is float:
        if not isfinite(value):
            raise PluginSchemaIdentityError("plug-in schema contains a non-finite float")
        return value
    if type(value) is str:
        if len(value) > _MAX_ATOM_UNITS:
            raise PluginSchemaIdentityError("plug-in schema contains an oversized string")
        return value
    if type(value) is bytes:
        if len(value) > _MAX_ATOM_UNITS:
            raise PluginSchemaIdentityError("plug-in schema contains oversized bytes")
        return {"type": "bytes", "encoding": "hex", "value": value.hex()}
    if isinstance(value, UUID):
        return str(value)

    mapping = isinstance(value, Mapping)
    sequence = type(value) in {tuple, list}
    record = is_dataclass(value) and not isinstance(value, type)
    if not (mapping or sequence or record):
        raise PluginSchemaIdentityError(
            f"plug-in schema contains unsupported type {type(value).__name__}"
        )
    identity = id(value)
    if identity in active:
        raise PluginSchemaIdentityError("plug-in schema contains a reference cycle")
    active.add(identity)
    try:
        if mapping:
            if len(value) > _MAX_CONTAINER_ITEMS:
                raise PluginSchemaIdentityError("plug-in schema mapping exceeds 1024 items")
            if any(type(key) is not str for key in value):
                raise PluginSchemaIdentityError("plug-in schema mappings require string keys")
            return {
                key: _json_value(
                    item,
                    depth=depth + 1,
                    units=units,
                    active=active,
                )
                for key, item in value.items()
            }
        if sequence:
            if len(value) > _MAX_CONTAINER_ITEMS:
                raise PluginSchemaIdentityError("plug-in schema sequence exceeds 1024 items")
            return [
                _json_value(
                    item,
                    depth=depth + 1,
                    units=units,
                    active=active,
                )
                for item in value
            ]
        descriptors = fields(value)
        if len(descriptors) > _MAX_CONTAINER_ITEMS:
            raise PluginSchemaIdentityError("plug-in schema record exceeds 1024 fields")
        return {
            descriptor.name: _json_value(
                getattr(value, descriptor.name),
                depth=depth + 1,
                units=units,
                active=active,
            )
            for descriptor in descriptors
        }
    finally:
        active.remove(identity)


def plugin_schema_dataset(schema: PluginSchema) -> dict[str, Any]:
    """Return the normalized descriptor and schema fields used by ingestion."""

    if type(schema) is not PluginSchema:
        raise TypeError("schema must be an exact PluginSchema")
    # Project the schema as one object so the depth, container and total-value
    # budgets apply across every descriptor family rather than restarting for
    # each top-level item.
    projected = _json_value(schema)
    if type(projected) is not dict:  # pragma: no cover - exact type above
        raise PluginSchemaIdentityError("plug-in schema projection is invalid")
    resource_kinds = projected["resource_kinds"]
    relationship_types = projected["relationship_types"]
    causal_link_types = projected["causal_link_types"]
    dashboards = projected["dashboards"]
    resource_table_views = projected["resource_table_views"]
    source_record_groups = projected["source_record_groups"]
    source_record_types = projected["source_record_types"]
    record_lane_presets = projected["record_lane_presets"]
    status_perspectives = projected["status_perspectives"]
    topology_projections = projected["topology_projections"]
    connector_match_policies = projected["connector_match_policies"]
    return {
        "kind_descriptors": resource_kinds,
        "relationship_descriptors": relationship_types,
        "relationship_type_descriptors": relationship_types,
        "causal_link_descriptors": causal_link_types,
        "dashboard_descriptors": dashboards,
        "resource_table_view_descriptors": resource_table_views,
        "source_record_group_descriptors": source_record_groups,
        "source_record_descriptors": source_record_types,
        "record_lane_presets": record_lane_presets,
        "connector_match_policy_descriptors": connector_match_policies,
        "schema": {
            "semantic_owner": "plugin",
            "core_interprets_domain_types": False,
            "resource_kinds": resource_kinds,
            "relationship_types": relationship_types,
            "causal_link_types": causal_link_types,
            "dashboards": dashboards,
            "resource_table_views": resource_table_views,
            "source_record_groups": source_record_groups,
            "source_record_types": source_record_types,
            "record_lane_presets": record_lane_presets,
            "status_perspectives": status_perspectives,
            "topology_projections": topology_projections,
            "connector_match_policies": connector_match_policies,
        },
    }


def plugin_schema_digest(schema: PluginSchema) -> str:
    """Return the execution-plan digest for an exact plug-in schema."""

    payload = plugin_schema_dataset(schema)["schema"]
    return "sha256:" + sha256(canonical_json(payload).encode("utf-8")).hexdigest()


__all__ = [
    "PluginSchemaIdentityError",
    "plugin_schema_dataset",
    "plugin_schema_digest",
]
