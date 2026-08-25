"""Plan-bound materialization of revision-scoped relationship declarations.

The input world is an immutable *base* revision world.  Every selected
projector reads that same world; declarations produced in this phase are not
visible to any peer projector.  The result is therefore independent of
provider execution order and can be used to construct the augmented world on
which the later consistency phase runs.
"""

from __future__ import annotations

import json
from base64 import b64decode
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum, StrEnum
from hashlib import sha256
from math import isfinite
from types import MappingProxyType
from typing import Any, Final, cast
from uuid import UUID

from .canonical import (
    normalized_opaque_value_json,
    strict_canonical_json,
    strict_canonical_json_bytes,
)
from .capability_executor import PluginCapabilityOutputError
from .capability_router import (
    CapabilityProviderRef,
    CapabilityRouteSelector,
    PlanBoundCapabilityRouter,
)
from .consistency_materialization import (
    ConsistencyMaterializationError,
    ConsistencyMaterializationLimits,
    validate_materialized_consistency_basis,
)
from .plugin_api import (
    MAX_DIAGNOSTIC_CODE_LENGTH,
    MAX_DIAGNOSTIC_MESSAGE_LENGTH,
    MAX_TIMESTAMP_NS,
    MIN_TIMESTAMP_NS,
    DiagnosticOrigin,
    DiagnosticSeverity,
    DiagnosticStage,
    Evidence,
    KeyAtom,
    PluginCapability,
    PluginDiagnostic,
    PluginSchema,
    PropertyPatch,
    Provenance,
    Quality,
    ReadOnlyWorld,
    RelationDirection,
    RelationshipDeclaration,
    RelationshipView,
    ResourceKey,
    ResourceStateView,
    StatusPerspectiveRef,
    UnknownField,
    WorldBasis,
)
from .plugin_composition import REVISION_RELATIONSHIP_PROJECTION_ROLE
from .plugin_execution_plan import (
    PluginExecutionPin,
    PluginExecutionPlan,
    primary_parser_execution_pin,
    snapshot_plugin_execution_plan,
)
from .plugin_schema_identity import plugin_schema_digest
from .process_control import PROCESS_CONTROL_EXCEPTIONS
from .revision_world import _canonical_resource_identity
from .value_core import parse_canonical_decimal_integer

RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION: Final[str] = (
    "router_dump_analyzer.relationship_projection_materialization.v1"
)
_JSON_SAFE_INTEGER_MAX: Final[int] = (1 << 53) - 1
_PROPERTY_VALUE_MAX_DEPTH: Final[int] = 16
_PROPERTY_VALUE_MAX_UNITS: Final[int] = 4_096
_PROPERTY_VALUE_MAX_ITEMS: Final[int] = 1_024
_PROPERTY_VALUE_MAX_ATOM_UNITS: Final[int] = 65_536
_PROPERTY_VALUE_MAX_INTEGER_BITS: Final[int] = 4_096


class RelationshipProjectionMaterializationError(RuntimeError):
    """A selected relationship projector could not be materialized safely."""


class RelationshipProjectionMaterializationStatus(StrEnum):
    COMPLETE = "complete"
    NOT_APPLICABLE = "not_applicable"


class _RelationshipProjectionScope(StrEnum):
    REVISION = "revision"


class _RelationshipProjectionPropertyContainerType(StrEnum):
    MAPPING = "mapping"


@dataclass(frozen=True, slots=True)
class RelationshipProjectionMaterializationLimits:
    """Revision-wide limits, charged before duplicate elimination."""

    max_providers: int = 32
    max_declarations: int = 10_000
    max_diagnostics: int = 2_000
    max_evidence_references: int = 100_000
    max_world_reads: int = 200_000
    max_base_resources: int = 100_000
    max_artifact_ids: int = 100_000
    max_serialized_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        for name in (
            "max_providers",
            "max_declarations",
            "max_diagnostics",
            "max_evidence_references",
            "max_world_reads",
            "max_base_resources",
            "max_artifact_ids",
            "max_serialized_bytes",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 1_000_000_000:
                raise ValueError(
                    f"{name} must be an integer between 1 and 1000000000"
                )


def _digest(payload: object) -> str:
    return "sha256:" + sha256(strict_canonical_json_bytes(payload)).hexdigest()


def _resource_projection(resource: ResourceKey) -> dict[str, Any]:
    if type(resource) is not ResourceKey:
        raise TypeError("relationship endpoint must be an exact ResourceKey")
    resource_id, typed = _canonical_resource_identity(resource)
    return {"resource_id": resource_id, "typed_resource_key": typed}


def _evidence_projection(
    evidence: Evidence,
    *,
    artifact_ids: frozenset[UUID],
) -> dict[str, Any]:
    if type(evidence) is not Evidence:
        raise TypeError("relationship evidence must contain exact Evidence values")
    if type(evidence.artifact_id) is not UUID or evidence.artifact_id not in artifact_ids:
        raise ValueError("relationship evidence is outside the revision inventory")
    if type(evidence.locator) is not str or not evidence.locator or len(evidence.locator) > 4_096 or "\x00" in evidence.locator:
        raise ValueError("relationship evidence locator is invalid")
    if evidence.raw_timestamp_ns is not None and (
        type(evidence.raw_timestamp_ns) is not int
        or not MIN_TIMESTAMP_NS
        <= evidence.raw_timestamp_ns
        <= MAX_TIMESTAMP_NS
    ):
        raise ValueError("relationship evidence timestamp is invalid")
    if evidence.clock_domain is not None and (
        type(evidence.clock_domain) is not str
        or not evidence.clock_domain
        or len(evidence.clock_domain) > 256
        or "\x00" in evidence.clock_domain
    ):
        raise ValueError("relationship evidence clock domain is invalid")
    excerpt = evidence.excerpt_sha256
    if excerpt is not None and (
        type(excerpt) is not str
        or len(excerpt) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in excerpt)
    ):
        raise ValueError("relationship evidence digest is invalid")
    return {
        "artifact_id": str(evidence.artifact_id),
        "locator": evidence.locator,
        "raw_timestamp_ns": (
            str(evidence.raw_timestamp_ns)
            if evidence.raw_timestamp_ns is not None
            else None
        ),
        "clock_domain": evidence.clock_domain,
        "excerpt_sha256": excerpt.lower() if excerpt is not None else None,
    }


def _property_value_projection(
    value: Any,
    *,
    label: str,
    depth: int = 0,
    units: list[int] | None = None,
    active: set[int] | None = None,
) -> dict[str, Any]:
    """Encode one general Property value without matcher-key restrictions.

    Property values support substantially deeper and larger containers than
    opaque resource-key atoms.  A separate tagged transport keeps scalar
    types exact while representing mapping keys as real JSON object keys; the
    latter lets the browser projection redact declared nested property paths
    without interpreting plug-in values.
    """

    current_units = units if units is not None else [0]
    current_active = active if active is not None else set()
    current_units[0] += 1
    if current_units[0] > _PROPERTY_VALUE_MAX_UNITS:
        raise RelationshipProjectionMaterializationError(
            f"{label} exceeds {_PROPERTY_VALUE_MAX_UNITS} value units"
        )
    if depth > _PROPERTY_VALUE_MAX_DEPTH:
        raise RelationshipProjectionMaterializationError(
            f"{label} exceeds {_PROPERTY_VALUE_MAX_DEPTH} container levels"
        )
    value_type = type(value)
    if value is None:
        return {"type": "null", "value": None}
    if value_type is bool:
        return {"type": "boolean", "value": value}
    if value_type is int:
        if value.bit_length() > _PROPERTY_VALUE_MAX_INTEGER_BITS:
            raise RelationshipProjectionMaterializationError(
                f"{label} contains an oversized integer"
            )
        return {"type": "integer", "value": str(value)}
    if value_type is float:
        if not isfinite(value):
            raise RelationshipProjectionMaterializationError(
                f"{label} contains a non-finite number"
            )
        return {
            "type": "number",
            "encoding": "python-float-hex",
            "value": value.hex(),
        }
    if value_type is str:
        if len(value) > _PROPERTY_VALUE_MAX_ATOM_UNITS:
            raise RelationshipProjectionMaterializationError(
                f"{label} contains oversized text"
            )
        return {"type": "string", "value": value}
    if value_type is bytes:
        if len(value) > _PROPERTY_VALUE_MAX_ATOM_UNITS:
            raise RelationshipProjectionMaterializationError(
                f"{label} contains oversized bytes"
            )
        return {"type": "bytes", "encoding": "hex", "value": value.hex()}
    if value_type is UUID:
        return {"type": "uuid", "encoding": "rfc4122", "value": str(value)}
    if value_type is tuple or isinstance(value, Mapping):
        if len(value) > _PROPERTY_VALUE_MAX_ITEMS:
            raise RelationshipProjectionMaterializationError(
                f"{label} contains too many items"
            )
        identity = id(value)
        if identity in current_active:
            raise RelationshipProjectionMaterializationError(
                f"{label} contains a reference cycle"
            )
        current_active.add(identity)
        try:
            if value_type is tuple:
                return {
                    "type": "tuple",
                    "items": [
                        _property_value_projection(
                            item,
                            label=label,
                            depth=depth + 1,
                            units=current_units,
                            active=current_active,
                        )
                        for item in value
                    ],
                }
            entries: dict[str, dict[str, Any]] = {}
            for key, item in value.items():
                if (
                    type(key) is not str
                    or not key
                    or len(key) > 256
                    or "\x00" in key
                ):
                    raise RelationshipProjectionMaterializationError(
                        f"{label} mappings require bounded non-empty string keys"
                    )
                entries[key] = _property_value_projection(
                    item,
                    label=label,
                    depth=depth + 1,
                    units=current_units,
                    active=current_active,
                )
            return {"type": "mapping", "entries": dict(sorted(entries.items()))}
        finally:
            current_active.remove(identity)
    raise RelationshipProjectionMaterializationError(
        f"{label} contains an unsupported property value"
    )


def _validate_property_value_projection(
    value: object,
    *,
    label: str,
    depth: int = 0,
    units: list[int] | None = None,
) -> dict[str, Any]:
    """Validate one already-tagged general Property transport value."""

    current_units = units if units is not None else [0]
    current_units[0] += 1
    if current_units[0] > _PROPERTY_VALUE_MAX_UNITS:
        raise ValueError(f"{label} exceeds the property value-unit limit")
    if depth > _PROPERTY_VALUE_MAX_DEPTH:
        raise ValueError(f"{label} exceeds the property container-depth limit")
    if type(value) is not dict or type(value.get("type")) is not str:
        raise ValueError(f"{label} is not a tagged property value")
    value_type = value["type"]
    if value_type == "null":
        record = _exact_dict(value, frozenset({"type", "value"}), label)
        if record["value"] is not None:
            raise ValueError(f"{label} null payload is invalid")
        return record
    if value_type == "boolean":
        record = _exact_dict(value, frozenset({"type", "value"}), label)
        if type(record["value"]) is not bool:
            raise ValueError(f"{label} boolean payload is invalid")
        return record
    if value_type == "integer":
        record = _exact_dict(value, frozenset({"type", "value"}), label)
        payload = record["value"]
        if type(payload) is not str:
            raise ValueError(f"{label} integer payload is invalid")
        try:
            parse_canonical_decimal_integer(
                payload,
                label,
                max_bits=_PROPERTY_VALUE_MAX_INTEGER_BITS,
            )
        except ValueError as error:
            raise ValueError(f"{label} integer payload is invalid") from error
        return record
    if value_type == "number":
        record = _exact_dict(
            value, frozenset({"type", "encoding", "value"}), label
        )
        if record["encoding"] != "python-float-hex" or type(record["value"]) is not str:
            raise ValueError(f"{label} number payload is invalid")
        try:
            parsed_number = float.fromhex(record["value"])
        except (OverflowError, ValueError) as error:
            raise ValueError(f"{label} number payload is invalid") from error
        if not isfinite(parsed_number) or parsed_number.hex() != record["value"]:
            raise ValueError(f"{label} number payload is not canonical")
        return record
    if value_type == "string":
        record = _exact_dict(value, frozenset({"type", "value"}), label)
        if (
            type(record["value"]) is not str
            or len(record["value"]) > _PROPERTY_VALUE_MAX_ATOM_UNITS
        ):
            raise ValueError(f"{label} string payload is invalid")
        return record
    if value_type == "bytes":
        record = _exact_dict(
            value, frozenset({"type", "encoding", "value"}), label
        )
        payload = record["value"]
        if (
            record["encoding"] != "hex"
            or type(payload) is not str
            or len(payload) > _PROPERTY_VALUE_MAX_ATOM_UNITS * 2
            or len(payload) % 2
            or any(character not in "0123456789abcdef" for character in payload)
        ):
            raise ValueError(f"{label} byte payload is invalid")
        try:
            bytes.fromhex(payload)
        except ValueError as error:
            raise ValueError(f"{label} byte payload is invalid") from error
        if payload != payload.lower():
            raise ValueError(f"{label} byte payload is not canonical")
        return record
    if value_type == "uuid":
        record = _exact_dict(
            value, frozenset({"type", "encoding", "value"}), label
        )
        if record["encoding"] != "rfc4122" or type(record["value"]) is not str:
            raise ValueError(f"{label} UUID payload is invalid")
        try:
            identifier = UUID(record["value"])
        except (AttributeError, ValueError) as error:
            raise ValueError(f"{label} UUID payload is invalid") from error
        if str(identifier) != record["value"]:
            raise ValueError(f"{label} UUID payload is not canonical")
        return record
    if value_type == "tuple":
        record = _exact_dict(value, frozenset({"type", "items"}), label)
        items = record["items"]
        if type(items) is not list or len(items) > _PROPERTY_VALUE_MAX_ITEMS:
            raise ValueError(f"{label} tuple payload is invalid")
        for index, item in enumerate(items):
            _validate_property_value_projection(
                item,
                label=f"{label}.items[{index}]",
                depth=depth + 1,
                units=current_units,
            )
        return record
    if value_type == "mapping":
        record = _exact_dict(value, frozenset({"type", "entries"}), label)
        entries = record["entries"]
        if type(entries) is not dict or len(entries) > _PROPERTY_VALUE_MAX_ITEMS:
            raise ValueError(f"{label} mapping payload is invalid")
        for key, item in entries.items():
            if (
                type(key) is not str
                or not key
                or len(key) > 256
                or "\x00" in key
            ):
                raise ValueError(f"{label} mapping key is invalid")
            _validate_property_value_projection(
                item,
                label=f"{label}.entries[{key!r}]",
                depth=depth + 1,
                units=current_units,
            )
        return record
    raise ValueError(f"{label} has an unsupported property value tag")


def _unknown_projection(
    value: UnknownField,
    *,
    artifact_ids: frozenset[UUID],
) -> dict[str, Any]:
    if type(value) is not UnknownField:
        raise TypeError("relationship unknown fields must be exact UnknownField values")
    return {
        "name": value.name,
        "reason_code": value.reason_code,
        "message": value.message,
        "evidence": sorted(
            (
                _evidence_projection(item, artifact_ids=artifact_ids)
                for item in value.evidence
            ),
            key=strict_canonical_json,
        ),
    }


def _patch_projection(
    patch: PropertyPatch,
    *,
    artifact_ids: frozenset[UUID],
) -> dict[str, Any]:
    if type(patch) is not PropertyPatch:
        raise TypeError("relationship attributes must be an exact PropertyPatch")
    value_units = [1]
    return {
        "set_values": {
            name: _property_value_projection(
                value,
                label="relationship attribute values",
                depth=1,
                units=value_units,
            )
            for name, value in sorted(patch.set_values.items())
        },
        "remove_fields": list(patch.remove_fields),
        "unknown_fields": sorted(
            (
                _unknown_projection(item, artifact_ids=artifact_ids)
                for item in patch.unknown_fields
            ),
            key=strict_canonical_json,
        ),
        "field_quality": {
            name: value.value for name, value in sorted(patch.field_quality.items())
        },
        "field_provenance": {
            name: value.value
            for name, value in sorted(patch.field_provenance.items())
        },
        "complete": patch.complete,
    }


def _contract_projection(
    value: object,
    *,
    artifact_ids: frozenset[UUID],
    depth: int = 0,
    units: list[int] | None = None,
) -> Any:
    """Boundedly project a core-owned contract record for basis identity."""

    current_units = [0] if units is None else units
    current_units[0] += 1
    if depth > 24 or current_units[0] > 2_000_000:
        raise RelationshipProjectionMaterializationError(
            "revision world basis exceeds the projection budget"
        )
    if value is None or type(value) in (str, bool):
        return value
    if type(value) is int:
        return str(value)
    if type(value) is bytes:
        return {"type": "bytes", "hex": value.hex()}
    if type(value) is UUID:
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if type(value) is Evidence:
        return _evidence_projection(value, artifact_ids=artifact_ids)
    if isinstance(value, Mapping):
        if len(value) > 100_000 or any(type(key) is not str for key in value):
            raise RelationshipProjectionMaterializationError(
                "revision world basis contains an invalid mapping"
            )
        return {
            key: _contract_projection(
                item,
                artifact_ids=artifact_ids,
                depth=depth + 1,
                units=current_units,
            )
            for key, item in sorted(value.items())
        }
    if type(value) in (tuple, list):
        sequence = cast(Collection[Any], value)
        if len(sequence) > 100_000:
            raise RelationshipProjectionMaterializationError(
                "revision world basis contains an oversized sequence"
            )
        return [
            _contract_projection(
                item,
                artifact_ids=artifact_ids,
                depth=depth + 1,
                units=current_units,
            )
            for item in sequence
        ]
    if is_dataclass(value) and not isinstance(value, type):
        return {
            descriptor.name: _contract_projection(
                getattr(value, descriptor.name),
                artifact_ids=artifact_ids,
                depth=depth + 1,
                units=current_units,
            )
            for descriptor in fields(value)
        }
    raise RelationshipProjectionMaterializationError(
        "revision world basis contains an unsupported value"
    )


def _provider_projection(provider: CapabilityProviderRef) -> dict[str, Any]:
    pin = provider.pin
    return {
        "catalog_revision_id": provider.catalog_revision_id,
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


_PROVIDER_FIELDS = frozenset(
    {
        "catalog_revision_id",
        "member_id",
        "node_id",
        "basis_revision_id",
        "plan_digest",
        "instance_id",
        "plugin_id",
        "plugin_version",
        "registered_execution_identity",
        "configuration_digest",
        "schema_digest",
        "package_hash",
        "capability",
        "roles",
    }
)


def _exact_dict(value: object, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != expected:
        raise ValueError(f"{label} must contain its exact canonical fields")
    return value


def _provider_from_projection(
    value: object,
    *,
    plan: PluginExecutionPlan,
    label: str,
) -> CapabilityProviderRef:
    record = _exact_dict(value, _PROVIDER_FIELDS, label)
    matches = tuple(pin for pin in plan.plugins if pin.instance_id == record["instance_id"])
    if len(matches) != 1:
        raise ValueError(f"{label} does not identify one plan pin")
    provider = CapabilityProviderRef(
        catalog_revision_id=record["catalog_revision_id"],
        member_id=record["member_id"],
        node_id=record["node_id"],
        basis_revision_id=record["basis_revision_id"],
        plan_digest=record["plan_digest"],
        capability=PluginCapability.RELATIONSHIP_PROJECTION,
        pin=matches[0],
    )
    if _provider_projection(provider) != record:
        raise ValueError(f"{label} does not match its plan-bound provider")
    return provider


def _decode_key_value(value: object) -> Any:
    normalized = normalized_opaque_value_json(value)
    value_type = normalized["type"]
    if value_type == "integer":
        return int(normalized["value"], 10)
    if value_type == "string":
        return normalized["value"]
    if value_type == "bytes":
        return b64decode(normalized["value"], validate=True)
    if value_type == "uuid":
        return UUID(normalized["value"])
    if value_type == "tuple":
        return tuple(_decode_key_value(item) for item in normalized["items"])
    if value_type == "key_atom":
        return KeyAtom(normalized["type_tag"], _decode_key_value(normalized["value"]))
    raise ValueError("typed resource key contains a non-KeyValue value")


def _resource_from_projection(value: object, label: str) -> ResourceKey:
    record = _exact_dict(
        value, frozenset({"resource_id", "typed_resource_key"}), label
    )
    identity = _exact_dict(
        record["typed_resource_key"],
        frozenset({"namespace", "node", "layer", "kind", "parts"}),
        f"{label}.typed_resource_key",
    )
    parts = identity["parts"]
    if type(parts) is not list or not 1 <= len(parts) <= 32:
        raise ValueError(f"{label}.typed_resource_key.parts is invalid")
    decoded: list[tuple[str, Any]] = []
    names: set[str] = set()
    for item in parts:
        part = _exact_dict(item, frozenset({"name", "value"}), f"{label}.part")
        name = part["name"]
        if type(name) is not str or not name or name in names:
            raise ValueError(f"{label}.typed_resource_key part is invalid")
        names.add(name)
        decoded.append((name, _decode_key_value(part["value"])))
    resource = ResourceKey(
        namespace=identity["namespace"],
        node=identity["node"],
        layer=identity["layer"],
        kind=identity["kind"],
        parts=tuple(decoded),
    )
    if _resource_projection(resource) != record:
        raise ValueError(f"{label} is not canonical")
    return resource


def _evidence_from_projection(
    value: object,
    *,
    artifact_ids: frozenset[UUID],
    label: str,
) -> Evidence:
    record = _exact_dict(
        value,
        frozenset(
            {
                "artifact_id",
                "locator",
                "raw_timestamp_ns",
                "clock_domain",
                "excerpt_sha256",
            }
        ),
        label,
    )
    artifact_text = record["artifact_id"]
    if type(artifact_text) is not str:
        raise ValueError(f"{label}.artifact_id must be a canonical UUID string")
    try:
        artifact_id = UUID(artifact_text)
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(
            f"{label}.artifact_id must be a canonical UUID string"
        ) from error
    raw_timestamp = record["raw_timestamp_ns"]
    if raw_timestamp is not None:
        if type(raw_timestamp) is not str:
            raise ValueError(f"{label}.raw_timestamp_ns is not canonical")
        try:
            raw_timestamp = parse_canonical_decimal_integer(
                raw_timestamp,
                f"{label}.raw_timestamp_ns",
                minimum=MIN_TIMESTAMP_NS,
                maximum=MAX_TIMESTAMP_NS,
            )
        except ValueError as error:
            raise ValueError(
                f"{label}.raw_timestamp_ns is not canonical"
            ) from error
    evidence = Evidence(
        artifact_id=artifact_id,
        locator=record["locator"],
        raw_timestamp_ns=raw_timestamp,
        clock_domain=record["clock_domain"],
        excerpt_sha256=record["excerpt_sha256"],
    )
    if _evidence_projection(evidence, artifact_ids=artifact_ids) != record:
        raise ValueError(f"{label} is not canonical")
    return evidence


def _validate_patch_projection(
    value: object,
    label: str,
    *,
    artifact_ids: frozenset[UUID],
) -> dict[str, Any]:
    record = _exact_dict(
        value,
        frozenset(
            {
                "set_values",
                "remove_fields",
                "unknown_fields",
                "field_quality",
                "field_provenance",
                "complete",
            }
        ),
        label,
    )
    if record["complete"] is not True or record["remove_fields"] != []:
        raise ValueError(f"{label} must be a complete self-contained patch")
    set_values = record["set_values"]
    if type(set_values) is not dict or len(set_values) > 1_024:
        raise ValueError(f"{label}.set_values is invalid")
    value_units = [1]
    for name, item in set_values.items():
        if (
            type(name) is not str
            or not name
            or len(name) > 256
            or "\x00" in name
        ):
            raise ValueError(f"{label}.set_values contains an invalid name")
        _validate_property_value_projection(
            item,
            label=f"{label}.set_values[{name!r}]",
            depth=1,
            units=value_units,
        )
    unknown_fields = record["unknown_fields"]
    if type(unknown_fields) is not list or len(unknown_fields) > 1_024:
        raise ValueError(f"{label}.unknown_fields is invalid")
    unknown_names: set[str] = set()
    previous_unknown_key: str | None = None
    for index, item in enumerate(unknown_fields):
        unknown = _exact_dict(
            item,
            frozenset({"name", "reason_code", "message", "evidence"}),
            f"{label}.unknown_fields[{index}]",
        )
        name = unknown["name"]
        if (
            type(name) is not str
            or not name
            or len(name) > 256
            or "\x00" in name
            or name in unknown_names
            or type(unknown["reason_code"]) is not str
            or not unknown["reason_code"]
            or len(unknown["reason_code"]) > 256
            or "\x00" in unknown["reason_code"]
            or type(unknown["message"]) is not str
            or not unknown["message"]
            or len(unknown["message"]) > 8_192
            or "\x00" in unknown["message"]
        ):
            raise ValueError(f"{label}.unknown_fields contains an invalid name")
        unknown_names.add(name)
        unknown_key = strict_canonical_json(unknown)
        if previous_unknown_key is not None and unknown_key <= previous_unknown_key:
            raise ValueError(f"{label}.unknown_fields is not canonically ordered")
        previous_unknown_key = unknown_key
        evidence = unknown["evidence"]
        if type(evidence) is not list:
            raise ValueError(f"{label}.unknown_fields evidence is invalid")
        previous_evidence_key: str | None = None
        for evidence_index, evidence_item in enumerate(evidence):
            evidence_key = strict_canonical_json(evidence_item)
            if (
                previous_evidence_key is not None
                and evidence_key < previous_evidence_key
            ):
                raise ValueError(
                    f"{label}.unknown_fields evidence is not canonically ordered"
                )
            previous_evidence_key = evidence_key
            _evidence_from_projection(
                evidence_item,
                artifact_ids=artifact_ids,
                label=f"{label}.unknown_fields[{index}].evidence[{evidence_index}]",
            )
    for metadata_name, enum_type in (
        ("field_quality", Quality),
        ("field_provenance", Provenance),
    ):
        metadata = record[metadata_name]
        if type(metadata) is not dict or len(metadata) > 1_024:
            raise ValueError(f"{label}.{metadata_name} is invalid")
        for name, item in metadata.items():
            if (
                type(name) is not str
                or not name
                or len(name) > 256
                or "\x00" in name
                or item not in {value.value for value in enum_type}
            ):
                raise ValueError(f"{label}.{metadata_name} is invalid")
    mentioned = set(set_values) | unknown_names
    if set(set_values).intersection(unknown_names):
        raise ValueError(f"{label} mentions one attribute as known and unknown")
    if (set(record["field_quality"]) | set(record["field_provenance"])) - mentioned:
        raise ValueError(f"{label} metadata references an unmentioned attribute")
    return record


def _canonical_perspective(
    value: StatusPerspectiveRef | None,
    *,
    primary_pin: PluginExecutionPin,
    allowed_ids: frozenset[str],
) -> StatusPerspectiveRef | None:
    if value is None:
        return None
    if type(value) is not StatusPerspectiveRef or value.perspective_id not in allowed_ids:
        raise RelationshipProjectionMaterializationError(
            "relationship declaration references a perspective outside the primary revision schema"
        )
    if value.plugin_instance_id not in (None, primary_pin.instance_id):
        raise RelationshipProjectionMaterializationError(
            "relationship declaration perspective belongs to a different provider"
        )
    if value.schema_digest not in (None, primary_pin.schema_digest):
        raise RelationshipProjectionMaterializationError(
            "relationship declaration perspective belongs to a different schema"
        )
    return StatusPerspectiveRef(
        perspective_id=value.perspective_id,
        plugin_instance_id=primary_pin.instance_id,
        schema_digest=primary_pin.schema_digest,
    )


def _perspective_projection(
    value: StatusPerspectiveRef | None,
) -> dict[str, str | None] | None:
    if value is None:
        return None
    return {
        "perspective_id": value.perspective_id,
        "plugin_instance_id": value.plugin_instance_id,
        "schema_digest": value.schema_digest,
    }


class _AggregateWorld:
    """One shared base world with a revision-wide read budget."""

    def __init__(
        self,
        world: ReadOnlyWorld,
        maximum_reads: int,
        *,
        perspective_ref: StatusPerspectiveRef | None,
    ) -> None:
        self._world = world
        self._basis = world.basis
        self._perspective_ref = perspective_ref
        self._remaining = maximum_reads
        self._maximum = maximum_reads

    @property
    def basis(self) -> WorldBasis:
        return self._basis

    @property
    def perspective_ref(self) -> StatusPerspectiveRef | None:
        return self._perspective_ref

    @property
    def reads_used(self) -> int:
        return self._maximum - self._remaining

    def _charge(self) -> None:
        if self._remaining <= 0:
            raise RelationshipProjectionMaterializationError(
                "relationship projectors exceeded the aggregate world-read limit"
            )
        self._remaining -= 1

    def state_of(self, resource: ResourceKey) -> ResourceStateView | None:
        self._charge()
        return self._world.state_of(resource)

    def _bounded_iter[Item](
        self,
        producer: Callable[[int], Iterable[Item]],
        requested: int | None,
    ) -> Iterable[Item]:
        if requested is not None and (type(requested) is not int or requested < 0):
            raise ValueError("world read limit must be a non-negative integer")
        allowed = self._remaining if requested is None else min(requested, self._remaining)
        # An explicit request equal to the remaining budget is already bounded
        # by the caller and needs no sentinel read. Only an unbounded request or
        # one larger than the aggregate remainder needs the +1 overflow probe.
        aggregate_limited = requested is None or requested > self._remaining
        producer_limit = allowed + 1 if aggregate_limited and requested != 0 else allowed
        iterator = iter(producer(producer_limit))
        count = 0
        try:
            for item in iterator:
                if count >= allowed:
                    raise RelationshipProjectionMaterializationError(
                        "relationship projectors exceeded the aggregate world-read limit"
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
                layers=layers, kinds=kinds, limit=bounded
            ),
            limit,
        )

    def related(
        self,
        resource: ResourceKey,
        direction: RelationDirection = RelationDirection.OUTGOING,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
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
                relation_types=relation_types, layers=layers, limit=bounded
            ),
            limit,
        )


def _selected_pins(plan: PluginExecutionPlan) -> tuple[PluginExecutionPin, ...]:
    primary = primary_parser_execution_pin(plan)
    capability = PluginCapability.RELATIONSHIP_PROJECTION.value
    selected: list[PluginExecutionPin] = []
    if capability in primary.capabilities:
        selected.append(primary)
    auxiliaries: list[PluginExecutionPin] = []
    for pin in plan.plugins:
        if pin == primary:
            continue
        selected_role = REVISION_RELATIONSHIP_PROJECTION_ROLE in pin.roles
        declares = capability in pin.capabilities
        if selected_role and not declares:
            raise RelationshipProjectionMaterializationError(
                "revision relationship projector role requires the declared capability"
            )
        if selected_role and declares:
            auxiliaries.append(pin)
    auxiliaries.sort(key=lambda item: (item.instance_id, item.registered_execution_identity))
    return (*selected, *auxiliaries)


def revision_relationship_projection_selected_pins(
    plan: PluginExecutionPlan,
) -> tuple[PluginExecutionPin, ...]:
    if type(plan) is not PluginExecutionPlan:
        raise TypeError("plan must be an exact PluginExecutionPlan")
    return _selected_pins(snapshot_plugin_execution_plan(plan))


@dataclass(frozen=True, slots=True)
class MaterializedRelationshipContribution:
    provider: CapabilityProviderRef
    evidence: tuple[Evidence, ...]
    occurrence_count: int
    canonical_record: str

    def __post_init__(self) -> None:
        if type(self.provider) is not CapabilityProviderRef:
            raise TypeError("provider must be an exact CapabilityProviderRef")
        if type(self.evidence) is not tuple or any(type(item) is not Evidence for item in self.evidence):
            raise TypeError("evidence must contain exact Evidence values")
        if type(self.occurrence_count) is not int or not 1 <= self.occurrence_count <= _JSON_SAFE_INTEGER_MAX:
            raise ValueError("occurrence_count must be a JSON-safe positive integer")
        if type(self.canonical_record) is not str:
            raise TypeError("canonical_record must be an exact string")

    def client_projection(self) -> dict[str, Any]:
        value = json.loads(self.canonical_record)
        assert type(value) is dict
        return value


@dataclass(frozen=True, slots=True)
class MaterializedRelationshipDeclaration:
    declaration_id: str
    semantic_claim_id: str
    ambiguity_group_id: str | None
    declaration: RelationshipDeclaration
    contributions: tuple[MaterializedRelationshipContribution, ...]
    canonical_record: str

    def __post_init__(self) -> None:
        if type(self.declaration) is not RelationshipDeclaration:
            raise TypeError("declaration must be an exact RelationshipDeclaration")
        if type(self.contributions) is not tuple or not self.contributions:
            raise ValueError("contributions must be a non-empty exact tuple")
        if any(type(item) is not MaterializedRelationshipContribution for item in self.contributions):
            raise TypeError("contributions contain an invalid value")
        if any(
            type(value) is not str or not value.startswith("sha256:") or len(value) != 71
            for value in (self.declaration_id, self.semantic_claim_id)
        ):
            raise ValueError("relationship declaration identities are invalid")
        if self.ambiguity_group_id is not None and (
            type(self.ambiguity_group_id) is not str
            or not self.ambiguity_group_id.startswith("sha256:")
            or len(self.ambiguity_group_id) != 71
        ):
            raise ValueError("ambiguity_group_id is invalid")

    def client_projection(self) -> dict[str, Any]:
        value = json.loads(self.canonical_record)
        assert type(value) is dict
        return value


@dataclass(frozen=True, slots=True)
class MaterializedRelationshipProjectionDiagnostic:
    diagnostic_id: str
    provider: CapabilityProviderRef
    diagnostic: PluginDiagnostic
    canonical_record: str

    def client_projection(self) -> dict[str, Any]:
        value = json.loads(self.canonical_record)
        assert type(value) is dict
        return value


@dataclass(frozen=True, slots=True)
class MaterializedProjectedRelationship:
    """One conservative revision-scoped edge resolved from retained claims."""

    relationship_id: str
    view: RelationshipView
    ambiguity_group_id: str | None
    declaration_ids: tuple[str, ...]
    canonical_record: str

    def client_projection(self) -> dict[str, Any]:
        value = json.loads(self.canonical_record)
        assert type(value) is dict
        return value


@dataclass(frozen=True, slots=True)
class RelationshipProjectionMaterializationResult:
    status: RelationshipProjectionMaterializationStatus
    plan_digest: str
    basis_digest: str | None
    basis_canonical_json: str | None
    providers: tuple[CapabilityProviderRef, ...]
    declarations: tuple[MaterializedRelationshipDeclaration, ...]
    resolved_relationships: tuple[MaterializedProjectedRelationship, ...]
    diagnostics: tuple[MaterializedRelationshipProjectionDiagnostic, ...]
    emitted_declarations: int
    emitted_diagnostics: int
    duplicate_emissions_collapsed: int
    semantic_conflict_groups: int
    world_reads: int
    base_resource_count: int

    @property
    def plugin_diagnostics(self) -> tuple[PluginDiagnostic, ...]:
        return tuple(item.diagnostic for item in self.diagnostics)

    @property
    def augmented_declarations(self) -> tuple[RelationshipDeclaration, ...]:
        """Return one revision-scoped declaration per retained semantic claim."""

        values: list[RelationshipDeclaration] = []
        for item in self.declarations:
            evidence_by_key: dict[str, Evidence] = {}
            for contribution in item.contributions:
                for evidence in contribution.evidence:
                    key = strict_canonical_json(
                        _evidence_projection(
                            evidence,
                            artifact_ids=frozenset(
                                nested.artifact_id
                                for current in item.contributions
                                for nested in current.evidence
                            ),
                        )
                    )
                    evidence_by_key.setdefault(key, evidence)
            values.append(
                replace(
                    item.declaration,
                    evidence=tuple(evidence_by_key[key] for key in sorted(evidence_by_key)),
                    quality=(
                        Quality.AMBIGUOUS
                        if item.ambiguity_group_id is not None
                        else item.declaration.quality
                    ),
                )
            )
        return tuple(values)

    @property
    def augmented_relationships(self) -> tuple[RelationshipView, ...]:
        """Return conservative resolved edges for the augmented revision world."""

        return tuple(item.view for item in self.resolved_relationships)

    def dataset_fragment(self) -> dict[str, Any]:
        return {
            "relationship_declarations": [
                item.client_projection() for item in self.declarations
            ],
            "relationship_projection_diagnostics": [
                item.client_projection() for item in self.diagnostics
            ],
            "relationship_projection_edges": [
                item.client_projection() for item in self.resolved_relationships
            ],
            "relationship_projection_materialization": {
                "schema_version": RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION,
                "status": self.status.value,
                "scope": "revision",
                "plan_digest": self.plan_digest,
                "basis_digest": self.basis_digest,
                "basis": (
                    json.loads(self.basis_canonical_json)
                    if self.basis_canonical_json is not None
                    else None
                ),
                "providers": [_provider_projection(item) for item in self.providers],
                "provider_count": len(self.providers),
                "declaration_count": len(self.declarations),
                "resolved_edge_count": len(self.resolved_relationships),
                "diagnostic_count": len(self.diagnostics),
                "emitted_declaration_count": self.emitted_declarations,
                "emitted_diagnostic_count": self.emitted_diagnostics,
                "duplicate_emissions_collapsed": self.duplicate_emissions_collapsed,
                "semantic_conflict_groups": self.semantic_conflict_groups,
                "world_reads": self.world_reads,
                "base_resource_count": self.base_resource_count,
            },
        }


@dataclass(slots=True)
class _ContributionBuilder:
    provider: CapabilityProviderRef
    evidence: tuple[Evidence, ...]
    projection: dict[str, Any]
    occurrences: int = 1


@dataclass(slots=True)
class _ClaimBuilder:
    declaration: RelationshipDeclaration
    semantic_payload: dict[str, Any]
    edge_payload: dict[str, Any]
    contributions: dict[str, _ContributionBuilder]


def _not_applicable(plan: PluginExecutionPlan) -> RelationshipProjectionMaterializationResult:
    return RelationshipProjectionMaterializationResult(
        status=RelationshipProjectionMaterializationStatus.NOT_APPLICABLE,
        plan_digest=plan.plan_digest,
        basis_digest=None,
        basis_canonical_json=None,
        providers=(),
        declarations=(),
        resolved_relationships=(),
        diagnostics=(),
        emitted_declarations=0,
        emitted_diagnostics=0,
        duplicate_emissions_collapsed=0,
        semantic_conflict_groups=0,
        world_reads=0,
        base_resource_count=0,
    )


def not_applicable_relationship_projection_materialization(
    plan: PluginExecutionPlan,
) -> RelationshipProjectionMaterializationResult:
    if type(plan) is not PluginExecutionPlan:
        raise TypeError("plan must be an exact PluginExecutionPlan")
    detached = snapshot_plugin_execution_plan(plan)
    if _selected_pins(detached):
        raise RelationshipProjectionMaterializationError(
            "not_applicable relationship projection requires no selected provider"
        )
    return _not_applicable(detached)


def _materialized_diagnostic(
    diagnostic: PluginDiagnostic,
    *,
    provider: CapabilityProviderRef,
    artifact_ids: frozenset[UUID],
) -> MaterializedRelationshipProjectionDiagnostic:
    evidence = [
        _evidence_projection(item, artifact_ids=artifact_ids)
        for item in diagnostic.evidence
    ]
    record: dict[str, Any] = {
        "stage": diagnostic.stage.value,
        "severity": diagnostic.severity.value,
        "code": diagnostic.code,
        "message": diagnostic.message,
        "recoverable": diagnostic.recoverable,
        "evidence": evidence,
        "details": _property_value_projection(
            diagnostic.details,
            label="relationship projection diagnostic details",
        ),
        "origin": diagnostic.origin.value,
        "producer": _provider_projection(provider),
    }
    diagnostic_id = _digest(record)
    record["diagnostic_id"] = diagnostic_id
    return MaterializedRelationshipProjectionDiagnostic(
        diagnostic_id=diagnostic_id,
        provider=provider,
        diagnostic=diagnostic,
        canonical_record=strict_canonical_json(record),
    )


def materialize_revision_relationship_projection(
    *,
    plan: PluginExecutionPlan,
    router: PlanBoundCapabilityRouter,
    world: ReadOnlyWorld,
    primary_schema: PluginSchema,
    artifact_ids: Collection[UUID],
    limits: RelationshipProjectionMaterializationLimits | None = None,
) -> RelationshipProjectionMaterializationResult:
    """Materialize selected projectors against one immutable base world."""

    selected_limits = limits or RelationshipProjectionMaterializationLimits()
    if type(selected_limits) is not RelationshipProjectionMaterializationLimits:
        raise TypeError("limits must be exact RelationshipProjectionMaterializationLimits")
    if type(plan) is not PluginExecutionPlan or type(router) is not PlanBoundCapabilityRouter:
        raise TypeError("plan and router must be exact plan-bound core values")
    if type(primary_schema) is not PluginSchema:
        raise TypeError("primary_schema must be an exact PluginSchema")
    detached = snapshot_plugin_execution_plan(plan)
    if router.plan != detached or router.member_id != detached.basis_revision_id:
        raise RelationshipProjectionMaterializationError(
            "capability router is not bound to the supplied revision plan"
        )
    primary_pin = primary_parser_execution_pin(detached)
    if plugin_schema_digest(primary_schema) != primary_pin.schema_digest:
        raise RelationshipProjectionMaterializationError(
            "primary schema does not match the execution-plan pin"
        )
    selected = _selected_pins(detached)
    if len(selected) > selected_limits.max_providers:
        raise RelationshipProjectionMaterializationError(
            "relationship projector count exceeded the configured limit"
        )
    if not selected:
        not_applicable = _not_applicable(detached)
        if (
            len(
                strict_canonical_json(not_applicable.dataset_fragment()).encode(
                    "utf-8"
                )
            )
            > selected_limits.max_serialized_bytes
        ):
            raise RelationshipProjectionMaterializationError(
                "published relationship projection exceeded the aggregate byte limit"
            )
        return not_applicable

    try:
        admitted_artifacts = frozenset(artifact_ids)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise RelationshipProjectionMaterializationError(
            "artifact inventory could not be validated"
        ) from error
    if (
        len(admitted_artifacts) > selected_limits.max_artifact_ids
        or any(type(item) is not UUID for item in admitted_artifacts)
    ):
        raise RelationshipProjectionMaterializationError(
            "artifact inventory exceeds the configured exact UUID limit"
        )

    allowed_perspectives = frozenset(
        item.perspective_id for item in primary_schema.status_perspectives
    )
    canonical_world_perspective = _canonical_perspective(
        world.perspective_ref,
        primary_pin=primary_pin,
        allowed_ids=allowed_perspectives,
    )
    aggregate_world = _AggregateWorld(
        world,
        selected_limits.max_world_reads,
        perspective_ref=canonical_world_perspective,
    )
    if type(aggregate_world.basis) is not WorldBasis:
        raise RelationshipProjectionMaterializationError(
            "base revision world has an invalid basis"
        )
    basis_projection = _contract_projection(
        aggregate_world.basis, artifact_ids=admitted_artifacts
    )
    canonical_basis = strict_canonical_json(basis_projection)
    basis_digest = _digest(basis_projection)

    # Build the one endpoint index before any provider executes.  Validation
    # below uses only this frozen set and never performs post-hook world reads.
    resource_index: set[ResourceKey] = set()
    for emitted_states, state in enumerate(
        aggregate_world.iter_states(limit=selected_limits.max_base_resources + 1),
        start=1,
    ):
        if emitted_states > selected_limits.max_base_resources:
            raise RelationshipProjectionMaterializationError(
                "base revision resource count exceeded the configured limit"
            )
        if type(state) is not ResourceStateView or type(state.resource) is not ResourceKey:
            raise RelationshipProjectionMaterializationError(
                "base revision world emitted an invalid resource state"
            )
        if state.exists is True:
            resource_index.add(state.resource)

    relationship_descriptors = {
        item.relation_type: item for item in primary_schema.relationship_types
    }
    claims: dict[str, _ClaimBuilder] = {}
    providers: list[CapabilityProviderRef] = []
    diagnostics_by_id: dict[str, MaterializedRelationshipProjectionDiagnostic] = {}
    emitted_declarations = 0
    emitted_diagnostics = 0
    evidence_references = 0
    charged_bytes = len(strict_canonical_json(basis_projection).encode("utf-8"))

    for pin in selected:
        role = (
            "primary_parser"
            if "primary_parser" in pin.roles
            else REVISION_RELATIONSHIP_PROJECTION_ROLE
        )
        try:
            route = router.resolve(
                CapabilityRouteSelector(
                    PluginCapability.RELATIONSHIP_PROJECTION,
                    role=role,
                    instance_id=pin.instance_id,
                )
            )
            invocation = route._project_relationships_for_revision(
                aggregate_world,
                declaration_schema=primary_schema,
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except (PluginCapabilityOutputError, RelationshipProjectionMaterializationError) as error:
            raise RelationshipProjectionMaterializationError(
                "selected relationship projector failed"
            ) from error
        except BaseException as error:
            raise RelationshipProjectionMaterializationError(
                "selected relationship projector failed"
            ) from error
        provider = invocation.provider
        if (
            provider.plan_digest != detached.plan_digest
            or provider.pin != pin
            or provider.capability is not PluginCapability.RELATIONSHIP_PROJECTION
        ):
            raise RelationshipProjectionMaterializationError(
                "relationship projection returned stale provider provenance"
            )
        providers.append(provider)

        for declaration in invocation.result.declarations:
            emitted_declarations += 1
            if emitted_declarations > selected_limits.max_declarations:
                raise RelationshipProjectionMaterializationError(
                    "relationship declarations exceeded the aggregate limit"
                )
            if type(declaration) is not RelationshipDeclaration:
                raise RelationshipProjectionMaterializationError(
                    "relationship projector emitted an invalid declaration"
                )
            if (
                type(declaration.attributes) is not PropertyPatch
                or declaration.attributes.complete is not True
                or declaration.attributes.remove_fields
            ):
                raise RelationshipProjectionMaterializationError(
                    "relationship declaration attributes must be a complete self-contained patch"
                )
            evidence_references += len(declaration.evidence) + sum(
                len(item.evidence) for item in declaration.attributes.unknown_fields
            )
            if evidence_references > selected_limits.max_evidence_references:
                raise RelationshipProjectionMaterializationError(
                    "relationship evidence exceeded the aggregate limit"
                )
            if declaration.source not in resource_index or declaration.target not in resource_index:
                raise RelationshipProjectionMaterializationError(
                    "relationship declaration endpoint does not exist in the base world"
                )
            descriptor = relationship_descriptors.get(declaration.relation_type)
            if descriptor is None:
                raise RelationshipProjectionMaterializationError(
                    "relationship declaration type is outside the primary revision schema"
                )
            perspective = _canonical_perspective(
                declaration.perspective_ref,
                primary_pin=primary_pin,
                allowed_ids=allowed_perspectives,
            )
            source = declaration.source
            target = declaration.target
            source_projection = _resource_projection(source)
            target_projection = _resource_projection(target)
            source_resource_id, _source_identity = _canonical_resource_identity(source)
            target_resource_id, _target_identity = _canonical_resource_identity(target)
            if not descriptor.directed and source_resource_id > target_resource_id:
                source, target = target, source
                source_projection, target_projection = target_projection, source_projection
            detached_declaration = replace(
                declaration,
                source=source,
                target=target,
                perspective_ref=perspective,
                evidence=tuple(
                    item
                    for _key, item in sorted(
                        (
                            (
                                strict_canonical_json(
                                    _evidence_projection(
                                        item, artifact_ids=admitted_artifacts
                                    )
                                ),
                                item,
                            )
                            for item in declaration.evidence
                        ),
                        key=lambda pair: pair[0],
                    )
                ),
            )
            evidence_projection = sorted(
                (
                _evidence_projection(item, artifact_ids=admitted_artifacts)
                for item in detached_declaration.evidence
                ),
                key=strict_canonical_json,
            )
            perspective_projection = _perspective_projection(perspective)
            attributes_projection = _patch_projection(
                detached_declaration.attributes,
                artifact_ids=admitted_artifacts,
            )
            edge_payload = {
                "basis_digest": basis_digest,
                "source": source_projection,
                "target": target_projection,
                "relation_type": detached_declaration.relation_type,
                "perspective_ref": perspective_projection,
            }
            semantic_payload = {
                **edge_payload,
                "attributes": attributes_projection,
                "provenance": detached_declaration.provenance.value,
                "quality": detached_declaration.quality.value,
            }
            semantic_claim_id = _digest(semantic_payload)
            contribution_payload = {
                "producer": _provider_projection(provider),
                "evidence": evidence_projection,
            }
            charged_bytes += len(
                strict_canonical_json(
                    {
                        "semantic": semantic_payload,
                        "contribution": contribution_payload,
                    }
                ).encode("utf-8")
            )
            if charged_bytes > selected_limits.max_serialized_bytes:
                raise RelationshipProjectionMaterializationError(
                    "relationship projection exceeded the aggregate byte limit"
                )
            contribution_key = strict_canonical_json(contribution_payload)
            claim = claims.get(semantic_claim_id)
            if claim is None:
                claim = _ClaimBuilder(
                    declaration=detached_declaration,
                    semantic_payload=semantic_payload,
                    edge_payload=edge_payload,
                    contributions={},
                )
                claims[semantic_claim_id] = claim
            elif strict_canonical_json(claim.semantic_payload) != strict_canonical_json(semantic_payload):
                raise RelationshipProjectionMaterializationError(
                    "relationship semantic identity collision"
                )
            contribution = claim.contributions.get(contribution_key)
            if contribution is None:
                claim.contributions[contribution_key] = _ContributionBuilder(
                    provider=provider,
                    evidence=tuple(detached_declaration.evidence),
                    projection=contribution_payload,
                )
            else:
                contribution.occurrences += 1

        for diagnostic in invocation.result.diagnostics:
            emitted_diagnostics += 1
            if emitted_diagnostics > selected_limits.max_diagnostics:
                raise RelationshipProjectionMaterializationError(
                    "relationship projection diagnostics exceeded the aggregate limit"
                )
            evidence_references += len(diagnostic.evidence)
            if evidence_references > selected_limits.max_evidence_references:
                raise RelationshipProjectionMaterializationError(
                    "relationship evidence exceeded the aggregate limit"
                )
            materialized_diagnostic = _materialized_diagnostic(
                diagnostic,
                provider=provider,
                artifact_ids=admitted_artifacts,
            )
            charged_bytes += len(materialized_diagnostic.canonical_record.encode("utf-8"))
            if charged_bytes > selected_limits.max_serialized_bytes:
                raise RelationshipProjectionMaterializationError(
                    "relationship projection exceeded the aggregate byte limit"
                )
            if materialized_diagnostic.diagnostic_id in diagnostics_by_id:
                raise RelationshipProjectionMaterializationError(
                    "relationship projector emitted a duplicate diagnostic"
                )
            diagnostics_by_id[materialized_diagnostic.diagnostic_id] = (
                materialized_diagnostic
            )

    claims_by_edge: dict[str, list[str]] = {}
    for semantic_claim_id, claim in claims.items():
        edge_key = strict_canonical_json(claim.edge_payload)
        claims_by_edge.setdefault(edge_key, []).append(semantic_claim_id)
    conflict_groups = {
        edge_key: _digest({"scope": "revision", "edge": json.loads(edge_key)})
        for edge_key, claim_ids in claims_by_edge.items()
        if len(claim_ids) > 1
    }

    materialized_declarations: list[MaterializedRelationshipDeclaration] = []
    duplicate_emissions = 0
    for semantic_claim_id in sorted(claims):
        claim = claims[semantic_claim_id]
        edge_key = strict_canonical_json(claim.edge_payload)
        ambiguity_group_id = conflict_groups.get(edge_key)
        materialized_contributions: list[MaterializedRelationshipContribution] = []
        contribution_records: list[dict[str, Any]] = []
        for key in sorted(claim.contributions):
            builder = claim.contributions[key]
            duplicate_emissions += builder.occurrences - 1
            contribution_record = {
                **builder.projection,
                "occurrence_count": builder.occurrences,
            }
            canonical_record = strict_canonical_json(contribution_record)
            materialized_contributions.append(
                MaterializedRelationshipContribution(
                    provider=builder.provider,
                    evidence=builder.evidence,
                    occurrence_count=builder.occurrences,
                    canonical_record=canonical_record,
                )
            )
            contribution_records.append(contribution_record)
        declaration_record: dict[str, Any] = {
            "scope": "revision",
            "source": claim.semantic_payload["source"],
            "target": claim.semantic_payload["target"],
            "relation_type": claim.semantic_payload["relation_type"],
            "attributes": claim.semantic_payload["attributes"],
            "provenance": claim.semantic_payload["provenance"],
            "quality": claim.semantic_payload["quality"],
            "effective_quality": (
                Quality.AMBIGUOUS.value
                if ambiguity_group_id is not None
                else claim.semantic_payload["quality"]
            ),
            "perspective_ref": claim.semantic_payload["perspective_ref"],
            "basis_digest": basis_digest,
            "execution_plan_digest": detached.plan_digest,
            "semantic_claim_id": semantic_claim_id,
            "ambiguity_group_id": ambiguity_group_id,
            "contributions": contribution_records,
        }
        declaration_id = _digest(declaration_record)
        declaration_record["declaration_id"] = declaration_id
        materialized_declarations.append(
            MaterializedRelationshipDeclaration(
                declaration_id=declaration_id,
                semantic_claim_id=semantic_claim_id,
                ambiguity_group_id=ambiguity_group_id,
                declaration=claim.declaration,
                contributions=tuple(materialized_contributions),
                canonical_record=strict_canonical_json(declaration_record),
            )
        )

    declarations_by_edge: dict[str, list[MaterializedRelationshipDeclaration]] = {}
    for item in materialized_declarations:
        edge_payload = claims[item.semantic_claim_id].edge_payload
        declarations_by_edge.setdefault(
            strict_canonical_json(edge_payload), []
        ).append(item)
    resolved_relationships: list[MaterializedProjectedRelationship] = []
    for edge_key in sorted(declarations_by_edge):
        grouped = sorted(
            declarations_by_edge[edge_key], key=lambda item: item.declaration_id
        )
        edge = json.loads(edge_key)
        ambiguity_group_id = conflict_groups.get(edge_key)
        common_names = set(grouped[0].declaration.attributes.set_values)
        for item in grouped[1:]:
            common_names.intersection_update(item.declaration.attributes.set_values)
        common_values: dict[str, Any] = {}
        common_value_projections: dict[str, dict[str, Any]] = {}
        for name in sorted(common_names):
            normalized = claims[grouped[0].semantic_claim_id].semantic_payload[
                "attributes"
            ]["set_values"][name]
            if all(
                claims[item.semantic_claim_id].semantic_payload["attributes"][
                    "set_values"
                ][name]
                == normalized
                for item in grouped[1:]
            ):
                common_values[name] = grouped[0].declaration.attributes.set_values[name]
                common_value_projections[name] = normalized
        evidence_by_projection: dict[str, Evidence] = {}
        for item in grouped:
            for materialized_contribution in item.contributions:
                for evidence in materialized_contribution.evidence:
                    projection = _evidence_projection(
                        evidence, artifact_ids=admitted_artifacts
                    )
                    evidence_by_projection.setdefault(
                        strict_canonical_json(projection), evidence
                    )
        representative = grouped[0].declaration
        view = RelationshipView(
            source=representative.source,
            target=representative.target,
            relation_type=representative.relation_type,
            attributes=MappingProxyType(dict(common_values)),
            provenance=(
                Provenance.CORRELATED
                if ambiguity_group_id is not None
                else representative.provenance
            ),
            quality=(
                Quality.AMBIGUOUS
                if ambiguity_group_id is not None
                else representative.quality
            ),
            valid_from_ns=None,
            valid_to_ns=None,
            evidence=tuple(
                evidence_by_projection[key] for key in sorted(evidence_by_projection)
            ),
            perspective_ref=representative.perspective_ref,
        )
        resolved_record: dict[str, Any] = {
            "scope": "revision",
            "source": edge["source"],
            "target": edge["target"],
            "relation_type": edge["relation_type"],
            "attributes": dict(sorted(common_value_projections.items())),
            "provenance": view.provenance.value,
            "quality": view.quality.value,
            "perspective_ref": edge["perspective_ref"],
            "basis_digest": basis_digest,
            "execution_plan_digest": detached.plan_digest,
            "ambiguity_group_id": ambiguity_group_id,
            "declaration_ids": [item.declaration_id for item in grouped],
            "evidence": [
                _evidence_projection(item, artifact_ids=admitted_artifacts)
                for item in view.evidence
            ],
        }
        relationship_id = _digest(resolved_record)
        resolved_record["relationship_id"] = relationship_id
        resolved_relationships.append(
            MaterializedProjectedRelationship(
                relationship_id=relationship_id,
                view=view,
                ambiguity_group_id=ambiguity_group_id,
                declaration_ids=tuple(
                    item.declaration_id for item in grouped
                ),
                canonical_record=strict_canonical_json(resolved_record),
            )
        )

    result = RelationshipProjectionMaterializationResult(
        status=RelationshipProjectionMaterializationStatus.COMPLETE,
        plan_digest=detached.plan_digest,
        basis_digest=basis_digest,
        basis_canonical_json=canonical_basis,
        providers=tuple(providers),
        declarations=tuple(materialized_declarations),
        resolved_relationships=tuple(resolved_relationships),
        diagnostics=tuple(diagnostics_by_id[key] for key in sorted(diagnostics_by_id)),
        emitted_declarations=emitted_declarations,
        emitted_diagnostics=emitted_diagnostics,
        duplicate_emissions_collapsed=duplicate_emissions,
        semantic_conflict_groups=len(conflict_groups),
        world_reads=aggregate_world.reads_used,
        base_resource_count=len(resource_index),
    )
    published_size = len(strict_canonical_json(result.dataset_fragment()).encode("utf-8"))
    if published_size > selected_limits.max_serialized_bytes:
        raise RelationshipProjectionMaterializationError(
            "published relationship projection exceeded the aggregate byte limit"
        )
    return result


_MATERIALIZATION_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "scope",
        "plan_digest",
        "basis_digest",
        "basis",
        "providers",
        "provider_count",
        "declaration_count",
        "resolved_edge_count",
        "diagnostic_count",
        "emitted_declaration_count",
        "emitted_diagnostic_count",
        "duplicate_emissions_collapsed",
        "semantic_conflict_groups",
        "world_reads",
        "base_resource_count",
    }
)
_DECLARATION_FIELDS = frozenset(
    {
        "scope",
        "source",
        "target",
        "relation_type",
        "attributes",
        "provenance",
        "quality",
        "effective_quality",
        "perspective_ref",
        "basis_digest",
        "execution_plan_digest",
        "semantic_claim_id",
        "ambiguity_group_id",
        "contributions",
        "declaration_id",
    }
)
_RESOLVED_EDGE_FIELDS = frozenset(
    {
        "scope",
        "source",
        "target",
        "relation_type",
        "attributes",
        "provenance",
        "quality",
        "perspective_ref",
        "basis_digest",
        "execution_plan_digest",
        "ambiguity_group_id",
        "declaration_ids",
        "evidence",
        "relationship_id",
    }
)
_DIAGNOSTIC_FIELDS = frozenset(
    {
        "stage",
        "severity",
        "code",
        "message",
        "recoverable",
        "evidence",
        "details",
        "origin",
        "producer",
        "diagnostic_id",
    }
)


def _validated_perspective_projection(
    value: object,
    *,
    primary_pin: PluginExecutionPin,
    allowed_ids: frozenset[str],
    label: str,
) -> dict[str, str] | None:
    if value is None:
        return None
    record = _exact_dict(
        value,
        frozenset({"perspective_id", "plugin_instance_id", "schema_digest"}),
        label,
    )
    if (
        record["perspective_id"] not in allowed_ids
        or record["plugin_instance_id"] != primary_pin.instance_id
        or record["schema_digest"] != primary_pin.schema_digest
    ):
        raise ValueError(f"{label} is outside the primary revision schema")
    return record


def _validate_relationship_projection_fragment_context(
    value: object,
    *,
    detached_plan: PluginExecutionPlan,
    primary_pin: PluginExecutionPin,
    expected_basis_digest: str | None,
    base_resource_ids: frozenset[str],
    relationship_type_directions: Mapping[str, bool],
    allowed_perspectives: frozenset[str],
    admitted_artifacts: frozenset[UUID],
    selected_limits: RelationshipProjectionMaterializationLimits,
) -> dict[str, Any]:
    fragment = _exact_dict(
        value,
        frozenset(
            {
                "relationship_declarations",
                "relationship_projection_diagnostics",
                "relationship_projection_edges",
                "relationship_projection_materialization",
            }
        ),
        "relationship projection fragment",
    )
    metadata = _exact_dict(
        fragment["relationship_projection_materialization"],
        _MATERIALIZATION_FIELDS,
        "relationship projection materialization",
    )
    try:
        materialization_scope = _RelationshipProjectionScope(metadata["scope"])
    except (TypeError, ValueError) as error:
        raise ValueError(
            "relationship projection materialization scope is invalid"
        ) from error
    if (
        metadata["schema_version"]
        != RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION
        or materialization_scope is not _RelationshipProjectionScope.REVISION
        or metadata["plan_digest"] != detached_plan.plan_digest
    ):
        raise ValueError("relationship projection materialization identity is invalid")

    selected = _selected_pins(detached_plan)
    declarations = fragment["relationship_declarations"]
    diagnostics = fragment["relationship_projection_diagnostics"]
    resolved_edges = fragment["relationship_projection_edges"]
    providers_value = metadata["providers"]
    if any(type(item) is not list for item in (declarations, diagnostics, resolved_edges, providers_value)):
        raise ValueError("relationship projection arrays are invalid")
    if (
        len(declarations) > selected_limits.max_declarations
        or len(diagnostics) > selected_limits.max_diagnostics
        or len(providers_value) > selected_limits.max_providers
    ):
        raise ValueError("relationship projection fragment exceeds configured limits")

    count_fields = (
        "provider_count",
        "declaration_count",
        "resolved_edge_count",
        "diagnostic_count",
        "emitted_declaration_count",
        "emitted_diagnostic_count",
        "duplicate_emissions_collapsed",
        "semantic_conflict_groups",
        "world_reads",
        "base_resource_count",
    )
    for field in count_fields:
        if (
            type(metadata[field]) is not int
            or not 0 <= metadata[field] <= _JSON_SAFE_INTEGER_MAX
        ):
            raise ValueError(f"relationship projection {field} is invalid")

    if metadata["status"] == RelationshipProjectionMaterializationStatus.NOT_APPLICABLE.value:
        if selected or any((declarations, diagnostics, resolved_edges, providers_value)):
            raise ValueError("not_applicable relationship projection contains output")
        if metadata["basis_digest"] is not None:
            raise ValueError("not_applicable relationship projection carries a basis")
        if metadata["basis"] is not None:
            raise ValueError(
                "not_applicable relationship projection carries a basis record"
            )
        for field in (
            "provider_count",
            "declaration_count",
            "resolved_edge_count",
            "diagnostic_count",
            "emitted_declaration_count",
            "emitted_diagnostic_count",
            "duplicate_emissions_collapsed",
            "semantic_conflict_groups",
            "world_reads",
            "base_resource_count",
        ):
            if metadata[field] != 0:
                raise ValueError("not_applicable relationship projection has nonzero counts")
        if (
            len(strict_canonical_json(fragment).encode("utf-8"))
            > selected_limits.max_serialized_bytes
        ):
            raise ValueError("relationship projection fragment exceeds the byte limit")
        detached = json.loads(strict_canonical_json(fragment))
        assert type(detached) is dict
        return detached
    if metadata["status"] != RelationshipProjectionMaterializationStatus.COMPLETE.value:
        raise ValueError("relationship projection status is invalid")
    if not selected:
        raise ValueError(
            "complete relationship projection requires a selected provider"
        )

    if expected_basis_digest is None:
        raise ValueError(
            "complete relationship projection requires an independently supplied "
            "basis digest"
        )
    try:
        canonical_basis = validate_materialized_consistency_basis(
            metadata["basis"],
            artifact_ids=admitted_artifacts,
            limits=ConsistencyMaterializationLimits(),
        )
    except (ConsistencyMaterializationError, TypeError, ValueError) as error:
        raise ValueError(
            "complete relationship projection has an invalid basis record"
        ) from error
    derived_basis_digest = "sha256:" + sha256(
        canonical_basis.encode("utf-8")
    ).hexdigest()
    if derived_basis_digest != expected_basis_digest:
        raise ValueError(
            "relationship projection basis record does not match the expected basis"
        )
    if metadata["basis_digest"] != expected_basis_digest:
        raise ValueError("relationship projection basis digest does not match")

    provider_refs = tuple(
        _provider_from_projection(
            item,
            plan=detached_plan,
            label=f"relationship projection provider[{index}]",
        )
        for index, item in enumerate(providers_value)
    )
    if any(
        provider.member_id != detached_plan.basis_revision_id
        or provider.node_id != detached_plan.node_id
        or provider.basis_revision_id != detached_plan.basis_revision_id
        for provider in provider_refs
    ):
        raise ValueError(
            "relationship projection providers are outside the revision authority"
        )
    if tuple(provider.pin for provider in provider_refs) != selected:
        raise ValueError("relationship projection providers do not match plan selection")
    provider_records = {
        strict_canonical_json(_provider_projection(item)): item for item in provider_refs
    }

    declarations_by_id: dict[str, dict[str, Any]] = {}
    claims_by_edge: dict[str, list[dict[str, Any]]] = {}
    occurrence_total = 0
    duplicate_total = 0
    evidence_total = 0
    pre_dedup_charged_bytes = len(canonical_basis.encode("utf-8"))
    previous_semantic_claim_id = ""
    for index, item in enumerate(declarations):
        record = _exact_dict(item, _DECLARATION_FIELDS, f"declaration[{index}]")
        try:
            declaration_scope = _RelationshipProjectionScope(record["scope"])
        except (TypeError, ValueError) as error:
            raise ValueError(f"declaration[{index}] scope is invalid") from error
        if (
            declaration_scope is not _RelationshipProjectionScope.REVISION
            or record["basis_digest"] != expected_basis_digest
            or record["execution_plan_digest"] != detached_plan.plan_digest
        ):
            raise ValueError(f"declaration[{index}] scope is invalid")
        source_resource = _resource_from_projection(
            record["source"], f"declaration[{index}].source"
        )
        target_resource = _resource_from_projection(
            record["target"], f"declaration[{index}].target"
        )
        if (
            record["source"]["resource_id"] not in base_resource_ids
            or record["target"]["resource_id"] not in base_resource_ids
        ):
            raise ValueError(f"declaration[{index}] endpoint is absent from the base world")
        directed = relationship_type_directions.get(record["relation_type"])
        if directed is None:
            raise ValueError(f"declaration[{index}] relation type is undeclared")
        source_resource_id, _source_identity = _canonical_resource_identity(
            source_resource
        )
        target_resource_id, _target_identity = _canonical_resource_identity(
            target_resource
        )
        if not directed and source_resource_id > target_resource_id:
            raise ValueError(
                f"declaration[{index}] undirected endpoints are not canonical"
            )
        attributes = _validate_patch_projection(
            record["attributes"],
            f"declaration[{index}].attributes",
            artifact_ids=admitted_artifacts,
        )
        unknown_evidence_count = sum(
            len(unknown["evidence"]) for unknown in attributes["unknown_fields"]
        )
        perspective = _validated_perspective_projection(
            record["perspective_ref"],
            primary_pin=primary_pin,
            allowed_ids=allowed_perspectives,
            label=f"declaration[{index}].perspective_ref",
        )
        try:
            Provenance(record["provenance"])
            original_quality = Quality(record["quality"])
        except (TypeError, ValueError) as error:
            raise ValueError(f"declaration[{index}] enum vocabulary is invalid") from error
        edge_payload = {
            "basis_digest": expected_basis_digest,
            "source": record["source"],
            "target": record["target"],
            "relation_type": record["relation_type"],
            "perspective_ref": perspective,
        }
        semantic_payload = {
            **edge_payload,
            "attributes": attributes,
            "provenance": record["provenance"],
            "quality": original_quality.value,
        }
        if record["semantic_claim_id"] != _digest(semantic_payload):
            raise ValueError(f"declaration[{index}] semantic identity is invalid")
        if record["semantic_claim_id"] <= previous_semantic_claim_id:
            raise ValueError("relationship declarations are not canonically ordered")
        previous_semantic_claim_id = record["semantic_claim_id"]
        contributions = record["contributions"]
        if type(contributions) is not list or not contributions:
            raise ValueError(f"declaration[{index}] contributions are invalid")
        previous_contribution = ""
        for contribution_index, contribution_value in enumerate(contributions):
            contribution = _exact_dict(
                contribution_value,
                frozenset({"producer", "evidence", "occurrence_count"}),
                f"declaration[{index}].contribution[{contribution_index}]",
            )
            producer_key = strict_canonical_json(contribution["producer"])
            if producer_key not in provider_records:
                raise ValueError(f"declaration[{index}] contribution provider is not selected")
            evidence = contribution["evidence"]
            if type(evidence) is not list:
                raise ValueError(f"declaration[{index}] contribution evidence is invalid")
            if evidence != sorted(evidence, key=strict_canonical_json):
                raise ValueError(f"declaration[{index}] contribution evidence is not canonical")
            for evidence_index, evidence_value in enumerate(evidence):
                _evidence_from_projection(
                    evidence_value,
                    artifact_ids=admitted_artifacts,
                    label=f"declaration[{index}].evidence[{evidence_index}]",
                )
            occurrences = contribution["occurrence_count"]
            if type(occurrences) is not int or not 1 <= occurrences <= _JSON_SAFE_INTEGER_MAX:
                raise ValueError(f"declaration[{index}] occurrence count is invalid")
            evidence_total += (
                unknown_evidence_count + len(evidence)
            ) * occurrences
            pre_dedup_charged_bytes += len(
                strict_canonical_json(
                    {
                        "semantic": semantic_payload,
                        "contribution": {
                            "producer": contribution["producer"],
                            "evidence": evidence,
                        },
                    }
                ).encode("utf-8")
            ) * occurrences
            occurrence_total += occurrences
            duplicate_total += occurrences - 1
            canonical_contribution = strict_canonical_json(
                {"producer": contribution["producer"], "evidence": evidence}
            )
            if canonical_contribution <= previous_contribution:
                raise ValueError(f"declaration[{index}] contributions are not canonical")
            previous_contribution = canonical_contribution
        payload = dict(record)
        declaration_id = payload.pop("declaration_id")
        if declaration_id != _digest(payload) or declaration_id in declarations_by_id:
            raise ValueError(f"declaration[{index}] content identity is invalid")
        declarations_by_id[declaration_id] = record
        claims_by_edge.setdefault(strict_canonical_json(edge_payload), []).append(record)

    expected_conflicts: dict[str, str] = {
        edge_key: _digest({"scope": "revision", "edge": json.loads(edge_key)})
        for edge_key, records in claims_by_edge.items()
        if len(records) > 1
    }
    for edge_key, records in claims_by_edge.items():
        expected_ambiguity = expected_conflicts.get(edge_key)
        for record in records:
            if record["ambiguity_group_id"] != expected_ambiguity:
                raise ValueError("relationship ambiguity group is invalid")
            expected_quality = (
                Quality.AMBIGUOUS.value
                if expected_ambiguity is not None
                else record["quality"]
            )
            if record["effective_quality"] != expected_quality:
                raise ValueError("relationship effective quality is invalid")

    # Recompute each conservative edge from the retained claims, including the
    # intersection of known, canonically identical attributes.
    expected_edges: list[dict[str, Any]] = []
    for edge_key in sorted(claims_by_edge):
        records = sorted(claims_by_edge[edge_key], key=lambda item: item["declaration_id"])
        edge = json.loads(edge_key)
        ambiguity = expected_conflicts.get(edge_key)
        common_names = set(records[0]["attributes"]["set_values"])
        for record in records[1:]:
            common_names.intersection_update(record["attributes"]["set_values"])
        common = {
            name: records[0]["attributes"]["set_values"][name]
            for name in sorted(common_names)
            if all(
                record["attributes"]["set_values"][name]
                == records[0]["attributes"]["set_values"][name]
                for record in records[1:]
            )
        }
        evidence_by_key: dict[str, dict[str, Any]] = {}
        for record in records:
            for contribution in record["contributions"]:
                for evidence in contribution["evidence"]:
                    evidence_by_key.setdefault(strict_canonical_json(evidence), evidence)
        resolved: dict[str, Any] = {
            "scope": "revision",
            "source": edge["source"],
            "target": edge["target"],
            "relation_type": edge["relation_type"],
            "attributes": common,
            "provenance": (
                Provenance.CORRELATED.value if ambiguity is not None else records[0]["provenance"]
            ),
            "quality": (
                Quality.AMBIGUOUS.value if ambiguity is not None else records[0]["quality"]
            ),
            "perspective_ref": edge["perspective_ref"],
            "basis_digest": expected_basis_digest,
            "execution_plan_digest": detached_plan.plan_digest,
            "ambiguity_group_id": ambiguity,
            "declaration_ids": [record["declaration_id"] for record in records],
            "evidence": [evidence_by_key[key] for key in sorted(evidence_by_key)],
        }
        resolved["relationship_id"] = _digest(resolved)
        expected_edges.append(resolved)
    if resolved_edges != expected_edges:
        raise ValueError("resolved relationship projection edges are not canonical")

    diagnostic_ids: set[str] = set()
    previous_diagnostic_id = ""
    for index, item in enumerate(diagnostics):
        record = _exact_dict(item, _DIAGNOSTIC_FIELDS, f"diagnostic[{index}]")
        try:
            stage = DiagnosticStage(record["stage"])
            DiagnosticSeverity(record["severity"])
            origin = DiagnosticOrigin(record["origin"])
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"diagnostic[{index}] enum vocabulary is invalid"
            ) from error
        if stage is not DiagnosticStage.RELATIONSHIP_PROJECTION:
            raise ValueError(
                f"diagnostic[{index}] stage is invalid for relationship projection"
            )
        if origin is not DiagnosticOrigin.PLUGIN:
            raise ValueError(f"diagnostic[{index}] origin must be plugin")
        if record["recoverable"] is not True:
            raise ValueError(
                f"diagnostic[{index}] must be a recoverable plug-in diagnostic"
            )
        for text_field, maximum in (
            ("code", MAX_DIAGNOSTIC_CODE_LENGTH),
            ("message", MAX_DIAGNOSTIC_MESSAGE_LENGTH),
        ):
            text = record[text_field]
            if (
                type(text) is not str
                or not text
                or len(text) > maximum
                or "\x00" in text
            ):
                raise ValueError(
                    f"diagnostic[{index}].{text_field} is invalid"
                )
        producer_key = strict_canonical_json(record["producer"])
        if producer_key not in provider_records:
            raise ValueError(f"diagnostic[{index}] provider is not selected")
        evidence = record["evidence"]
        if type(evidence) is not list:
            raise ValueError(f"diagnostic[{index}] evidence is invalid")
        evidence_total += len(evidence)
        for evidence_index, evidence_value in enumerate(evidence):
            _evidence_from_projection(
                evidence_value,
                artifact_ids=admitted_artifacts,
                label=f"diagnostic[{index}].evidence[{evidence_index}]",
            )
        _validate_property_value_projection(
            record["details"],
            label=f"diagnostic[{index}].details",
        )
        try:
            details_type = _RelationshipProjectionPropertyContainerType(
                record["details"].get("type")
            )
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"diagnostic[{index}].details must be a mapping"
            ) from error
        if details_type is not _RelationshipProjectionPropertyContainerType.MAPPING:
            raise ValueError(f"diagnostic[{index}].details must be a mapping")
        payload = dict(record)
        diagnostic_id = payload.pop("diagnostic_id")
        if diagnostic_id != _digest(payload) or diagnostic_id in diagnostic_ids:
            raise ValueError(f"diagnostic[{index}] identity is invalid")
        if diagnostic_id <= previous_diagnostic_id:
            raise ValueError("relationship projection diagnostics are not canonical")
        previous_diagnostic_id = diagnostic_id
        diagnostic_ids.add(diagnostic_id)
        pre_dedup_charged_bytes += len(strict_canonical_json(record).encode("utf-8"))
    if evidence_total > selected_limits.max_evidence_references:
        raise ValueError("relationship projection evidence exceeds configured limits")
    if pre_dedup_charged_bytes > selected_limits.max_serialized_bytes:
        raise ValueError(
            "relationship projection pre-dedup output exceeds the byte limit"
        )

    expected_counts = {
        "provider_count": len(provider_refs),
        "declaration_count": len(declarations),
        "resolved_edge_count": len(resolved_edges),
        "diagnostic_count": len(diagnostics),
        "emitted_declaration_count": occurrence_total,
        "duplicate_emissions_collapsed": duplicate_total,
        "semantic_conflict_groups": len(expected_conflicts),
        "base_resource_count": len(base_resource_ids),
    }
    for field, expected in expected_counts.items():
        if metadata[field] != expected:
            raise ValueError(f"relationship projection {field} is invalid")
    if metadata["emitted_diagnostic_count"] != len(diagnostics):
        raise ValueError("relationship projection emitted diagnostic count is invalid")
    if (
        occurrence_total > selected_limits.max_declarations
        or metadata["emitted_diagnostic_count"] > selected_limits.max_diagnostics
        or metadata["world_reads"] > selected_limits.max_world_reads
        or metadata["world_reads"] < len(base_resource_ids)
    ):
        raise ValueError("relationship projection aggregate counts exceed limits")
    if len(strict_canonical_json(fragment).encode("utf-8")) > selected_limits.max_serialized_bytes:
        raise ValueError("relationship projection fragment exceeds the byte limit")
    detached = json.loads(strict_canonical_json(fragment))
    assert type(detached) is dict
    return detached


def _validated_storage_context(
    *,
    plan: PluginExecutionPlan,
    expected_basis_digest: str | None,
    base_resource_ids: Collection[str],
    relationship_type_directions: Mapping[str, bool],
    perspective_ids: Collection[str],
    artifact_ids: Collection[UUID],
    limits: RelationshipProjectionMaterializationLimits | None,
) -> tuple[
    PluginExecutionPlan,
    PluginExecutionPin,
    str | None,
    frozenset[str],
    Mapping[str, bool],
    frozenset[str],
    frozenset[UUID],
    RelationshipProjectionMaterializationLimits,
]:
    selected_limits = limits or RelationshipProjectionMaterializationLimits()
    if type(selected_limits) is not RelationshipProjectionMaterializationLimits:
        raise TypeError("limits must be exact RelationshipProjectionMaterializationLimits")
    if type(plan) is not PluginExecutionPlan:
        raise TypeError("plan must be an exact PluginExecutionPlan")
    detached_plan = snapshot_plugin_execution_plan(plan)
    primary_pin = primary_parser_execution_pin(detached_plan)
    if expected_basis_digest is not None and (
        type(expected_basis_digest) is not str
        or not expected_basis_digest.startswith("sha256:")
        or len(expected_basis_digest) != 71
        or any(character not in "0123456789abcdef" for character in expected_basis_digest[7:])
    ):
        raise ValueError("expected_basis_digest is invalid")
    try:
        resource_ids = frozenset(base_resource_ids)
        perspectives = frozenset(perspective_ids)
        admitted_artifacts = frozenset(artifact_ids)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise ValueError("relationship projection validation context is invalid") from error
    if (
        len(resource_ids) > selected_limits.max_base_resources
        or any(type(item) is not str or not item or len(item) > 4_096 for item in resource_ids)
    ):
        raise ValueError("base_resource_ids are invalid")
    if len(perspectives) > 10_000 or any(
        type(item) is not str or not item or len(item) > 256 for item in perspectives
    ):
        raise ValueError("perspective_ids are invalid")
    if (
        len(admitted_artifacts) > selected_limits.max_artifact_ids
        or any(type(item) is not UUID for item in admitted_artifacts)
    ):
        raise ValueError("artifact inventory is invalid")
    if not isinstance(relationship_type_directions, Mapping) or len(relationship_type_directions) > 10_000:
        raise ValueError("relationship_type_directions are invalid")
    directions: dict[str, bool] = {}
    for name, directed in relationship_type_directions.items():
        if type(name) is not str or not name or len(name) > 256 or type(directed) is not bool:
            raise ValueError("relationship_type_directions are invalid")
        directions[name] = directed
    return (
        detached_plan,
        primary_pin,
        expected_basis_digest,
        resource_ids,
        MappingProxyType(dict(sorted(directions.items()))),
        perspectives,
        admitted_artifacts,
        selected_limits,
    )


def validate_relationship_projection_storage_fragment(
    value: object,
    *,
    plan: PluginExecutionPlan,
    expected_basis_digest: str | None,
    base_resource_ids: Collection[str],
    relationship_type_directions: Mapping[str, bool],
    perspective_ids: Collection[str],
    artifact_ids: Collection[UUID],
    limits: RelationshipProjectionMaterializationLimits | None = None,
) -> dict[str, Any]:
    """Validate a persisted fragment from already-validated storage context.

    This is the durable reload boundary.  The caller obtains the expected
    basis digest, base resource IDs, relationship directions, perspective IDs,
    and artifact inventory from their independently validated revision fields;
    no executable plug-in object or reconstructed ``ReadOnlyWorld`` is needed.
    """

    context = _validated_storage_context(
        plan=plan,
        expected_basis_digest=expected_basis_digest,
        base_resource_ids=base_resource_ids,
        relationship_type_directions=relationship_type_directions,
        perspective_ids=perspective_ids,
        artifact_ids=artifact_ids,
        limits=limits,
    )
    return _validate_relationship_projection_fragment_context(
        value,
        detached_plan=context[0],
        primary_pin=context[1],
        expected_basis_digest=context[2],
        base_resource_ids=context[3],
        relationship_type_directions=context[4],
        allowed_perspectives=context[5],
        admitted_artifacts=context[6],
        selected_limits=context[7],
    )


def validate_relationship_projection_dataset_fragment(
    value: object,
    *,
    plan: PluginExecutionPlan,
    world: ReadOnlyWorld,
    primary_schema: PluginSchema,
    artifact_ids: Collection[UUID],
    limits: RelationshipProjectionMaterializationLimits | None = None,
) -> dict[str, Any]:
    """Validate a fragment against its exact typed base revision inputs."""

    selected_limits = limits or RelationshipProjectionMaterializationLimits()
    if type(selected_limits) is not RelationshipProjectionMaterializationLimits:
        raise TypeError("limits must be exact RelationshipProjectionMaterializationLimits")
    if type(plan) is not PluginExecutionPlan or type(primary_schema) is not PluginSchema:
        raise TypeError("plan and primary_schema must be exact contract values")
    detached_plan = snapshot_plugin_execution_plan(plan)
    primary_pin = primary_parser_execution_pin(detached_plan)
    if plugin_schema_digest(primary_schema) != primary_pin.schema_digest:
        raise ValueError("primary schema does not match the execution plan")
    try:
        admitted_artifacts = frozenset(artifact_ids)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise ValueError("artifact inventory is invalid") from error
    if (
        len(admitted_artifacts) > selected_limits.max_artifact_ids
        or any(type(item) is not UUID for item in admitted_artifacts)
    ):
        raise ValueError("artifact inventory is invalid")
    if not _selected_pins(detached_plan):
        return validate_relationship_projection_storage_fragment(
            value,
            plan=detached_plan,
            expected_basis_digest=None,
            base_resource_ids=(),
            relationship_type_directions={},
            perspective_ids=(),
            artifact_ids=admitted_artifacts,
            limits=selected_limits,
        )
    basis = world.basis
    if type(basis) is not WorldBasis:
        raise ValueError("base revision world has an invalid basis")
    expected_basis_digest = _digest(
        _contract_projection(basis, artifact_ids=admitted_artifacts)
    )
    resource_ids: set[str] = set()
    emitted_states = 0
    iterator = iter(world.iter_states(limit=selected_limits.max_base_resources + 1))
    try:
        for state in iterator:
            emitted_states += 1
            if emitted_states > selected_limits.max_base_resources:
                raise ValueError("base revision resources exceed the configured limit")
            if type(state) is not ResourceStateView or type(state.resource) is not ResourceKey:
                raise ValueError("base revision world emitted an invalid resource state")
            if state.exists is True:
                resource_ids.add(_resource_projection(state.resource)["resource_id"])
    finally:
        close = getattr(iterator, "close", None)
        if callable(close):
            close()
    return validate_relationship_projection_storage_fragment(
        value,
        plan=detached_plan,
        expected_basis_digest=expected_basis_digest,
        base_resource_ids=resource_ids,
        relationship_type_directions={
            item.relation_type: item.directed
            for item in primary_schema.relationship_types
        },
        perspective_ids={
            item.perspective_id for item in primary_schema.status_perspectives
        },
        artifact_ids=admitted_artifacts,
        limits=selected_limits,
    )


__all__ = [
    "RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION",
    "MaterializedProjectedRelationship",
    "MaterializedRelationshipContribution",
    "MaterializedRelationshipDeclaration",
    "MaterializedRelationshipProjectionDiagnostic",
    "RelationshipProjectionMaterializationError",
    "RelationshipProjectionMaterializationLimits",
    "RelationshipProjectionMaterializationResult",
    "RelationshipProjectionMaterializationStatus",
    "materialize_revision_relationship_projection",
    "not_applicable_relationship_projection_materialization",
    "revision_relationship_projection_selected_pins",
    "validate_relationship_projection_dataset_fragment",
    "validate_relationship_projection_storage_fragment",
]
