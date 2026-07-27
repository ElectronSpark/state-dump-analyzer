"""Canonical handling for plug-in-owned typed and opaque values.

The core has two established JSON representations with different consumers:

* packet projections preserve their compact wire format; and
* topology matcher keys tag every scalar and container for exact comparison.

This module owns both profiles so UUIDs, bytes, tagged key atoms, tuples, and
the broader opaque matcher value set cannot acquire conflicting collision or
ordering rules in separate services.  It deliberately does not interpret any
plug-in vocabulary.

``key_atom_type`` is injected by :mod:`plugin_api` to avoid a dependency cycle
while retaining ``KeyAtom`` as a public plug-in API type.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any
from uuid import UUID


MAX_TYPED_VALUE_DEPTH = 4
MAX_TYPED_TUPLE_ITEMS = 32
MAX_TYPED_VALUE_UNITS = 1_024
MAX_TYPED_ATOM_PAYLOAD_UNITS = 4_096
MAX_TYPED_INTEGER_BITS = 4_096


class CanonicalValueError(ValueError):
    """A value cannot be represented by the requested canonical profile."""


def _is_key_atom(value: Any, key_atom_type: type[Any] | None) -> bool:
    return key_atom_type is not None and isinstance(value, key_atom_type)


def typed_value_units(
    value: Any,
    label: str,
    *,
    key_atom_type: type[Any],
    depth: int = 0,
) -> int:
    """Validate one bounded, exactly comparable plug-in key value.

    The returned unit count lets callers apply one aggregate bound across an
    ordered set of named values.  Container order and atom types are retained;
    mappings and booleans are intentionally not part of this contract.
    """

    if depth > MAX_TYPED_VALUE_DEPTH:
        raise CanonicalValueError(
            f"{label} supports at most four tuple levels"
        )
    if isinstance(value, bool):
        raise CanonicalValueError(f"Boolean {label} values are forbidden")
    if _is_key_atom(value, key_atom_type):
        payload = value.value
        if isinstance(payload, int) and payload.bit_length() > MAX_TYPED_INTEGER_BITS:
            raise CanonicalValueError(
                f"{label} integer values exceed 4096 bits"
            )
        return 1
    if isinstance(value, int):
        if value.bit_length() > MAX_TYPED_INTEGER_BITS:
            raise CanonicalValueError(
                f"{label} integer values exceed 4096 bits"
            )
        return 1
    if isinstance(value, (str, bytes)):
        if len(value) > MAX_TYPED_ATOM_PAYLOAD_UNITS:
            raise CanonicalValueError(
                f"{label} values exceed 4096 units"
            )
        return 1
    if isinstance(value, UUID):
        return 1
    if isinstance(value, tuple):
        if len(value) > MAX_TYPED_TUPLE_ITEMS:
            raise CanonicalValueError(
                f"{label} tuples support at most 32 values"
            )
        return 1 + sum(
            typed_value_units(
                item,
                label,
                key_atom_type=key_atom_type,
                depth=depth + 1,
            )
            for item in value
        )
    raise CanonicalValueError(
        f"{label} must use KeyValue scalars, KeyAtom, or tuples"
    )


def validate_named_typed_parts(
    parts: Any,
    label: str,
    *,
    key_atom_type: type[Any],
    validate_name: Callable[[str, str], None],
    require_nonempty: bool,
) -> None:
    """Validate one ordered set of named, exact-match typed values."""

    if not isinstance(parts, tuple):
        raise CanonicalValueError(f"{label} must be a tuple")
    minimum = 1 if require_nonempty else 0
    if not minimum <= len(parts) <= MAX_TYPED_TUPLE_ITEMS:
        if require_nonempty:
            raise CanonicalValueError(
                f"{label} requires 1 to 32 typed parts"
            )
        raise CanonicalValueError(
            f"{label} supports at most 32 typed parts"
        )
    names: list[str] = []
    total_units = 0
    for part in parts:
        if (
            not isinstance(part, tuple)
            or len(part) != 2
            or not isinstance(part[0], str)
        ):
            raise CanonicalValueError(
                f"{label} must contain (name, KeyValue) pairs"
            )
        name, value = part
        validate_name(name, f"{label} name")
        names.append(name)
        total_units += typed_value_units(
            value,
            label,
            key_atom_type=key_atom_type,
        )
    if len(names) != len(set(names)):
        raise CanonicalValueError(f"{label} names must be unique")
    if total_units > MAX_TYPED_VALUE_UNITS:
        raise CanonicalValueError(
            f"{label} supports at most 1024 typed value units"
        )


def packet_value_json(
    value: Any,
    *,
    key_atom_type: type[Any],
) -> Any:
    """Encode one validated packet value using the established wire profile."""

    if isinstance(value, bool):
        raise CanonicalValueError(
            "Boolean packet forwarding values are forbidden"
        )
    if _is_key_atom(value, key_atom_type):
        return {
            "type": "key_atom",
            "type_tag": value.type_tag,
            "value": packet_value_json(
                value.value,
                key_atom_type=key_atom_type,
            ),
        }
    if isinstance(value, UUID):
        return {
            "type": "uuid",
            "encoding": "rfc4122",
            "value": str(value),
        }
    if isinstance(value, tuple):
        return {
            "type": "tuple",
            "items": [
                packet_value_json(item, key_atom_type=key_atom_type)
                for item in value
            ],
        }
    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "encoding": "hex",
            "length": len(value),
            "value": value.hex(),
        }
    if isinstance(value, (str, int)) or value is None:
        return value
    raise CanonicalValueError(
        "packet forwarding value contains an unsupported type: "
        f"{type(value).__name__}"
    )


def canonical_json(value: Any) -> str:
    """Return stable compact JSON for an already normalized value."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def opaque_value_json(
    value: Any,
    *,
    key_atom_type: type[Any] | None = None,
) -> dict[str, Any]:
    """Normalize one exact-match opaque value with explicit type tags."""

    if value is None:
        return {"type": "null", "value": None}
    if isinstance(value, bool):
        return {"type": "boolean", "value": value}
    if _is_key_atom(value, key_atom_type):
        return {
            "type": "key_atom",
            "type_tag": value.type_tag,
            "value": opaque_value_json(
                value.value,
                key_atom_type=key_atom_type,
            ),
        }
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        return {
            "type": "number",
            "encoding": "python-float-hex",
            "value": value.hex(),
        }
    if isinstance(value, UUID):
        return {
            "type": "uuid",
            "encoding": "rfc4122",
            "value": str(value),
        }
    if isinstance(value, str):
        return {"type": "string", "value": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        payload = bytes(value)
        return {
            "type": "bytes",
            "encoding": "base64",
            "length": len(payload),
            "value": base64.b64encode(payload).decode("ascii"),
        }
    if isinstance(value, tuple):
        return {
            "type": "tuple",
            "items": [
                opaque_value_json(item, key_atom_type=key_atom_type)
                for item in value
            ],
        }
    if isinstance(value, list):
        return {
            "type": "list",
            "items": [
                opaque_value_json(item, key_atom_type=key_atom_type)
                for item in value
            ],
        }
    if isinstance(value, dict):
        entries = [
            {
                "key": opaque_value_json(key, key_atom_type=key_atom_type),
                "value": opaque_value_json(item, key_atom_type=key_atom_type),
            }
            for key, item in value.items()
        ]
        entries.sort(
            key=lambda entry: (
                canonical_json(entry["key"]),
                canonical_json(entry["value"]),
            )
        )
        return {"type": "mapping", "entries": entries}
    raise CanonicalValueError(
        f"opaque matcher key contains unsupported type {type(value).__name__}"
    )


def canonical_opaque_value(
    value: Any,
    *,
    key_atom_type: type[Any] | None = None,
) -> tuple[dict[str, Any], str]:
    """Return an opaque value's normalized form and stable comparison token."""

    normalized = opaque_value_json(value, key_atom_type=key_atom_type)
    return normalized, canonical_json(normalized)
