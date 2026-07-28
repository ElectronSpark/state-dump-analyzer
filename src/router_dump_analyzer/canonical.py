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
import binascii
import json
import re
from collections.abc import Callable, Mapping
from math import isfinite
from typing import Any
from uuid import UUID

MAX_TYPED_VALUE_DEPTH = 4
MAX_TYPED_TUPLE_ITEMS = 32
MAX_TYPED_VALUE_UNITS = 1_024
MAX_TYPED_ATOM_PAYLOAD_UNITS = 4_096
MAX_TYPED_INTEGER_BITS = 4_096
MAX_OPAQUE_VALUE_DEPTH = MAX_TYPED_VALUE_DEPTH
MAX_OPAQUE_CONTAINER_ITEMS = MAX_TYPED_TUPLE_ITEMS
MAX_OPAQUE_VALUE_UNITS = MAX_TYPED_VALUE_UNITS
MAX_OPAQUE_ATOM_PAYLOAD_UNITS = MAX_TYPED_ATOM_PAYLOAD_UNITS
MAX_OPAQUE_INTEGER_BITS = MAX_TYPED_INTEGER_BITS
_STANDARD_KEY_ATOM_TAGS = frozenset(
    {"opaque_int", "opaque_uint", "ipv4", "ipv6", "uuid", "bytes"}
)
_PLUGIN_KEY_ATOM_TAG_PATTERN = re.compile(
    r"^plugin:[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*:"
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
)
_KEY_ATOM_MAX_TAG_LENGTH = 128
_CANONICAL_INTEGER_PATTERN = re.compile(r"-?(?:0|[1-9][0-9]*)")
_MAX_OPAQUE_INTEGER_DECIMAL_DIGITS = 1_234


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
        raise CanonicalValueError(f"{label} supports at most four tuple levels")
    if isinstance(value, bool):
        raise CanonicalValueError(f"Boolean {label} values are forbidden")
    if _is_key_atom(value, key_atom_type):
        payload = value.value
        if isinstance(payload, int) and payload.bit_length() > MAX_TYPED_INTEGER_BITS:
            raise CanonicalValueError(f"{label} integer values exceed 4096 bits")
        return 1
    if isinstance(value, int):
        if value.bit_length() > MAX_TYPED_INTEGER_BITS:
            raise CanonicalValueError(f"{label} integer values exceed 4096 bits")
        return 1
    if isinstance(value, (str, bytes)):
        if len(value) > MAX_TYPED_ATOM_PAYLOAD_UNITS:
            raise CanonicalValueError(f"{label} values exceed 4096 units")
        return 1
    if isinstance(value, UUID):
        return 1
    if isinstance(value, tuple):
        if len(value) > MAX_TYPED_TUPLE_ITEMS:
            raise CanonicalValueError(f"{label} tuples support at most 32 values")
        return 1 + sum(
            typed_value_units(
                item,
                label,
                key_atom_type=key_atom_type,
                depth=depth + 1,
            )
            for item in value
        )
    raise CanonicalValueError(f"{label} must use KeyValue scalars, KeyAtom, or tuples")


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
            raise CanonicalValueError(f"{label} requires 1 to 32 typed parts")
        raise CanonicalValueError(f"{label} supports at most 32 typed parts")
    names: list[str] = []
    total_units = 0
    for part in parts:
        if (
            not isinstance(part, tuple)
            or len(part) != 2
            or not isinstance(part[0], str)
        ):
            raise CanonicalValueError(f"{label} must contain (name, KeyValue) pairs")
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
        raise CanonicalValueError(f"{label} supports at most 1024 typed value units")


def packet_value_json(
    value: Any,
    *,
    key_atom_type: type[Any],
) -> Any:
    """Encode one validated packet value using the established wire profile."""

    if isinstance(value, bool):
        raise CanonicalValueError("Boolean packet forwarding values are forbidden")
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
                packet_value_json(item, key_atom_type=key_atom_type) for item in value
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
        f"packet forwarding value contains an unsupported type: {type(value).__name__}"
    )


def canonical_json(value: Any) -> str:
    """Return stable compact JSON for an already normalized value."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def opaque_value_json(
    value: Any,
    *,
    key_atom_type: type[Any] | None = None,
) -> dict[str, Any]:
    """Normalize one bounded exact-match opaque value with explicit type tags."""

    return _opaque_value_json(
        value,
        key_atom_type=key_atom_type,
        container_depth=0,
        active_container_ids=set(),
        units=[0],
    )


def _opaque_value_json(
    value: Any,
    *,
    key_atom_type: type[Any] | None,
    container_depth: int,
    active_container_ids: set[int],
    units: list[int],
) -> dict[str, Any]:
    units[0] += 1
    if units[0] > MAX_OPAQUE_VALUE_UNITS:
        raise CanonicalValueError(
            "opaque matcher keys support at most 1024 value units"
        )

    if value is None:
        return {"type": "null", "value": None}
    if isinstance(value, bool):
        return {"type": "boolean", "value": value}
    if _is_key_atom(value, key_atom_type):
        return {
            "type": "key_atom",
            "type_tag": value.type_tag,
            "value": _opaque_value_json(
                value.value,
                key_atom_type=key_atom_type,
                container_depth=container_depth,
                active_container_ids=active_container_ids,
                units=units,
            ),
        }
    if isinstance(value, int):
        if value.bit_length() > MAX_OPAQUE_INTEGER_BITS:
            raise CanonicalValueError("opaque matcher key integers exceed 4096 bits")
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        if not isfinite(value):
            raise CanonicalValueError(
                "opaque matcher keys require finite floating-point values"
            )
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
        if len(value) > MAX_OPAQUE_ATOM_PAYLOAD_UNITS:
            raise CanonicalValueError(
                "opaque matcher key strings exceed 4096 characters"
            )
        return {"type": "string", "value": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        payload = bytes(value)
        if len(payload) > MAX_OPAQUE_ATOM_PAYLOAD_UNITS:
            raise CanonicalValueError(
                "opaque matcher key byte strings exceed 4096 bytes"
            )
        return {
            "type": "bytes",
            "encoding": "base64",
            "length": len(payload),
            "value": base64.b64encode(payload).decode("ascii"),
        }
    if isinstance(value, (tuple, list, dict)):
        child_container_depth = container_depth + 1
        if child_container_depth > MAX_OPAQUE_VALUE_DEPTH:
            raise CanonicalValueError(
                "opaque matcher keys support at most four container levels"
            )
        if len(value) > MAX_OPAQUE_CONTAINER_ITEMS:
            raise CanonicalValueError(
                "opaque matcher key containers support at most 32 items"
            )
        container_id = id(value)
        if container_id in active_container_ids:
            raise CanonicalValueError(
                "opaque matcher keys must not contain reference cycles"
            )
        active_container_ids.add(container_id)
        try:
            if isinstance(value, tuple):
                return {
                    "type": "tuple",
                    "items": [
                        _opaque_value_json(
                            item,
                            key_atom_type=key_atom_type,
                            container_depth=child_container_depth,
                            active_container_ids=active_container_ids,
                            units=units,
                        )
                        for item in value
                    ],
                }
            if isinstance(value, list):
                return {
                    "type": "list",
                    "items": [
                        _opaque_value_json(
                            item,
                            key_atom_type=key_atom_type,
                            container_depth=child_container_depth,
                            active_container_ids=active_container_ids,
                            units=units,
                        )
                        for item in value
                    ],
                }
            entries = [
                {
                    "key": _opaque_value_json(
                        key,
                        key_atom_type=key_atom_type,
                        container_depth=child_container_depth,
                        active_container_ids=active_container_ids,
                        units=units,
                    ),
                    "value": _opaque_value_json(
                        item,
                        key_atom_type=key_atom_type,
                        container_depth=child_container_depth,
                        active_container_ids=active_container_ids,
                        units=units,
                    ),
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
        finally:
            active_container_ids.remove(container_id)
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


def normalized_opaque_value_json(value: Any) -> dict[str, Any]:
    """Validate and canonicalize one already-normalized opaque value.

    This is deliberately separate from :func:`opaque_value_json`: callers
    must know whether they hold a raw plug-in value or its tagged transport
    representation.  Treating the latter as raw data would count transport
    dictionaries and arrays as logical containers and would change its exact
    identity.
    """

    return _normalized_opaque_value_json(
        value,
        container_depth=0,
        units=[0],
    )


def _normalized_fields(
    value: Any,
    expected: frozenset[str],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CanonicalValueError(
            "normalized opaque matcher values have an invalid tagged shape"
        )
    try:
        actual = frozenset(value)
    except TypeError as error:
        raise CanonicalValueError(
            "normalized opaque matcher object fields must be strings"
        ) from error
    if any(not isinstance(field, str) for field in actual) or actual != expected:
        raise CanonicalValueError(
            "normalized opaque matcher values have an invalid tagged shape"
        )
    return value


def _normalized_opaque_value_json(
    value: Any,
    *,
    container_depth: int,
    units: list[int],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CanonicalValueError(
            "normalized opaque matcher values require a tagged object"
        )
    tagged = value
    value_type = tagged.get("type")
    if not isinstance(value_type, str):
        raise CanonicalValueError(
            "normalized opaque matcher values require a string type tag"
        )

    units[0] += 1
    if units[0] > MAX_OPAQUE_VALUE_UNITS:
        raise CanonicalValueError(
            "opaque matcher keys support at most 1024 value units"
        )

    if value_type == "null":
        tagged = _normalized_fields(value, frozenset({"type", "value"}))
        if tagged["value"] is not None:
            raise CanonicalValueError(
                "normalized null matcher values require a null payload"
            )
        return {"type": "null", "value": None}

    if value_type == "boolean":
        tagged = _normalized_fields(value, frozenset({"type", "value"}))
        if type(tagged["value"]) is not bool:
            raise CanonicalValueError(
                "normalized boolean matcher values require a boolean payload"
            )
        return {"type": "boolean", "value": tagged["value"]}

    if value_type == "integer":
        tagged = _normalized_fields(value, frozenset({"type", "value"}))
        payload = tagged["value"]
        if (
            not isinstance(payload, str)
            or _CANONICAL_INTEGER_PATTERN.fullmatch(payload) is None
        ):
            raise CanonicalValueError(
                "normalized integer matcher values require canonical decimal text"
            )
        digits = payload.removeprefix("-")
        if len(digits) > _MAX_OPAQUE_INTEGER_DECIMAL_DIGITS:
            raise CanonicalValueError(
                "opaque matcher key integers exceed 4096 bits"
            )
        try:
            integer = int(payload)
        except ValueError as error:
            raise CanonicalValueError(
                "normalized integer matcher values contain invalid decimal text"
            ) from error
        if integer.bit_length() > MAX_OPAQUE_INTEGER_BITS:
            raise CanonicalValueError("opaque matcher key integers exceed 4096 bits")
        return {"type": "integer", "value": payload}

    if value_type == "number":
        tagged = _normalized_fields(
            value,
            frozenset({"type", "encoding", "value"}),
        )
        if tagged["encoding"] != "python-float-hex" or not isinstance(
            tagged["value"], str
        ):
            raise CanonicalValueError(
                "normalized number matcher values require python-float-hex encoding"
            )
        try:
            number = float.fromhex(tagged["value"])
        except (OverflowError, ValueError) as error:
            raise CanonicalValueError(
                "normalized number matcher values contain invalid hexadecimal text"
            ) from error
        if not isfinite(number) or number.hex() != tagged["value"]:
            raise CanonicalValueError(
                "normalized number matcher values require canonical finite floats"
            )
        return {
            "type": "number",
            "encoding": "python-float-hex",
            "value": tagged["value"],
        }

    if value_type == "uuid":
        tagged = _normalized_fields(
            value,
            frozenset({"type", "encoding", "value"}),
        )
        if tagged["encoding"] != "rfc4122" or not isinstance(
            tagged["value"], str
        ):
            raise CanonicalValueError(
                "normalized UUID matcher values require rfc4122 encoding"
            )
        try:
            identifier = UUID(tagged["value"])
        except (AttributeError, ValueError) as error:
            raise CanonicalValueError(
                "normalized UUID matcher values contain an invalid UUID"
            ) from error
        if str(identifier) != tagged["value"]:
            raise CanonicalValueError(
                "normalized UUID matcher values require canonical UUID text"
            )
        return {
            "type": "uuid",
            "encoding": "rfc4122",
            "value": tagged["value"],
        }

    if value_type == "string":
        tagged = _normalized_fields(value, frozenset({"type", "value"}))
        payload = tagged["value"]
        if not isinstance(payload, str):
            raise CanonicalValueError(
                "normalized string matcher values require a string payload"
            )
        if len(payload) > MAX_OPAQUE_ATOM_PAYLOAD_UNITS:
            raise CanonicalValueError(
                "opaque matcher key strings exceed 4096 characters"
            )
        return {"type": "string", "value": payload}

    if value_type == "bytes":
        tagged = _normalized_fields(
            value,
            frozenset({"type", "encoding", "length", "value"}),
        )
        encoded = tagged["value"]
        length = tagged["length"]
        if (
            tagged["encoding"] != "base64"
            or not isinstance(encoded, str)
            or type(length) is not int
            or length < 0
        ):
            raise CanonicalValueError(
                "normalized byte matcher values require base64 encoding and length"
            )
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise CanonicalValueError(
                "normalized byte matcher values contain invalid base64"
            ) from error
        if (
            len(payload) != length
            or base64.b64encode(payload).decode("ascii") != encoded
        ):
            raise CanonicalValueError(
                "normalized byte matcher values have inconsistent encoding or length"
            )
        if len(payload) > MAX_OPAQUE_ATOM_PAYLOAD_UNITS:
            raise CanonicalValueError(
                "opaque matcher key byte strings exceed 4096 bytes"
            )
        return {
            "type": "bytes",
            "encoding": "base64",
            "length": length,
            "value": encoded,
        }

    if value_type == "key_atom":
        tagged = _normalized_fields(
            value,
            frozenset({"type", "type_tag", "value"}),
        )
        type_tag = tagged["type_tag"]
        if (
            not isinstance(type_tag, str)
            or not type_tag
            or len(type_tag) > _KEY_ATOM_MAX_TAG_LENGTH
            or (
                type_tag not in _STANDARD_KEY_ATOM_TAGS
                and _PLUGIN_KEY_ATOM_TAG_PATTERN.fullmatch(type_tag) is None
            )
        ):
            raise CanonicalValueError(
                "normalized key atoms require a supported or plug-in-namespaced tag"
            )
        raw_payload = tagged["value"]
        if not isinstance(raw_payload, Mapping):
            raise CanonicalValueError(
                "normalized key atoms require one tagged scalar payload"
            )
        payload_type = raw_payload.get("type")
        allowed_payload_types = {
            "opaque_int": {"integer"},
            "opaque_uint": {"integer"},
            "ipv4": {"integer"},
            "ipv6": {"bytes"},
            "uuid": {"bytes"},
            "bytes": {"bytes"},
        }.get(type_tag, {"integer", "string", "bytes", "uuid"})
        if (
            not isinstance(payload_type, str)
            or payload_type not in allowed_payload_types
        ):
            raise CanonicalValueError(
                "normalized key atom payload does not match its type tag"
            )
        payload = _normalized_opaque_value_json(
            raw_payload,
            container_depth=container_depth,
            units=units,
        )
        if payload["type"] == "integer":
            integer = int(payload["value"])
            if type_tag == "opaque_uint" and integer < 0:
                raise CanonicalValueError(
                    "normalized opaque_uint key atoms must be non-negative"
                )
            if type_tag == "ipv4" and not 0 <= integer <= 0xFFFFFFFF:
                raise CanonicalValueError(
                    "normalized ipv4 key atoms must fit in 32 bits"
                )
        if type_tag in {"ipv6", "uuid"} and payload.get("length") != 16:
            raise CanonicalValueError(
                f"normalized {type_tag} key atoms require exactly 16 bytes"
            )
        return {
            "type": "key_atom",
            "type_tag": type_tag,
            "value": payload,
        }

    if value_type in {"tuple", "list", "mapping"}:
        next_container_depth = container_depth + 1
        if next_container_depth > MAX_OPAQUE_VALUE_DEPTH:
            raise CanonicalValueError(
                "opaque matcher keys support at most four container levels"
            )

        if value_type in {"tuple", "list"}:
            tagged = _normalized_fields(value, frozenset({"type", "items"}))
            raw_items = tagged["items"]
            if not isinstance(raw_items, list):
                raise CanonicalValueError(
                    "normalized tuple and list matcher values require an items array"
                )
            if len(raw_items) > MAX_OPAQUE_CONTAINER_ITEMS:
                raise CanonicalValueError(
                    "opaque matcher key containers support at most 32 items"
                )
            return {
                "type": value_type,
                "items": [
                    _normalized_opaque_value_json(
                        item,
                        container_depth=next_container_depth,
                        units=units,
                    )
                    for item in raw_items
                ],
            }

        tagged = _normalized_fields(value, frozenset({"type", "entries"}))
        raw_entries = tagged["entries"]
        if not isinstance(raw_entries, list):
            raise CanonicalValueError(
                "normalized mapping matcher values require an entries array"
            )
        if len(raw_entries) > MAX_OPAQUE_CONTAINER_ITEMS:
            raise CanonicalValueError(
                "opaque matcher key containers support at most 32 items"
            )
        entries: list[dict[str, Any]] = []
        key_tokens: set[str] = set()
        for raw_entry in raw_entries:
            entry = _normalized_fields(
                raw_entry,
                frozenset({"key", "value"}),
            )
            key = _normalized_opaque_value_json(
                entry["key"],
                container_depth=next_container_depth,
                units=units,
            )
            key_token = canonical_json(key)
            if key_token in key_tokens:
                raise CanonicalValueError(
                    "normalized mapping matcher values require unique keys"
                )
            key_tokens.add(key_token)
            item = _normalized_opaque_value_json(
                entry["value"],
                container_depth=next_container_depth,
                units=units,
            )
            entries.append({"key": key, "value": item})
        entries.sort(
            key=lambda entry: (
                canonical_json(entry["key"]),
                canonical_json(entry["value"]),
            )
        )
        return {"type": "mapping", "entries": entries}

    raise CanonicalValueError(
        f"normalized opaque matcher values use unsupported type tag {value_type!r}"
    )


def canonical_normalized_opaque_value(
    value: Any,
    *,
    typed_key: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Return canonical identity for a tagged opaque transport value.

    ``typed_key`` is the optional serialized comparison token emitted beside
    normalized topology keys.  Supplying it verifies that the cached token and
    normalized value have not diverged.
    """

    if typed_key is not None and not isinstance(typed_key, str):
        raise CanonicalValueError("normalized opaque typed_key must be a string")
    normalized = normalized_opaque_value_json(value)
    token = canonical_json(normalized)
    if typed_key is not None and typed_key != token:
        raise CanonicalValueError(
            "normalized opaque typed_key does not match its tagged value"
        )
    return normalized, token
