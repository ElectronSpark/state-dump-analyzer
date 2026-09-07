"""Small value-normalization primitives shared across core consumers."""

from __future__ import annotations

import math
from enum import Enum
from types import MappingProxyType
from typing import Any

# Largest integer that survives a JSON number -> JavaScript Number -> integer
# round trip exactly.  Browser-visible counters and page coordinates use this
# shared boundary unless their domain is deliberately smaller.
MAX_JSON_SAFE_INTEGER: int = (1 << 53) - 1


def _copy_json_value(
    value: Any, *, immutable: bool, active: set[int], depth: int
) -> Any:
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value
    if value_type not in (dict, MappingProxyType, list, tuple):
        raise ValueError("JSON values must contain only supported JSON types")
    if depth >= 64:
        raise ValueError("JSON values must not exceed 64 nested containers")
    identity = id(value)
    if identity in active:
        raise ValueError("JSON values must not contain cycles")
    active.add(identity)
    try:
        if value_type in (dict, MappingProxyType):
            if any(type(key) is not str for key in value):
                raise ValueError("JSON objects must use string keys")
            copied = {
                key: _copy_json_value(
                    item, immutable=immutable, active=active, depth=depth + 1
                )
                for key, item in value.items()
            }
            return MappingProxyType(copied) if immutable else copied
        copied_items = [
            _copy_json_value(
                item, immutable=immutable, active=active, depth=depth + 1
            )
            for item in value
        ]
        return tuple(copied_items) if immutable else copied_items
    finally:
        active.remove(identity)


def snapshot_json_value(value: Any) -> Any:
    """Detach JSON data into read-only mappings and tuples at every depth.

    Accept built-in JSON scalars, dictionaries and lists, plus the immutable
    mapping/tuple representation returned here. Reject custom objects, cycles,
    non-string object keys, non-finite numbers and nesting beyond 64 containers.
    """

    return _copy_json_value(value, immutable=True, active=set(), depth=0)


def mutable_json_value(value: Any) -> Any:
    """Return independent JSON dictionaries/lists from a validated snapshot.

    The accepted types and validation are the same as ``snapshot_json_value``.
    Nested output containers share no mutable state with the input.
    """

    return _copy_json_value(value, immutable=False, active=set(), depth=0)


def require_bounded_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    """Validate an exact in-memory integer without accepting wire coercions."""

    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


class CanonicalIntegerErrorReason(str, Enum):
    """Closed failure categories for exact decimal-integer admission."""

    GRAMMAR = "grammar"
    BELOW_MINIMUM = "below_minimum"
    ABOVE_MAXIMUM = "above_maximum"
    BIT_LIMIT = "bit_limit"


class CanonicalIntegerError(ValueError):
    """A typed parse failure whose message remains backward compatible."""

    def __init__(
        self,
        message: str,
        *,
        field: str,
        reason: CanonicalIntegerErrorReason,
    ) -> None:
        super().__init__(message)
        self.field: str = field
        self.reason: CanonicalIntegerErrorReason = reason


def parse_canonical_decimal_integer(
    value: Any,
    field: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    max_bits: int | None = None,
) -> int:
    """Parse an exact integer or canonical ASCII decimal integer string.

    The accepted string grammar is ``0|-?[1-9][0-9]*``.  In particular,
    leading zeroes, ``-0``, a leading plus sign, whitespace, Unicode digits,
    booleans, and floating-point values are rejected.  Callers may add their
    domain range without duplicating the wire grammar.
    """

    message = f"{field} must be an integer or canonical decimal integer string"
    if type(value) is int:
        parsed = value
    elif type(value) is str:
        if value == "0":
            parsed = 0
        else:
            negative = value.startswith("-")
            digits = value[1:] if negative else value
            if (
                not digits
                or digits[0] == "0"
                or not digits.isascii()
                or not digits.isdigit()
            ):
                raise CanonicalIntegerError(
                    message,
                    field=field,
                    reason=CanonicalIntegerErrorReason.GRAMMAR,
                )
            try:
                parsed = int(value, 10)
            except ValueError as error:
                # Python may reject an otherwise digit-only, attacker-sized
                # decimal through its interpreter-wide conversion limit.  It
                # remains a wire-grammar admission failure at this boundary,
                # not an untyped implementation detail.
                raise CanonicalIntegerError(
                    message,
                    field=field,
                    reason=CanonicalIntegerErrorReason.GRAMMAR,
                ) from error
    else:
        raise CanonicalIntegerError(
            message,
            field=field,
            reason=CanonicalIntegerErrorReason.GRAMMAR,
        )

    if minimum is not None and parsed < minimum:
        raise CanonicalIntegerError(
            f"{field} must be at least {minimum}",
            field=field,
            reason=CanonicalIntegerErrorReason.BELOW_MINIMUM,
        )
    if maximum is not None and parsed > maximum:
        raise CanonicalIntegerError(
            f"{field} must be no greater than {maximum}",
            field=field,
            reason=CanonicalIntegerErrorReason.ABOVE_MAXIMUM,
        )
    if max_bits is not None:
        if type(max_bits) is not int or max_bits < 0:
            raise ValueError("max_bits must be a non-negative integer or None")
        if parsed.bit_length() > max_bits:
            raise CanonicalIntegerError(
                f"{field} exceeds {max_bits} bits",
                field=field,
                reason=CanonicalIntegerErrorReason.BIT_LIMIT,
            )
    return parsed


def parse_decimal_integer(value: Any, field: str) -> int:
    """Compatibility name for the shared canonical decimal parser."""

    try:
        return parse_canonical_decimal_integer(value, field)
    except ValueError as error:
        raise ValueError(
            f"{field} must be an integer or decimal integer string"
        ) from error


__all__ = [
    "CanonicalIntegerError",
    "CanonicalIntegerErrorReason",
    "MAX_JSON_SAFE_INTEGER",
    "mutable_json_value",
    "parse_canonical_decimal_integer",
    "parse_decimal_integer",
    "require_bounded_integer",
    "snapshot_json_value",
]
