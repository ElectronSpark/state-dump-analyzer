"""Small value-normalization primitives shared across core consumers."""

from __future__ import annotations

from enum import Enum
from typing import Any


# Largest integer that survives a JSON number -> JavaScript Number -> integer
# round trip exactly.  Browser-visible counters and page coordinates use this
# shared boundary unless their domain is deliberately smaller.
MAX_JSON_SAFE_INTEGER: int = (1 << 53) - 1


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
    "parse_canonical_decimal_integer",
    "parse_decimal_integer",
]
