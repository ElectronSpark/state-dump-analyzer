"""Small value-normalization primitives shared across core consumers."""

from __future__ import annotations

from typing import Any


def parse_decimal_integer(value: Any, field: str) -> int:
    """Parse an integer or an unadorned decimal integer string.

    Booleans are rejected even though ``bool`` is an ``int`` subclass. Strings
    intentionally accept only digits with an optional leading minus sign so
    API consumers cannot accidentally broaden their wire format through
    Python's more permissive :func:`int` syntax.
    """

    message = f"{field} must be an integer or decimal integer string"
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, str))
        or (
            isinstance(value, str)
            and not (
                (value.isascii() and value.isdigit())
                or (
                    value.startswith("-")
                    and value[1:].isascii()
                    and value[1:].isdigit()
                )
            )
        )
    ):
        raise ValueError(message)
    try:
        return int(value)
    except (ValueError, OverflowError) as error:
        raise ValueError(message) from error


__all__ = ["parse_decimal_integer"]
