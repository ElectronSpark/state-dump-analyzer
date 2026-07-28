"""Small validation combinators shared by public contract boundaries.

These helpers intentionally do not know router, protocol, or plug-in
vocabulary.  They make strict scalar/container semantics concise and keep
error messages attached to the caller-provided field label.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
from typing import Any, Never, cast


def _raise(message: str | None, fallback: str) -> Never:
    raise ValueError(message or fallback)


def bounded_string(
    value: object,
    label: str,
    *,
    minimum: int = 1,
    maximum: int = 256,
    message: str | None = None,
) -> str:
    """Return a length-bounded string without coercing other scalar types."""

    if minimum < 0 or maximum < minimum:
        raise ValueError("string bounds are invalid")
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _raise(
            message,
            f"{label} must contain {minimum} to {maximum} characters",
        )
    return value


def strict_boolean(
    value: object,
    label: str,
    *,
    message: str | None = None,
) -> bool:
    """Return a real boolean; integers never stand in for booleans."""

    if type(value) is not bool:
        _raise(message, f"{label} must be a boolean")
    return value


def strict_integer(
    value: object,
    label: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    exact: bool = True,
    message: str | None = None,
) -> int:
    """Return a non-boolean integer and optionally enforce a closed range.

    ``exact=False`` is reserved for compatibility boundaries that historically
    accepted integer subclasses.
    """

    if minimum is not None and maximum is not None and minimum > maximum:
        raise ValueError("integer bounds are invalid")
    is_integer = (
        type(value) is int
        if exact
        else isinstance(value, int) and not isinstance(value, bool)
    )
    if not is_integer:
        _raise(message, f"{label} must be an integer")
    result = cast(int, value)
    if minimum is not None and result < minimum:
        _raise(message, f"{label} must be at least {minimum}")
    if maximum is not None and result > maximum:
        _raise(message, f"{label} must be at most {maximum}")
    return result


def coerce_enum[EnumType: Enum](
    enum_type: type[EnumType],
    value: object,
    label: str,
    *,
    message: str | None = None,
) -> EnumType:
    """Return one declared enum member with a uniform boundary error."""

    try:
        return enum_type(value)
    except (TypeError, ValueError) as error:
        raise ValueError(message or f"{label} is not supported") from error


def typed_tuple[ItemType](
    value: object,
    label: str,
    item_type: type[ItemType] | tuple[type[Any], ...],
    *,
    minimum: int = 0,
    maximum: int = 1_024,
    unique_key: Callable[[ItemType], Any] | None = None,
    tuple_message: str | None = None,
    bounds_message: str | None = None,
    item_message: str | None = None,
    duplicate_message: str | None = None,
) -> tuple[ItemType, ...]:
    """Validate a bounded tuple, its item types, and optional uniqueness."""

    if minimum < 0 or maximum < minimum:
        raise ValueError("tuple bounds are invalid")
    if not isinstance(value, tuple):
        _raise(tuple_message, f"{label} must be a tuple")
    raw_items = value
    if not minimum <= len(raw_items) <= maximum:
        _raise(
            bounds_message,
            f"{label} must contain {minimum} to {maximum} items",
        )
    if any(not isinstance(item, item_type) for item in raw_items):
        _raise(item_message, f"{label} contains an unsupported item")
    result = cast(tuple[ItemType, ...], raw_items)
    if unique_key is not None:
        keys = [unique_key(item) for item in result]
        if len(keys) != len(set(keys)):
            _raise(
                duplicate_message,
                f"{label} must not contain duplicates",
            )
    return result


def validity_bounds(
    minimum_value: object,
    maximum_value: object,
    label: str,
    *,
    allow_open: bool = True,
    allow_partial: bool = False,
    exact_integers: bool = True,
    minimum_type_message: str | None = None,
    maximum_type_message: str | None = None,
    presence_message: str | None = None,
    order_message: str | None = None,
) -> tuple[int | None, int | None]:
    """Validate an ordered pair of optional exact-integer bounds."""

    if minimum_value is None and maximum_value is None:
        if allow_open:
            return None, None
        _raise(
            presence_message,
            f"{label} bounds must both be present",
        )
    if not allow_partial and (minimum_value is None or maximum_value is None):
        _raise(
            presence_message,
            f"{label} bounds must both be present or both be absent",
        )
    minimum_ns = (
        None
        if minimum_value is None
        else strict_integer(
            minimum_value,
            f"{label} minimum",
            exact=exact_integers,
            message=minimum_type_message,
        )
    )
    maximum_ns = (
        None
        if maximum_value is None
        else strict_integer(
            maximum_value,
            f"{label} maximum",
            exact=exact_integers,
            message=maximum_type_message,
        )
    )
    if minimum_ns is not None and maximum_ns is not None and minimum_ns > maximum_ns:
        _raise(
            order_message,
            f"{label} minimum must not exceed maximum",
        )
    return minimum_ns, maximum_ns


__all__ = [
    "bounded_string",
    "coerce_enum",
    "strict_boolean",
    "strict_integer",
    "typed_tuple",
    "validity_bounds",
]
