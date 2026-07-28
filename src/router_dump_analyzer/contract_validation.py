"""Small validation combinators shared by public contract boundaries.

These helpers intentionally do not know router, protocol, or plug-in
vocabulary.  They make strict scalar/container semantics concise and keep
error messages attached to the caller-provided field label.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from enum import Enum
from math import isfinite
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


def bounded_mapping(
    value: object,
    label: str,
    *,
    maximum_items: int = 128,
    maximum_key_characters: int = 128,
    allow_none: bool = False,
    message: str | None = None,
) -> dict[str, Any]:
    """Return a shallow copy of one bounded string-keyed mapping.

    Recursive value validation remains the caller's responsibility because
    different public contracts intentionally permit different scalar sets.
    Iteration itself is bounded rather than trusting a custom mapping's
    reported length.
    """

    if maximum_items < 0 or maximum_key_characters < 1:
        raise ValueError("mapping bounds are invalid")
    if value is None and allow_none:
        return {}
    if not isinstance(value, Mapping):
        _raise(message, f"{label} must be a mapping")
    result: dict[str, Any] = {}
    for index, (key, nested) in enumerate(value.items()):
        if index >= maximum_items:
            _raise(
                message,
                f"{label} supports at most {maximum_items} items",
            )
        if (
            not isinstance(key, str)
            or not key
            or len(key) > maximum_key_characters
        ):
            _raise(
                message,
                f"{label} keys must contain 1 to "
                f"{maximum_key_characters} characters",
            )
        result[key] = nested
    return result


def validate_bounded_json_value(
    value: object,
    label: str,
    *,
    maximum_depth: int = 16,
    maximum_container_items: int = 1_024,
    maximum_units: int = 4_096,
    maximum_atom_units: int = 65_536,
    maximum_integer_bits: int = 4_096,
) -> None:
    """Validate a bounded value accepted by strict JSON serialization.

    The validator fails before serialization for cycles, non-finite floats,
    non-string mapping keys, and Python-only atoms such as bytes or UUIDs.
    Tuples are accepted because the standard JSON encoder represents them as
    arrays; callers that need to distinguish tuple from list must use a typed
    contract instead.
    """

    if (
        maximum_depth < 0
        or maximum_container_items < 0
        or maximum_units < 1
        or maximum_atom_units < 0
        or maximum_integer_bits < 0
    ):
        raise ValueError("JSON value bounds are invalid")

    units = [0]
    active_container_ids: set[int] = set()

    def validate(nested: object, depth: int) -> None:
        if depth > maximum_depth:
            raise ValueError(
                f"{label} supports at most {maximum_depth} container levels"
            )
        units[0] += 1
        if units[0] > maximum_units:
            raise ValueError(
                f"{label} supports at most {maximum_units} value units"
            )

        if nested is None or type(nested) is bool:
            return
        if isinstance(nested, int) and not isinstance(nested, bool):
            if nested.bit_length() > maximum_integer_bits:
                raise ValueError(
                    f"{label} integers exceed {maximum_integer_bits} bits"
                )
            return
        if isinstance(nested, float):
            if not isfinite(nested):
                raise ValueError(
                    f"{label} floats must be finite JSON numbers"
                )
            return
        if isinstance(nested, str):
            if len(nested) > maximum_atom_units:
                raise ValueError(
                    f"{label} strings exceed {maximum_atom_units} characters"
                )
            return
        if isinstance(nested, dict):
            container_id = id(nested)
            if container_id in active_container_ids:
                raise ValueError(f"{label} must not contain reference cycles")
            active_container_ids.add(container_id)
            try:
                for index, (key, child) in enumerate(nested.items()):
                    if index >= maximum_container_items:
                        raise ValueError(
                            f"{label} mappings support at most "
                            f"{maximum_container_items} items"
                        )
                    if not isinstance(key, str):
                        _raise(None, f"{label} mappings require string keys")
                    if len(key) > maximum_atom_units:
                        raise ValueError(
                            f"{label} mapping keys exceed "
                            f"{maximum_atom_units} characters"
                        )
                    validate(child, depth + 1)
            finally:
                active_container_ids.remove(container_id)
            return
        if isinstance(nested, Mapping):
            raise ValueError(
                f"{label} contains non-JSON mapping type "
                f"{type(nested).__name__}"
            )
        if isinstance(nested, (list, tuple)):
            container_id = id(nested)
            if container_id in active_container_ids:
                raise ValueError(f"{label} must not contain reference cycles")
            active_container_ids.add(container_id)
            try:
                for index, child in enumerate(nested):
                    if index >= maximum_container_items:
                        raise ValueError(
                            f"{label} arrays support at most "
                            f"{maximum_container_items} items"
                        )
                    validate(child, depth + 1)
            finally:
                active_container_ids.remove(container_id)
            return
        raise ValueError(
            f"{label} contains non-JSON type {type(nested).__name__}"
        )

    validate(value, 0)


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
    "bounded_mapping",
    "bounded_string",
    "coerce_enum",
    "strict_boolean",
    "strict_integer",
    "typed_tuple",
    "validate_bounded_json_value",
    "validity_bounds",
]
