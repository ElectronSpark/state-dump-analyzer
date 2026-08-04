"""Strict JSON-wire helpers shared by private-analysis value contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from ..value_core import parse_canonical_decimal_integer


class SealedContractValue:
    """Allow direct contract declarations but reject derived runtime values."""

    __slots__ = ()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if any(
            base is not SealedContractValue
            and issubclass(base, SealedContractValue)
            for base in cls.__bases__
        ):
            raise TypeError("private-analysis contract values cannot be subclassed")


def exact_json_object(
    value: object,
    label: str,
    fields: set[str],
) -> dict[str, Any]:
    """Require one built-in dictionary with exactly the declared members."""

    if type(value) is not dict or len(value) != len(fields):
        raise ValueError(f"{label} must contain exactly {sorted(fields)}")
    if any(type(key) is not str for key in value) or set(value) != fields:
        raise ValueError(f"{label} must contain exactly {sorted(fields)}")
    return value


def exact_contract_version(value: object, expected: str, label: str) -> str:
    """Require an exact built-in string equal to one declared version."""

    if type(value) is not str or value != expected:
        raise ValueError(f"unsupported {label} version")
    return value


def bounded_utf8_text(value: object, label: str, maximum_bytes: int) -> str:
    """Reject an oversized or non-scalar string before a downstream parser."""

    if type(value) is not str or not value:
        raise TypeError(f"{label} must be a non-empty string")
    if len(value) > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} encoded UTF-8 bytes")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain Unicode scalar values") from error
    if len(encoded) > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} encoded UTF-8 bytes")
    return value


def bounded_canonical_decimal_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    """Parse a decimal without scanning text wider than its numeric domain."""

    if type(value) is not str:
        raise TypeError(f"{label} must be a canonical decimal string")
    maximum_characters = max(len(str(minimum)), len(str(maximum)))
    if not value or len(value) > maximum_characters:
        raise ValueError(f"{label} is outside its canonical decimal domain")
    return parse_canonical_decimal_integer(
        value,
        label,
        minimum=minimum,
        maximum=maximum,
    )


def strict_string_enum[EnumType: StrEnum](
    enum_type: type[EnumType],
    value: object,
    label: str,
) -> EnumType:
    """Parse one closed string enum without coercing another scalar type."""

    if type(value) is not str:
        raise TypeError(f"{label} must be a string")
    maximum_characters = max(len(member.value) for member in enum_type)
    if len(value) > maximum_characters:
        raise ValueError(f"{label} is unsupported")
    try:
        return enum_type(value)
    except ValueError as error:
        raise ValueError(f"{label} is unsupported") from error


def reject_duplicate_json_object_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate member names."""

    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON object member")
    return result


__all__ = [
    "SealedContractValue",
    "bounded_canonical_decimal_integer",
    "bounded_utf8_text",
    "exact_contract_version",
    "exact_json_object",
    "reject_duplicate_json_object_pairs",
    "strict_string_enum",
]
