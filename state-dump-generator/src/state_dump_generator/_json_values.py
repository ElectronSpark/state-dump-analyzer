"""Shared JSON projection mechanics with explicit generator boundary policies."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any


def stable_json_key(value: Any, *, allow_nan: bool = False) -> str:
    return json.dumps(
        value,
        allow_nan=allow_nan,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def plain_value(
    value: Any,
    *,
    set_sort_key: Callable[[Any], str] | None = None,
    path_strings: bool = False,
    error_type: type[Exception] = TypeError,
    unsupported_message: str = "cannot serialize {kind}",
) -> Any:
    """Project nested records without broadening a caller's accepted values.

    CLI accepts ordinary records only; HTTP additionally permits sorted sets;
    archives also permit paths and require finite values in set sort keys.
    """

    def project(item: Any) -> Any:
        if dataclasses.is_dataclass(item) and not isinstance(item, type):
            return {
                field.name: project(getattr(item, field.name))
                for field in dataclasses.fields(item)
            }
        if isinstance(item, Mapping):
            return {str(key): project(member) for key, member in item.items()}
        if isinstance(item, tuple | list):
            return [project(member) for member in item]
        if set_sort_key is not None and isinstance(item, set | frozenset):
            return sorted((project(member) for member in item), key=set_sort_key)
        if path_strings and isinstance(item, Path):
            return str(item)
        if item is None or isinstance(item, str | int | float | bool):
            return item
        to_dict = getattr(item, "to_dict", None)
        if callable(to_dict):
            return project(to_dict())
        raise error_type(unsupported_message.format(kind=type(item).__name__))

    return project(value)
