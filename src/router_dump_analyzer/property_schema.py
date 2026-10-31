"""Bounded structural property validation; opaque type names stay plug-in-owned."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .plugin_api import PropertyDescriptor, PropertyPatch


def validate_property_patch(
    patch: PropertyPatch,
    descriptors: tuple[PropertyDescriptor, ...],
) -> None:
    """Check supplied fields, including dotted updates, without requiring absent fields."""
    by_name = {item.name: item for item in descriptors}
    typed_roots = tuple(item.name for item in descriptors if (
        item.validate_type or item.properties or item.items is not None or not item.nullable
    ))

    def typed(name: str) -> bool:
        return any(name == root or name.startswith(root + ".") or root.startswith(name + ".")
                   for root in typed_roots)

    def resolve(name: str) -> PropertyDescriptor | None:
        if name in by_name:
            return by_name[name]
        parts = name.split(".")
        current = by_name.get(parts[0])
        for part in parts[1:]:
            if current is None:
                return None  # Legacy dotted descriptors are validated individually.
            if not current.properties and current.value_type not in {"array", "object"}:
                # Opaque semantic types have no core-defined shape.
                if current.value_type in {"string", "integer", "number", "boolean", "bytes"}:
                    raise ValueError(f"property {name!r} traverses a scalar")
                return None
            if current.value_type == "array":
                raise ValueError(f"property {name!r} cannot patch an array element by field path")
            if not current.properties:
                return None
            current = next((item for item in current.properties if item.name == part), None)
            if current is None:
                raise ValueError(f"property {name!r} references an undeclared nested field")
        return current

    units = 0

    def check(value: Any, rule: PropertyDescriptor, path: str, depth: int = 0) -> None:
        nonlocal units
        units += 1
        if units > 4_096 or depth > 16:
            raise ValueError("property value exceeds its structural validation budget")
        if value is None:
            if not rule.nullable:
                raise ValueError(f"property {path!r} cannot be null")
            return
        expected = rule.value_type
        matches = {
            "string": type(value) is str,
            "integer": type(value) is int,
            "number": type(value) is int or type(value) is float,
            "boolean": type(value) is bool,
            "bytes": type(value) is bytes,
            "object": isinstance(value, Mapping),
            "array": type(value) is tuple or type(value) is list,
        }
        if expected in matches and not matches[expected]:
            raise ValueError(f"property {path!r} requires {expected}")
        if expected == "object" and rule.properties:
            children = {item.name: item for item in rule.properties}
            if len(value) > 1_024:
                raise ValueError("property object exceeds 1024 fields")
            for index, (key, child) in enumerate(value.items()):
                if index >= 1_024:
                    raise ValueError("property object exceeds 1024 fields")
                if key not in children:
                    raise ValueError(f"property {path!r} references an undeclared nested field")
                check(child, children[key], f"{path}.{key}", depth + 1)
        elif expected == "array" and rule.items is not None:
            if len(value) > 1_024:
                raise ValueError("property array exceeds 1024 items")
            for index, child in enumerate(value):
                check(child, rule.items, f"{path}[{index}]", depth + 1)

    for name, value in patch.set_values.items():
        if not typed(name):
            continue
        rule = resolve(name)
        if rule is not None:
            check(value, rule, name)
        if any(declared.startswith(name + ".") for declared in typed_roots):
            # A root replacement may contain declared dotted leaf properties.
            for declared_name, leaf in by_name.items():
                if not declared_name.startswith(name + "."):
                    continue
                if not typed(declared_name):
                    continue
                nested = value
                for part in declared_name[len(name) + 1:].split("."):
                    if not isinstance(nested, Mapping):
                        raise ValueError(f"property {declared_name!r} traverses a scalar")  # noqa: TRY004 - structural contract error
                    if part not in nested:
                        break
                    nested = nested[part]
                else:
                    check(nested, leaf, declared_name)
    for name in (*patch.remove_fields, *(item.name for item in patch.unknown_fields)):
        if typed(name):
            resolve(name)


__all__ = ["validate_property_patch"]
