"""Generic evaluation of plug-in-declared dashboard widgets.

The evaluator deliberately knows nothing about router resource kinds or status
vocabulary.  A plug-in selects resource kinds, fields, filters, columns, and
aggregations; the core applies those declarations to authoritative temporal
resource envelopes and enforces output bounds.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from math import isfinite
from typing import Any

_CORE_TABLE_ENVELOPE_FIELDS = (
    "resource_id",
    "kind",
    "layer",
    "label",
    "exists",
    "status",
    "status_class",
    "valid_from_ns",
    "valid_to_ns",
    "source_event_uid",
    "quality",
)
_MAX_EQUALITY_DEPTH = 16
_MAX_EQUALITY_CONTAINER_ITEMS = 1_024
_MAX_EQUALITY_UNITS = 4_096
_MAX_EQUALITY_ATOM_UNITS = 65_536
_MAX_EQUALITY_INTEGER_BITS = 4_096


def dashboard_field_value(row: Mapping[str, Any], field: str | None) -> Any:
    """Resolve a safe descriptor field without evaluating expressions."""

    if not field:
        return None
    parts = str(field).split(".")

    def descend(value: Any, path: Sequence[str]) -> Any:
        current = value
        for part in path:
            if not isinstance(current, Mapping) or part not in current:
                return None
            current = current[part]
        return current

    direct = descend(row, parts)
    if direct is not None or len(parts) > 1:
        return direct
    # Unqualified legacy fields are resolved predictably.  The plug-in still
    # owns the field name; the core only searches the generic envelope scopes.
    name = parts[0]
    for scope in (
        row.get("state"),
        row.get("key"),
        (row.get("resource") or {}).get("state")
        if isinstance(row.get("resource"), Mapping)
        else None,
        (row.get("resource") or {}).get("key")
        if isinstance(row.get("resource"), Mapping)
        else None,
    ):
        if isinstance(scope, Mapping) and name in scope:
            return scope[name]
    return None


def _comparable(value: Any) -> str | None:
    if value is None:
        return "null"
    if isinstance(value, (dict, list, tuple)):
        try:
            _equality_key(value)
        except ValueError:
            return None
        try:
            return json.dumps(
                value,
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            )
        except (TypeError, ValueError):
            # Equality remains well-defined for type-rich mappings, but their
            # Python representation is not a stable cross-process sort token.
            return None
    return str(value)


def _equality_key(
    value: Any,
    *,
    _depth: int = 0,
    _active_container_ids: set[int] | None = None,
    _units: list[int] | None = None,
) -> tuple[Any, ...]:
    """Return one bounded hashable key without erasing scalar types."""

    if _active_container_ids is None:
        _active_container_ids = set()
    if _units is None:
        _units = [0]
    if _depth > _MAX_EQUALITY_DEPTH:
        raise ValueError("dashboard values support at most 16 container levels")
    _units[0] += 1
    if _units[0] > _MAX_EQUALITY_UNITS:
        raise ValueError("dashboard values support at most 4096 comparison units")

    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        if value.bit_length() > _MAX_EQUALITY_INTEGER_BITS:
            raise ValueError("dashboard integers exceed 4096 bits")
        return ("int", value)
    if isinstance(value, float):
        if not isfinite(value):
            return ("float", repr(value))
        return ("float", value)
    if isinstance(value, str):
        if len(value) > _MAX_EQUALITY_ATOM_UNITS:
            raise ValueError("dashboard strings exceed 65536 characters")
        return ("string", value)
    if isinstance(value, bytes):
        if len(value) > _MAX_EQUALITY_ATOM_UNITS:
            raise ValueError("dashboard byte strings exceed 65536 bytes")
        return ("bytes", value)
    if isinstance(value, Mapping):
        if len(value) > _MAX_EQUALITY_CONTAINER_ITEMS:
            raise ValueError("dashboard mappings support at most 1024 items")
        container_id = id(value)
        if container_id in _active_container_ids:
            raise ValueError("dashboard values must not contain reference cycles")
        _active_container_ids.add(container_id)
        try:
            entries = [
                (
                    _equality_key(
                        key,
                        _depth=_depth + 1,
                        _active_container_ids=_active_container_ids,
                        _units=_units,
                    ),
                    _equality_key(
                        nested,
                        _depth=_depth + 1,
                        _active_container_ids=_active_container_ids,
                        _units=_units,
                    ),
                )
                for key, nested in value.items()
            ]
            return (
                "mapping",
                frozenset(
                    Counter(entries).items()
                ),
            )
        finally:
            _active_container_ids.remove(container_id)
    if isinstance(value, (list, tuple)):
        # Tuples are the in-process representation of plug-in Value sequences;
        # JSON transports them as arrays. Treat those two containers alike while
        # retaining the types of every nested item.
        if len(value) > _MAX_EQUALITY_CONTAINER_ITEMS:
            raise ValueError("dashboard sequences support at most 1024 items")
        container_id = id(value)
        if container_id in _active_container_ids:
            raise ValueError("dashboard values must not contain reference cycles")
        _active_container_ids.add(container_id)
        try:
            return (
                "sequence",
                tuple(
                    _equality_key(
                        item,
                        _depth=_depth + 1,
                        _active_container_ids=_active_container_ids,
                        _units=_units,
                    )
                    for item in value
                ),
            )
        finally:
            _active_container_ids.remove(container_id)
    raise ValueError(
        f"dashboard values contain unsupported type {type(value).__name__}"
    )


def _comparison_key(value: Any) -> tuple[Any, ...] | None:
    try:
        return _equality_key(value)
    except ValueError:
        return None


def dashboard_filter_matches(
    row: Mapping[str, Any], descriptor: Mapping[str, Any]
) -> bool:
    actual = dashboard_field_value(row, str(descriptor.get("field") or ""))
    expected = descriptor.get("value")
    operator = str(descriptor.get("operator") or "eq")
    if operator == "eq":
        actual_key = _comparison_key(actual)
        expected_key = _comparison_key(expected)
        return (
            actual_key is not None
            and expected_key is not None
            and actual_key == expected_key
        )
    if operator == "not_eq":
        actual_key = _comparison_key(actual)
        expected_key = _comparison_key(expected)
        return (
            actual_key is not None
            and expected_key is not None
            and actual_key != expected_key
        )
    if operator in {"in", "not_in"}:
        candidates = expected if isinstance(expected, (list, tuple)) else ()
        actual_key = _comparison_key(actual)
        candidate_keys = [_comparison_key(item) for item in candidates]
        if actual_key is None or any(key is None for key in candidate_keys):
            return False
        found = any(actual_key == key for key in candidate_keys)
        return found if operator == "in" else not found
    if operator == "exists":
        return (actual is not None) is bool(True if expected is None else expected)
    if operator == "contains":
        if isinstance(actual, (list, tuple)):
            expected_key = _comparison_key(expected)
            if expected_key is None:
                return False
            return any(
                item_key == expected_key
                for item in actual
                if (item_key := _comparison_key(item)) is not None
            )
        if isinstance(actual, str) and isinstance(expected, str):
            return expected.casefold() in actual.casefold()
        if isinstance(actual, bytes) and isinstance(expected, bytes):
            return expected in actual
        if isinstance(actual, Mapping) and isinstance(expected, str):
            comparable = _comparable(actual)
            return (
                comparable is not None and expected.casefold() in comparable.casefold()
            )
        return False
    return False


def _widget_rows(
    rows: Sequence[Mapping[str, Any]], descriptor: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    kinds = {str(item) for item in descriptor.get("resource_kinds", ())}
    include_absent = bool(descriptor.get("include_absent", False))
    filters = [
        item for item in descriptor.get("filters", ()) if isinstance(item, Mapping)
    ]
    return [
        row
        for row in rows
        if (not kinds or str(row.get("kind")) in kinds)
        and (include_absent or row.get("exists") is True)
        and all(dashboard_filter_matches(row, item) for item in filters)
    ]


def _statistic(
    rows: Sequence[Mapping[str, Any]], descriptor: Mapping[str, Any]
) -> dict[str, Any]:
    matching = _widget_rows(rows, descriptor)
    field = descriptor.get("field")
    values = [
        value
        for row in matching
        if (value := dashboard_field_value(row, str(field) if field else None))
        is not None
    ]
    aggregation = str(descriptor.get("aggregation") or "count")
    statistic_value: Any = None
    sample_count = len(values)
    if aggregation == "count":
        statistic_value = len(matching)
        sample_count = len(matching)
    elif aggregation == "count_distinct":
        keys = [key for item in values if (key := _comparison_key(item)) is not None]
        statistic_value = len(set(keys))
        sample_count = len(keys)
    elif aggregation in {"sum", "average", "minimum", "maximum"}:
        numeric: list[int | float] = []
        for item in values:
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                continue
            if isinstance(item, float) and not isfinite(item):
                continue
            numeric.append(item)
        sample_count = len(numeric)
        if aggregation == "sum":
            statistic_value = sum(numeric)
        elif numeric and aggregation == "average":
            total = sum(numeric)
            if all(isinstance(item, int) for item in numeric):
                quotient, remainder = divmod(total, len(numeric))
                statistic_value = quotient if remainder == 0 else total / len(numeric)
            else:
                statistic_value = total / len(numeric)
        elif numeric and aggregation == "minimum":
            statistic_value = min(numeric)
        elif numeric and aggregation == "maximum":
            statistic_value = max(numeric)
    return {
        "statistic_id": descriptor.get("statistic_id"),
        "value": statistic_value,
        "matching_count": len(matching),
        "sample_count": sample_count,
        "aggregation": aggregation,
    }


def _sort_key(value: Any) -> tuple[int, int | float | str]:
    if value is None:
        return (2, "")
    if isinstance(value, bool):
        return (1, str(value).casefold())
    if isinstance(value, int):
        return (0, value)
    if isinstance(value, float) and isfinite(value):
        return (0, value)
    comparable = _comparable(value)
    return (1, comparable.casefold()) if comparable is not None else (2, "")


def _assign_projected_field(
    target: dict[str, Any],
    field: str,
    value: Any,
) -> None:
    parts = field.split(".")
    if len(parts) == 1:
        target[parts[0]] = deepcopy(value)
        return
    current = target
    for part in parts[:-1]:
        nested = current.get(part)
        if nested is None:
            nested = {}
            current[part] = nested
        if not isinstance(nested, dict):
            # A malformed field path must not replace a core envelope scalar.
            return
        current = nested
    current[parts[-1]] = deepcopy(value)


def _project_table_row(
    row: Mapping[str, Any],
    descriptor: Mapping[str, Any],
) -> dict[str, Any]:
    projected = {
        field: deepcopy(row[field])
        for field in _CORE_TABLE_ENVELOPE_FIELDS
        if field in row
    }
    for column in descriptor.get("columns") or ():
        if not isinstance(column, Mapping):
            continue
        field = str(column.get("field") or "")
        if not field:
            continue
        _assign_projected_field(
            projected,
            field,
            dashboard_field_value(row, field),
        )
    return projected


def _table(
    rows: Sequence[Mapping[str, Any]], descriptor: Mapping[str, Any]
) -> dict[str, Any]:
    matching = _widget_rows(rows, descriptor)
    sort_field = descriptor.get("sort_field")
    if sort_field:
        matching.sort(
            key=lambda row: _sort_key(dashboard_field_value(row, str(sort_field))),
            reverse=str(descriptor.get("sort_direction")) == "descending",
        )
    max_rows = max(1, min(int(descriptor.get("max_rows") or 50), 500))
    page = matching[:max_rows]
    return {
        "table_id": descriptor.get("table_id"),
        "items": [_project_table_row(row, descriptor) for row in page],
        "total_count": len(matching),
        "returned_count": len(page),
        "truncated": len(matching) > max_rows,
    }


def evaluate_dashboards(
    descriptors: Iterable[Mapping[str, Any]],
    rows: Sequence[Mapping[str, Any]],
    *,
    dashboard_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate selected descriptors against one immutable temporal population."""

    results: list[dict[str, Any]] = []
    for descriptor in descriptors:
        dashboard_id = str(descriptor.get("dashboard_id") or "")
        if not dashboard_id or (
            dashboard_ids is not None and dashboard_id not in dashboard_ids
        ):
            continue
        statistics = [
            _statistic(rows, item)
            for item in descriptor.get("statistics", ())
            if isinstance(item, Mapping)
            and str(item.get("aggregation") or "count") != "precomputed"
        ]
        tables = [
            _table(rows, item)
            for item in descriptor.get("tables", ())
            if isinstance(item, Mapping)
        ]
        results.append(
            {
                "dashboard_id": dashboard_id,
                "statistics": statistics,
                "tables": tables,
            }
        )
    return results
