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
from typing import Any, NoReturn

from .plugin_api import (
    DashboardAggregation,
    DashboardFilterOperator,
    DashboardSortDirection,
    DashboardValueFormat,
)

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


class DashboardDescriptorValidationError(ValueError):
    """One deterministic failure in a serialized dashboard descriptor."""

    code = "invalid_dashboard_descriptor"

    def __init__(
        self,
        message: str,
        *,
        path: str,
        dashboard_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.path = path
        self.dashboard_id = dashboard_id

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "path": self.path,
            "message": str(self),
        }
        if self.dashboard_id is not None:
            result["dashboard_id"] = self.dashboard_id
        return result


def _descriptor_error(
    message: str,
    *,
    path: str,
    dashboard_id: str | None,
) -> NoReturn:
    raise DashboardDescriptorValidationError(
        message,
        path=path,
        dashboard_id=dashboard_id,
    )


def _descriptor_sequence(
    value: Any,
    *,
    path: str,
    dashboard_id: str | None,
) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(
        value,
        (str, bytes, bytearray),
    ):
        _descriptor_error(
            "dashboard descriptor collections must be arrays",
            path=path,
            dashboard_id=dashboard_id,
        )
    return value


def _validate_resource_kinds(
    descriptor: Mapping[str, Any],
    *,
    path: str,
    dashboard_id: str,
) -> None:
    if "resource_kinds" not in descriptor:
        return
    resource_kinds = _descriptor_sequence(
        descriptor["resource_kinds"],
        path=f"{path}.resource_kinds",
        dashboard_id=dashboard_id,
    )
    if any(not isinstance(item, str) or not item for item in resource_kinds):
        _descriptor_error(
            "dashboard resource_kinds must contain non-empty strings",
            path=f"{path}.resource_kinds",
            dashboard_id=dashboard_id,
        )


def _validate_include_absent(
    descriptor: Mapping[str, Any],
    *,
    path: str,
    dashboard_id: str,
) -> None:
    if "include_absent" in descriptor and not isinstance(
        descriptor["include_absent"],
        bool,
    ):
        _descriptor_error(
            "dashboard include_absent must be a boolean",
            path=f"{path}.include_absent",
            dashboard_id=dashboard_id,
        )


def _validate_filters(
    descriptor: Mapping[str, Any],
    *,
    path: str,
    dashboard_id: str,
) -> None:
    filters = _descriptor_sequence(
        descriptor.get("filters", ()),
        path=f"{path}.filters",
        dashboard_id=dashboard_id,
    )
    supported_operators = {item.value for item in DashboardFilterOperator}
    for index, filter_descriptor in enumerate(filters):
        filter_path = f"{path}.filters[{index}]"
        if not isinstance(filter_descriptor, Mapping):
            _descriptor_error(
                "dashboard filters must be objects",
                path=filter_path,
                dashboard_id=dashboard_id,
            )
        field = filter_descriptor.get("field")
        if not isinstance(field, str) or not field:
            _descriptor_error(
                "dashboard filter field must be a non-empty string",
                path=f"{filter_path}.field",
                dashboard_id=dashboard_id,
            )
        operator = filter_descriptor.get("operator")
        if not isinstance(operator, str) or operator not in supported_operators:
            _descriptor_error(
                "unsupported dashboard filter operator",
                path=f"{filter_path}.operator",
                dashboard_id=dashboard_id,
            )
        if operator in {
            DashboardFilterOperator.IN.value,
            DashboardFilterOperator.NOT_IN.value,
        }:
            _descriptor_sequence(
                filter_descriptor.get("value"),
                path=f"{filter_path}.value",
                dashboard_id=dashboard_id,
            )
        if (
            operator == DashboardFilterOperator.EXISTS.value
            and "value" in filter_descriptor
            and not isinstance(filter_descriptor["value"], bool)
        ):
            _descriptor_error(
                "dashboard exists filters require a boolean value",
                path=f"{filter_path}.value",
                dashboard_id=dashboard_id,
            )


def _validate_statistic(
    descriptor: Mapping[str, Any],
    *,
    path: str,
    dashboard_id: str,
) -> None:
    statistic_id = descriptor.get("statistic_id")
    if not isinstance(statistic_id, str) or not statistic_id:
        _descriptor_error(
            "dashboard statistic_id must be a non-empty string",
            path=f"{path}.statistic_id",
            dashboard_id=dashboard_id,
        )
    aggregation = descriptor.get("aggregation")
    supported_aggregations = {
        *(item.value for item in DashboardAggregation),
        "precomputed",
    }
    if not isinstance(aggregation, str) or aggregation not in supported_aggregations:
        _descriptor_error(
            "unsupported dashboard aggregation",
            path=f"{path}.aggregation",
            dashboard_id=dashboard_id,
        )
    field = descriptor.get("field")
    if aggregation not in {
        DashboardAggregation.COUNT.value,
        "precomputed",
    } and (not isinstance(field, str) or not field):
        _descriptor_error(
            "non-count dashboard statistics require a field",
            path=f"{path}.field",
            dashboard_id=dashboard_id,
        )
    if field is not None and (not isinstance(field, str) or not field):
        _descriptor_error(
            "dashboard statistic field must be a non-empty string",
            path=f"{path}.field",
            dashboard_id=dashboard_id,
        )
    _validate_resource_kinds(
        descriptor,
        path=path,
        dashboard_id=dashboard_id,
    )
    _validate_include_absent(
        descriptor,
        path=path,
        dashboard_id=dashboard_id,
    )
    _validate_filters(
        descriptor,
        path=path,
        dashboard_id=dashboard_id,
    )


def _validate_table(
    descriptor: Mapping[str, Any],
    *,
    path: str,
    dashboard_id: str,
) -> None:
    table_id = descriptor.get("table_id")
    if not isinstance(table_id, str) or not table_id:
        _descriptor_error(
            "dashboard table_id must be a non-empty string",
            path=f"{path}.table_id",
            dashboard_id=dashboard_id,
        )
    columns = _descriptor_sequence(
        descriptor.get("columns"),
        path=f"{path}.columns",
        dashboard_id=dashboard_id,
    )
    if not columns:
        _descriptor_error(
            "dashboard tables require at least one column",
            path=f"{path}.columns",
            dashboard_id=dashboard_id,
        )
    value_formats = {item.value for item in DashboardValueFormat}
    for index, column in enumerate(columns):
        column_path = f"{path}.columns[{index}]"
        if not isinstance(column, Mapping):
            _descriptor_error(
                "dashboard table columns must be objects",
                path=column_path,
                dashboard_id=dashboard_id,
            )
        field = column.get("field")
        if not isinstance(field, str) or not field:
            _descriptor_error(
                "dashboard table column field must be a non-empty string",
                path=f"{column_path}.field",
                dashboard_id=dashboard_id,
            )
        value_format = column.get(
            "value_format",
            DashboardValueFormat.AUTO.value,
        )
        if not isinstance(value_format, str) or value_format not in value_formats:
            _descriptor_error(
                "unsupported dashboard column value_format",
                path=f"{column_path}.value_format",
                dashboard_id=dashboard_id,
            )
    max_rows = descriptor.get("max_rows", 50)
    if type(max_rows) is not int or not 1 <= max_rows <= 500:
        _descriptor_error(
            "dashboard table max_rows must be an integer between 1 and 500",
            path=f"{path}.max_rows",
            dashboard_id=dashboard_id,
        )
    sort_field = descriptor.get("sort_field")
    if sort_field is not None and (not isinstance(sort_field, str) or not sort_field):
        _descriptor_error(
            "dashboard table sort_field must be a non-empty string or null",
            path=f"{path}.sort_field",
            dashboard_id=dashboard_id,
        )
    sort_direction = descriptor.get(
        "sort_direction",
        DashboardSortDirection.ASCENDING.value,
    )
    if not isinstance(sort_direction, str) or sort_direction not in {
        item.value for item in DashboardSortDirection
    }:
        _descriptor_error(
            "unsupported dashboard table sort_direction",
            path=f"{path}.sort_direction",
            dashboard_id=dashboard_id,
        )
    _validate_resource_kinds(
        descriptor,
        path=path,
        dashboard_id=dashboard_id,
    )
    _validate_include_absent(
        descriptor,
        path=path,
        dashboard_id=dashboard_id,
    )
    _validate_filters(
        descriptor,
        path=path,
        dashboard_id=dashboard_id,
    )


def validate_dashboard_descriptors(
    descriptors: Iterable[Mapping[str, Any]],
    *,
    dashboard_ids: set[str] | None = None,
) -> tuple[Mapping[str, Any], ...]:
    """Validate serialized evaluator inputs before any resource evaluation."""

    if isinstance(descriptors, (str, bytes, bytearray, Mapping)):
        _descriptor_error(
            "dashboard descriptors must be an array",
            path="dashboards",
            dashboard_id=None,
        )
    try:
        iterator = iter(descriptors)
    except TypeError:
        _descriptor_error(
            "dashboard descriptors must be an array",
            path="dashboards",
            dashboard_id=None,
        )
    validated: list[Mapping[str, Any]] = []
    for index, descriptor in enumerate(iterator):
        path = f"dashboards[{index}]"
        if not isinstance(descriptor, Mapping):
            _descriptor_error(
                "dashboard descriptors must be objects",
                path=path,
                dashboard_id=None,
            )
        dashboard_id = descriptor.get("dashboard_id")
        if not isinstance(dashboard_id, str) or not dashboard_id:
            _descriptor_error(
                "dashboard_id must be a non-empty string",
                path=f"{path}.dashboard_id",
                dashboard_id=None,
            )
        if dashboard_ids is not None and dashboard_id not in dashboard_ids:
            continue
        statistics = _descriptor_sequence(
            descriptor.get("statistics", ()),
            path=f"{path}.statistics",
            dashboard_id=dashboard_id,
        )
        tables = _descriptor_sequence(
            descriptor.get("tables", ()),
            path=f"{path}.tables",
            dashboard_id=dashboard_id,
        )
        for statistic_index, statistic in enumerate(statistics):
            statistic_path = f"{path}.statistics[{statistic_index}]"
            if not isinstance(statistic, Mapping):
                _descriptor_error(
                    "dashboard statistics must be objects",
                    path=statistic_path,
                    dashboard_id=dashboard_id,
                )
            _validate_statistic(
                statistic,
                path=statistic_path,
                dashboard_id=dashboard_id,
            )
        for table_index, table in enumerate(tables):
            table_path = f"{path}.tables[{table_index}]"
            if not isinstance(table, Mapping):
                _descriptor_error(
                    "dashboard tables must be objects",
                    path=table_path,
                    dashboard_id=dashboard_id,
                )
            _validate_table(
                table,
                path=table_path,
                dashboard_id=dashboard_id,
            )
        validated.append(descriptor)
    return tuple(validated)


def _dashboard_field_lookup(
    row: Mapping[str, Any],
    field: str | None,
) -> tuple[bool, Any]:
    """Return field presence separately from a possibly-null field value."""

    if not field:
        return False, None
    parts = str(field).split(".")

    def descend(value: Any, path: Sequence[str]) -> tuple[bool, Any]:
        current = value
        for part in path:
            if not isinstance(current, Mapping) or part not in current:
                return False, None
            current = current[part]
        return True, current

    direct_found, direct = descend(row, parts)
    if direct_found or len(parts) > 1:
        return direct_found, direct
    # Root-envelope presence wins, including an explicit null. Unqualified
    # legacy fields fall back only when the envelope truly lacks that name.
    name = parts[0]
    resource = row.get("resource")
    for scope in (
        row.get("state"),
        row.get("key"),
        resource.get("state") if isinstance(resource, Mapping) else None,
        resource.get("key") if isinstance(resource, Mapping) else None,
    ):
        if isinstance(scope, Mapping) and name in scope:
            return True, scope[name]
    return False, None


def dashboard_field_value(row: Mapping[str, Any], field: str | None) -> Any:
    """Resolve a safe descriptor field without evaluating expressions."""

    return _dashboard_field_lookup(row, field)[1]


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
                frozenset(Counter(entries).items()),
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
    found, actual = _dashboard_field_lookup(
        row,
        str(descriptor.get("field") or ""),
    )
    expected = descriptor.get("value")
    operator = str(descriptor.get("operator") or "eq")
    if operator == "eq":
        if not found:
            return False
        actual_key = _comparison_key(actual)
        expected_key = _comparison_key(expected)
        return (
            actual_key is not None
            and expected_key is not None
            and actual_key == expected_key
        )
    if operator == "not_eq":
        if not found:
            return False
        actual_key = _comparison_key(actual)
        expected_key = _comparison_key(expected)
        return (
            actual_key is not None
            and expected_key is not None
            and actual_key != expected_key
        )
    if operator in {"in", "not_in"}:
        if not found:
            return False
        candidates = expected if isinstance(expected, (list, tuple)) else ()
        actual_key = _comparison_key(actual)
        candidate_keys = [_comparison_key(item) for item in candidates]
        if actual_key is None or any(key is None for key in candidate_keys):
            return False
        found = any(actual_key == key for key in candidate_keys)
        return found if operator == "in" else not found
    if operator == "exists":
        return found is bool(True if expected is None else expected)
    if operator == "contains":
        if not found:
            return False
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
    values: list[Any] = []
    for row in matching:
        found, value = _dashboard_field_lookup(
            row,
            str(field) if field else None,
        )
        if found:
            values.append(value)
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
    else:
        raise DashboardDescriptorValidationError(
            "unsupported dashboard aggregation",
            path="aggregation",
        )
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
        found, value = _dashboard_field_lookup(row, field)
        if not found:
            continue
        _assign_projected_field(
            projected,
            field,
            value,
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
    max_rows = descriptor.get("max_rows", 50)
    if type(max_rows) is not int or not 1 <= max_rows <= 500:
        raise DashboardDescriptorValidationError(
            "dashboard table max_rows must be an integer between 1 and 500",
            path="max_rows",
        )
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

    validated = validate_dashboard_descriptors(
        descriptors,
        dashboard_ids=dashboard_ids,
    )
    results: list[dict[str, Any]] = []
    for descriptor in validated:
        dashboard_id = str(descriptor["dashboard_id"])
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
