"""Generic core services for retained source records and regex timeline lanes.

This module deliberately knows nothing about router resource types or vendor
event names.  Plug-ins choose source descriptors, labels, and useful presets;
the core validates bounded regex rules, pages records, and projects timestamped
matches into timeline lanes with stable navigation identifiers.
"""

from __future__ import annotations

import re
from typing import Any, Iterable


MAX_RECORD_LANES = 8
MAX_RECORD_PATTERN_LENGTH = 160
MAX_RECORD_HAYSTACK_LENGTH = 4096
MAX_RECORD_LANE_MARKS = 5_000
MAX_SOURCE_QUERY_LIMIT = 500
MAX_PROJECTED_IDENTIFIER_LENGTH = 256
MAX_PROJECTED_MESSAGE_LENGTH = 1_024

_LANE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_BACKREFERENCE_PATTERN = re.compile(r"\\[1-9]")
_NESTED_QUANTIFIER_PATTERN = re.compile(
    r"\([^)]*[*+{][^)]*\)\s*(?:[*+]|\{\d+(?:,\d*)?\})"
)
_STACKED_QUANTIFIER_PATTERN = re.compile(
    r"(?:[*+]|\{\d+(?:,\d*)?\})\s*(?:[*+]|\{\d+(?:,\d*)?\})"
)


def _bounded_text(value: Any, limit: int = MAX_RECORD_HAYSTACK_LENGTH) -> str:
    text = str(value if value is not None else "")
    return text[:limit]


def _integer_value(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, str))
        or (
            isinstance(value, str)
            and not (
                value.isdigit()
                or (value.startswith("-") and value[1:].isdigit())
            )
        )
    ):
        raise ValueError(f"{field} must be an integer or decimal integer string")
    try:
        return int(value)
    except (ValueError, OverflowError) as error:
        raise ValueError(
            f"{field} must be an integer or decimal integer string"
        ) from error


def _boolean_field(
    values: dict[str, Any],
    field: str,
    *,
    default: bool,
) -> bool:
    if field not in values:
        return default
    value = values[field]
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _string_array_field(
    values: dict[str, Any],
    field: str,
) -> tuple[str, ...]:
    if field not in values:
        return ()
    supplied = values[field]
    if not isinstance(supplied, list):
        raise ValueError(f"{field} must be an array of strings")
    if any(not isinstance(item, str) or not item for item in supplied):
        raise ValueError(f"{field} must be an array of non-empty strings")
    return tuple(dict.fromkeys(supplied))


def _source_record_timestamp_ns(record: dict[str, Any]) -> int | None:
    """Return a usable timestamp without inventing one for untimed input."""

    value = record.get("timestamp_ns")
    if value is None:
        return None
    try:
        return _integer_value(value, "timestamp_ns")
    except ValueError as error:
        identifier = _bounded_text(
            record.get("source_record_uid") or "<unknown>",
            MAX_PROJECTED_IDENTIFIER_LENGTH,
        )
        raise ValueError(
            f"source record {identifier!r} has an invalid timestamp_ns"
        ) from error


def _project_source_record_mark(
    record: dict[str, Any],
    *,
    timestamp_ns: int,
) -> dict[str, Any]:
    """Return the bounded, domain-neutral record fields safe for a lane mark.

    Retained records can contain plug-in-private attributes or original raw
    payloads. Timeline projection does not need those values, so the core
    exposes only its stable navigation/display envelope.
    """

    matched_event_uid = record.get("matched_event_uid")
    return {
        "source_record_uid": _bounded_text(
            record.get("source_record_uid"),
            MAX_PROJECTED_IDENTIFIER_LENGTH,
        ),
        "timestamp_ns": str(timestamp_ns),
        "source_type": _bounded_text(
            record.get("source_type") or "unknown",
            MAX_PROJECTED_IDENTIFIER_LENGTH,
        ),
        "source_name": _bounded_text(
            record.get("source_name") or "source",
            MAX_PROJECTED_IDENTIFIER_LENGTH,
        ),
        "layer": _bounded_text(
            record.get("layer") or "unknown",
            MAX_PROJECTED_IDENTIFIER_LENGTH,
        ),
        "record_name": _bounded_text(
            record.get("record_name") or "record",
            MAX_PROJECTED_IDENTIFIER_LENGTH,
        ),
        "message": _bounded_text(
            record.get("message"),
            MAX_PROJECTED_MESSAGE_LENGTH,
        ),
        "matched_event_uid": (
            _bounded_text(matched_event_uid, MAX_PROJECTED_IDENTIFIER_LENGTH)
            if matched_event_uid
            else None
        ),
        "matched": bool(matched_event_uid),
    }


def _source_record_lane_mark(
    record: dict[str, Any],
    *,
    timestamp_ns: int,
) -> dict[str, Any]:
    projection = _project_source_record_mark(record, timestamp_ns=timestamp_ns)
    return {
        **projection,
        "time_ns": projection["timestamp_ns"],
        # Kept for the existing client shape, but this is deliberately a copy
        # of the safe projection rather than the retained/raw record.
        "record": dict(projection),
    }


def source_record_haystack(record: dict[str, Any]) -> str:
    """Return the bounded, domain-neutral text searched by lane regexes."""

    attributes = record.get("attributes")
    fields = (
        record.get("source_record_uid"),
        record.get("source_type"),
        record.get("source_name"),
        record.get("layer"),
        record.get("record_name"),
        record.get("message"),
        attributes if isinstance(attributes, (str, int, float, bool)) else "",
    )
    return "\n".join(_bounded_text(value, 1024) for value in fields)[
        :MAX_RECORD_HAYSTACK_LENGTH
    ]


def compile_record_pattern(
    pattern: Any,
    *,
    case_sensitive: bool = False,
) -> re.Pattern[str]:
    """Compile the intentionally small regex subset exposed by the core.

    Input length and searched text are bounded.  Lookarounds/extensions,
    backreferences, and common nested/stacked repetition forms are rejected so
    a UI-created lane cannot turn one timeline query into unbounded regex work.
    """

    if not isinstance(pattern, str):
        raise ValueError("record lane pattern must be a string")
    if not isinstance(case_sensitive, bool):
        raise ValueError("case_sensitive must be a boolean")
    value = pattern
    if not value:
        raise ValueError("record lane pattern must not be empty")
    if len(value) > MAX_RECORD_PATTERN_LENGTH:
        raise ValueError(
            f"record lane pattern must be at most {MAX_RECORD_PATTERN_LENGTH} characters"
        )
    if "(?" in value:
        raise ValueError("record lane patterns do not support regex extensions")
    if _BACKREFERENCE_PATTERN.search(value):
        raise ValueError("record lane patterns do not support backreferences")
    if _NESTED_QUANTIFIER_PATTERN.search(value) or _STACKED_QUANTIFIER_PATTERN.search(
        value
    ):
        raise ValueError("record lane pattern contains unsafe repeated quantifiers")
    try:
        return re.compile(value, 0 if case_sensitive else re.IGNORECASE)
    except re.error as error:
        raise ValueError(f"invalid record lane pattern: {error.msg}") from error


def normalize_record_lane_rule(
    raw: dict[str, Any],
    *,
    known_source_types: set[str] | None = None,
) -> tuple[dict[str, Any], re.Pattern[str]]:
    if not isinstance(raw, dict):
        raise ValueError("record lane rule must be an object")
    lane_id = raw.get("lane_id")
    if (
        not isinstance(lane_id, str)
        or not lane_id
        or len(lane_id) > 128
        or _LANE_ID_PATTERN.fullmatch(lane_id) is None
    ):
        raise ValueError(
            "record lane_id must be a lowercase dotted, dashed, or underscored identifier"
        )
    label_value = raw.get("label", lane_id)
    if not isinstance(label_value, str):
        raise ValueError("record lane label must be a string")
    label = label_value.strip()
    if not label or len(label) > 120:
        raise ValueError("record lane label must contain 1 to 120 characters")
    source_types = _string_array_field(raw, "source_types")
    if known_source_types is not None:
        unknown = set(source_types) - known_source_types
        if unknown:
            raise ValueError(
                "record lane references unknown source types: "
                + ", ".join(sorted(unknown))
            )
    case_sensitive = _boolean_field(raw, "case_sensitive", default=False)
    pattern = raw.get("pattern")
    if not isinstance(pattern, str):
        raise ValueError("record lane pattern must be a string")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise ValueError("record lane description must be a string")
    compiled = compile_record_pattern(pattern, case_sensitive=case_sensitive)
    normalized = {
        "lane_id": lane_id,
        "label": label,
        "description": _bounded_text(description, 300),
        "pattern": pattern,
        "source_types": list(source_types),
        "unmatched_only": _boolean_field(raw, "unmatched_only", default=False),
        "case_sensitive": case_sensitive,
        "plugin_defined": _boolean_field(raw, "plugin_defined", default=False),
    }
    return normalized, compiled


def _record_matches(
    record: dict[str, Any],
    rule: dict[str, Any],
    compiled: re.Pattern[str],
) -> bool:
    source_types = rule["source_types"]
    if source_types and str(record.get("source_type")) not in source_types:
        return False
    if rule["unmatched_only"] and record.get("matched_event_uid"):
        return False
    return compiled.search(source_record_haystack(record)) is not None


def query_source_records(
    records: Iterable[dict[str, Any]],
    body: dict[str, Any],
    *,
    known_source_types: set[str] | None = None,
) -> dict[str, Any]:
    """Filter and page retained records without applying domain semantics."""

    if not isinstance(body, dict):
        raise ValueError("source-record query must be an object")
    start = body.get("start_ns")
    end = body.get("end_ns")
    start_ns = _integer_value(start, "start_ns") if start is not None else None
    end_ns = _integer_value(end, "end_ns") if end is not None else None
    if start_ns is not None and end_ns is not None and end_ns < start_ns:
        raise ValueError("end_ns must be >= start_ns")
    source_types = set(_string_array_field(body, "source_types"))
    if known_source_types is not None and (unknown := source_types - known_source_types):
        raise ValueError(
            "source-record query references unknown source types: "
            + ", ".join(sorted(unknown))
        )
    matched = body.get("matched")
    if matched is not None and not isinstance(matched, bool):
        raise ValueError("matched must be a boolean or null")
    regex_value = body.get("pattern")
    if regex_value is not None and not isinstance(regex_value, str):
        raise ValueError("pattern must be a string or null")
    case_sensitive = _boolean_field(body, "case_sensitive", default=False)
    compiled = (
        compile_record_pattern(
            regex_value,
            case_sensitive=case_sensitive,
        )
        if regex_value
        else None
    )
    search_value = body.get("search")
    if search_value is not None and not isinstance(search_value, str):
        raise ValueError("search must be a string or null")
    search = (search_value or "").casefold()
    offset = max(0, _integer_value(body.get("offset", 0), "offset"))
    limit = max(
        1,
        min(
            _integer_value(body.get("limit", 100), "limit"),
            MAX_SOURCE_QUERY_LIMIT,
        ),
    )

    selected: list[dict[str, Any]] = []
    unplaced_count = 0
    has_time_window = start_ns is not None or end_ns is not None
    for record in records:
        if source_types and str(record.get("source_type")) not in source_types:
            continue
        is_matched = bool(record.get("matched_event_uid"))
        if matched is not None and is_matched is not matched:
            continue
        haystack = source_record_haystack(record)
        if search and search not in haystack.casefold():
            continue
        if compiled is not None and compiled.search(haystack) is None:
            continue
        timestamp_ns = _source_record_timestamp_ns(record)
        if timestamp_ns is None:
            unplaced_count += 1
            if has_time_window:
                continue
        elif start_ns is not None and timestamp_ns < start_ns:
            continue
        elif end_ns is not None and timestamp_ns > end_ns:
            continue
        selected.append(record)

    page = selected[offset : offset + limit]
    next_offset = offset + len(page)
    return {
        "items": page,
        "count": len(selected),
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset if next_offset < len(selected) else None,
        "unplaced_count": unplaced_count,
    }


def record_lanes_for_window(
    records: Iterable[dict[str, Any]],
    raw_rules: Iterable[dict[str, Any]],
    *,
    start_ns: int,
    end_ns: int,
    known_source_types: set[str] | None = None,
    max_marks: int = MAX_RECORD_LANE_MARKS,
) -> list[dict[str, Any]]:
    """Project retained records into bounded, regex-selected timeline lanes."""

    rules = list(raw_rules)
    if len(rules) > MAX_RECORD_LANES:
        raise ValueError(f"timeline supports at most {MAX_RECORD_LANES} record lanes")
    record_window: list[tuple[dict[str, Any], int]] = []
    unplaced_records: list[dict[str, Any]] = []
    for record in records:
        timestamp_ns = _source_record_timestamp_ns(record)
        if timestamp_ns is None:
            unplaced_records.append(record)
        elif start_ns <= timestamp_ns <= end_ns:
            record_window.append((record, timestamp_ns))
    prepared: list[
        tuple[dict[str, Any], list[tuple[dict[str, Any], int]], int]
    ] = []
    for raw_rule in rules:
        rule, compiled = normalize_record_lane_rule(
            raw_rule,
            known_source_types=known_source_types,
        )
        matched_records = [
            (record, timestamp_ns)
            for record, timestamp_ns in record_window
            if _record_matches(record, rule, compiled)
        ]
        unplaced_count = sum(
            1
            for record in unplaced_records
            if _record_matches(record, rule, compiled)
        )
        prepared.append((rule, matched_records, unplaced_count))

    # The global safety budget is shared fairly. Reserve one mark for every
    # non-empty lane first, then distribute the remainder in balanced rounds.
    # This keeps a broad rule from starving an exact Ctrl-click jump lane that
    # appears later in plug-in/user ordering.
    remaining = max(0, min(int(max_marks), MAX_RECORD_LANE_MARKS))
    allocations = [0 for _ in prepared]
    for index, (_rule, matched_records, _unplaced_count) in enumerate(prepared):
        if remaining <= 0:
            break
        if matched_records:
            allocations[index] = 1
            remaining -= 1
    while remaining > 0:
        pending = [
            index
            for index, (_rule, matched_records, _unplaced_count) in enumerate(
                prepared
            )
            if allocations[index] < len(matched_records)
        ]
        if not pending:
            break
        share = max(1, remaining // len(pending))
        progressed = 0
        for index in pending:
            matched_records = prepared[index][1]
            granted = min(
                share,
                remaining,
                len(matched_records) - allocations[index],
            )
            allocations[index] += granted
            remaining -= granted
            progressed += granted
            if remaining <= 0:
                break
        if progressed <= 0:
            break

    lanes: list[dict[str, Any]] = []
    for (rule, matched_records, unplaced_count), allocation in zip(
        prepared,
        allocations,
        strict=True,
    ):
        visible = matched_records[:allocation]
        lanes.append(
            {
                **rule,
                "record_count": len(matched_records),
                "unplaced_count": unplaced_count,
                "truncated": len(visible) < len(matched_records),
                "marks": [
                    _source_record_lane_mark(
                        record,
                        timestamp_ns=timestamp_ns,
                    )
                    for record, timestamp_ns in visible
                ],
            }
        )
    return lanes
