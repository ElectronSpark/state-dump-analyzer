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

    value = str(pattern or "")
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
    lane_id = str(raw.get("lane_id") or "")
    if (
        not lane_id
        or len(lane_id) > 128
        or _LANE_ID_PATTERN.fullmatch(lane_id) is None
    ):
        raise ValueError(
            "record lane_id must be a lowercase dotted, dashed, or underscored identifier"
        )
    label = str(raw.get("label") or lane_id).strip()
    if not label or len(label) > 120:
        raise ValueError("record lane label must contain 1 to 120 characters")
    source_types = tuple(
        dict.fromkeys(str(item) for item in raw.get("source_types") or [] if item)
    )
    if known_source_types is not None:
        unknown = set(source_types) - known_source_types
        if unknown:
            raise ValueError(
                "record lane references unknown source types: "
                + ", ".join(sorted(unknown))
            )
    case_sensitive = bool(raw.get("case_sensitive", False))
    pattern = str(raw.get("pattern") or "")
    compiled = compile_record_pattern(pattern, case_sensitive=case_sensitive)
    normalized = {
        "lane_id": lane_id,
        "label": label,
        "description": _bounded_text(raw.get("description"), 300),
        "pattern": pattern,
        "source_types": list(source_types),
        "unmatched_only": bool(raw.get("unmatched_only", False)),
        "case_sensitive": case_sensitive,
        "plugin_defined": bool(raw.get("plugin_defined", False)),
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

    start = body.get("start_ns")
    end = body.get("end_ns")
    start_ns = int(start) if start is not None else None
    end_ns = int(end) if end is not None else None
    if start_ns is not None and end_ns is not None and end_ns < start_ns:
        raise ValueError("end_ns must be >= start_ns")
    source_types = set(str(item) for item in body.get("source_types") or [] if item)
    if known_source_types is not None and (unknown := source_types - known_source_types):
        raise ValueError(
            "source-record query references unknown source types: "
            + ", ".join(sorted(unknown))
        )
    matched = body.get("matched")
    if matched is not None and not isinstance(matched, bool):
        raise ValueError("matched must be a boolean or null")
    regex_value = body.get("pattern")
    compiled = (
        compile_record_pattern(
            regex_value,
            case_sensitive=bool(body.get("case_sensitive", False)),
        )
        if regex_value
        else None
    )
    search = str(body.get("search") or "").casefold()
    offset = max(0, int(body.get("offset", 0)))
    limit = max(1, min(int(body.get("limit", 100)), MAX_SOURCE_QUERY_LIMIT))

    selected: list[dict[str, Any]] = []
    for record in records:
        timestamp_ns = int(record.get("timestamp_ns", 0))
        if start_ns is not None and timestamp_ns < start_ns:
            continue
        if end_ns is not None and timestamp_ns > end_ns:
            continue
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
        selected.append(record)

    page = selected[offset : offset + limit]
    next_offset = offset + len(page)
    return {
        "items": page,
        "count": len(selected),
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset if next_offset < len(selected) else None,
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
    record_window = [
        record
        for record in records
        if start_ns <= int(record.get("timestamp_ns", 0)) <= end_ns
    ]
    lanes: list[dict[str, Any]] = []
    remaining = max(0, min(int(max_marks), MAX_RECORD_LANE_MARKS))
    for raw_rule in rules:
        rule, compiled = normalize_record_lane_rule(
            raw_rule,
            known_source_types=known_source_types,
        )
        matched_records = [
            record
            for record in record_window
            if _record_matches(record, rule, compiled)
        ]
        visible = matched_records[:remaining]
        remaining -= len(visible)
        lanes.append(
            {
                **rule,
                "record_count": len(matched_records),
                "truncated": len(visible) < len(matched_records),
                "marks": [
                    {
                        "source_record_uid": str(record["source_record_uid"]),
                        "time_ns": str(record["timestamp_ns"]),
                        "timestamp_ns": str(record["timestamp_ns"]),
                        "source_type": str(record.get("source_type", "unknown")),
                        "record_name": str(record.get("record_name", "record")),
                        "source_name": str(record.get("source_name", "source")),
                        "message": _bounded_text(record.get("message"), 1024),
                        "matched_event_uid": record.get("matched_event_uid"),
                        "matched": bool(record.get("matched_event_uid")),
                        "record": record,
                    }
                    for record in visible
                ],
            }
        )
        if remaining <= 0:
            # Preserve subsequent lanes as explicit, empty/truncated results so
            # client ordering and remove controls remain stable.
            remaining = 0
    return lanes
