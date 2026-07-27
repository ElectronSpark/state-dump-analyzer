"""Generic core services for retained source records and regex timeline lanes.

This module deliberately knows nothing about router resource types or vendor
event names.  Plug-ins choose source descriptors, labels, and useful presets;
the core validates bounded regex rules, pages records, and projects timestamped
matches into timeline lanes with stable navigation identifiers.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .value_core import parse_decimal_integer


MAX_RECORD_LANES = 8
MAX_RECORD_PATTERN_LENGTH = 160
MAX_RECORD_HAYSTACK_LENGTH = 4096
MAX_RECORD_LANE_MARKS = 5_000
MAX_SOURCE_QUERY_LIMIT = 500
MAX_PROJECTED_IDENTIFIER_LENGTH = 256
MAX_PROJECTED_MESSAGE_LENGTH = 1_024
MAX_COPY_TEXT_FRAGMENT_BYTES = 65_536
MAX_COPY_TEXT_ITEMS = 5_000
MAX_COPY_TEXT_TOTAL_BYTES = 1_048_576

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
        return parse_decimal_integer(value, "timestamp_ns")
    except ValueError as error:
        identifier = _bounded_text(
            record.get("source_record_uid") or "<unknown>",
            MAX_PROJECTED_IDENTIFIER_LENGTH,
        )
        raise ValueError(
            f"source record {identifier!r} has an invalid timestamp_ns"
        ) from error


def source_record_event_uids(record: dict[str, Any]) -> tuple[str, ...]:
    """Return every normalized event linked by one retained source record.

    ``matched_event_uid`` remains a compatibility alias. New plug-ins may use
    ``matched_event_uids`` when one decoded input contributes to several
    normalized events.
    """

    values: list[str] = []
    plural = record.get("matched_event_uids")
    if isinstance(plural, (list, tuple)):
        values.extend(
            str(value)
            for value in plural
            if value is not None and str(value)
        )
    singular = record.get("matched_event_uid")
    if singular is not None and str(singular):
        values.append(str(singular))
    return tuple(dict.fromkeys(values))


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

    matched_event_uids = source_record_event_uids(record)
    matched_event_uid = matched_event_uids[0] if matched_event_uids else None
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
        "matched_event_uids": [
            _bounded_text(value, MAX_PROJECTED_IDENTIFIER_LENGTH)
            for value in matched_event_uids
        ],
        "matched": bool(matched_event_uids),
    }


def project_source_record_for_log(record: dict[str, Any]) -> dict[str, Any]:
    """Return the bounded source-record envelope used by virtual log rows.

    Raw attributes and ``copy_text`` stay private. The latter is only exposed
    through the explicit, quota-bound text projection below.
    """

    timestamp_ns = _source_record_timestamp_ns(record)
    projection = _project_source_record_mark(
        record,
        timestamp_ns=timestamp_ns if timestamp_ns is not None else 0,
    )
    projection["timestamp_ns"] = (
        str(timestamp_ns) if timestamp_ns is not None else None
    )
    return projection


def _validated_copy_text(record: dict[str, Any]) -> tuple[str | None, str | None]:
    if "copy_text" not in record or record.get("copy_text") is None:
        return None, "copy_text_unavailable"
    value = record.get("copy_text")
    if not isinstance(value, str):
        return None, "invalid_copy_text"
    if "\x00" in value:
        return None, "invalid_copy_text"
    size = len(value.encode("utf-8"))
    if size > MAX_COPY_TEXT_FRAGMENT_BYTES:
        return None, "copy_text_too_large"
    return value, None


def project_source_record_text_selection(
    records: Iterable[dict[str, Any]],
    selection: Iterable[dict[str, Any]],
    *,
    max_items: int = MAX_COPY_TEXT_ITEMS,
    max_total_bytes: int = MAX_COPY_TEXT_TOTAL_BYTES,
) -> dict[str, Any]:
    """Resolve a stable event/source selection to plug-in-supplied text.

    The core owns ordering, deduplication and quotas. Plug-ins own eligibility
    and the exact plain-text representation through ``copy_text``.
    """

    if max_items < 1 or max_items > MAX_COPY_TEXT_ITEMS:
        raise ValueError(f"max_items must be between 1 and {MAX_COPY_TEXT_ITEMS}")
    if max_total_bytes < 1 or max_total_bytes > MAX_COPY_TEXT_TOTAL_BYTES:
        raise ValueError(
            "max_total_bytes must be between 1 and "
            f"{MAX_COPY_TEXT_TOTAL_BYTES}"
        )

    materialized = list(records)
    by_uid: dict[str, dict[str, Any]] = {}
    by_event: dict[str, list[dict[str, Any]]] = {}
    for record in materialized:
        uid = str(record.get("source_record_uid") or "")
        if uid:
            by_uid[uid] = record
        for event_uid in source_record_event_uids(record):
            by_event.setdefault(event_uid, []).append(record)

    items: list[dict[str, Any]] = []
    omitted: list[dict[str, str]] = []
    seen_source_uids: set[str] = set()
    total_bytes = 0
    truncated = False

    for raw in selection:
        if not isinstance(raw, dict):
            omitted.append(
                {"selection_id": "invalid", "reason": "invalid_selection"}
            )
            continue
        kind = str(raw.get("kind") or "")
        uid = str(raw.get("uid") or "")
        selection_id = f"{kind}:{uid}" if kind and uid else "invalid"
        candidates = (
            [by_uid[uid]]
            if kind == "source" and uid in by_uid
            else by_event.get(uid, [])
            if kind == "event"
            else []
        )
        copyable_for_selection = False
        unavailable_reasons: list[str] = []
        for record in candidates:
            source_uid = str(record.get("source_record_uid") or "")
            if not source_uid or source_uid in seen_source_uids:
                continue
            text, reason = _validated_copy_text(record)
            if text is None:
                if reason:
                    unavailable_reasons.append(reason)
                continue
            encoded_size = len(text.encode("utf-8"))
            if len(items) >= max_items or total_bytes + encoded_size > max_total_bytes:
                truncated = True
                break
            seen_source_uids.add(source_uid)
            total_bytes += encoded_size
            copyable_for_selection = True
            items.append(
                {
                    "selection_id": selection_id,
                    "source_record_uid": _bounded_text(
                        source_uid,
                        MAX_PROJECTED_IDENTIFIER_LENGTH,
                    ),
                    "source_type": _bounded_text(
                        record.get("source_type") or "unknown",
                        MAX_PROJECTED_IDENTIFIER_LENGTH,
                    ),
                    "record_name": _bounded_text(
                        record.get("record_name") or "record",
                        MAX_PROJECTED_IDENTIFIER_LENGTH,
                    ),
                    "text": text,
                }
            )
        if truncated:
            break
        if not candidates:
            omitted.append(
                {
                    "selection_id": selection_id,
                    "reason": "source_record_not_found",
                }
            )
        elif not copyable_for_selection and not any(
            str(candidate.get("source_record_uid") or "") in seen_source_uids
            for candidate in candidates
        ):
            omitted.append(
                {
                    "selection_id": selection_id,
                    "reason": (
                        unavailable_reasons[0]
                        if unavailable_reasons
                        else "copy_text_unavailable"
                    ),
                }
            )

    return {
        "items": items,
        "item_count": len(items),
        "total_bytes": total_bytes,
        "omitted": omitted,
        "omitted_count": len(omitted),
        "truncated": truncated,
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
    if rule["unmatched_only"] and source_record_event_uids(record):
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
    start_ns = (
        parse_decimal_integer(start, "start_ns")
        if start is not None
        else None
    )
    end_ns = (
        parse_decimal_integer(end, "end_ns")
        if end is not None
        else None
    )
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
    offset = max(
        0,
        parse_decimal_integer(body.get("offset", 0), "offset"),
    )
    limit = max(
        1,
        min(
            parse_decimal_integer(body.get("limit", 100), "limit"),
            MAX_SOURCE_QUERY_LIMIT,
        ),
    )

    selected: list[dict[str, Any]] = []
    unplaced_count = 0
    has_time_window = start_ns is not None or end_ns is not None
    for record in records:
        if source_types and str(record.get("source_type")) not in source_types:
            continue
        is_matched = bool(source_record_event_uids(record))
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
