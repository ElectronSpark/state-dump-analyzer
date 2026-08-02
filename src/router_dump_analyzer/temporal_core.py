"""Shared, domain-neutral temporal ordering and comparison semantics."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .canonical import CanonicalValueError, bounded_value_key
from .value_core import parse_canonical_decimal_integer

RESOURCE_CREATION_OPERATIONS = frozenset({"create", "add", "insert"})
RESOURCE_DELETION_OPERATIONS = frozenset({"delete", "remove"})

# Ordering-dependent cursors and cluster handles must change version whenever
# the canonical temporal order changes.
TEMPORAL_ORDER_VERSION = 2

# Every public nanosecond coordinate uses the same signed-64 domain as the
# plug-in contract and durable stores.  Keeping the invariant here prevents
# topology, route, and history adapters from acquiring subtly different
# integer ranges.
MIN_TEMPORAL_NS = -(1 << 63)
MAX_TEMPORAL_NS = (1 << 63) - 1

_TEMPORAL_STATE_FIELDS = (
    "exists",
    "status",
    "state",
    "valid_from_ns",
    "valid_to_ns",
)


def temporal_integer(value: Any, field: str) -> int:
    """Parse one exact signed-64 nanosecond integer without coercion."""

    return parse_canonical_decimal_integer(
        value,
        field,
        minimum=MIN_TEMPORAL_NS,
        maximum=MAX_TEMPORAL_NS,
    )


def checked_temporal_add(left: int, right: int, field: str) -> int:
    """Add two nanosecond values and reject signed-64 overflow."""

    if type(left) is not int or type(right) is not int:
        raise ValueError(f"{field} operands must be exact integers")
    return temporal_integer(left + right, field)


def checked_temporal_subtract(left: int, right: int, field: str) -> int:
    """Subtract two nanosecond values and reject signed-64 overflow."""

    if type(left) is not int or type(right) is not int:
        raise ValueError(f"{field} operands must be exact integers")
    return temporal_integer(left - right, field)


def temporal_order_key(
    record: Mapping[str, Any],
    *,
    time_field: str,
    identifier_fields: Sequence[str],
    default_source_sequence: int = 0,
) -> tuple[int, int, str]:
    """Return the deterministic order shared by all temporal event streams."""

    timestamp_ns = temporal_integer(record.get(time_field), time_field)
    source_sequence = temporal_integer(
        record.get("source_sequence", default_source_sequence),
        "source_sequence",
    )
    identifier = ""
    for field in identifier_fields:
        value = record.get(field)
        if value is not None:
            identifier = str(value)
            break
    return timestamp_ns, source_sequence, identifier


def temporal_state_comparison_key(
    view: Mapping[str, Any],
) -> tuple[Any, ...]:
    """Return a bounded key for one state and its temporal validity.

    Validity is part of the state view: equal payloads on opposite sides of a
    transition are still distinct temporal observations.
    """

    return bounded_value_key(
        tuple(view.get(field) for field in _TEMPORAL_STATE_FIELDS)
    )


def distinct_temporal_states(
    samples: Iterable[tuple[int, Mapping[str, Any]]],
) -> tuple[list[tuple[int, Mapping[str, Any]]], bool]:
    """Deduplicate sampled states, reporting whether comparison was complete.

    Unsupported, cyclic, or over-budget state is never stringified. Callers
    receive ``comparison_complete=False`` so they can fail closed instead of
    claiming a stable state.
    """

    unique: dict[
        tuple[Any, ...],
        tuple[int, Mapping[str, Any]],
    ] = {}
    try:
        for sampled_at, view in samples:
            unique[temporal_state_comparison_key(view)] = (sampled_at, view)
    except CanonicalValueError:
        return [], False
    return list(unique.values()), True


__all__ = [
    "MAX_TEMPORAL_NS",
    "MIN_TEMPORAL_NS",
    "RESOURCE_CREATION_OPERATIONS",
    "RESOURCE_DELETION_OPERATIONS",
    "TEMPORAL_ORDER_VERSION",
    "checked_temporal_add",
    "checked_temporal_subtract",
    "distinct_temporal_states",
    "temporal_integer",
    "temporal_order_key",
    "temporal_state_comparison_key",
]
