"""Shared rules for keeping private authoring truth out of node dumps."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Iterator


FORBIDDEN_AUTHORING_KEYS = frozenset(
    {
        "authoring",
        "authoring_state",
        "ground_truth",
        "global_participants",
        "media",
        "oracle",
        "participants",
        "physical_links",
        "physical_topology",
        "project",
        "propagation_plan",
        "scenario",
        "scenario_id",
        "timeline",
        "topology",
    }
)


def normalized_key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_")


def forbidden_authoring_paths(
    value: Any,
    *,
    location: str = "$",
) -> Iterator[tuple[str, str]]:
    """Yield ``(path, key)`` pairs that cannot cross the dump boundary."""

    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = normalized_key(raw_key)
            path = f"{location}.{raw_key}"
            if key in FORBIDDEN_AUTHORING_KEYS:
                yield path, str(raw_key)
            yield from forbidden_authoring_paths(item, location=path)
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            yield from forbidden_authoring_paths(
                item,
                location=f"{location}[{index}]",
            )


__all__ = [
    "FORBIDDEN_AUTHORING_KEYS",
    "forbidden_authoring_paths",
    "normalized_key",
]
