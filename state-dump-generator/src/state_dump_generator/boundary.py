"""Shared rules for keeping private authoring truth out of node dumps."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

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

PRIVATE_IDENTITY_KEYS = frozenset(
    {
        "connectivity_domain_id",
        "domain_id",
        "id",
        "ids",
        "key",
        "keys",
        "link_id",
        "medium_id",
        "network_segment_id",
        "parent_resource_id",
        "physical_link_id",
        "physical_medium_id",
        "resource_id",
        "segment_id",
        "segment_key",
        "source_resource_id",
        "target_resource_id",
        "topology_id",
    }
)
PRIVATE_IDENTITY_SUFFIXES = (
    "_id",
    "_ids",
    "_key",
    "_keys",
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


def private_identifier_paths(
    value: Any,
    private_ids: frozenset[str],
    *,
    location: str = "$",
) -> Iterator[str]:
    """Yield identity-bearing paths that copy a private authoring identifier.

    Private medium IDs are ordinary strings, so comparing every projected
    scalar creates false positives when an author chooses an ID such as
    ``"up"`` or ``"interface"``.  Only fields whose names explicitly carry
    identity (including plug-in-defined ``*_id`` and ``*_key`` fields)
    participate in this check.  Arbitrary authoring attachment metadata is
    excluded earlier by the node-local projection envelope.
    """

    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = normalized_key(raw_key)
            child_location = f"{location}.{raw_key}"
            if key in PRIVATE_IDENTITY_KEYS or key.endswith(
                PRIVATE_IDENTITY_SUFFIXES
            ):
                yield from _matching_private_values(
                    item,
                    private_ids,
                    location=child_location,
                )
            elif isinstance(item, Mapping | list | tuple):
                yield from private_identifier_paths(
                    item,
                    private_ids,
                    location=child_location,
                )
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            yield from private_identifier_paths(
                item,
                private_ids,
                location=f"{location}[{index}]",
            )


def _matching_private_values(
    value: Any,
    private_ids: frozenset[str],
    *,
    location: str,
) -> Iterator[str]:
    if isinstance(value, str):
        if value in private_ids:
            yield location
        return
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            yield from _matching_private_values(
                item,
                private_ids,
                location=f"{location}.{raw_key}",
            )
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            yield from _matching_private_values(
                item,
                private_ids,
                location=f"{location}[{index}]",
            )


def node_dump_projection_issue(
    value: Any,
    private_ids: frozenset[str],
    *,
    location: str,
) -> tuple[str, str] | None:
    """Return the first shared validation/compile boundary violation."""

    forbidden = next(
        forbidden_authoring_paths(value, location=location),
        None,
    )
    if forbidden is not None:
        path, key = forbidden
        return (
            path,
            f"field {key!r} is private authoring truth and cannot enter a node dump",
        )
    private_path = next(
        private_identifier_paths(
            value,
            private_ids,
            location=location,
        ),
        None,
    )
    if private_path is not None:
        return (
            private_path,
            (
                "identity-bearing node-local evidence copies a private "
                "physical medium identifier"
            ),
        )
    return None


__all__ = [
    "FORBIDDEN_AUTHORING_KEYS",
    "PRIVATE_IDENTITY_KEYS",
    "forbidden_authoring_paths",
    "node_dump_projection_issue",
    "normalized_key",
    "private_identifier_paths",
]
