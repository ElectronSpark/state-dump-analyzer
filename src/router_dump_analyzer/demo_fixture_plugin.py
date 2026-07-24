"""Compatibility presentation policy for the small illustrative fixture.

Generated modern fixtures carry these descriptors directly.  The helpers here
exist only for older demo archives and intentionally sit on the plug-in side of
the boundary: generic core/query code must not parse resource IDs or recognize
special resource kinds.
"""

from __future__ import annotations

from typing import Any


def fixture_resource_label(identifier: str) -> str:
    parts = identifier.split("/")
    if len(parts) <= 2:
        return identifier
    return "/".join(
        parts[-2:]
        if parts[1] in {"ETG", "ETE", "EVPN_ROUTE"}
        else parts[-1:]
    )


def fixture_kind_descriptor(kind: str) -> dict[str, Any]:
    tags = ["connector", "compact"] if kind == "GLUE" else []
    return {
        "kind": kind,
        "display_name": kind.replace("_", " ").title(),
        "display_name_fields": ["name", "id"],
        "default_table_fields": ["status", "oper_state", "program_state"],
        "condition_field": "status",
        "presentation_tags": tags,
        "plugin_defined": True,
    }


def fixture_relationship_descriptor(relation_type: str) -> dict[str, Any]:
    return {
        "relation_type": relation_type,
        "label": relation_type.replace("_", " ").title(),
        "directed": True,
        "structural": False,
        "plugin_defined": True,
    }


def fixture_causal_link_descriptor(link_type: str) -> dict[str, Any]:
    return {
        "link_type": link_type,
        "label": link_type.replace("_", " ").title(),
        "directed": True,
        "plugin_defined": True,
    }
