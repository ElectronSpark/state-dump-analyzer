"""Domain and presentation policy for the synthetic 100K fixture plug-in.

The packed scale archive uses a compact compatibility table.  This module is
the plug-in adapter for that format: it interprets fixture status vocabulary,
chooses display labels/icons, declares dashboards, and selects useful initial
resources.  The archive loader and temporal/query engines consume these
normalized declarations without learning ETG, ETE, EVPN, or other router
semantics.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic_core import from_json


RESOURCE_TABLE_COLUMNS = (
    "KIND",
    "RESOURCE_ID",
    "LAYER",
    "VRF",
    "SERVICE_ID",
    "PARENT_ID",
    "ES_ID",
    "ESI",
    "HOME_MODE",
    "ROLE",
    "MATCH",
    "PACKET_ACTION",
    "NEXT_HOP",
    "ENCAP",
    "ADMIN",
    "OPER",
    "DF_STATE",
    "NEIGHBOR",
)

RESOURCE_TABLE_JSON_COLUMNS = (
    "KEY_JSON",
    "STATE_JSON",
)


_CONDITION_CLASSES = {
    "active": "healthy",
    "observed": "healthy",
    "programmed": "healthy",
    "reachable": "healthy",
    "ready": "healthy",
    "restored": "healthy",
    "standby": "healthy",
    "up": "healthy",
    "degraded": "degraded",
    "down": "error",
    "error": "error",
    "failed": "error",
    "unreachable": "error",
    "withdrawn": "error",
}


@lru_cache(maxsize=64)
def _scale_condition_class_cached(normalized: str) -> str:
    return _CONDITION_CLASSES.get(normalized, "unknown")


def scale_condition_class(status: Any) -> str:
    """Normalize the synthetic fixture's condition vocabulary.

    This mapping is intentionally exact and plug-in-owned.  Generic core code
    must not search arbitrary status text for words such as ``fail`` or
    ``withdraw``.
    """

    return _scale_condition_class_cached(str(status or "unknown").casefold())


def scale_resource_label(resource_id: str) -> str:
    """Return the fixture plug-in's compact label for an opaque core handle."""

    parts = resource_id.split("/")
    if len(parts) <= 2:
        return resource_id
    return "/".join(
        parts[-2:] if parts[1] in {"ETG", "ETE"} else parts[-1:]
    )


def _resource_json_object(raw: str, column: str) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = from_json(raw)
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            f"packed resource table {column} must contain valid JSON"
        ) from error
    if not isinstance(value, dict):
        raise RuntimeError(
            f"packed resource table {column} must contain a JSON object"
        )
    return value


def scale_resource_record(
    values: tuple[str, ...],
    *,
    key_json: str = "",
    state_json: str = "",
) -> dict[str, Any]:
    """Normalize one legacy fixture table row into the generic resource view."""

    (
        kind,
        resource_id,
        layer,
        vrf,
        service_id,
        parent_id,
        es_id,
        esi,
        home_mode,
        role,
        match,
        packet_action,
        next_hop,
        encapsulation,
        admin_state,
        oper_state,
        df_state,
        neighbor,
    ) = values
    state: dict[str, Any] = {}
    for field, value in (
        ("vrf", vrf),
        ("service_id", service_id),
        ("parent_id", parent_id),
        ("es_id", es_id),
        ("esi", esi),
        ("home_mode", home_mode),
        ("role", role),
        ("match", match),
        ("packet_action", packet_action),
        ("next_hop", next_hop),
        ("encapsulation", encapsulation),
        ("admin_state", admin_state),
        ("oper_state", oper_state),
        ("df_state", df_state),
        ("neighbor", neighbor),
    ):
        if value:
            state[field] = value
    state.update(_resource_json_object(state_json, "STATE_JSON"))
    status = str(
        state.get("status")
        or state.get("oper_state")
        or state.get("admin_state")
        or "observed"
    )
    status_class = scale_condition_class(status)
    state["status"] = status
    state["status_class"] = status_class

    key: dict[str, Any] = {}
    if parent_id:
        # This compound-child convention belongs solely to the fixture plug-in.
        key["parent_resource_id"] = parent_id
        key["path_id"] = resource_id.rsplit("/", 1)[-1]
    else:
        for field, value in (
            ("vrf", vrf),
            ("service_id", service_id),
            ("es_id", es_id),
            ("esi", esi),
        ):
            if value:
                key[field] = value
    key.update(_resource_json_object(key_json, "KEY_JSON"))
    return {
        "resource_id": resource_id,
        "kind": kind,
        "layer": layer,
        "label": scale_resource_label(resource_id),
        "key": key,
        "state": state,
        "status": status,
        "status_class": status_class,
        "quality": "exact",
        "plugin_defined": True,
        "presentation_tags": [],
    }


_KIND_SEMANTIC_FIELDS = frozenset(
    {
        "layer",
        "key_fields",
        "properties",
        "display_name",
        "default_timeline_fields",
        "display_name_fields",
        "default_table_fields",
        "condition_field",
    }
)

_SCALE_KIND_DISPLAY_NAMES = {
    "DTE": "Decapsulation Tunnel Entry",
    "ETE": "Encapsulation Tunnel Entry",
    "ETG": "Encapsulation Tunnel Group",
    "EVPN_ES": "EVPN Ethernet Segment",
    "IP_ROUTING": "IP routing",
    "NEIGHBOR": "Neighbor",
    "VIRTUAL_INTERFACE": "Virtual Interface",
}


def scale_icon_descriptor(
    kind: str,
    review_descriptors: dict[str, dict[str, Any]],
    scale_descriptors: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Combine review icons with authoritative scale plug-in semantics."""

    descriptor = dict(review_descriptors.get(kind, {}))
    if not descriptor and kind == "EVPN_ES":
        descriptor = dict(review_descriptors.get("EVPN_ROUTE", {}))
        descriptor.pop("display_name", None)
    for field in _KIND_SEMANTIC_FIELDS:
        descriptor.pop(field, None)
    descriptor.update(scale_descriptors.get(kind, {}))
    descriptor["kind"] = kind
    descriptor["plugin_defined"] = True
    descriptor.setdefault(
        "display_name",
        _SCALE_KIND_DISPLAY_NAMES.get(kind, kind),
    )
    descriptor.setdefault("key_fields", [])
    descriptor.setdefault("display_name_fields", ["name", "id"])
    descriptor.setdefault(
        "default_table_fields",
        ["status", "oper_state", "next_hop"],
    )
    descriptor.setdefault("condition_field", "status")
    descriptor.setdefault("presentation_tags", [])
    return descriptor


def scale_relationship_descriptor(
    relation_type: str,
    review_descriptors: dict[str, dict[str, Any]],
    structural: bool,
) -> dict[str, Any]:
    descriptor = dict(review_descriptors.get(relation_type, {}))
    descriptor.setdefault("label", relation_type)
    descriptor.setdefault("directed", True)
    descriptor.setdefault("structural", structural)
    descriptor.update(
        {
            "relation_type": relation_type,
            "plugin_defined": True,
        }
    )
    return descriptor


def scale_dashboards(event_count: int) -> list[dict[str, Any]]:
    """Declare fixture-specific dashboard modules for the generic renderer."""

    return [
        {
            "dashboard_id": "scale-overview",
            "title": f"{event_count:,}-event scale overview",
            "description": "Exact counts loaded from the packed normalized corpus.",
            "default_open": True,
            "default_expanded": True,
            "collapsible": True,
            "movable": True,
            "plugin_defined": True,
            "statistics": [
                {
                    "statistic_id": "scale-events",
                    "label": "Matched events",
                    "aggregation": "precomputed",
                    "scale_metric": "matched_events",
                },
                {
                    "statistic_id": "scale-resources",
                    "label": "Resources",
                    "aggregation": "precomputed",
                    "scale_metric": "resources",
                },
                {
                    "statistic_id": "scale-relationships",
                    "label": "Temporal relationships",
                    "aggregation": "precomputed",
                    "scale_metric": "relationships",
                },
                {
                    "statistic_id": "scale-failures",
                    "label": "Failed updates",
                    "aggregation": "precomputed",
                    "scale_metric": "failures",
                },
            ],
            "tables": [],
        },
        {
            "dashboard_id": "forwarding-population",
            "title": "Final forwarding catalog",
            "description": (
                "Precomputed counts from the final packed resource catalog; "
                "the table below is only the bounded visible query sample."
            ),
            "default_open": True,
            "default_expanded": True,
            "collapsible": True,
            "movable": True,
            "plugin_defined": True,
            "statistics": [
                {
                    "statistic_id": f"kind-{kind.lower()}",
                    "label": kind.replace("_", " ").title(),
                    "aggregation": "precomputed",
                    "scale_metric": f"by_kind.{kind}",
                }
                for kind in ("ETG", "ETE", "DTE", "EVPN_ES")
            ],
            "tables": [
                {
                    "table_id": "forwarding-sample",
                    "title": "Visible resource sample",
                    "resource_kinds": ["ETG", "ETE", "DTE", "EVPN_ES"],
                    "sort_field": "kind",
                    "sort_direction": "ascending",
                    "max_rows": 40,
                    "columns": [
                        {
                            "field": "label",
                            "label": "Resource",
                            "value_format": "resource",
                        },
                        {
                            "field": "kind",
                            "label": "Type",
                            "value_format": "text",
                        },
                        {
                            "field": "status",
                            "label": "Status",
                            "value_format": "status",
                        },
                        {
                            "field": "state.next_hop",
                            "label": "Next hop",
                            "value_format": "text",
                        },
                    ],
                }
            ],
        },
        {
            "dashboard_id": "event-phases",
            "title": "Mass-operation phases",
            "description": "Exact event counts for each generated phase.",
            "default_open": False,
            "default_expanded": True,
            "collapsible": True,
            "movable": True,
            "plugin_defined": True,
            "statistics": [
                {
                    "statistic_id": f"phase-{phase}",
                    "label": phase.replace("_", " ").title(),
                    "aggregation": "precomputed",
                    "scale_metric": f"by_phase.{phase}",
                }
                for phase in (
                    "single_home_create",
                    "multihome_add",
                    "mass_es_withdraw",
                    "mass_es_restore",
                    "next_hop_churn",
                )
            ],
            "tables": [],
        },
    ]


def scale_projection_capabilities(
    plugin_schema: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Return only topology/route projections declared safe by this plug-in."""

    defaults: dict[str, dict[str, Any]] = {
        "resource_association_topology": {
            "available": True,
            "description": "Generic topology over time-valid scale relationships.",
        },
        "underlay_topology": {
            "available": False,
            "reason": "The scale plug-in supplied no underlay projection.",
        },
        "route_resolution": {
            "available": False,
            "reason": "The scale plug-in supplied no route resolver.",
        },
    }
    declared = plugin_schema.get("projection_capabilities")
    if not isinstance(declared, dict):
        return defaults
    for capability_id, descriptor in declared.items():
        if not isinstance(descriptor, dict):
            continue
        merged = dict(defaults.get(str(capability_id), {}))
        merged.update(descriptor)
        merged["available"] = descriptor.get("available") is True
        defaults[str(capability_id)] = merged
    return defaults


def scale_initial_resource_ids(
    walkthrough: dict[str, Any],
    resources_by_kind: dict[str, list[dict[str, Any]]],
) -> list[str]:
    """Select the fixture's useful initial lanes; this is presentation policy."""

    identifiers: list[str] = []
    for service in walkthrough.get("services", [])[:2]:
        identifiers.extend(service.get("resource_ids", {}).values())
    for kind in ("VIRTUAL_INTERFACE", "NEIGHBOR", "IP_ROUTING"):
        if resources_by_kind.get(kind):
            identifiers.append(resources_by_kind[kind][0]["resource_id"])
    return list(dict.fromkeys(str(item) for item in identifiers if item))
