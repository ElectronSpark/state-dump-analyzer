"""Example plug-in temporal projection contract builder."""

from __future__ import annotations

from typing import Any

from router_dump_analyzer.temporal_topology import (
    TemporalTopologyRequestError,
)


def build_demo_plugin_contract(dataset: dict[str, Any]) -> dict[str, Any]:
    """Return declarative fixture semantics as if supplied by a plug-in.

    The core temporal service does not know that an IS-IS adjacency or
    physical interface represents reachability. Those choices live here.
    """

    default_node = str(dataset["demo"].get("node", "node-a"))
    descriptors = dataset.get("relationship_descriptors", [])
    relationship_types = sorted(
        {
            str(item.get("relation_type", item.get("type", "related_to")))
            for item in descriptors
        }
        or {
            str(item.get("relation_type", item.get("type", "related_to")))
            for item in dataset.get("relationship_intervals", [])
        }
    )
    connectivity_types = [
        value
        for value in (
            "uses_interface",
            "binds_hardware",
            "associates",
            "egresses_via",
            "active_path",
        )
        if value in relationship_types
    ]
    perspectives = [
        {
            "perspective_id": "control-plane",
            "label": "Control-plane reachability",
            "layer": "control-plane",
            "layer_id": "control-plane",
            "role": "intended",
            "usable_statuses": ["active", "ready", "restored", "selected", "up"],
            "unusable_statuses": ["down", "failed", "withdrawn"],
            "semantic_owner": "plugin",
        },
        {
            "perspective_id": "data-bridge-layer",
            "label": "Data bridge programmed state",
            "layer": "data-bridge-layer",
            "layer_id": "data-bridge-layer",
            "role": "programmed",
            "usable_statuses": ["active", "bound", "programmed", "ready", "standby", "up"],
            "unusable_statuses": ["down", "error", "failed", "ineligible", "withdrawn"],
            "semantic_owner": "plugin",
        },
        {
            "perspective_id": "hardware-driver-plane",
            "label": "Hardware observed forwarding",
            "layer": "hardware-driver-plane",
            "layer_id": "hardware-driver-plane",
            "role": "observed",
            "usable_statuses": ["active", "programmed", "reachable", "up"],
            "unusable_statuses": ["down", "error", "failed", "unreachable"],
            "semantic_owner": "plugin",
        },
    ]
    clock_specs = {
        "control-plane": (17_000_000, 3_000_000),
        "data-bridge-layer": (-9_000_000, 5_000_000),
        "hardware-driver-plane": (4_000_000, 1_000_000),
    }

    def clocks(node_id: str, extra_offset_ns: int, extra_uncertainty_ns: int) -> dict[str, Any]:
        return {
            perspective_id: {
                "clock_domain": f"{node_id}-{perspective_id}-raw",
                "source_clock_domain": "utc",
                "target_clock_domain": f"{node_id}-{perspective_id}-raw",
                "local_minus_absolute_ns": offset + extra_offset_ns,
                "uncertainty_ns": uncertainty + extra_uncertainty_ns,
                "method": "synthetic_piecewise_clock_anchors",
                "quality": "exact" if extra_uncertainty_ns == 0 else "best_effort",
            }
            for perspective_id, (offset, uncertainty) in clock_specs.items()
        }

    capture_ns = int(dataset["demo"]["capture_ns"])
    projection_capabilities = dataset.get("projection_capabilities")
    if not isinstance(projection_capabilities, dict):
        projection_capabilities = dataset.get("schema", {}).get(
            "projection_capabilities"
        )
    # Existing illustrative fixtures predate capability declarations and keep
    # their plug-in underlay. Scale fixtures declare this unavailable so the
    # generic core does not expose topology without scale-owned evidence.
    underlay_available = not isinstance(projection_capabilities, dict) or (
        isinstance(projection_capabilities.get("underlay_topology"), dict)
        and projection_capabilities["underlay_topology"].get("available") is True
    )
    projection_ids = ["plugin.resource-association"]
    if underlay_available:
        projection_ids.append("plugin.underlay-connectivity")

    def watermarks(
        node_clocks: dict[str, Any], lag_ns: int, quality: str
    ) -> dict[str, Any]:
        # These are fixture/plugin completeness declarations. They are
        # intentionally not inferred from the greatest event timestamp.
        return {
            item["perspective_id"]: {
                projection_id: {
                    "query_time_ns": capture_ns
                    - lag_ns
                    - (
                        2_000_000
                        if projection_id == "plugin.underlay-connectivity"
                        else 0
                    ),
                    "local_time_ns": capture_ns
                    - lag_ns
                    - (
                        2_000_000
                        if projection_id == "plugin.underlay-connectivity"
                        else 0
                    )
                    + int(
                        node_clocks[item["perspective_id"]][
                            "local_minus_absolute_ns"
                        ]
                    ),
                    "clock_domain": node_clocks[item["perspective_id"]][
                        "clock_domain"
                    ],
                    "absolute_min_ns": capture_ns
                    - lag_ns
                    - (
                        2_000_000
                        if projection_id == "plugin.underlay-connectivity"
                        else 0
                    )
                    - int(
                        node_clocks[item["perspective_id"]]["uncertainty_ns"]
                    ),
                    "absolute_max_ns": capture_ns
                    - lag_ns
                    - (
                        2_000_000
                        if projection_id == "plugin.underlay-connectivity"
                        else 0
                    )
                    + int(
                        node_clocks[item["perspective_id"]]["uncertainty_ns"]
                    ),
                    "mapping_method": node_clocks[item["perspective_id"]]["method"],
                    "quality": quality,
                    "complete": True,
                }
                for projection_id in projection_ids
            }
            for item in perspectives
        }

    underlay_specs = [
        {
            "connectivity_id": "underlay:pe-a:p-1",
            "endpoint_a": {"topology_node_id": "pe-a", "node_id": default_node},
            "endpoint_b": {"topology_node_id": "p-1", "node_id": "transit-p-1"},
            "status_node_id": default_node,
            "directed": False,
            "rule_id": "demo.underlay.path-status.v1",
            "status_sources": {
                "control-plane": ["control-plane/ISIS_ADJACENCY/pe-a/p-1"],
                "data-bridge-layer": [
                    "data-bridge-layer/VIRTUAL_INTERFACE/vi-p1",
                    "data-bridge-layer/GLUE/glue-p1",
                ],
                "hardware-driver-plane": [
                    "hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet1"
                ],
            },
        },
        {
            "connectivity_id": "underlay:pe-a:p-2",
            "endpoint_a": {"topology_node_id": "pe-a", "node_id": default_node},
            "endpoint_b": {"topology_node_id": "p-2", "node_id": "transit-p-2"},
            "status_node_id": default_node,
            "directed": False,
            "rule_id": "demo.underlay.path-status.v1",
            "status_sources": {
                "control-plane": ["control-plane/ISIS_ADJACENCY/pe-a/p-2"],
                "data-bridge-layer": [
                    "data-bridge-layer/VIRTUAL_INTERFACE/vi-p2",
                    "data-bridge-layer/GLUE/glue-p2",
                ],
                "hardware-driver-plane": [
                    "hardware-driver-plane/PHYSICAL_INTERFACE/Ethernet2"
                ],
            },
        },
    ]
    node_a_clocks = clocks(default_node, 0, 0)
    node_b_clocks = clocks("node-b", -41_000_000, 4_000_000)
    topology_projections = [
        {
            "projection_id": "plugin.resource-association",
            "label": "Resource association topology",
            "description": "Plugin-selected temporal resource relationships.",
            "relationship_types": relationship_types,
            "connectivity_relation_types": connectivity_types,
            "resource_kinds": [],
            "semantic_owner": "plugin",
            "supported_status_perspective_ids": [
                item["perspective_id"] for item in perspectives
            ],
            "default_status_perspective_id": "data-bridge-layer",
            "status_source_combination_policy": "all_required_usable",
            "static_connectivity": [],
        }
    ]
    if underlay_available:
        topology_projections.append(
            {
                "projection_id": "plugin.underlay-connectivity",
                "label": "Underlay connectivity",
                "description": (
                    "Plugin inference over protocol, bridge, and hardware status."
                ),
                "relationship_types": connectivity_types,
                "connectivity_relation_types": connectivity_types,
                "resource_kinds": [],
                "semantic_owner": "plugin",
                "supported_status_perspective_ids": [
                    item["perspective_id"] for item in perspectives
                ],
                "default_status_perspective_id": "hardware-driver-plane",
                "status_source_combination_policy": "all_required_usable",
                "static_connectivity": underlay_specs,
            }
        )
    return {
        "absolute_clock_domains": {"utc"},
        "default_projection_id": "plugin.resource-association",
        "default_status_perspective_id": "data-bridge-layer",
        "status_perspectives": perspectives,
        "nodes": [
            {
                "node_id": default_node,
                "resources_available": True,
                "status_scope": "local_revision",
                "clocks": node_a_clocks,
                "watermarks": watermarks(
                    node_a_clocks, 0, "synthetic_complete_projection"
                ),
            },
            {
                "node_id": "node-b",
                "resources_available": False,
                "status_scope": "topology_and_clock_observation_only",
                "remote_watermark_lag_ns": 37_000_000,
                "clocks": node_b_clocks,
                "watermarks": watermarks(
                    node_b_clocks,
                    37_000_000,
                    "synthetic_remote_complete_projection",
                ),
            },
        ],
        "topology_projections": topology_projections,
    }


def build_temporal_metadata(dataset: dict[str, Any]) -> dict[str, Any]:
    """Return the example plug-in's revision and temporal bounds."""

    metadata = dataset.get("demo")
    if not isinstance(metadata, dict):
        raise TemporalTopologyRequestError(
            "example dataset lacks temporal metadata"
        )
    default_node = metadata.get("node")
    if not isinstance(default_node, str) or not default_node:
        raise TemporalTopologyRequestError(
            "example dataset lacks a default node"
        )
    return {
        "revision_id": str(metadata["revision_id"]),
        "timeline_start_ns": int(metadata["timeline_start_ns"]),
        "timeline_end_ns": int(metadata["timeline_end_ns"]),
        "capture_ns": int(metadata["capture_ns"]),
        "default_node": default_node,
        "data_disclosure": (
            "All temporal resources, relationships, clocks, and status "
            "perspectives are synthetic example plug-in output."
        ),
    }


__all__ = [
    "build_demo_plugin_contract",
    "build_temporal_metadata",
]
