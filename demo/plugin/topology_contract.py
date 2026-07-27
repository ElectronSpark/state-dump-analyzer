"""Example plug-in adapter that builds the generated topology contract."""

from __future__ import annotations

from typing import Any

from router_dump_analyzer.multi_node_topology import MultiNodeTopologyRequestError

from .assembly_store import DemoAssemblyStore
from . import (
    GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID,
    GENERATED_TOPOLOGY_PROFILE,
    GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID,
)


DEMO_TOPOLOGY_ID = "demo.fabric.multi-node"


def build_topology_contract(
    revision_store: DemoAssemblyStore,
) -> dict[str, Any]:
    """Build the generated fabric solely from assembly and plug-in evidence.

    Assembly descriptors and per-node topology projections are the complete
    source of truth.  This adapter validates and normalizes that evidence; it
    does not supplement it with a packaged demo topology catalog.
    """

    projection_reader = getattr(revision_store, "projection_for_node", None)
    if not callable(projection_reader):
        raise MultiNodeTopologyRequestError(
            "generated assembly store does not expose topology projections"
        )

    nodes: list[dict[str, Any]] = []
    for descriptor in revision_store.assembly.revisions:
        metadata = dict(descriptor.metadata)
        raw_role = metadata.get("role")
        role = (
            str(raw_role)
            if isinstance(raw_role, str) and raw_role
            else "router"
        )
        raw_roles = metadata.get("roles")
        roles = (
            [str(value) for value in raw_roles if value]
            if isinstance(raw_roles, (list, tuple))
            else [role]
        )
        raw_clock = metadata.get("clock")
        clock = None
        if isinstance(raw_clock, dict):
            clock = {
                "clock_domain": str(
                    raw_clock.get("domain")
                    or f"{descriptor.node_id}:generated-realtime"
                ),
                "local_minus_absolute_ns": int(
                    raw_clock.get("offset_ns", 0)
                ),
                "uncertainty_ns": int(
                    raw_clock.get("uncertainty_ns", 0)
                ),
                "mapping_method": "generated_node_manifest",
                "mapping_quality": "best_effort",
            }
        nodes.append(
            {
                "node_id": descriptor.node_id,
                "member_id": f"member:{descriptor.node_id}",
                "label": descriptor.label,
                "revision_id": descriptor.revision_id,
                "device_family": str(
                    metadata.get("device_family")
                    or f"generated-{role.replace('_', '-')}"
                ),
                "site": str(metadata.get("site") or "unspecified"),
                "roles": roles,
                "available": True,
                "optional": False,
                "default_selected": True,
                "unavailable_reason": None,
                "clock": clock,
                "archive_event_count": descriptor.event_count,
                "archive_resource_count": descriptor.resource_count,
                "archive_source": "generated-node-archive",
                "active_plugin_set_id": "",
                "plugin_sets": [],
            }
        )

    contract = {
        "nodes": nodes,
        "federation_plugin": {
            "plugin_id": GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID,
            "plugin_instance_id": "assembly/demo-fabric-linker",
            "plugin_run_id": "run:assembly:demo-fabric-linker:v1",
            "plugin_version": "1.0.0",
            "api_version": "1.0",
            "role": "inter_node_connector_resolution",
        },
        # The generated example currently emits shared-segment attachment
        # claims, not connector-pair claims.  Do not advertise the unrelated
        # connector matchers from the hand-written algorithm fixture.
        "inter_node_matchers": [],
        "network_segment_matchers": [
            {
                "matcher_id": GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID,
                "contract_version": "1.0",
                "match_semantics": "exact_token",
                "result_shape": "connectivity_domain",
                "owner_plugin_id": GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID,
                "description": (
                    "Exact equality of the generated plug-in's opaque "
                    "connectivity-domain key."
                ),
                "merge_critical_semantic_fields": [
                    "network_kind",
                    "role",
                    "routing_scope",
                    "address_family",
                    "prefix",
                    "participates_in_connectivity",
                    "presentation_group",
                    "topology_presentation",
                ],
                "status_combination_policy": (
                    "all_existing_attachments_usable"
                ),
                "external_classification_policy": (
                    "plugin_role_external_and_complete_projection_coverage"
                ),
            }
        ],
    }
    _install_generated_node_projections(
        contract,
        projection_reader,
        revision_store,
    )
    return contract


def _install_generated_node_projections(
    contract: dict[str, Any],
    projection_reader: Any,
    revision_store: DemoAssemblyStore,
) -> None:
    """Install bounded generated plug-in evidence on descriptor-built nodes."""

    matcher_id = GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID
    plugin_manifest = getattr(revision_store, "manifest", {})
    plugin_metadata = (
        plugin_manifest.get("plugin", {})
        if isinstance(plugin_manifest, dict)
        else {}
    )
    plugin_id = str(
        plugin_metadata.get("plugin_id") or "demo.example-router"
    )
    plugin_version = str(plugin_metadata.get("version") or "0.1.0")
    for node in contract["nodes"]:
        if not node.get("available"):
            continue
        node_id = str(node["node_id"])
        projection_payload = projection_reader(node_id)
        topology = projection_payload.get("topology", {})
        if not isinstance(topology, dict):
            raise MultiNodeTopologyRequestError(
                f"generated topology for {node_id} must be an object"
            )
        raw_profile = topology.get("profile")
        if isinstance(raw_profile, dict):
            profile_id = str(raw_profile.get("profile_id") or "")
            if profile_id != GENERATED_TOPOLOGY_PROFILE.profile_id:
                raise MultiNodeTopologyRequestError(
                    f"generated topology for {node_id} declares unsupported "
                    f"profile {profile_id or '<empty>'}"
                )
        raw_resources = topology.get("resources", [])
        raw_claims = topology.get("claims", [])
        if not isinstance(raw_resources, list) or not isinstance(
            raw_claims,
            list,
        ):
            raise MultiNodeTopologyRequestError(
                f"generated topology for {node_id} is malformed"
            )
        resources_by_id: dict[str, dict[str, Any]] = {}
        for item in raw_resources:
            if not isinstance(item, dict) or not item.get("resource_id"):
                raise MultiNodeTopologyRequestError(
                    f"generated topology resource for {node_id} is malformed"
                )
            resource_id = str(item["resource_id"])
            resources_by_id[resource_id] = {
                "resource_id": resource_id,
                "kind": str(item.get("kind") or "RESOURCE"),
                "label": str(item.get("label") or resource_id),
                "initial_status": str(item.get("status") or "up"),
                "initial_state": {
                    key: value
                    for key, value in item.items()
                    if key
                    not in {
                        "resource_id",
                        "kind",
                        "label",
                        "status",
                    }
                },
                "changes": list(item.get("changes") or []),
                "properties": {
                    key: value
                    for key, value in item.items()
                    if key
                    not in {
                        "resource_id",
                        "kind",
                        "label",
                        "status",
                        "changes",
                    }
                },
            }
        segment_claims: list[dict[str, Any]] = []
        for item in raw_claims:
            if (
                not isinstance(item, dict)
                or not item.get("interface_resource_id")
                or not item.get("segment_key")
            ):
                raise MultiNodeTopologyRequestError(
                    f"generated topology claim for {node_id} is malformed"
                )
            resource_id = str(item["interface_resource_id"])
            if resource_id not in resources_by_id:
                resources_by_id[resource_id] = {
                    "resource_id": resource_id,
                    "kind": "TOPOLOGY_ENDPOINT",
                    "label": str(item.get("interface_name") or resource_id),
                    "initial_status": str(item.get("status") or "up"),
                    "initial_state": {},
                    "changes": [],
                    "properties": {},
                }
            subnet = item.get("subnet")
            subnet = dict(subnet) if isinstance(subnet, dict) else {}
            classification = str(
                subnet.get("classification") or "underlay"
            )
            prefix = subnet.get("prefix")
            render_hint = str(
                subnet.get("render_hint") or "shared_subnet"
            )
            confidence_value = item.get("confidence", "best_effort")
            confidence_score = (
                1.0
                if confidence_value in {"exact", "plugin_declared"}
                else 0.75
                if confidence_value in {"inferred", "best_effort"}
                else 0.5
            )
            evidence_resource_ids = [
                str(value)
                for value in item.get("evidence_resource_ids", [])
                if value
            ]
            claim_matcher_id = str(
                item.get("matcher_id") or matcher_id
            )
            if claim_matcher_id != matcher_id:
                raise MultiNodeTopologyRequestError(
                    f"generated topology claim for {node_id} uses "
                    f"unsupported matcher {claim_matcher_id}"
                )
            declared_presentation = item.get("topology_presentation")
            if not isinstance(declared_presentation, dict):
                declared_presentation = {}
            two_participant_shape = str(
                declared_presentation.get(
                    "two_participant_shape",
                    (
                        "compact_edge"
                        if render_hint == "direct_line"
                        else "domain_node"
                    ),
                )
            )
            if two_participant_shape not in {
                "compact_edge",
                "domain_node",
            }:
                raise MultiNodeTopologyRequestError(
                    f"generated topology claim for {node_id} has invalid "
                    "two_participant_shape"
                )
            segment_claims.append(
                {
                    "resource_id": resource_id,
                    "segment_key": item["segment_key"],
                    "matcher_id": claim_matcher_id,
                    "plugin_semantics": {
                        "label": str(
                            item.get("label")
                            or prefix
                            or item["segment_key"]
                        ),
                        "network_kind": "subnet",
                        "role": classification,
                        "routing_scope": "global",
                        "address_family": (
                            "ipv6"
                            if isinstance(prefix, str) and ":" in prefix
                            else "ipv4"
                        ),
                        "prefix": prefix,
                        "participates_in_connectivity": not bool(
                            item.get("excluded_from_connectivity")
                        ),
                        "presentation_group": (
                            "management"
                            if classification == "management"
                            else "logical"
                            if classification == "loopback"
                            else "physical"
                        ),
                        "topology_presentation": {
                            "render_hint": render_hint,
                            "two_participant_shape": two_participant_shape,
                            "reason": declared_presentation.get("reason"),
                        },
                        "coverage_complete": True,
                    },
                    "attachment_model": {
                        "kind": str(
                            item.get("attachment_kind") or "logical"
                        ),
                        "components": dict(item.get("components") or {}),
                    },
                    "component_resource_ids": list(
                        dict.fromkeys([resource_id, *evidence_resource_ids])
                    ),
                    "confidence": {
                        "score": confidence_score,
                        "level": (
                            "high"
                            if confidence_score >= 0.9
                            else "medium"
                            if confidence_score >= 0.7
                            else "low"
                        ),
                        "owner": "plugin",
                    },
                    "inference": dict(item.get("calculation") or {})
                    | {
                        "owner": "plugin",
                        "method": "generated_example_plugin",
                    },
                    "evidence": [
                        {
                            "resource_id": evidence_id,
                            "basis": "generated_node_dump",
                        }
                        for evidence_id in evidence_resource_ids
                    ],
                    "valid_from_ns": item.get("valid_from_ns"),
                    "valid_to_ns": item.get("valid_to_ns"),
                    "semantic_owner": "plugin",
                }
            )
        plugin_set_id = f"{node_id}.generated.v1"
        projection_id = f"{node_id}.generated-topology"
        perspective_id = f"{node_id}.generated-observed"
        node["active_plugin_set_id"] = plugin_set_id
        node["plugin_sets"] = [
            {
                "plugin_set_id": plugin_set_id,
                "label": "Generated example plug-in",
                "active": True,
                "plugins": [
                    {
                        "plugin_id": plugin_id,
                        "plugin_instance_id": f"{node_id}/generated-plugin",
                        "plugin_run_id": (
                            f"run:{node_id}:generated-plugin:{plugin_version}"
                        ),
                        "version": plugin_version,
                        "api_version": "1.0",
                        "installed": True,
                        "active": True,
                        "available": True,
                        "roles": [
                            "resource_status",
                            "topology_projection",
                        ],
                        "projections": [
                            {
                                "projection_id": projection_id,
                                "label": "Generated subnet and interface evidence",
                                "description": (
                                    "Plug-in projection parsed from this node's "
                                    "generated dump packet."
                                ),
                                "supported_status_perspective_ids": [
                                    perspective_id
                                ],
                                "default_status_perspective_id": perspective_id,
                                "default_enabled": True,
                                "watermark_lag_ns": 0,
                                "watermark_scope": (
                                    "node/plugin/projection/status-perspective"
                                ),
                                "usable_statuses": [
                                    "active",
                                    "established",
                                    "programmed",
                                    "up",
                                    "usable",
                                ],
                                "unusable_statuses": [
                                    "down",
                                    "failed",
                                    "withdrawn",
                                ],
                                "resources": list(
                                    resources_by_id.values()
                                ),
                                "local_links": [],
                                "connector_claims": [],
                                "network_segment_claims": (
                                    segment_claims
                                ),
                            }
                        ],
                    }
                ],
            }
        ]


def build_topology_profiles(
    contract: dict[str, Any],
) -> list[dict[str, Any]]:
    plugin_sets: dict[str, str] = {}
    projections: dict[str, str] = {}
    perspectives: dict[str, str] = {}
    for node in contract["nodes"]:
        if not node.get("available"):
            continue
        member_id = str(node["member_id"])
        plugin_set_id = str(node["active_plugin_set_id"])
        plugin_set = next(
            item
            for item in node["plugin_sets"]
            if item["plugin_set_id"] == plugin_set_id
        )
        plugin = next(
            item
            for item in plugin_set["plugins"]
            if item.get("available", True)
        )
        projection = next(
            item
            for item in plugin["projections"]
            if item.get("default_enabled", True)
        )
        plugin_sets[member_id] = plugin_set_id
        projections[member_id] = str(projection["projection_id"])
        perspectives[member_id] = str(
            projection["default_status_perspective_id"]
        )
    return [
        {
            "profile_id": GENERATED_TOPOLOGY_PROFILE.profile_id,
            "label": GENERATED_TOPOLOGY_PROFILE.label,
            "projection_role": (
                GENERATED_TOPOLOGY_PROFILE.projection_role
            ),
            "presentation_roles": list(
                GENERATED_TOPOLOGY_PROFILE.presentation_roles
            ),
            "plugin_set_by_member": plugin_sets,
            "projection_by_member": projections,
            "perspective_by_member": perspectives,
        }
    ]


def build_topology_metadata(
    dataset: dict[str, Any],
    revision_store: DemoAssemblyStore,
) -> dict[str, Any]:
    """Return example labels and time bounds without exposing the archive store."""

    metadata = dataset.get("demo")
    if not isinstance(metadata, dict):
        raise MultiNodeTopologyRequestError(
            "example dataset lacks topology metadata"
        )
    return {
        "topology_id": DEMO_TOPOLOGY_ID,
        "assembly_id": revision_store.assembly.assembly_id,
        "revision_id": str(metadata["revision_id"]),
        "capture_ns": int(metadata["capture_ns"]),
        "timeline_start_ns": int(metadata["timeline_start_ns"]),
        "timeline_end_ns": int(metadata["timeline_end_ns"]),
        "label": "Heterogeneous EVPN fabric",
        "description": (
            "Synthetic multi-node reconstruction with independently selected "
            "device plug-ins, clocks, projections, and status perspectives."
        ),
        "default_profile_id": GENERATED_TOPOLOGY_PROFILE.profile_id,
        "default_clock_policy": "best_effort",
        "data_disclosure": (
            "All topology resources and claims are synthetic example "
            "plug-in output."
        ),
    }


__all__ = [
    "DEMO_TOPOLOGY_ID",
    "build_topology_contract",
    "build_topology_metadata",
    "build_topology_profiles",
]
