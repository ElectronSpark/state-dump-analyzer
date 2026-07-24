"""Heterogeneous multi-node topology reconstruction for the review demo.

The coordinator in this module deliberately treats node plug-ins as opaque
projection providers.  A provider emits resources, local links, point-to-point
connector claims, and multi-access segment attachments; the core resolves time
bases, preserves provenance, bounds results, and joins only claims that name
the same plug-in-declared matcher/key.  It does not parse prefixes or infer
networking meaning from resource kinds, labels, keys, VLANs, or VRFs.

Nanosecond values are serialized as strings because epoch-sized integers are
not safe JavaScript numbers.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from itertools import combinations
from typing import Any
from urllib.parse import quote, urlencode


MULTI_NODE_TOPOLOGY_ID = "demo.fabric.multi-node"


class MultiNodeTopologyRequestError(ValueError):
    """A multi-node request cannot be executed by the advertised providers."""


def _normalize_opaque_key(value: Any) -> dict[str, Any]:
    """Return a recursively type-tagged, JSON-safe exact-match key.

    Plug-ins own the meaning of every atom. The coordinator preserves atom and
    container types so, for example, a UUID never aliases its display string
    and binary bytes never alias a string that happens to look like ``repr``.
    """

    if value is None:
        return {"type": "null", "value": None}
    if isinstance(value, bool):
        return {"type": "boolean", "value": value}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        return {"type": "number", "encoding": "python-float-hex", "value": value.hex()}
    if isinstance(value, uuid.UUID):
        return {"type": "uuid", "encoding": "rfc4122", "value": str(value)}
    if isinstance(value, str):
        return {"type": "string", "value": value}
    if isinstance(value, (bytes, bytearray, memoryview)):
        payload = bytes(value)
        return {
            "type": "bytes",
            "encoding": "base64",
            "length": len(payload),
            "value": base64.b64encode(payload).decode("ascii"),
        }
    if isinstance(value, tuple):
        return {
            "type": "tuple",
            "items": [_normalize_opaque_key(item) for item in value],
        }
    if isinstance(value, list):
        return {
            "type": "list",
            "items": [_normalize_opaque_key(item) for item in value],
        }
    if isinstance(value, dict):
        entries = [
            {
                "key": _normalize_opaque_key(key),
                "value": _normalize_opaque_key(item),
            }
            for key, item in value.items()
        ]
        entries.sort(
            key=lambda entry: json.dumps(
                entry["key"], sort_keys=True, separators=(",", ":")
            )
        )
        return {"type": "mapping", "entries": entries}
    raise MultiNodeTopologyRequestError(
        f"opaque matcher key contains unsupported type {type(value).__name__}"
    )


def _canonical_opaque_key(value: Any) -> tuple[dict[str, Any], str]:
    normalized = _normalize_opaque_key(value)
    return normalized, json.dumps(normalized, sort_keys=True, separators=(",", ":"))


def _integer_ns(value: Any, field: str) -> int:
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
        raise MultiNodeTopologyRequestError(
            f"{field} must be an integer nanosecond value"
        )
    try:
        return int(value)
    except (ValueError, OverflowError) as error:
        raise MultiNodeTopologyRequestError(
            f"{field} must be an integer nanosecond value"
        ) from error


def _canonical_topology_basis(
    value: Any,
    field: str = "basis",
) -> dict[str, Any]:
    """Validate and normalize an API time basis for stable semantic comparison."""

    if not isinstance(value, dict):
        raise MultiNodeTopologyRequestError(f"{field} must be an object")
    raw_kind = value.get("kind", "relative_to_watermark")
    if not isinstance(raw_kind, str) or not raw_kind:
        raise MultiNodeTopologyRequestError(f"{field}.kind must be a string")
    kind = (
        "relative_to_watermark"
        if raw_kind == "relative_to_scope_end"
        else raw_kind
    )
    if kind == "absolute_time":
        raw_domain = value.get("clock_domain", "utc")
        if not isinstance(raw_domain, str) or not raw_domain:
            raise MultiNodeTopologyRequestError(
                f"{field}.clock_domain must be a string"
            )
        if raw_domain != "utc":
            raise MultiNodeTopologyRequestError(
                f"unsupported absolute clock domain: {raw_domain}"
            )
        has_time = "time_ns" in value
        has_timestamp = "timestamp_ns" in value
        if not has_time and not has_timestamp:
            raise MultiNodeTopologyRequestError(
                f"{field}.time_ns must be an integer nanosecond value"
            )
        time_ns = _integer_ns(
            value["time_ns"] if has_time else value["timestamp_ns"],
            f"{field}.time_ns",
        )
        if has_time and has_timestamp:
            timestamp_ns = _integer_ns(
                value["timestamp_ns"], f"{field}.timestamp_ns"
            )
            if timestamp_ns != time_ns:
                raise MultiNodeTopologyRequestError(
                    f"{field}.time_ns and {field}.timestamp_ns disagree"
                )
        return {
            "kind": "absolute_time",
            "clock_domain": "utc",
            "time_ns": str(time_ns),
        }
    if kind == "relative_to_watermark":
        offset_ns = _integer_ns(value.get("offset_ns", 0), f"{field}.offset_ns")
        if offset_ns > 0:
            raise MultiNodeTopologyRequestError(
                f"{field}.offset_ns must be zero or negative"
            )
        return {
            "kind": "relative_to_watermark",
            "offset_ns": str(offset_ns),
        }
    raise MultiNodeTopologyRequestError(
        f"{field}.kind must be absolute_time or relative_to_watermark"
    )


def _status_at(resource: dict[str, Any], timestamp_ns: int) -> tuple[bool, str, dict[str, Any]]:
    valid_from = resource.get("valid_from_ns")
    valid_to = resource.get("valid_to_ns")
    exists = (valid_from is None or timestamp_ns >= int(valid_from)) and (
        valid_to is None or timestamp_ns < int(valid_to)
    )
    status = str(resource.get("initial_status", "unknown"))
    state = dict(resource.get("initial_state") or {})
    for change in sorted(
        resource.get("changes", []), key=lambda item: int(item["time_ns"])
    ):
        if timestamp_ns < int(change["time_ns"]):
            break
        status = str(change.get("status", status))
        state.update(change.get("state") or {})
    return exists, status if exists else "absent", state


class MultiNodeTopologyDemo:
    """Coordinate independently selected plug-in projections across nodes."""

    def __init__(self, dataset: dict[str, Any]) -> None:
        self.dataset = dataset
        self.revision_id = str(dataset["demo"]["revision_id"])
        self.capture_ns = int(dataset["demo"]["capture_ns"])
        self.start_ns = int(dataset["demo"]["timeline_start_ns"])
        self.end_ns = int(dataset["demo"]["timeline_end_ns"])
        self.contract = _demo_contract(self.revision_id, self.capture_ns)
        self.nodes_by_id = {
            str(item["node_id"]): item for item in self.contract["nodes"]
        }
        self._node_order = {
            str(item["node_id"]): index
            for index, item in enumerate(self.contract["nodes"])
        }
        self._contexts: dict[str, dict[str, Any]] = {}

    @staticmethod
    def normalize_basis(
        basis: Any,
        field: str = "basis",
    ) -> dict[str, Any]:
        """Return the canonical form used in contexts and cross-API comparisons."""

        return _canonical_topology_basis(basis, field)

    def capabilities(self) -> dict[str, Any]:
        profiles = _topology_profiles()
        return {
            "api_version": "v1",
            "topology_id": MULTI_NODE_TOPOLOGY_ID,
            "assembly_id": MULTI_NODE_TOPOLOGY_ID,
            "label": "Heterogeneous EVPN fabric",
            "description": (
                "Synthetic multi-node reconstruction with independently selected "
                "device plug-ins, clocks, projections, and status perspectives."
            ),
            "revision_id": self.revision_id,
            "defaults": {
                "basis": {
                    "kind": "relative_to_watermark",
                    "offset_ns": "0",
                },
                "clock_policy": "best_effort",
                "profile_id": "fabric-underlay",
                "node_ids": [
                    item["node_id"]
                    for item in self.contract["nodes"]
                    if item.get("default_selected", True)
                ],
            },
            "time_bounds": {
                "start_ns": str(self.start_ns),
                "end_ns": str(self.end_ns),
                "capture_ns": str(self.capture_ns),
            },
            "absolute_clock_domains": ["utc"],
            "time_bases": [
                {
                    "kind": "absolute_time",
                    "required": ["time_ns"],
                    "semantics": "One UTC instant mapped independently through each node clock.",
                },
                {
                    "kind": "relative_to_watermark",
                    "required": ["offset_ns"],
                    "semantics": (
                        "An offset from each selected plug-in projection watermark; "
                        "the result is a capture vector and is not necessarily simultaneous."
                    ),
                },
            ],
            "clock_policies": ["strict", "best_effort"],
            "default_profile_id": "fabric-underlay",
            "default_clock_policy": "best_effort",
            "topology_profiles": profiles,
            "status_perspectives": [
                {
                    "perspective_id": "observed-status",
                    "label": "Device-specific observed status",
                    "semantic_role": "observed",
                },
                {
                    "perspective_id": "control-state",
                    "label": "Device-specific control state",
                    "semantic_role": "control",
                },
            ],
            "nodes": [self._public_node(item) for item in self.contract["nodes"]],
            "members": [self._public_node(item) for item in self.contract["nodes"]],
            "inter_node_matchers": self.contract["inter_node_matchers"],
            "network_segment_matchers": self.contract[
                "network_segment_matchers"
            ],
            "federation_plugin": self.contract["federation_plugin"],
            "request_contract": {
                "node_queries": {
                    "required": ["node_id", "plugin_set_id"],
                    "projection_selection": (
                        "projections[] contains plugin_id, projection_id, and "
                        "status_perspective_id advertised by that node."
                    ),
                    "basis_override": "optional per-node basis",
                }
            },
            "limits": {
                "max_nodes": 32,
                "max_projections_per_node": 16,
                "max_resources_per_projection": 500,
                "max_inter_node_links": 1000,
                "max_network_segments": 500,
                "max_segment_attachments": 4000,
            },
            "network_segment_contract": {
                "contract_version": "1.0",
                "match_semantics": "exact_token",
                "result_shape": "connectivity_domain",
                "plugin_record_model": {
                    "segment": "TopologyResourceRecord(role=connectivity-domain)",
                    "attachment": (
                        "TopologyLinkRecord(endpoint resource -> connectivity-domain resource)"
                    ),
                    "endpoint": "TopologyEndpointRecord when an explicit port anchor is needed",
                },
                "normalized_view": (
                    "The coordinator federates those ordinary graph records into "
                    "network_segments and segment_attachments without changing the v1 payload union."
                ),
                "federation_key": ["matcher_id", "segment_key"],
                "key_encoding": {
                    "form": "recursive_type_tagged_json",
                    "binary_encoding": "base64",
                    "large_integer_encoding": "decimal_string",
                    "compound_types_preserved": True,
                },
                "attachment_identity": {
                    "stable_fields": [
                        "assembly_id",
                        "segment_id",
                        "member_id",
                        "revision_id",
                        "resource_id",
                        "optional_plugin_attachment_key",
                    ],
                    "plugin_run_id_is_provenance_only": True,
                },
                "resource_preview_independent": True,
                "result_fields": [
                    "network_segments",
                    "segment_attachments",
                    "segment_resolutions",
                ],
                "single_attachment_semantics": (
                    "single_sided_in_query_scope; external is asserted only by a plugin"
                ),
                "presentation": {
                    "plugin_field": "topology_presentation.two_participant_shape",
                    "values": ["domain_node", "compact_edge"],
                    "default": "domain_node",
                    "core_guard": (
                        "compact_edge requires a physical conflict-free domain, "
                        "complete current membership, and exactly two distinct participants"
                    ),
                    "view_only": True,
                },
                "compatibility_projection": (
                    "inter_node_links remains route_trace_compatibility data and is "
                    "suppressed in the physical view when network_segments is available"
                ),
            },
            "semantic_ownership": {
                "core": [
                    "capability negotiation and request validation",
                    "absolute/relative time-basis resolution",
                    "bounded merge and completeness reporting",
                    "joining compatible connector claims by declared matcher and key",
                    "stable segment and attachment identifiers",
                    "bounded grouping of opaque segment claims without N-squared links",
                    "safe validation and rendering of declared topology presentation hints",
                    "temporal envelopes, provenance, confidence aggregation, and ambiguity reporting",
                    "stable navigation identifiers",
                ],
                "plugin": [
                    "resource identity and status interpretation",
                    "topology projections and local links",
                    "connector claim keys and inter-node matcher semantics",
                    "segment matching keys and all prefix/address interpretation",
                    "segment role, routing scope, VPN, management, and loopback classification",
                    "VLAN, LAG, subinterface, physical-member, neighbor, and route inference details",
                    "whether a segment participates in connectivity or a separate presentation",
                    "whether a complete two-participant domain may use compact-edge presentation",
                    "status perspective and usability mapping",
                    "projection completeness watermarks",
                ],
            },
            "deep_links": {
                "topology": {
                    "href": f"/?topology_id={quote(MULTI_NODE_TOPOLOGY_ID)}",
                    "route": "/",
                }
            },
            "demo_disclosure": (
                "All remote nodes, plug-in inventories, connector claims, and clocks "
                "are synthetic. The orchestration contract is implementation-neutral."
            ),
        }

    def node_capabilities(self, node_id: str) -> dict[str, Any]:
        node = self._node(node_id)
        return {
            "api_version": "v1",
            "topology_id": MULTI_NODE_TOPOLOGY_ID,
            "revision_id": node["revision_id"],
            "node": self._public_node(node),
            "member": self._public_node(node),
            "parent": self.capabilities()["deep_links"]["topology"],
        }

    def context_member(self, context_id: str, member_id: str) -> dict[str, Any]:
        """Return one immutable member snapshot from a prior reconstruction."""

        result = self._contexts.get(context_id)
        if result is None:
            raise MultiNodeTopologyRequestError("unknown or expired topology context")
        member = next(
            (
                item
                for item in result["nodes"]
                if item["member_id"] == member_id or item["node_id"] == member_id
            ),
            None,
        )
        if member is None:
            raise MultiNodeTopologyRequestError(
                f"member {member_id} is not part of topology context {context_id}"
            )
        return {
            "api_version": "v1",
            "assembly_id": MULTI_NODE_TOPOLOGY_ID,
            "topology_id": MULTI_NODE_TOPOLOGY_ID,
            "context_id": context_id,
            "member": member,
            "incident_inter_node_links": [
                link
                for link in result["inter_node_links"]
                if member["member_id"]
                in {
                    link["endpoint_a"]["member_id"],
                    link["endpoint_b"]["member_id"],
                }
            ],
            "incident_segment_attachments": [
                attachment
                for attachment in result.get("segment_attachments", [])
                if attachment["member_id"] == member["member_id"]
            ],
            "network_segments": [
                segment
                for segment in result.get("network_segments", [])
                if member["member_id"] in segment["observed_member_ids"]
            ],
            "navigation": result["deep_links"],
        }

    def query_node(self, node_id: str, body: dict[str, Any]) -> dict[str, Any]:
        node = self._node(node_id)
        node_query = {
            "node_id": node_id,
            "plugin_set_id": body.get(
                "plugin_set_id", node["active_plugin_set_id"]
            ),
        }
        for field in ("basis", "projections"):
            if field in body:
                node_query[field] = body[field]
        if "projections" not in node_query and any(
            field in body
            for field in ("plugin_id", "projection_id", "status_perspective_id")
        ):
            node_query["projections"] = [
                {
                    key: body[key]
                    for key in (
                        "plugin_id",
                        "projection_id",
                        "status_perspective_id",
                    )
                    if key in body
                }
            ]
        result = self.query(
            {
                **body,
                "node_queries": [node_query],
            }
        )
        snapshot = result["nodes"][0]
        return {
            "api_version": result["api_version"],
            "topology_id": result["topology_id"],
            "revision_id": snapshot["revision_id"],
            "resolved_basis": result["resolved_basis"],
            "node": snapshot,
            "incident_inter_node_links": result["inter_node_links"],
            "network_segments": result["network_segments"],
            "segment_attachments": result["segment_attachments"],
            "segment_resolutions": result["segment_resolutions"],
            "completeness": result["completeness"],
            "navigation": {
                "parent_topology": result["deep_links"]["self"],
                "individual_node": snapshot["deep_links"]["individual_node"],
            },
        }

    def query(self, body: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise MultiNodeTopologyRequestError("request body must be an object")
        clock_policy = str(body.get("clock_policy", "best_effort"))
        if clock_policy not in {"strict", "best_effort"}:
            raise MultiNodeTopologyRequestError(
                "clock_policy must be strict or best_effort"
            )
        global_basis = self.normalize_basis(
            body["basis"]
            if "basis" in body
            else {
                "kind": "relative_to_watermark",
                "offset_ns": "0",
            }
        )
        node_queries = self._node_queries(body)
        if len(node_queries) > 32:
            raise MultiNodeTopologyRequestError("at most 32 nodes may be queried")
        resource_limit = max(
            1,
            min(
                _integer_ns(
                    body.get(
                        "resource_limit", body.get("resource_preview_limit", 100)
                    ),
                    "resource_limit",
                ),
                500,
            ),
        )
        link_limit = max(
            1,
            min(
                _integer_ns(
                    body.get("inter_node_link_limit", body.get("link_limit", 1000)),
                    "inter_node_link_limit",
                ),
                1000,
            ),
        )
        segment_limit = max(
            1,
            min(
                _integer_ns(
                    body.get("network_segment_limit", 500),
                    "network_segment_limit",
                ),
                500,
            ),
        )
        attachment_limit = max(
            1,
            min(
                _integer_ns(
                    body.get("segment_attachment_limit", 4000),
                    "segment_attachment_limit",
                ),
                4000,
            ),
        )
        context_material = {
            "assembly_id": MULTI_NODE_TOPOLOGY_ID,
            "basis": global_basis,
            "clock_policy": clock_policy,
            "node_queries": node_queries,
            "resource_limit": resource_limit,
            "inter_node_link_limit": link_limit,
            "network_segment_limit": segment_limit,
            "segment_attachment_limit": attachment_limit,
        }
        context_digest = hashlib.sha256(
            json.dumps(
                context_material,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        ).hexdigest()[:24]
        context_id = f"tctx1-{context_digest}"

        snapshots: list[dict[str, Any]] = []
        all_claims: list[dict[str, Any]] = []
        all_segment_claims: list[dict[str, Any]] = []
        basis_kinds: set[str] = set()
        for node_query in node_queries:
            node = self._node(str(node_query["node_id"]))
            basis = node_query.get("basis", global_basis)
            snapshot = self._query_one_node(
                node,
                node_query,
                basis,
                clock_policy,
                resource_limit,
                context_id,
            )
            snapshots.append(snapshot)
            all_claims.extend(snapshot.pop("_connector_claims"))
            all_segment_claims.extend(snapshot.pop("_network_segment_claims"))
            basis_kinds.update(
                item["basis_kind"] for item in snapshot["resolved_times"]
            )

        (
            inter_node_links,
            connector_resolutions,
            unmatched_claims,
            links_truncated,
        ) = self._join_claims(all_claims, link_limit, context_id)
        (
            network_segments,
            segment_attachments,
            segment_resolutions,
            segments_truncated,
            attachments_truncated,
        ) = self._assemble_network_segments(
            all_segment_claims,
            segment_limit,
            attachment_limit,
        )
        unresolved_segment_claims = [
            item
            for item in segment_resolutions
            if item.get("resolution") == "unsupported_matcher_contract"
        ]
        incomplete_nodes = [
            item["node_id"] for item in snapshots if not item["complete"]
        ]
        relative = any(kind == "relative_capture_vector" for kind in basis_kinds)
        mixed = len(basis_kinds) > 1
        requested_node_ids = [item["node_id"] for item in snapshots]
        resolved_basis = {
            "requested": global_basis,
            "kind": (
                "mixed_capture_vector"
                if mixed
                else next(iter(basis_kinds), "unresolved")
            ),
            "clock_policy": clock_policy,
            "simultaneity": (
                "not_implied" if relative or mixed else "same_absolute_instant"
            ),
            "node_count": len(snapshots),
            "projection_time_count": sum(
                len(item["resolved_times"]) for item in snapshots
            ),
        }
        topology_href = self._topology_href(
            global_basis,
            requested_node_ids,
            body.get("selected_link_id"),
            context_id,
        )
        response = {
            "api_version": "v1",
            "topology_id": MULTI_NODE_TOPOLOGY_ID,
            "assembly_id": MULTI_NODE_TOPOLOGY_ID,
            "context_id": context_id,
            "revision_id": self.revision_id,
            "resolved_basis": resolved_basis,
            "nodes": snapshots,
            "inter_node_links": inter_node_links,
            "connector_resolutions": connector_resolutions,
            "network_segments": network_segments,
            "segment_attachments": segment_attachments,
            "segment_resolutions": segment_resolutions,
            "counts": {
                "nodes": len(snapshots),
                "plugin_results": sum(
                    len(item["plugin_results"]) for item in snapshots
                ),
                "resources": sum(len(item["resources"]) for item in snapshots),
                "local_links": sum(len(item["local_links"]) for item in snapshots),
                "connector_claims": len(all_claims),
                "inter_node_links": len(inter_node_links),
                "unmatched_connector_claims": len(unmatched_claims),
                "connector_resolutions": len(connector_resolutions),
                "network_segment_claims": len(all_segment_claims),
                "network_segments": len(network_segments),
                "segment_attachments": len(segment_attachments),
            },
            "complete": (
                not incomplete_nodes
                and not links_truncated
                and not unmatched_claims
                and not segments_truncated
                and not attachments_truncated
                and not unresolved_segment_claims
            ),
            "completeness": {
                "complete": (
                    not incomplete_nodes
                    and not links_truncated
                    and not unmatched_claims
                    and not segments_truncated
                    and not attachments_truncated
                    and not unresolved_segment_claims
                ),
                "incomplete_nodes": incomplete_nodes,
                "unmatched_connector_claims": unmatched_claims,
                "inter_node_links_truncated": links_truncated,
                "network_segments_truncated": segments_truncated,
                "segment_attachments_truncated": attachments_truncated,
                "unresolved_network_segment_claims": unresolved_segment_claims,
                "clock_alignment": (
                    "capture_vector_not_simultaneous"
                    if resolved_basis["simultaneity"] == "not_implied"
                    else "common_absolute_instant_with_per_node_uncertainty"
                ),
            },
            "deep_links": {
                "self": {
                    "href": topology_href,
                    "route": "/",
                    "topology_id": MULTI_NODE_TOPOLOGY_ID,
                    "assembly_id": MULTI_NODE_TOPOLOGY_ID,
                    "context_id": context_id,
                },
                "individual_nodes": [
                    item["deep_links"]["individual_node"] for item in snapshots
                ],
            },
            "semantic_ownership": {
                "node_projection": "plugin",
                "connector_matcher": "plugin",
                "segment_matcher_and_semantics": "plugin",
                "interface_stack_and_inference": "plugin",
                "time_resolution": "core",
                "claim_join_and_pagination": "core",
                "segment_grouping_and_pagination": "core",
            },
        }
        self._contexts[context_id] = response
        while len(self._contexts) > 32:
            self._contexts.pop(next(iter(self._contexts)))
        return response

    def _node_queries(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        if "node_ids" in body and "node_queries" in body:
            raise MultiNodeTopologyRequestError(
                "node_ids and node_queries cannot both be supplied"
            )
        raw = body.get("node_queries")
        if raw is None:
            selected_ids = body.get("node_ids")
            if selected_ids is None:
                selected_ids = [
                    item["node_id"]
                    for item in self.contract["nodes"]
                    if item.get("default_selected", True)
                ]
            if not isinstance(selected_ids, list):
                raise MultiNodeTopologyRequestError("node_ids must be an array")
            if not selected_ids:
                raise MultiNodeTopologyRequestError(
                    "node_ids must be a non-empty array"
                )
            result: list[dict[str, Any]] = []
            seen: set[str] = set()
            for selected_id in selected_ids:
                node_id = str(selected_id)
                if node_id in seen:
                    raise MultiNodeTopologyRequestError(
                        f"duplicate node id: {node_id}"
                    )
                seen.add(node_id)
                result.append(
                    {
                        "node_id": node_id,
                        "plugin_set_id": self._node(node_id)[
                            "active_plugin_set_id"
                        ],
                    }
                )
            return result
        if not isinstance(raw, list) or not raw:
            raise MultiNodeTopologyRequestError(
                "node_queries must be a non-empty array"
            )
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in raw:
            if not isinstance(item, dict) or not item.get("node_id"):
                raise MultiNodeTopologyRequestError(
                    "each node query requires node_id"
                )
            node_id = str(item["node_id"])
            if node_id in seen:
                raise MultiNodeTopologyRequestError(
                    f"duplicate node query: {node_id}"
                )
            seen.add(node_id)
            normalized = dict(item)
            if "basis" in normalized:
                normalized["basis"] = self.normalize_basis(
                    normalized["basis"], f"basis for node {node_id}"
                )
            result.append(normalized)
        return result

    def _query_one_node(
        self,
        node: dict[str, Any],
        request: dict[str, Any],
        basis: dict[str, Any],
        clock_policy: str,
        resource_limit: int,
        context_id: str,
    ) -> dict[str, Any]:
        plugin_set_id = str(
            request.get("plugin_set_id", node["active_plugin_set_id"])
        )
        plugin_set = next(
            (
                item
                for item in node["plugin_sets"]
                if item["plugin_set_id"] == plugin_set_id
            ),
            None,
        )
        if plugin_set is None:
            raise MultiNodeTopologyRequestError(
                f"unknown plugin_set_id {plugin_set_id} for node {node['node_id']}"
            )
        selections = self._projection_selections(node, plugin_set, request)
        plugin_results: list[dict[str, Any]] = []
        resolved_times: list[dict[str, Any]] = []
        resources: list[dict[str, Any]] = []
        local_links: list[dict[str, Any]] = []
        claims: list[dict[str, Any]] = []
        segment_claims: list[dict[str, Any]] = []
        incomplete_reasons: list[dict[str, Any]] = []

        for selection in selections:
            plugin = selection["plugin"]
            projection = selection["projection"]
            perspective_id = selection["status_perspective_id"]
            if not node.get("available", True) or not plugin.get("available", True):
                reason = plugin.get("unavailable_reason") or node.get(
                    "unavailable_reason", "node_data_unavailable"
                )
                incomplete_reasons.append(
                    {
                        "plugin_id": plugin["plugin_id"],
                        "projection_id": projection["projection_id"],
                        "reason_code": reason,
                    }
                )
                plugin_results.append(
                    self._unavailable_plugin_result(
                        node, plugin_set_id, plugin, projection, perspective_id, reason
                    )
                )
                continue
            resolved_time = self._resolve_time(
                node,
                plugin_set_id,
                plugin,
                projection,
                perspective_id,
                basis,
                clock_policy,
            )
            resolved_times.append(resolved_time)
            if resolved_time["resolution"] == "clock_unaligned":
                incomplete_reasons.append(
                    {
                        "plugin_id": plugin["plugin_id"],
                        "projection_id": projection["projection_id"],
                        "reason_code": "clock_unaligned",
                    }
                )
                plugin_results.append(
                    self._unaligned_plugin_result(
                        node,
                        plugin_set_id,
                        plugin,
                        projection,
                        perspective_id,
                        resolved_time,
                    )
                )
                continue
            result = self._run_projection(
                node,
                plugin_set_id,
                plugin,
                projection,
                perspective_id,
                resolved_time,
                basis,
                resource_limit,
                context_id,
            )
            plugin_results.append(result)
            resources.extend(result["resources"])
            local_links.extend(result["local_links"])
            claims.extend(result.pop("connector_claims"))
            segment_claims.extend(result.pop("network_segment_claims"))
            if not result["complete"]:
                incomplete_reasons.append(
                    {
                        "plugin_id": plugin["plugin_id"],
                        "projection_id": projection["projection_id"],
                        "reason_code": "projection_truncated",
                    }
                )

        primary_projection = selections[0] if selections else None
        primary_time = resolved_times[0] if resolved_times else None
        individual_link = self._node_deep_link(
            node,
            plugin_set_id,
            primary_projection,
            basis,
            primary_time,
            context_id,
        )
        primary_plan = (
            {
                "plugin_set_id": plugin_set_id,
                "plugin_id": primary_projection["plugin"]["plugin_id"],
                "plugin_run_id": primary_projection["plugin"]["plugin_run_id"],
                "projection_id": primary_projection["projection"]["projection_id"],
                "status_perspective_id": primary_projection[
                    "status_perspective_id"
                ],
            }
            if primary_projection
            else {"plugin_set_id": plugin_set_id}
        )
        return {
            "node_id": node["node_id"],
            "member_id": node["member_id"],
            "label": node["label"],
            "site": node.get("site"),
            "roles": list(node.get("roles", [])),
            "revision_id": node["revision_id"],
            "available": bool(node.get("available", True)),
            "resources_available": bool(node.get("available", True)),
            "plugin_set_id": plugin_set_id,
            "node_query": primary_plan,
            "installed_plugin_sets": [
                self._public_plugin_set(item) for item in node["plugin_sets"]
            ],
            "selected_plugins": [
                self._plugin_provenance(item["plugin"], plugin_set_id)
                | {
                    "projection_id": item["projection"]["projection_id"],
                    "status_perspective_id": item["status_perspective_id"],
                }
                for item in selections
            ],
            "resolved_time": primary_time,
            "resolved_basis": primary_time,
            "resolved_times": resolved_times,
            "plugin_results": plugin_results,
            "resources": resources,
            "resource_previews": resources,
            "resource_count": len(resources),
            "local_links": local_links,
            "counts": {
                "plugin_results": len(plugin_results),
                "resources": len(resources),
                "local_links": len(local_links),
                "connector_claims": len(claims),
                "network_segment_claims": len(segment_claims),
            },
            "complete": not incomplete_reasons,
            "completeness": {
                "complete": not incomplete_reasons,
                "status": "complete" if not incomplete_reasons else "partial",
                "reasons": incomplete_reasons,
            },
            "navigation_target": individual_link,
            "deep_links": {"individual_node": individual_link},
            "_connector_claims": claims,
            "_network_segment_claims": segment_claims,
        }

    def _projection_selections(
        self,
        node: dict[str, Any],
        plugin_set: dict[str, Any],
        request: dict[str, Any],
    ) -> list[dict[str, Any]]:
        plugins = {
            item["plugin_id"]: item for item in plugin_set.get("plugins", [])
        }
        raw = request.get("projections")
        if raw is None and any(
            field in request
            for field in ("plugin_id", "projection_id", "status_perspective_id")
        ):
            raw = [
                {
                    field: request[field]
                    for field in (
                        "plugin_id",
                        "projection_id",
                        "status_perspective_id",
                    )
                    if field in request
                }
            ]
        if raw is None:
            raw = [
                {
                    "plugin_id": plugin["plugin_id"],
                    "projection_id": projection["projection_id"],
                    "status_perspective_id": projection[
                        "default_status_perspective_id"
                    ],
                }
                for plugin in plugins.values()
                if plugin.get("active", True)
                for projection in plugin.get("projections", [])
                if projection.get("default_enabled", True)
            ]
        if not isinstance(raw, list) or len(raw) > 16:
            raise MultiNodeTopologyRequestError(
                f"projections for node {node['node_id']} must be an array of at most 16"
            )
        selections: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for item in raw:
            if isinstance(item, str):
                item = {"projection_id": item}
            if not isinstance(item, dict):
                raise MultiNodeTopologyRequestError(
                    f"invalid projection selection for node {node['node_id']}"
                )
            plugin_id = item.get("plugin_id")
            projection_id = item.get("projection_id")
            candidates = [
                (plugin, projection)
                for plugin in plugins.values()
                if plugin_id is None or plugin["plugin_id"] == str(plugin_id)
                for projection in plugin.get("projections", [])
                if projection_id is None
                or projection["projection_id"] == str(projection_id)
            ]
            if len(candidates) != 1:
                raise MultiNodeTopologyRequestError(
                    "projection selection must resolve to exactly one installed provider "
                    f"for node {node['node_id']}: plugin={plugin_id!r}, "
                    f"projection={projection_id!r}"
                )
            plugin, projection = candidates[0]
            perspective_id = str(
                item.get("status_perspective_id")
                or projection["default_status_perspective_id"]
            )
            supported = set(projection["supported_status_perspective_ids"])
            if perspective_id not in supported:
                raise MultiNodeTopologyRequestError(
                    f"status perspective {perspective_id} is not supported by "
                    f"{plugin['plugin_id']}:{projection['projection_id']} on "
                    f"node {node['node_id']}"
                )
            key = (plugin["plugin_id"], projection["projection_id"], perspective_id)
            if key in seen:
                raise MultiNodeTopologyRequestError(
                    f"duplicate projection selection on node {node['node_id']}: {key}"
                )
            seen.add(key)
            selections.append(
                {
                    "plugin": plugin,
                    "projection": projection,
                    "status_perspective_id": perspective_id,
                }
            )
        if not selections:
            raise MultiNodeTopologyRequestError(
                f"node {node['node_id']} has no selected topology projection"
            )
        return selections

    def _resolve_time(
        self,
        node: dict[str, Any],
        plugin_set_id: str,
        plugin: dict[str, Any],
        projection: dict[str, Any],
        perspective_id: str,
        basis: dict[str, Any],
        clock_policy: str,
    ) -> dict[str, Any]:
        kind = str(basis.get("kind", "relative_to_watermark"))
        if kind == "relative_to_scope_end":
            kind = "relative_to_watermark"
        clock = node.get("clock")
        if kind == "absolute_time":
            domain = str(basis.get("clock_domain", "utc"))
            if domain != "utc":
                raise MultiNodeTopologyRequestError(
                    f"unsupported absolute clock domain: {domain}"
                )
            query_time = _integer_ns(
                basis.get("time_ns", basis.get("timestamp_ns")),
                "basis.time_ns",
            )
            watermark = None
            basis_kind = "absolute_time"
        elif kind == "relative_to_watermark":
            offset = _integer_ns(basis.get("offset_ns", 0), "basis.offset_ns")
            if offset > 0:
                raise MultiNodeTopologyRequestError(
                    "basis.offset_ns must be zero or negative"
                )
            lag = int(projection.get("watermark_lag_ns", 0))
            watermark = self.capture_ns - lag
            query_time = watermark + offset
            basis_kind = "relative_capture_vector"
        else:
            raise MultiNodeTopologyRequestError(
                "basis.kind must be absolute_time or relative_to_watermark"
            )
        if not clock:
            if clock_policy == "strict":
                raise MultiNodeTopologyRequestError(
                    f"node {node['node_id']} has no usable clock mapping"
                )
            return {
                "node_id": node["node_id"],
                "member_id": node["member_id"],
                "revision_id": node["revision_id"],
                "plugin_set_id": plugin_set_id,
                "plugin_id": plugin["plugin_id"],
                "plugin_run_id": plugin["plugin_run_id"],
                "projection_id": projection["projection_id"],
                "status_perspective_id": perspective_id,
                "basis_kind": basis_kind,
                "kind": basis_kind,
                "query_time_ns": None,
                "local_time_ns": None,
                "absolute_min_ns": None,
                "absolute_max_ns": None,
                "uncertainty_ns": None,
                "resolution": "clock_unaligned",
                "reason_code": "clock_mapping_unavailable",
            }
        uncertainty = int(clock["uncertainty_ns"])
        result = {
            "node_id": node["node_id"],
            "member_id": node["member_id"],
            "revision_id": node["revision_id"],
            "plugin_set_id": plugin_set_id,
            "plugin_id": plugin["plugin_id"],
            "plugin_run_id": plugin["plugin_run_id"],
            "projection_id": projection["projection_id"],
            "status_perspective_id": perspective_id,
            "basis_kind": basis_kind,
            "kind": basis_kind,
            "query_time_ns": str(query_time),
            "local_time_ns": str(query_time + int(clock["local_minus_absolute_ns"])),
            "local_clock_domain": clock["clock_domain"],
            "absolute_min_ns": str(query_time - uncertainty),
            "absolute_max_ns": str(query_time + uncertainty),
            "uncertainty_ns": str(uncertainty),
            "resolution": "exact" if uncertainty == 0 else "bounded",
            "mapping_method": clock["mapping_method"],
            "mapping_quality": clock["mapping_quality"],
            "simultaneity": (
                "same_absolute_instant"
                if basis_kind == "absolute_time"
                else "not_implied"
            ),
        }
        if watermark is not None:
            result.update(
                {
                    "watermark_query_time_ns": str(watermark),
                    "watermark_local_time_ns": str(
                        watermark + int(clock["local_minus_absolute_ns"])
                    ),
                    "watermark_scope": {
                        "node_id": node["node_id"],
                        "member_id": node["member_id"],
                        "revision_id": node["revision_id"],
                        "plugin_set_id": plugin_set_id,
                        "plugin_id": plugin["plugin_id"],
                        "plugin_run_id": plugin["plugin_run_id"],
                        "projection_id": projection["projection_id"],
                        "status_perspective_id": perspective_id,
                    },
                    "relative_offset_ns": str(query_time - watermark),
                }
            )
        return result

    def _run_projection(
        self,
        node: dict[str, Any],
        plugin_set_id: str,
        plugin: dict[str, Any],
        projection: dict[str, Any],
        perspective_id: str,
        resolved_time: dict[str, Any],
        requested_basis: dict[str, Any],
        resource_limit: int,
        context_id: str,
    ) -> dict[str, Any]:
        timestamp_ns = int(resolved_time["query_time_ns"])
        all_resources = list(projection.get("fixture_resources", []))
        resources: list[dict[str, Any]] = []
        state_by_id: dict[str, dict[str, Any]] = {}
        # The resource limit bounds only the response preview. Connector and
        # connectivity-domain claims are evaluated against the complete,
        # coordinator-bounded projection so lowering a table/page budget cannot
        # silently remove topology edges.
        for resource_index, item in enumerate(all_resources):
            exists, status, state = _status_at(item, timestamp_ns)
            usable_statuses = set(projection.get("usable_statuses", []))
            unusable_statuses = set(projection.get("unusable_statuses", []))
            status_class = (
                "usable"
                if status in usable_statuses
                else "unusable"
                if status in unusable_statuses
                else "unknown"
            )
            record = {
                "resource_id": item["resource_id"],
                "node_id": node["node_id"],
                "member_id": node["member_id"],
                "revision_id": node["revision_id"],
                "resource_ref": {
                    "member_id": node["member_id"],
                    "node_id": node["node_id"],
                    "revision_id": node["revision_id"],
                    "local_resource_id": item["resource_id"],
                },
                "kind": item["kind"],
                "label": item["label"],
                "exists": exists,
                "status": status,
                "status_class": status_class,
                "state": state,
                "properties": item.get("properties", {}),
                "status_perspective_id": perspective_id,
                "basis_time_ns": str(timestamp_ns),
                "quality": (
                    "exact"
                    if resolved_time["resolution"] == "exact"
                    else "best_effort"
                ),
                "provenance": "plugin_projection",
                "plugin_provenance": self._plugin_provenance(
                    plugin, plugin_set_id
                )
                | {
                    "projection_id": projection["projection_id"],
                    "status_perspective_id": perspective_id,
                },
            }
            record["deep_link"] = self._resource_deep_link(
                node,
                plugin_set_id,
                plugin,
                projection,
                perspective_id,
                item["resource_id"],
                requested_basis,
                resolved_time,
                context_id,
            )
            record["navigation_target"] = record["deep_link"]
            state_by_id[item["resource_id"]] = record
            if resource_index < resource_limit:
                resources.append(record)

        local_links = []
        for item in projection.get("fixture_local_links", []):
            if item["source_resource_id"] not in state_by_id or item[
                "target_resource_id"
            ] not in state_by_id:
                continue
            local_links.append(
                {
                    **item,
                    "node_id": node["node_id"],
                    "exists": True,
                    "quality": "plugin_declared",
                    "plugin_provenance": self._plugin_provenance(
                        plugin, plugin_set_id
                    )
                    | {
                        "projection_id": projection["projection_id"],
                        "status_perspective_id": perspective_id,
                    },
                }
            )

        claims = []
        for item in projection.get("fixture_connector_claims", []):
            source = state_by_id.get(item["resource_id"])
            if not source:
                continue
            usable = (
                True
                if source["status_class"] == "usable"
                else False
                if source["status_class"] == "unusable"
                else None
            )
            claims.append(
                {
                    **item,
                    "node_id": node["node_id"],
                    "member_id": node["member_id"],
                    "revision_id": node["revision_id"],
                    "plugin_set_id": plugin_set_id,
                    "plugin_id": plugin["plugin_id"],
                    "plugin_instance_id": plugin["plugin_instance_id"],
                    "plugin_run_id": plugin["plugin_run_id"],
                    "plugin_version": plugin["version"],
                    "projection_id": projection["projection_id"],
                    "status_perspective_id": perspective_id,
                    "usable": usable,
                    "status": source["status"],
                    "exists": source["exists"],
                    "quality": source["quality"],
                    "resolved_time": resolved_time,
                    "deep_link": source["deep_link"],
                }
            )
        segment_claims = []
        for item in projection.get("fixture_network_segment_claims", []):
            source = state_by_id.get(item["resource_id"])
            if not source:
                continue
            valid_from_ns = item.get("valid_from_ns")
            valid_to_ns = item.get("valid_to_ns")
            claim_valid = (
                valid_from_ns is None or timestamp_ns >= int(valid_from_ns)
            ) and (valid_to_ns is None or timestamp_ns < int(valid_to_ns))
            claim_exists = source["exists"] is True and claim_valid
            usable = (
                True
                if claim_exists and source["status_class"] == "usable"
                else False
                if claim_exists and source["status_class"] == "unusable"
                else None
            )
            segment_claims.append(
                {
                    **item,
                    "node_id": node["node_id"],
                    "member_id": node["member_id"],
                    "revision_id": node["revision_id"],
                    "plugin_set_id": plugin_set_id,
                    "plugin_id": plugin["plugin_id"],
                    "plugin_instance_id": plugin["plugin_instance_id"],
                    "plugin_run_id": plugin["plugin_run_id"],
                    "plugin_version": plugin["version"],
                    "projection_id": projection["projection_id"],
                    "status_perspective_id": perspective_id,
                    "usable": usable,
                    "status": source["status"] if claim_exists else "absent",
                    "exists": claim_exists,
                    "claim_valid_at_basis": claim_valid,
                    "endpoint_exists_at_basis": source["exists"],
                    "quality": source["quality"],
                    "resolved_time": resolved_time,
                    "deep_link": source["deep_link"],
                }
            )
        truncated = len(all_resources) > len(resources)
        return {
            "plugin_provenance": self._plugin_provenance(plugin, plugin_set_id),
            "projection_id": projection["projection_id"],
            "status_perspective_id": perspective_id,
            "resolved_time": resolved_time,
            "resources": resources,
            "local_links": local_links,
            "connector_claims": claims,
            "network_segment_claims": segment_claims,
            "counts": {
                "resources": {
                    "total_count": len(all_resources),
                    "returned_count": len(resources),
                    "truncated": truncated,
                },
                "local_links": len(local_links),
                "connector_claims": len(claims),
                "network_segment_claims": len(segment_claims),
            },
            "complete": not truncated,
        }

    def _assemble_network_segments(
        self,
        claims: list[dict[str, Any]],
        segment_limit: int,
        attachment_limit: int,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        bool,
        bool,
    ]:
        """Normalize plugin-owned connectivity-domain resources and links.

        Matching is deliberately limited to equality of the opaque matcher/key
        pair declared by plug-ins.  The coordinator never groups by prefix,
        address overlap, VLAN number, resource kind, or display label.
        """

        matcher_contracts = {
            str(item["matcher_id"]): item
            for item in self.contract.get("network_segment_matchers", [])
        }
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        unresolved_matchers: list[dict[str, Any]] = []
        for claim in claims:
            matcher_id = str(claim["matcher_id"])
            normalized_segment_key, canonical_segment_key = _canonical_opaque_key(
                claim["segment_key"]
            )
            matcher_contract = matcher_contracts.get(matcher_id)
            if (
                matcher_contract is None
                or matcher_contract.get("match_semantics") != "exact_token"
                or matcher_contract.get("result_shape") != "connectivity_domain"
            ):
                unresolved_matchers.append(
                    {
                        "matcher_id": matcher_id,
                        "segment_key": normalized_segment_key,
                        "typed_key": canonical_segment_key,
                        "resolution": "unsupported_matcher_contract",
                        "reason_code": "matcher_not_declared_as_exact_connectivity_domain",
                        "member_id": claim.get("member_id"),
                        "node_id": claim.get("node_id"),
                        "resource_id": claim.get("resource_id"),
                    }
                )
                continue
            normalized_claim = dict(claim)
            normalized_claim["_normalized_segment_key"] = normalized_segment_key
            grouped.setdefault((matcher_id, canonical_segment_key), []).append(
                normalized_claim
            )

        groups = sorted(grouped.items())
        selected_groups = groups[:segment_limit]
        segments_truncated = len(groups) > len(selected_groups)
        attachments: list[dict[str, Any]] = []
        segments: list[dict[str, Any]] = []
        resolutions: list[dict[str, Any]] = unresolved_matchers

        for (matcher_id, canonical_segment_key), values in selected_groups:
            segment_key = values[0]["_normalized_segment_key"]
            matcher_contract = matcher_contracts.get(matcher_id, {})
            matcher_contract_version = str(
                matcher_contract.get("contract_version", "unspecified")
            )
            values = sorted(
                values,
                key=lambda item: (
                    str(item["member_id"]),
                    str(item["resource_id"]),
                    str(item["plugin_run_id"]),
                ),
            )
            segment_digest = hashlib.sha256(
                json.dumps(
                    [
                        MULTI_NODE_TOPOLOGY_ID,
                        matcher_id,
                        matcher_contract_version,
                        canonical_segment_key,
                    ],
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()[:24]
            segment_id = f"network-segment:{segment_digest}"

            semantic_variants_by_key: dict[str, dict[str, Any]] = {}
            for item in values:
                semantics = dict(item.get("plugin_semantics") or {})
                semantic_variants_by_key.setdefault(
                    json.dumps(
                        semantics,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    ),
                    semantics,
                )
            semantic_variants = list(semantic_variants_by_key.values())
            merge_critical_fields = tuple(
                str(field_name)
                for field_name in matcher_contract.get(
                    "merge_critical_semantic_fields", []
                )
            )
            semantic_conflicts: dict[str, list[Any]] = {}
            for field_name in merge_critical_fields:
                field_variants: dict[str, Any] = {}
                for semantics in semantic_variants:
                    value = semantics.get(field_name)
                    field_variants.setdefault(
                        json.dumps(
                            value,
                            sort_keys=True,
                            separators=(",", ":"),
                            default=str,
                        ),
                        value,
                    )
                if len(field_variants) > 1:
                    semantic_conflicts[field_name] = list(field_variants.values())
            semantic_conflict = bool(semantic_conflicts)
            plugin_semantics = semantic_variants[0] if semantic_variants else {}
            topology_presentation = dict(
                plugin_semantics.get("topology_presentation") or {}
            )
            topology_presentation.setdefault(
                "two_participant_shape", "domain_node"
            )

            existing = [item for item in values if item.get("exists") is True]
            observed_node_ids = sorted({str(item["node_id"]) for item in values})
            observed_member_ids = sorted(
                {str(item["member_id"]) for item in values}
            )
            node_ids = sorted({str(item["node_id"]) for item in existing})
            member_ids = sorted({str(item["member_id"]) for item in existing})
            usable_values = {item.get("usable") for item in existing}
            status_combination_policy = str(
                matcher_contract.get(
                    "status_combination_policy",
                    "plugin_policy_unspecified",
                )
            )
            if not existing:
                operational_status = "absent"
                exists: bool | None = False
            elif usable_values == {True}:
                operational_status = "usable"
                exists = True
            elif usable_values == {False}:
                operational_status = "unusable"
                exists = True
            elif True in usable_values and False in usable_values:
                operational_status = "degraded"
                exists = True
            else:
                operational_status = "unknown"
                exists = True

            attachment_ids: list[str] = []
            confidence_scores: list[float] = []
            evidence: list[dict[str, Any]] = []
            plugin_provenance: list[dict[str, Any]] = []
            endpoint_observations: list[dict[str, Any]] = []
            for item in values:
                explicit_attachment_key = item.get("attachment_key")
                canonical_attachment_key = (
                    _canonical_opaque_key(explicit_attachment_key)[1]
                    if explicit_attachment_key is not None
                    else None
                )
                attachment_digest = hashlib.sha256(
                    json.dumps(
                        [
                            MULTI_NODE_TOPOLOGY_ID,
                            segment_id,
                            item["member_id"],
                            item["revision_id"],
                            item["resource_id"],
                            canonical_attachment_key,
                        ],
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()[:20]
                attachment_id = f"segment-attachment:{attachment_digest}"
                attachment_ids.append(attachment_id)
                confidence = dict(item.get("confidence") or {})
                score = confidence.get("score")
                if isinstance(score, (int, float)) and not isinstance(score, bool):
                    confidence_scores.append(float(score))
                item_evidence = [dict(entry) for entry in item.get("evidence", [])]
                evidence.extend(
                    {
                        **entry,
                        "member_id": item["member_id"],
                        "node_id": item["node_id"],
                        "plugin_run_id": item["plugin_run_id"],
                    }
                    for entry in item_evidence
                )
                provenance = self._claim_provenance(item)
                if provenance not in plugin_provenance:
                    plugin_provenance.append(provenance)
                endpoint_observations.append(item["resolved_time"])
                component_refs = [
                    {
                        "member_id": item["member_id"],
                        "node_id": item["node_id"],
                        "revision_id": item["revision_id"],
                        "local_resource_id": resource_id,
                    }
                    for resource_id in item.get("component_resource_ids", [])
                ]
                attachments.append(
                    {
                        "attachment_id": attachment_id,
                        "segment_id": segment_id,
                        "member_id": item["member_id"],
                        "node_id": item["node_id"],
                        "revision_id": item["revision_id"],
                        "endpoint": self._claim_endpoint(item),
                        "resource_id": item["resource_id"],
                        "resource_ref": {
                            "member_id": item["member_id"],
                            "node_id": item["node_id"],
                            "revision_id": item["revision_id"],
                            "local_resource_id": item["resource_id"],
                        },
                        "exists": item.get("exists"),
                        "claim_valid_at_basis": item.get(
                            "claim_valid_at_basis"
                        ),
                        "endpoint_exists_at_basis": item.get(
                            "endpoint_exists_at_basis"
                        ),
                        "operational_status": (
                            "usable"
                            if item.get("usable") is True
                            else "unusable"
                            if item.get("usable") is False
                            else "unknown"
                        ),
                        "status": item.get("status", "unknown"),
                        "quality": item.get("quality", "unknown"),
                        "confidence": confidence,
                        "validity": {
                            "valid_from_ns": (
                                str(item["valid_from_ns"])
                                if item.get("valid_from_ns") is not None
                                else None
                            ),
                            "valid_to_ns": (
                                str(item["valid_to_ns"])
                                if item.get("valid_to_ns") is not None
                                else None
                            ),
                            "observed_at_ns": item["resolved_time"].get(
                                "query_time_ns"
                            ),
                            "claim_valid_at_basis": item.get(
                                "claim_valid_at_basis"
                            ),
                            "endpoint_exists_at_basis": item.get(
                                "endpoint_exists_at_basis"
                            ),
                        },
                        "attachment_model": dict(
                            item.get("attachment_model") or {}
                        ),
                        "component_resource_refs": component_refs,
                        "inference": dict(item.get("inference") or {}),
                        "evidence": item_evidence,
                        "plugin_provenance": provenance,
                        "resolved_time": item["resolved_time"],
                        "deep_link": item["deep_link"],
                    }
                )

            same_absolute = all(
                item.get("basis_kind") == "absolute_time"
                for item in endpoint_observations
            )
            quality_order = {
                "exact": 0,
                "best_effort": 1,
                "ambiguous": 2,
                "unknown": 3,
            }
            reported_qualities = [str(item.get("quality", "unknown")) for item in values]
            if semantic_conflict:
                reported_qualities.append("ambiguous")
            aggregate_quality = max(
                reported_qualities,
                key=lambda quality: quality_order.get(quality, quality_order["unknown"]),
                default="unknown",
            )
            returned_ids = {
                item["attachment_id"]
                for item in attachments[:attachment_limit]
                if item["segment_id"] == segment_id
            }
            plugin_asserted_external = (
                bool(existing)
                and len(node_ids) == 1
                and all(
                    (item.get("plugin_semantics") or {}).get("role") == "external"
                    and (item.get("plugin_semantics") or {}).get(
                        "coverage_complete"
                    )
                    is True
                    for item in existing
                )
            )
            segments.append(
                {
                    "segment_id": segment_id,
                    "match": {
                        "matcher_id": matcher_id,
                        "segment_key": segment_key,
                        "matcher_contract_version": matcher_contract_version,
                        "typed_key": canonical_segment_key,
                    },
                    "matcher_id": matcher_id,
                    "segment_key": segment_key,
                    "matcher_contract_version": matcher_contract_version,
                    "plugin_semantics": plugin_semantics,
                    "topology_presentation": topology_presentation,
                    "semantic_variants": semantic_variants,
                    "semantic_conflict": semantic_conflict,
                    "semantic_conflicts": semantic_conflicts,
                    "semantic_owner": "plugin",
                    "label": plugin_semantics.get("label", str(segment_key)),
                    "network_kind": plugin_semantics.get("network_kind", "unknown"),
                    "role": plugin_semantics.get("role", "unknown"),
                    "routing_scope": plugin_semantics.get("routing_scope"),
                    "address_family": plugin_semantics.get("address_family"),
                    "prefix": plugin_semantics.get("prefix"),
                    "connectivity_enabled": plugin_semantics.get(
                        "participates_in_connectivity"
                    ),
                    "presentation_plane": plugin_semantics.get(
                        "presentation_group", "physical"
                    ),
                    "node_ids": node_ids,
                    "member_ids": member_ids,
                    "node_count": len(node_ids),
                    "existing_node_count": len(node_ids),
                    "observed_node_ids": observed_node_ids,
                    "observed_member_ids": observed_member_ids,
                    "observed_node_count": len(observed_node_ids),
                    "attachment_count": len(values),
                    "existing_attachment_count": len(existing),
                    "returned_attachment_count": len(returned_ids),
                    "attachment_ids": [
                        item for item in attachment_ids if item in returned_ids
                    ],
                    "shared_by_multiple_nodes": len(node_ids) > 1,
                    "single_sided_in_query_scope": len(node_ids) == 1,
                    "plugin_asserted_external": plugin_asserted_external,
                    "exists": exists,
                    "operational_status": operational_status,
                    "status": operational_status,
                    "status_combination_policy": status_combination_policy,
                    "quality": aggregate_quality,
                    "confidence": {
                        "minimum_score": (
                            min(confidence_scores) if confidence_scores else None
                        ),
                        "maximum_score": (
                            max(confidence_scores) if confidence_scores else None
                        ),
                        "aggregation": "reported_attachment_range",
                    },
                    "inference": {
                        "owner": "plugin",
                        "coordinator_action": (
                            "grouped opaque connectivity-domain records by declared matcher/key"
                        ),
                        "never_matched_by_prefix_alone": True,
                    },
                    "evidence": evidence,
                    "plugin_provenance": plugin_provenance,
                    "time_alignment": {
                        "simultaneity": (
                            "same_absolute_instant"
                            if same_absolute
                            else "not_implied"
                        ),
                        "attachment_observations": endpoint_observations,
                    },
                }
            )
            resolutions.append(
                {
                    "segment_id": segment_id,
                    "matcher_id": matcher_id,
                    "segment_key": segment_key,
                    "resolution": (
                        "absent"
                        if not existing
                        else "semantic_conflict"
                        if semantic_conflict
                        else "shared"
                        if len(node_ids) > 1
                        else "single_sided"
                    ),
                    "claim_count": len(values),
                    "existing_claim_count": len(existing),
                    "node_count": len(node_ids),
                    "observed_node_count": len(observed_node_ids),
                    "semantic_variants": semantic_variants,
                    "semantic_conflicts": semantic_conflicts,
                }
            )

        all_attachment_count = len(attachments)
        attachments = attachments[:attachment_limit]
        returned_by_segment: dict[str, list[dict[str, Any]]] = {}
        for attachment in attachments:
            returned_by_segment.setdefault(attachment["segment_id"], []).append(
                attachment
            )
        for segment in segments:
            returned = returned_by_segment.get(segment["segment_id"], [])
            segment["attachment_ids"] = [
                attachment["attachment_id"] for attachment in returned
            ]
            segment["returned_attachment_count"] = len(returned)
            segment["members"] = [
                attachment
                for attachment in returned
                if attachment.get("exists") is True
            ]
        return (
            segments,
            attachments,
            resolutions,
            segments_truncated,
            all_attachment_count > len(attachments),
        )

    def _join_claims(
        self, claims: list[dict[str, Any]], limit: int, context_id: str
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        bool,
    ]:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for claim in claims:
            grouped.setdefault(
                (str(claim["matcher_id"]), str(claim["match_key"])), []
            ).append(claim)
        candidates: list[dict[str, Any]] = []
        resolutions: list[dict[str, Any]] = []
        unmatched: list[dict[str, Any]] = []
        linker = self.contract["federation_plugin"]
        for (matcher_id, match_key), values in sorted(grouped.items()):
            def claim_identity(claim: dict[str, Any]) -> tuple[Any, ...]:
                node_id = str(claim["node_id"])
                return (
                    self._node_order.get(node_id, len(self._node_order)),
                    node_id,
                    str(claim.get("member_id", "")),
                    str(claim.get("resource_id", "")),
                    str(claim.get("plugin_set_id", "")),
                    str(claim.get("plugin_id", "")),
                    str(claim.get("projection_id", "")),
                    str(claim.get("status_perspective_id", "")),
                )

            pair_by_identity: dict[
                tuple[tuple[Any, ...], tuple[Any, ...]],
                tuple[dict[str, Any], dict[str, Any]],
            ] = {}
            ordered_values = sorted(values, key=claim_identity)
            for first, second in combinations(ordered_values, 2):
                if first["node_id"] == second["node_id"]:
                    continue
                left, right = sorted((first, second), key=claim_identity)
                identity = (claim_identity(left), claim_identity(right))
                pair_by_identity.setdefault(identity, (left, right))
            cross_node_pairs = [
                pair_by_identity[identity]
                for identity in sorted(pair_by_identity)
            ]
            if not cross_node_pairs:
                unresolved = [
                    {
                        "member_id": item["member_id"],
                        "node_id": item["node_id"],
                        "revision_id": item["revision_id"],
                        "resource_id": item["resource_id"],
                        "matcher_id": matcher_id,
                        "match_key": match_key,
                        "resolution": "unresolved",
                        "reason_code": "no_compatible_remote_claim",
                    }
                    for item in values
                ]
                unmatched.extend(unresolved)
                resolutions.append(
                    {
                        "matcher_id": matcher_id,
                        "match_key": match_key,
                        "resolution": "unresolved",
                        "candidate_count": 0,
                        "claims": unresolved,
                        "linker_plugin_provenance": linker,
                    }
                )
                continue
            resolution = "matched" if len(cross_node_pairs) == 1 else "ambiguous"
            resolutions.append(
                {
                    "matcher_id": matcher_id,
                    "match_key": match_key,
                    "resolution": resolution,
                    "candidate_count": len(cross_node_pairs),
                    "claims": [self._claim_endpoint(item) for item in values],
                    "linker_plugin_provenance": linker,
                }
            )
            base_link_occurrences: dict[str, int] = {}
            used_link_ids: set[str] = set()
            for left, right in cross_node_pairs:
                policies = {
                    str(left.get("combination_policy", "all_claims_usable")),
                    str(right.get("combination_policy", "all_claims_usable")),
                }
                if len(policies) != 1:
                    operational = {
                        "usable": None,
                        "status": "unknown",
                        "reason": "plugin_claim_policy_mismatch",
                    }
                elif False in {left.get("usable"), right.get("usable")}:
                    operational = {
                        "usable": False,
                        "status": "unusable",
                        "reason": next(iter(policies)),
                    }
                elif {left.get("usable"), right.get("usable")} == {True}:
                    operational = {
                        "usable": True,
                        "status": "usable",
                        "reason": next(iter(policies)),
                    }
                else:
                    operational = {
                        "usable": None,
                        "status": "unknown",
                        "reason": "plugin_claim_status_incomplete",
                    }
                base_link_id = (
                    f"{matcher_id}:{match_key}:"
                    f"{left['node_id']}:{right['node_id']}"
                )
                occurrence = base_link_occurrences.get(base_link_id, 0)
                base_link_occurrences[base_link_id] = occurrence + 1
                if occurrence == 0:
                    link_id = base_link_id
                else:
                    candidate_material = {
                        "endpoint_a": claim_identity(left)[1:],
                        "endpoint_b": claim_identity(right)[1:],
                    }
                    candidate_digest = hashlib.sha256(
                        json.dumps(
                            candidate_material,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()[:16]
                    link_id = f"{base_link_id}:candidate-{candidate_digest}"
                    collision = 2
                    while link_id in used_link_ids:
                        link_id = (
                            f"{base_link_id}:candidate-{candidate_digest}-{collision}"
                        )
                        collision += 1
                used_link_ids.add(link_id)
                link_types = {str(left["link_type"]), str(right["link_type"])}
                route_trace_roles = {
                    str(item.get("presentation", {}).get("route_trace", "include"))
                    for item in (left, right)
                }
                route_trace_role = (
                    next(iter(route_trace_roles))
                    if len(route_trace_roles) == 1
                    else "conflict"
                )
                if route_trace_role == "conflict":
                    # Presentation disagreements fail closed: the coordinator
                    # must never promote a possibly-overlay claim to a physical
                    # route hop or adjacency.
                    operational = {
                        "usable": None,
                        "status": "unknown",
                        "reason": "plugin_route_trace_role_mismatch",
                    }
                if len(link_types) != 1:
                    operational = {
                        "usable": None,
                        "status": "unknown",
                        "reason": "plugin_link_type_mismatch",
                    }
                same_absolute = all(
                    item["resolved_time"]["basis_kind"] == "absolute_time"
                    for item in (left, right)
                )
                candidates.append(
                    {
                        "link_id": link_id,
                        "projection_role": (
                            "presentation_overlay"
                            if route_trace_role == "overlay"
                            else "route_trace_compatibility"
                            if route_trace_role == "include"
                            else "presentation_conflict"
                        ),
                        "presentation": {
                            "physical_topology": (
                                "suppress_when_network_segments_available"
                            ),
                            "route_trace": route_trace_role,
                        },
                        "resolution": resolution,
                        "link_type": next(iter(link_types), "unknown"),
                        "directed": bool(left.get("directed") or right.get("directed")),
                        "endpoint_a": self._claim_endpoint(left),
                        "endpoint_b": self._claim_endpoint(right),
                        "source": self._claim_endpoint(left),
                        "target": self._claim_endpoint(right),
                        "exists": (
                            True
                            if left.get("exists") is True
                            and right.get("exists") is True
                            else False
                            if left.get("exists") is False
                            or right.get("exists") is False
                            else None
                        ),
                        "operational": operational,
                        "status": operational["status"],
                        "operational_status": operational["status"],
                        "quality": (
                            "best_effort"
                            if operational["usable"] is not None
                            else "unknown"
                        ),
                        "inference": {
                            "owner": "federation_linker_plugin",
                            "plugin_id": linker["plugin_id"],
                            "plugin_run_id": linker["plugin_run_id"],
                            "matcher_id": matcher_id,
                            "match_key": match_key,
                            "coordinator_action": (
                                "paired compatible opaque connector claims"
                            ),
                        },
                        "plugin_provenance": [
                            self._claim_provenance(left),
                            self._claim_provenance(right),
                        ],
                        "evidence": [
                            {
                                "label": (
                                    f"{left['plugin_id']} + {right['plugin_id']} "
                                    f"via {linker['plugin_id']}"
                                ),
                                "plugin_run_ids": [
                                    left["plugin_run_id"],
                                    right["plugin_run_id"],
                                    linker["plugin_run_id"],
                                ],
                            }
                        ],
                        "candidates": (
                            [
                                self._claim_endpoint(left),
                                self._claim_endpoint(right),
                            ]
                            if resolution == "ambiguous"
                            else []
                        ),
                        "time_alignment": {
                            "simultaneity": (
                                "same_absolute_instant"
                                if same_absolute
                                else "not_implied"
                            ),
                            "endpoint_observations": [
                                left["resolved_time"], right["resolved_time"]
                            ],
                        },
                        "deep_links": {
                            "topology": {
                                "href": self._topology_href(
                                    {"kind": "absolute_time", "time_ns": left["resolved_time"].get("query_time_ns")}
                                    if same_absolute
                                    else {"kind": "relative_to_watermark", "offset_ns": left["resolved_time"].get("relative_offset_ns", "0")},
                                    [left["node_id"], right["node_id"]],
                                    link_id,
                                    context_id,
                                ),
                                "link_id": link_id,
                            },
                            "endpoint_a": left["deep_link"],
                            "endpoint_b": right["deep_link"],
                        },
                    }
                )
        candidates.sort(key=lambda item: item["link_id"])
        return (
            candidates[:limit],
            resolutions,
            unmatched,
            len(candidates) > limit,
        )

    @staticmethod
    def _claim_endpoint(claim: dict[str, Any]) -> dict[str, Any]:
        return {
            "member_id": claim["member_id"],
            "node_id": claim["node_id"],
            "revision_id": claim["revision_id"],
            "resource_id": claim["resource_id"],
            "resource_ref": {
                "member_id": claim["member_id"],
                "node_id": claim["node_id"],
                "revision_id": claim["revision_id"],
                "local_resource_id": claim["resource_id"],
            },
            "plugin_set_id": claim["plugin_set_id"],
            "plugin_id": claim["plugin_id"],
            "plugin_run_id": claim["plugin_run_id"],
            "projection_id": claim["projection_id"],
            "status_perspective_id": claim["status_perspective_id"],
            "status": claim["status"],
            "usable": claim["usable"],
        }

    @staticmethod
    def _claim_provenance(claim: dict[str, Any]) -> dict[str, Any]:
        return {
            "plugin_set_id": claim["plugin_set_id"],
            "plugin_id": claim["plugin_id"],
            "plugin_instance_id": claim["plugin_instance_id"],
            "plugin_run_id": claim["plugin_run_id"],
            "plugin_version": claim["plugin_version"],
            "projection_id": claim["projection_id"],
            "status_perspective_id": claim["status_perspective_id"],
        }

    @staticmethod
    def _plugin_provenance(
        plugin: dict[str, Any], plugin_set_id: str
    ) -> dict[str, Any]:
        return {
            "plugin_set_id": plugin_set_id,
            "plugin_id": plugin["plugin_id"],
            "plugin_instance_id": plugin["plugin_instance_id"],
            "plugin_run_id": plugin["plugin_run_id"],
            "plugin_version": plugin["version"],
        }

    def _node_deep_link(
        self,
        node: dict[str, Any],
        plugin_set_id: str,
        selection: dict[str, Any] | None,
        requested_basis: dict[str, Any],
        resolved_time: dict[str, Any] | None,
        context_id: str | None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "topology_id": MULTI_NODE_TOPOLOGY_ID,
            "node_id": node["node_id"],
            "revision_id": node["revision_id"],
            "plugin_set_id": plugin_set_id,
        }
        if context_id:
            params["context_id"] = context_id
        if selection:
            params.update(
                {
                    "plugin_id": selection["plugin"]["plugin_id"],
                    "projection_id": selection["projection"]["projection_id"],
                    "status_perspective_id": selection["status_perspective_id"],
                }
            )
        self._basis_link_params(params, requested_basis, resolved_time)
        return {
            "href": "/node?" + urlencode(params, quote_via=quote) + "#temporal-topology",
            "route": "/node",
            "fragment": "temporal-topology",
            "parameters": params,
            "api": {
                "method": "POST",
                "href": f"/v1/topologies/nodes/{quote(node['node_id'], safe='')}/query",
            },
        }

    def _resource_deep_link(
        self,
        node: dict[str, Any],
        plugin_set_id: str,
        plugin: dict[str, Any],
        projection: dict[str, Any],
        perspective_id: str,
        resource_id: str,
        requested_basis: dict[str, Any],
        resolved_time: dict[str, Any],
        context_id: str,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "topology_id": MULTI_NODE_TOPOLOGY_ID,
            "node_id": node["node_id"],
            "revision_id": node["revision_id"],
            "plugin_set_id": plugin_set_id,
            "plugin_id": plugin["plugin_id"],
            "projection_id": projection["projection_id"],
            "status_perspective_id": perspective_id,
            "resource_id": resource_id,
            "context_id": context_id,
        }
        self._basis_link_params(params, requested_basis, resolved_time)
        return {
            "href": "/node?" + urlencode(params, quote_via=quote) + "#timeline",
            "route": "/node",
            "fragment": "timeline",
            "parameters": params,
            "api": {
                "method": "POST",
                "href": f"/v1/topologies/nodes/{quote(node['node_id'], safe='')}/query",
            },
        }

    @staticmethod
    def _basis_link_params(
        params: dict[str, Any],
        requested_basis: dict[str, Any],
        resolved_time: dict[str, Any] | None,
    ) -> None:
        kind = str(requested_basis.get("kind", "relative_to_watermark"))
        if kind == "absolute_time":
            params["basis_kind"] = "absolute_time"
            params["time_ns"] = str(
                requested_basis.get("time_ns")
                or (resolved_time or {}).get("query_time_ns")
                or ""
            )
        else:
            params["basis_kind"] = "relative_to_watermark"
            params["offset_ns"] = str(requested_basis.get("offset_ns", "0"))
            params["basis_offset_ns"] = params["offset_ns"]

    def _topology_href(
        self,
        basis: dict[str, Any],
        node_ids: list[str],
        selected_link_id: Any = None,
        context_id: str | None = None,
    ) -> str:
        params: dict[str, Any] = {
            "topology_id": MULTI_NODE_TOPOLOGY_ID,
            "node_ids": ",".join(node_ids),
            "nodes": ",".join(node_ids),
        }
        self._basis_link_params(params, basis, None)
        if selected_link_id:
            params["link_id"] = str(selected_link_id)
        if context_id:
            params["context_id"] = context_id
        return "/?" + urlencode(params, quote_via=quote)

    def _node(self, node_id: str) -> dict[str, Any]:
        try:
            return self.nodes_by_id[node_id]
        except KeyError as error:
            raise MultiNodeTopologyRequestError(
                f"unknown topology node: {node_id}"
            ) from error

    def _public_node(self, node: dict[str, Any]) -> dict[str, Any]:
        active = next(
            item
            for item in node["plugin_sets"]
            if item["plugin_set_id"] == node["active_plugin_set_id"]
        )
        default_selections = [
            {
                "plugin_id": plugin["plugin_id"],
                "projection_id": projection["projection_id"],
                "status_perspective_id": projection[
                    "default_status_perspective_id"
                ],
            }
            for plugin in active["plugins"]
            if plugin.get("active", True)
            for projection in plugin.get("projections", [])
            if projection.get("default_enabled", True)
        ]
        public_plugin_sets = [
            self._public_plugin_set(item) for item in node["plugin_sets"]
        ]
        default_selection = default_selections[0] if default_selections else {}
        return {
            "node_id": node["node_id"],
            "member_id": node["member_id"],
            "label": node["label"],
            "revision_id": node["revision_id"],
            "device_family": node["device_family"],
            "site": node.get("site"),
            "roles": list(node.get("roles", [])),
            "available": bool(node.get("available", True)),
            "resources_available": bool(node.get("available", True)),
            "optional": bool(node.get("optional", False)),
            "default_selected": bool(node.get("default_selected", True)),
            "unavailable_reason": node.get("unavailable_reason"),
            "active_plugin_set_id": node["active_plugin_set_id"],
            "default_plugin_set_id": node["active_plugin_set_id"],
            "default_projection_id": default_selection.get("projection_id"),
            "default_status_perspective_id": default_selection.get(
                "status_perspective_id"
            ),
            "installed_plugin_sets": public_plugin_sets,
            "plugin_sets": public_plugin_sets,
            "default_projection_selections": default_selections,
            "clock": (
                None
                if not node.get("clock")
                else {
                    key: str(value) if key.endswith("_ns") else value
                    for key, value in node["clock"].items()
                }
            ),
            "deep_links": {
                "individual_node": self._node_deep_link(
                    node,
                    node["active_plugin_set_id"],
                    None,
                    {"kind": "relative_to_watermark", "offset_ns": "0"},
                    None,
                    None,
                )
            },
        }

    @staticmethod
    def _public_plugin_set(plugin_set: dict[str, Any]) -> dict[str, Any]:
        public_plugins = [
            {
                key: value
                for key, value in plugin.items()
                if key not in {"projections"}
            }
            | {
                "projections": [
                    {
                        key: value
                        for key, value in projection.items()
                        if not key.startswith("fixture_")
                        and key not in {"usable_statuses", "unusable_statuses"}
                    }
                    for projection in plugin.get("projections", [])
                ]
            }
            for plugin in plugin_set["plugins"]
        ]
        projections = [
            {
                **projection,
                "provider_plugin_id": plugin["plugin_id"],
                "plugin_run_id": plugin["plugin_run_id"],
            }
            for plugin in public_plugins
            for projection in plugin["projections"]
        ]
        perspectives = [
            {
                "perspective_id": perspective_id,
                "label": perspective_id.replace(".", " ").replace("-", " ").title(),
                "provider_plugin_id": projection["provider_plugin_id"],
            }
            for projection in projections
            for perspective_id in projection["supported_status_perspective_ids"]
        ]
        return {
            "plugin_set_id": plugin_set["plugin_set_id"],
            "label": plugin_set["label"],
            "version": "+".join(
                plugin["version"] for plugin in plugin_set["plugins"]
            ),
            "active": bool(plugin_set.get("active", False)),
            "projections": projections,
            "status_perspectives": perspectives,
            "plugins": public_plugins,
        }

    def _unavailable_plugin_result(
        self,
        node: dict[str, Any],
        plugin_set_id: str,
        plugin: dict[str, Any],
        projection: dict[str, Any],
        perspective_id: str,
        reason: str,
    ) -> dict[str, Any]:
        return {
            "plugin_provenance": self._plugin_provenance(plugin, plugin_set_id),
            "projection_id": projection["projection_id"],
            "status_perspective_id": perspective_id,
            "resolved_time": None,
            "resources": [],
            "local_links": [],
            "counts": {"resources": {"total_count": None, "returned_count": 0, "truncated": False}, "local_links": 0, "connector_claims": 0},
            "complete": False,
            "unknown_fields": [
                {"name": "projection", "reason_code": reason}
            ],
        }

    def _unaligned_plugin_result(
        self,
        node: dict[str, Any],
        plugin_set_id: str,
        plugin: dict[str, Any],
        projection: dict[str, Any],
        perspective_id: str,
        resolved_time: dict[str, Any],
    ) -> dict[str, Any]:
        result = self._unavailable_plugin_result(
            node,
            plugin_set_id,
            plugin,
            projection,
            perspective_id,
            "clock_unaligned",
        )
        result["resolved_time"] = resolved_time
        return result


def _resource(
    resource_id: str,
    kind: str,
    label: str,
    status: str = "up",
    *,
    changes: list[dict[str, Any]] | None = None,
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "resource_id": resource_id,
        "kind": kind,
        "label": label,
        "initial_status": status,
        "changes": changes or [],
        "properties": properties or {},
    }


def _projection(
    projection_id: str,
    label: str,
    perspective_id: str,
    resources: list[dict[str, Any]],
    local_links: list[dict[str, Any]],
    claims: list[dict[str, Any]],
    *,
    segment_claims: list[dict[str, Any]] | None = None,
    watermark_lag_ns: int = 0,
) -> dict[str, Any]:
    return {
        "projection_id": projection_id,
        "label": label,
        "description": "Synthetic plug-in-owned projection for multi-node review.",
        "supported_status_perspective_ids": [perspective_id],
        "default_status_perspective_id": perspective_id,
        "default_enabled": True,
        "watermark_lag_ns": watermark_lag_ns,
        "watermark_scope": "node/plugin/projection/status-perspective",
        "usable_statuses": ["active", "established", "programmed", "up"],
        "unusable_statuses": ["down", "failed", "withdrawn"],
        "fixture_resources": resources,
        "fixture_local_links": local_links,
        "fixture_connector_claims": claims,
        "fixture_network_segment_claims": segment_claims or [],
    }


def _claim(
    resource_id: str,
    match_key: str,
    link_type: str,
    matcher_id: str,
    *,
    route_trace_role: str = "include",
) -> dict[str, Any]:
    return {
        "resource_id": resource_id,
        "match_key": match_key,
        "link_type": link_type,
        "matcher_id": matcher_id,
        "directed": False,
        "combination_policy": "all_claims_usable",
        "semantic_owner": "plugin",
        "presentation": {"route_trace": route_trace_role},
    }


def _segment_claim(
    resource_id: str,
    segment_key: Any,
    matcher_id: str,
    *,
    plugin_semantics: dict[str, Any],
    attachment_model: dict[str, Any],
    component_resource_ids: list[str] | None = None,
    confidence_score: float = 1.0,
    inference_method: str = "plugin_declared",
    inference_rule_id: str = "declared-connected-network",
    evidence: list[dict[str, Any]] | None = None,
    valid_from_ns: int | None = None,
    valid_to_ns: int | None = None,
) -> dict[str, Any]:
    """Build one plug-in-owned interface-to-connectivity-domain record."""

    return {
        "resource_id": resource_id,
        "segment_key": segment_key,
        "matcher_id": matcher_id,
        "plugin_semantics": plugin_semantics,
        "attachment_model": attachment_model,
        "component_resource_ids": component_resource_ids or [resource_id],
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
        "inference": {
            "owner": "plugin",
            "method": inference_method,
            "rule_id": inference_rule_id,
        },
        "evidence": evidence or [],
        "valid_from_ns": valid_from_ns,
        "valid_to_ns": valid_to_ns,
        "semantic_owner": "plugin",
    }


def _topology_profiles() -> list[dict[str, Any]]:
    plugin_sets = {
        "member:node-a": "node-a.alpha-evpn.v1",
        "member:node-b": "node-b.beta-evpn.v2",
        "member:node-d": "node-d.zeta-evpn.v1",
        "member:node-e": "node-e.eta-evpn.v1",
        "member:transit-p-1": "transit-p-1.gamma.v1",
        "member:transit-p-2": "transit-p-2.delta-sr.v1",
        "member:node-c": "node-c.epsilon-edge.v1",
        "member:ce-west": "ce-west.access.v1",
        "member:ce-east": "ce-east.access.v1",
        "member:edge-c": "edge-c.delta.v1",
    }
    underlay_projections = {
        "member:node-a": "alpha.underlay-links",
        "member:node-b": "beta.forwarding-links",
        "member:node-d": "zeta.fabric-links",
        "member:node-e": "eta.border-links",
        "member:transit-p-1": "gamma.isis-links",
        "member:transit-p-2": "delta.sr-isis-links",
        "member:node-c": "epsilon.forwarding-links",
        "member:ce-west": "ce-west.access-links",
        "member:ce-east": "ce-east.access-links",
        "member:edge-c": "delta.legacy-links",
    }
    underlay_perspectives = {
        "member:node-a": "alpha.hardware-observed",
        "member:node-b": "beta.asic-observed",
        "member:node-d": "zeta.hardware-observed",
        "member:node-e": "eta.forwarding-observed",
        "member:transit-p-1": "gamma.isis-observed",
        "member:transit-p-2": "delta.sr-observed",
        "member:node-c": "epsilon.dataplane-observed",
        "member:ce-west": "ce-west.interface-observed",
        "member:ce-east": "ce-east.interface-observed",
        "member:edge-c": "delta.driver-observed",
    }
    return [
        {
            "profile_id": "fabric-underlay",
            "label": "Underlay forwarding",
            "projection_role": "underlay",
            "plugin_set_by_member": plugin_sets,
            "projection_by_member": underlay_projections,
            "perspective_by_member": underlay_perspectives,
        },
        {
            "profile_id": "evpn-service",
            "label": "EVPN service with underlay boundary",
            "projection_role": "evpn",
            "plugin_set_by_member": plugin_sets,
            "projection_by_member": {
                **underlay_projections,
                "member:node-a": "evpn.overlay",
                "member:node-b": "evpn.overlay",
                "member:node-d": "evpn.overlay",
                "member:node-e": "evpn.overlay",
            },
            "perspective_by_member": {
                **underlay_perspectives,
                "member:node-a": "evpn.control-state",
                "member:node-b": "evpn.control-state",
                "member:node-d": "evpn.control-state",
                "member:node-e": "evpn.control-state",
            },
        },
    ]


def _demo_contract(revision_id: str, capture_ns: int) -> dict[str, Any]:
    failure_ns = capture_ns - 2_980_000_000
    restore_ns = capture_ns - 2_180_000_000
    flap = [
        {"time_ns": failure_ns, "status": "down"},
        {"time_ns": restore_ns, "status": "up"},
    ]
    withdraw = [
        {"time_ns": failure_ns + 20_000_000, "status": "withdrawn"},
        {"time_ns": restore_ns + 35_000_000, "status": "active"},
    ]
    connector_matcher = "demo.connector-key.exact.v1"
    overlay_matcher = "demo.evpn-peer-key.exact.v1"
    segment_matcher = "demo.connectivity-domain-key.exact.v1"

    core_west_segment = {
        "network_kind": "l3_subnet",
        "label": "Core west multi-access",
        "role": "transit",
        "routing_scope": {"kind": "global", "id": "default"},
        "address_family": "ipv4",
        "prefix": "192.0.2.0/29",
        "medium": "broadcast_multi_access",
        "participates_in_connectivity": True,
        "presentation_group": "physical",
        "coverage_complete": True,
    }
    core_east_segment = {
        "network_kind": "l3_subnet",
        "label": "Core east multi-access",
        "role": "transit",
        "routing_scope": {"kind": "global", "id": "default"},
        "address_family": "ipv4",
        "prefix": "192.0.2.8/29",
        "medium": "broadcast_multi_access",
        "participates_in_connectivity": True,
        "presentation_group": "physical",
        "coverage_complete": True,
    }
    edge_segment = {
        "network_kind": "l3_subnet",
        "label": "P2 to PE-C access",
        "role": "transit",
        "routing_scope": {"kind": "global", "id": "default"},
        "address_family": "ipv4",
        "prefix": "192.0.2.16/30",
        "medium": "point_to_point_subnet",
        "participates_in_connectivity": True,
        "presentation_group": "physical",
        "coverage_complete": True,
        "topology_presentation": {
            "two_participant_shape": "compact_edge",
            "reason": (
                "The device plug-ins declare this exact connectivity domain safe "
                "to present as a direct line when current membership is complete."
            ),
        },
    }
    external_segment = {
        "network_kind": "l3_subnet",
        "label": "PE-C external services",
        "role": "external",
        "routing_scope": {"kind": "global", "id": "default"},
        "address_family": "ipv4",
        "prefix": "198.51.100.0/24",
        "medium": "external_network",
        "participates_in_connectivity": True,
        "presentation_group": "physical",
        "coverage_complete": True,
    }
    management_segment = {
        "network_kind": "l3_subnet",
        "label": "Out-of-band management",
        "role": "management",
        "routing_scope": {"kind": "management", "id": "oob"},
        "address_family": "ipv4",
        "prefix": "172.20.0.0/24",
        "medium": "broadcast_multi_access",
        "participates_in_connectivity": False,
        "presentation_group": "excluded_infrastructure",
        "coverage_complete": True,
    }
    vpn_blue_segment = {
        "network_kind": "vpn_l3_subnet",
        "label": "Blue tenant IP-VRF",
        "role": "vpn",
        "routing_scope": {"kind": "vrf", "id": "blue"},
        "address_family": "ipv4",
        "prefix": "10.20.0.0/24",
        "medium": "evpn_overlay",
        "participates_in_connectivity": False,
        "presentation_group": "vpn",
        "separate_view": True,
        "coverage_complete": True,
    }
    access_west_segment = {
        "network_kind": "l2_broadcast_domain",
        "label": "Blue west Ethernet segment / VLAN 310",
        "role": "access",
        "routing_scope": {"kind": "vrf", "id": "blue"},
        "address_family": "l2vpn",
        "prefix": None,
        "medium": "evpn_multihomed_ethernet_segment",
        "participates_in_connectivity": True,
        "presentation_group": "physical",
        "coverage_complete": True,
    }
    access_east_segment = {
        "network_kind": "l2_broadcast_domain",
        "label": "Blue east Ethernet segment / VLAN 320",
        "role": "access",
        "routing_scope": {"kind": "vrf", "id": "blue"},
        "address_family": "l2vpn",
        "prefix": None,
        "medium": "evpn_multihomed_ethernet_segment",
        "participates_in_connectivity": True,
        "presentation_group": "physical",
        "coverage_complete": True,
    }
    vpn_es_west_segment = {
        "network_kind": "evpn_ethernet_segment",
        "label": "Blue west EVPN ES control state",
        "role": "vpn",
        "routing_scope": {"kind": "vrf", "id": "blue"},
        "address_family": "l2vpn",
        "prefix": None,
        "medium": "evpn_overlay",
        "participates_in_connectivity": False,
        "presentation_group": "vpn",
        "separate_view": True,
        "coverage_complete": True,
    }
    vpn_es_east_segment = {
        **vpn_es_west_segment,
        "label": "Blue east EVPN ES control state",
    }
    vpn_red_segment = {
        "network_kind": "vpn_l3_subnet",
        "label": "Red tenant IP-VRF",
        "role": "vpn",
        "routing_scope": {"kind": "vrf", "id": "red"},
        "address_family": "ipv6",
        "prefix": "2001:db8:30::/64",
        "medium": "evpn_overlay",
        "participates_in_connectivity": False,
        "presentation_group": "vpn",
        "separate_view": True,
        "coverage_complete": True,
    }

    def external_network_segment(
        label: str,
        prefix: str,
        *,
        routing_scope: dict[str, Any] | None = None,
        address_family: str = "ipv4",
    ) -> dict[str, Any]:
        return {
            "network_kind": "l3_subnet",
            "label": label,
            "role": "external",
            "routing_scope": routing_scope or {"kind": "global", "id": "default"},
            "address_family": address_family,
            "prefix": prefix,
            "medium": "external_network",
            "participates_in_connectivity": True,
            "presentation_group": "physical",
            "coverage_complete": True,
        }

    def loopback_segment(label: str, prefix: str) -> dict[str, Any]:
        return {
            "network_kind": "host_subnet",
            "label": label,
            "role": "loopback",
            "routing_scope": {"kind": "global", "id": "default"},
            "address_family": "ipv4",
            "prefix": prefix,
            "medium": "local_only",
            "participates_in_connectivity": False,
            "presentation_group": "excluded_infrastructure",
            "coverage_complete": True,
        }

    def pe_underlay_projection(spec: dict[str, Any]) -> dict[str, Any]:
        """Build a synthetic plug-in projection from explicitly declared IDs."""

        node_id = str(spec["node_id"])
        display = str(spec["display"])
        core_members = list(spec["core_member_ids"])
        access_members = list(spec["access_member_ids"])
        core_lag_id = str(spec["core_lag_id"])
        access_lag_id = str(spec["access_lag_id"])
        subif_101_id = str(spec["subif_101_id"])
        subif_102_id = str(spec["subif_102_id"])
        access_subif_id = str(spec["access_subif_id"])
        management_id = str(spec["management_id"])
        loopback_id = str(spec["loopback_id"])
        resources = [
            _resource(
                loopback_id,
                "LOOPBACK",
                f"{display} loopback",
                "up",
                properties={"address": spec["loopback_address"]},
            ),
            *[
                _resource(
                    resource_id,
                    "INTERFACE",
                    f"{display} core trunk member {index}",
                    "up",
                    properties={
                        "lag_parent": core_lag_id,
                        "neighbor": ("transit-p-1" if index == 1 else "transit-p-2"),
                    },
                )
                for index, resource_id in enumerate(core_members, start=1)
            ],
            _resource(
                core_lag_id,
                "LAG",
                f"{display} core trunk",
                "up",
                properties={"lacp_mode": "active", "minimum_links": 1},
            ),
            _resource(
                subif_101_id,
                "SUBINTERFACE",
                f"{display} core west VLAN 101",
                "up",
                properties={"address": spec["address_101"], "vlan_id": 101},
            ),
            _resource(
                subif_102_id,
                "SUBINTERFACE",
                f"{display} core east VLAN 102",
                "up",
                properties={"address": spec["address_102"], "vlan_id": 102},
            ),
            *[
                _resource(
                    resource_id,
                    "INTERFACE",
                    f"{display} EVPN access member {index}",
                    "up",
                    properties={"lag_parent": access_lag_id},
                )
                for index, resource_id in enumerate(access_members, start=1)
            ],
            _resource(
                access_lag_id,
                "LAG",
                f"{display} EVPN multihoming bundle",
                "up",
                properties={"lacp_mode": "active", "minimum_links": 1},
            ),
            _resource(
                access_subif_id,
                "SUBINTERFACE",
                f"{display} access VLAN {spec['access_vlan']}",
                "up",
                properties={"vlan_id": spec["access_vlan"], "vrf": "blue"},
            ),
            _resource(
                management_id,
                "MANAGEMENT_INTERFACE",
                f"{display} management",
                "up",
                properties={"address": spec["management_address"]},
            ),
        ]
        external = spec.get("external")
        if external:
            resources.append(
                _resource(
                    str(external["resource_id"]),
                    "INTERFACE",
                    str(external["label"]),
                    "up",
                    properties={"address": external["address"], "role": "external"},
                )
            )

        local_links = [
            *[
                {
                    "link_id": f"{node_id}:core-member-{index}",
                    "link_type": f"{spec['rule_prefix']}.lag_member",
                    "source_resource_id": resource_id,
                    "target_resource_id": core_lag_id,
                    "directed": True,
                }
                for index, resource_id in enumerate(core_members, start=1)
            ],
            {
                "link_id": f"{node_id}:core-trunk-to-vlan-101",
                "link_type": f"{spec['rule_prefix']}.subinterface_parent",
                "source_resource_id": core_lag_id,
                "target_resource_id": subif_101_id,
                "directed": True,
            },
            {
                "link_id": f"{node_id}:core-trunk-to-vlan-102",
                "link_type": f"{spec['rule_prefix']}.subinterface_parent",
                "source_resource_id": core_lag_id,
                "target_resource_id": subif_102_id,
                "directed": True,
            },
            *[
                {
                    "link_id": f"{node_id}:access-member-{index}",
                    "link_type": f"{spec['rule_prefix']}.lag_member",
                    "source_resource_id": resource_id,
                    "target_resource_id": access_lag_id,
                    "directed": True,
                }
                for index, resource_id in enumerate(access_members, start=1)
            ],
            {
                "link_id": f"{node_id}:access-bundle-to-subinterface",
                "link_type": f"{spec['rule_prefix']}.subinterface_parent",
                "source_resource_id": access_lag_id,
                "target_resource_id": access_subif_id,
                "directed": True,
            },
        ]
        connector_claims = [
            *[
                _claim(
                    resource_id,
                    match_key,
                    "underlay-adjacency",
                    connector_matcher,
                )
                for resource_id, match_key in zip(
                    core_members, spec["boundary_keys"], strict=True
                )
            ],
            *[
                _claim(
                    resource_id,
                    match_key,
                    "access-ethernet",
                    connector_matcher,
                )
                for resource_id, match_key in zip(
                    access_members, spec["access_connector_keys"], strict=True
                )
            ],
        ]
        segment_claims = [
            _segment_claim(
                subif_101_id,
                "underlay:default:core-west:vlan-101",
                segment_matcher,
                plugin_semantics=core_west_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": subif_101_id,
                    "parent_interface_resource_id": core_lag_id,
                    "lag_resource_id": core_lag_id,
                    "physical_interface_resource_ids": core_members,
                    "vlan": {"id": 101, "encapsulation": "802.1Q"},
                    "addresses": [spec["address_101"]],
                },
                component_resource_ids=[subif_101_id, core_lag_id, *core_members],
                confidence_score=0.98,
                inference_method="interface_route_neighbor_lacp_consensus",
                inference_rule_id=f"{spec['rule_prefix']}.core-west-domain",
                evidence=[
                    {"kind": "interface_address", "value": spec["address_101"]},
                    {"kind": "connected_route", "value": "192.0.2.0/29"},
                    {"kind": "lacp_members", "count": len(core_members)},
                ],
            ),
            _segment_claim(
                subif_102_id,
                "underlay:default:core-east:vlan-102",
                segment_matcher,
                plugin_semantics=core_east_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": subif_102_id,
                    "parent_interface_resource_id": core_lag_id,
                    "lag_resource_id": core_lag_id,
                    "physical_interface_resource_ids": core_members,
                    "vlan": {"id": 102, "encapsulation": "802.1Q"},
                    "addresses": [spec["address_102"]],
                },
                component_resource_ids=[subif_102_id, core_lag_id, *core_members],
                confidence_score=0.98,
                inference_method="interface_route_neighbor_lacp_consensus",
                inference_rule_id=f"{spec['rule_prefix']}.core-east-domain",
                evidence=[
                    {"kind": "interface_address", "value": spec["address_102"]},
                    {"kind": "connected_route", "value": "192.0.2.8/29"},
                    {"kind": "lacp_members", "count": len(core_members)},
                ],
            ),
            _segment_claim(
                access_subif_id,
                spec["access_segment_key"],
                segment_matcher,
                plugin_semantics=spec["access_semantics"],
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": access_subif_id,
                    "parent_interface_resource_id": access_lag_id,
                    "lag_resource_id": access_lag_id,
                    "physical_interface_resource_ids": access_members,
                    "vlan": {
                        "id": spec["access_vlan"],
                        "encapsulation": "802.1Q",
                    },
                    "routing_scope": {"kind": "vrf", "id": "blue"},
                },
                component_resource_ids=[
                    access_subif_id,
                    access_lag_id,
                    *access_members,
                ],
                confidence_score=0.98,
                inference_method="evpn_es_interface_lacp_consensus",
                inference_rule_id=f"{spec['rule_prefix']}.blue-access-domain",
                evidence=[
                    {"kind": "vlan", "id": spec["access_vlan"]},
                    {"kind": "lacp_members", "count": len(access_members)},
                    {"kind": "evpn_esi", "value": spec["esi"]},
                ],
            ),
            _segment_claim(
                management_id,
                "management:oob:172.20.0.0-24",
                segment_matcher,
                plugin_semantics=management_segment,
                attachment_model={
                    "interface_kind": "management",
                    "logical_interface_resource_id": management_id,
                    "addresses": [spec["management_address"]],
                },
                evidence=[
                    {"kind": "interface_address", "value": spec["management_address"]}
                ],
            ),
            _segment_claim(
                loopback_id,
                spec["loopback_segment_key"],
                segment_matcher,
                plugin_semantics=loopback_segment(
                    f"{display} loopback", spec["loopback_address"]
                ),
                attachment_model={
                    "interface_kind": "loopback",
                    "logical_interface_resource_id": loopback_id,
                    "addresses": [spec["loopback_address"]],
                },
                evidence=[
                    {"kind": "loopback_address", "value": spec["loopback_address"]}
                ],
            ),
        ]
        if external:
            segment_claims.append(
                _segment_claim(
                    str(external["resource_id"]),
                    str(external["segment_key"]),
                    segment_matcher,
                    plugin_semantics=external["semantics"],
                    attachment_model={
                        "interface_kind": "physical",
                        "logical_interface_resource_id": external["resource_id"],
                        "physical_interface_resource_ids": [external["resource_id"]],
                        "addresses": [external["address"]],
                    },
                    confidence_score=float(external.get("confidence", 0.9)),
                    inference_method="interface_route_role_and_coverage",
                    inference_rule_id=f"{spec['rule_prefix']}.external-domain",
                    evidence=[
                        {"kind": "interface_address", "value": external["address"]},
                        {"kind": "connected_route", "value": external["prefix"]},
                        {"kind": "interface_role", "value": "external"},
                        {"kind": "selected_capture_coverage", "complete": True},
                    ],
                )
            )
        return _projection(
            spec["projection_id"],
            spec["projection_label"],
            spec["perspective_id"],
            resources,
            local_links,
            connector_claims,
            segment_claims=segment_claims,
            watermark_lag_ns=int(spec["watermark_lag_ns"]),
        )

    def ce_access_projection(spec: dict[str, Any]) -> dict[str, Any]:
        node_id = str(spec["node_id"])
        display = str(spec["display"])
        members = list(spec["member_ids"])
        lag_id = str(spec["lag_id"])
        subinterface_id = str(spec["subinterface_id"])
        loopback_id = str(spec["loopback_id"])
        management_id = str(spec["management_id"])
        external_id = str(spec["external_id"])
        resources = [
            _resource(
                loopback_id,
                "LOOPBACK",
                f"{display} loopback",
                "up",
                properties={"address": spec["loopback_address"]},
            ),
            *[
                _resource(
                    resource_id,
                    "INTERFACE",
                    f"{display} multihoming member {index}",
                    "up",
                    properties={"lag_parent": lag_id},
                )
                for index, resource_id in enumerate(members, start=1)
            ],
            _resource(
                lag_id,
                "LAG",
                f"{display} multi-chassis LAG",
                "up",
                properties={"lacp_mode": "active", "minimum_links": 1},
            ),
            _resource(
                subinterface_id,
                "SUBINTERFACE",
                f"{display} service VLAN {spec['vlan']}",
                "up",
                properties={"vlan_id": spec["vlan"], "vrf": "blue"},
            ),
            _resource(
                external_id,
                "INTERFACE",
                f"{display} customer LAN",
                "up",
                properties={"address": spec["external_address"], "role": "external"},
            ),
            _resource(
                management_id,
                "MANAGEMENT_INTERFACE",
                f"{display} management",
                "up",
                properties={"address": spec["management_address"]},
            ),
        ]
        local_links = [
            *[
                {
                    "link_id": f"{node_id}:member-{index}-to-lag",
                    "link_type": f"{spec['rule_prefix']}.lag_member",
                    "source_resource_id": resource_id,
                    "target_resource_id": lag_id,
                    "directed": True,
                }
                for index, resource_id in enumerate(members, start=1)
            ],
            {
                "link_id": f"{node_id}:lag-to-service-vlan",
                "link_type": f"{spec['rule_prefix']}.subinterface_parent",
                "source_resource_id": lag_id,
                "target_resource_id": subinterface_id,
                "directed": True,
            },
        ]
        connector_claims = [
            _claim(resource_id, key, "access-ethernet", connector_matcher)
            for resource_id, key in zip(
                members, spec["connector_keys"], strict=True
            )
        ]
        segment_claims = [
            _segment_claim(
                subinterface_id,
                spec["access_segment_key"],
                segment_matcher,
                plugin_semantics=spec["access_semantics"],
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": subinterface_id,
                    "parent_interface_resource_id": lag_id,
                    "lag_resource_id": lag_id,
                    "physical_interface_resource_ids": members,
                    "vlan": {"id": spec["vlan"], "encapsulation": "802.1Q"},
                    "routing_scope": {"kind": "vrf", "id": "blue"},
                },
                component_resource_ids=[subinterface_id, lag_id, *members],
                confidence_score=0.95,
                inference_method="interface_vlan_lacp_neighbor_consensus",
                inference_rule_id=f"{spec['rule_prefix']}.multihomed-access-domain",
                evidence=[
                    {"kind": "vlan", "id": spec["vlan"]},
                    {"kind": "lacp_members", "count": len(members)},
                    {"kind": "lldp_neighbors", "values": spec["neighbors"]},
                ],
            ),
            _segment_claim(
                external_id,
                spec["external_segment_key"],
                segment_matcher,
                plugin_semantics=external_network_segment(
                    f"{display} customer LAN",
                    spec["external_prefix"],
                    routing_scope={"kind": "vrf", "id": "blue"},
                ),
                attachment_model={
                    "interface_kind": "physical",
                    "logical_interface_resource_id": external_id,
                    "physical_interface_resource_ids": [external_id],
                    "addresses": [spec["external_address"]],
                    "routing_scope": {"kind": "vrf", "id": "blue"},
                },
                confidence_score=0.92,
                inference_method="interface_route_role_and_coverage",
                inference_rule_id=f"{spec['rule_prefix']}.customer-external-domain",
                evidence=[
                    {"kind": "interface_address", "value": spec["external_address"]},
                    {"kind": "connected_route", "value": spec["external_prefix"]},
                    {"kind": "selected_capture_coverage", "complete": True},
                ],
            ),
            _segment_claim(
                management_id,
                "management:oob:172.20.0.0-24",
                segment_matcher,
                plugin_semantics=management_segment,
                attachment_model={
                    "interface_kind": "management",
                    "logical_interface_resource_id": management_id,
                    "addresses": [spec["management_address"]],
                },
            ),
            _segment_claim(
                loopback_id,
                spec["loopback_segment_key"],
                segment_matcher,
                plugin_semantics=loopback_segment(
                    f"{display} loopback", spec["loopback_address"]
                ),
                attachment_model={
                    "interface_kind": "loopback",
                    "logical_interface_resource_id": loopback_id,
                    "addresses": [spec["loopback_address"]],
                },
            ),
        ]
        return _projection(
            spec["projection_id"],
            spec["projection_label"],
            spec["perspective_id"],
            resources,
            local_links,
            connector_claims,
            segment_claims=segment_claims,
            watermark_lag_ns=int(spec["watermark_lag_ns"]),
        )

    def pe_evpn_projection(spec: dict[str, Any]) -> dict[str, Any]:
        vtep_id = str(spec["vtep_id"])
        es_id = str(spec["es_id"])
        red_vrf_id = str(spec["red_vrf_id"])
        return _projection(
            "evpn.overlay",
            f"{spec['display']} EVPN overlay intent",
            "evpn.control-state",
            [
                _resource(vtep_id, "VTEP", f"{spec['display']} VTEP", "active"),
                _resource(
                    es_id,
                    "ETHERNET_SEGMENT",
                    f"{spec['display']} {spec['esi']}",
                    "active",
                    changes=spec["es_changes"],
                    properties={
                        "esi": spec["esi"],
                        "redundancy_mode": spec["redundancy_mode"],
                    },
                ),
                _resource(
                    red_vrf_id,
                    "VRF",
                    f"{spec['display']} red VRF",
                    "active",
                    properties={"vni": 50300, "route_target": "target:65000:300"},
                ),
            ],
            [
                {
                    "link_id": f"{spec['node_id']}:es-to-vtep",
                    "link_type": "evpn.advertised_by",
                    "source_resource_id": es_id,
                    "target_resource_id": vtep_id,
                    "directed": True,
                },
                {
                    "link_id": f"{spec['node_id']}:red-vrf-to-vtep",
                    "link_type": "evpn.uses_vtep",
                    "source_resource_id": red_vrf_id,
                    "target_resource_id": vtep_id,
                    "directed": True,
                },
            ],
            [],
            segment_claims=[
                _segment_claim(
                    vtep_id,
                    "vpn:blue:ipv4:10.20.0.0-24",
                    segment_matcher,
                    plugin_semantics=vpn_blue_segment,
                    attachment_model={
                        "interface_kind": "vtep",
                        "logical_interface_resource_id": vtep_id,
                        "routing_scope": {"kind": "vrf", "id": "blue"},
                        "vni": 50120,
                        "route_targets": ["target:65000:120"],
                    },
                    confidence_score=0.97,
                    inference_method="evpn_type5_and_vrf_state",
                    inference_rule_id="evpn.blue.ip-prefix-domain",
                    evidence=[
                        {"kind": "evpn_type5", "prefix": "10.20.0.0/24"},
                        {"kind": "vrf", "name": "blue", "vni": 50120},
                    ],
                ),
                _segment_claim(
                    es_id,
                    spec["es_segment_key"],
                    segment_matcher,
                    plugin_semantics=spec["es_semantics"],
                    attachment_model={
                        "interface_kind": "ethernet_segment",
                        "logical_interface_resource_id": es_id,
                        "routing_scope": {"kind": "vrf", "id": "blue"},
                        "ethernet_segment_id": spec["esi"],
                        "redundancy_mode": spec["redundancy_mode"],
                    },
                    confidence_score=0.97,
                    inference_method="evpn_type1_type4_and_df_state",
                    inference_rule_id=f"evpn.blue.{spec['site']}-ethernet-segment",
                    evidence=[
                        {"kind": "evpn_type1", "esi": spec["esi"]},
                        {"kind": "evpn_type4", "esi": spec["esi"]},
                    ],
                ),
                _segment_claim(
                    vtep_id,
                    "vpn:red:ipv6:2001-db8-30--64",
                    segment_matcher,
                    plugin_semantics=vpn_red_segment,
                    attachment_model={
                        "interface_kind": "vtep",
                        "logical_interface_resource_id": vtep_id,
                        "routing_scope": {"kind": "vrf", "id": "red"},
                        "vni": 50300,
                        "route_targets": ["target:65000:300"],
                    },
                    confidence_score=0.95,
                    inference_method="evpn_type5_and_vrf_state",
                    inference_rule_id="evpn.red.ipv6-prefix-domain",
                    evidence=[
                        {"kind": "evpn_type5", "prefix": "2001:db8:30::/64"},
                        {"kind": "vrf", "name": "red", "vni": 50300},
                    ],
                ),
            ],
            watermark_lag_ns=int(spec["watermark_lag_ns"]),
        )

    node_a_underlay = _projection(
        "alpha.underlay-links",
        "Alpha programmed underlay",
        "alpha.hardware-observed",
        [
            _resource(
                "node-a/LOOPBACK/lo0",
                "LOOPBACK",
                "PE-A lo0",
                "up",
                properties={"address": "10.255.0.1/32"},
            ),
            _resource(
                "node-a/INTERFACE/xe-0-0-0",
                "INTERFACE",
                "PE-A xe-0/0/0",
                "up",
                changes=flap,
                properties={"ifindex": 101, "encapsulation": "dot1q-101"},
            ),
            _resource(
                "node-a/INTERFACE/xe-0-0-1",
                "INTERFACE",
                "PE-A xe-0/0/1 to P2",
                "up",
                properties={
                    "ifindex": 201,
                    "encapsulation": "dot1q-201",
                    "sr_adj_sid": 24001,
                },
            ),
            _resource(
                "node-a/INTERFACE/xe-0-0-2",
                "INTERFACE",
                "PE-A xe-0/0/2 (ae0 member)",
                "up",
                properties={"ifindex": 102, "lag_parent": "ae0"},
            ),
            _resource(
                "node-a/LAG/ae0",
                "LAG",
                "PE-A ae0",
                "up",
                properties={"lacp_mode": "active", "minimum_links": 1},
            ),
            _resource(
                "node-a/SUBINTERFACE/ae0.101",
                "SUBINTERFACE",
                "PE-A ae0.101",
                "up",
                changes=flap,
                properties={"address": "192.0.2.1/29", "vlan_id": 101},
            ),
            _resource(
                "node-a/INTERFACE/xe-0-0-10",
                "INTERFACE",
                "PE-A west ES member 1",
                "up",
                properties={"ifindex": 3101, "lag_parent": "ae310"},
            ),
            _resource(
                "node-a/INTERFACE/xe-0-0-11",
                "INTERFACE",
                "PE-A west ES member 2",
                "up",
                properties={"ifindex": 3102, "lag_parent": "ae310"},
            ),
            _resource(
                "node-a/LAG/ae310",
                "LAG",
                "PE-A west EVPN multihoming bundle",
                "up",
                properties={"lacp_mode": "active", "minimum_links": 1},
            ),
            _resource(
                "node-a/SUBINTERFACE/ae310.310",
                "SUBINTERFACE",
                "PE-A west access VLAN 310",
                "up",
                properties={"vlan_id": 310, "vrf": "blue"},
            ),
            _resource(
                "node-a/INTERFACE/fxp0",
                "MANAGEMENT_INTERFACE",
                "PE-A fxp0",
                "up",
                properties={"address": "172.20.0.11/24"},
            ),
        ],
        [
            {
                "link_id": "node-a:loopback-to-uplink",
                "link_type": "alpha.resolves_via",
                "source_resource_id": "node-a/LOOPBACK/lo0",
                "target_resource_id": "node-a/INTERFACE/xe-0-0-0",
                "directed": True,
            },
            {
                "link_id": "node-a:loopback-to-p2-uplink",
                "link_type": "alpha.sr_resolves_via",
                "source_resource_id": "node-a/LOOPBACK/lo0",
                "target_resource_id": "node-a/INTERFACE/xe-0-0-1",
                "directed": True,
            },
            {
                "link_id": "node-a:xe-0-0-0-member-of-ae0",
                "link_type": "alpha.lag_member",
                "source_resource_id": "node-a/INTERFACE/xe-0-0-0",
                "target_resource_id": "node-a/LAG/ae0",
                "directed": True,
            },
            {
                "link_id": "node-a:xe-0-0-2-member-of-ae0",
                "link_type": "alpha.lag_member",
                "source_resource_id": "node-a/INTERFACE/xe-0-0-2",
                "target_resource_id": "node-a/LAG/ae0",
                "directed": True,
            },
            {
                "link_id": "node-a:ae0-to-ae0.101",
                "link_type": "alpha.parent_interface",
                "source_resource_id": "node-a/LAG/ae0",
                "target_resource_id": "node-a/SUBINTERFACE/ae0.101",
                "directed": True,
            },
            {
                "link_id": "node-a:xe-0-0-10-member-of-ae310",
                "link_type": "alpha.lag_member",
                "source_resource_id": "node-a/INTERFACE/xe-0-0-10",
                "target_resource_id": "node-a/LAG/ae310",
                "directed": True,
            },
            {
                "link_id": "node-a:xe-0-0-11-member-of-ae310",
                "link_type": "alpha.lag_member",
                "source_resource_id": "node-a/INTERFACE/xe-0-0-11",
                "target_resource_id": "node-a/LAG/ae310",
                "directed": True,
            },
            {
                "link_id": "node-a:ae310-to-vlan-310",
                "link_type": "alpha.parent_interface",
                "source_resource_id": "node-a/LAG/ae310",
                "target_resource_id": "node-a/SUBINTERFACE/ae310.310",
                "directed": True,
            },
        ],
        [
            _claim(
                "node-a/INTERFACE/xe-0-0-0",
                "underlay:circuit-101",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "node-a/INTERFACE/xe-0-0-1",
                "underlay:circuit-201",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "node-a/INTERFACE/xe-0-0-10",
                "access:west:node-a:member-1",
                "access-ethernet",
                connector_matcher,
            ),
            _claim(
                "node-a/INTERFACE/xe-0-0-11",
                "access:west:node-a:member-2",
                "access-ethernet",
                connector_matcher,
            ),
        ],
        segment_claims=[
            _segment_claim(
                "node-a/SUBINTERFACE/ae0.101",
                "underlay:default:core-west:vlan-101",
                segment_matcher,
                plugin_semantics=core_west_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "node-a/SUBINTERFACE/ae0.101",
                    "parent_interface_resource_id": "node-a/LAG/ae0",
                    "lag_resource_id": "node-a/LAG/ae0",
                    "physical_interface_resource_ids": [
                        "node-a/INTERFACE/xe-0-0-0",
                        "node-a/INTERFACE/xe-0-0-2",
                    ],
                    "vlan": {"id": 101, "encapsulation": "802.1Q"},
                    "addresses": ["192.0.2.1/29"],
                },
                component_resource_ids=[
                    "node-a/SUBINTERFACE/ae0.101",
                    "node-a/LAG/ae0",
                    "node-a/INTERFACE/xe-0-0-0",
                    "node-a/INTERFACE/xe-0-0-2",
                ],
                confidence_score=0.99,
                inference_method="interface_route_neighbor_consensus",
                inference_rule_id="alpha.connected-network-with-lacp-and-isis",
                evidence=[
                    {"kind": "interface_address", "value": "192.0.2.1/29"},
                    {"kind": "connected_route", "value": "192.0.2.0/29"},
                    {"kind": "lacp_members", "count": 2},
                    {"kind": "isis_neighbors", "count": 2},
                ],
            ),
            _segment_claim(
                "node-a/SUBINTERFACE/ae310.310",
                "access:blue:esi-west:vlan-310",
                segment_matcher,
                plugin_semantics=access_west_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "node-a/SUBINTERFACE/ae310.310",
                    "parent_interface_resource_id": "node-a/LAG/ae310",
                    "lag_resource_id": "node-a/LAG/ae310",
                    "physical_interface_resource_ids": [
                        "node-a/INTERFACE/xe-0-0-10",
                        "node-a/INTERFACE/xe-0-0-11",
                    ],
                    "vlan": {"id": 310, "encapsulation": "802.1Q"},
                    "routing_scope": {"kind": "vrf", "id": "blue"},
                },
                component_resource_ids=[
                    "node-a/SUBINTERFACE/ae310.310",
                    "node-a/LAG/ae310",
                    "node-a/INTERFACE/xe-0-0-10",
                    "node-a/INTERFACE/xe-0-0-11",
                ],
                confidence_score=0.99,
                inference_method="evpn_es_interface_lacp_consensus",
                inference_rule_id="alpha.blue-west-ethernet-segment",
                evidence=[
                    {"kind": "vlan", "id": 310},
                    {"kind": "lacp_members", "count": 2},
                    {"kind": "evpn_esi", "value": "0000:0000:0000:0000:0001"},
                ],
            ),
            _segment_claim(
                "node-a/INTERFACE/fxp0",
                "management:oob:172.20.0.0-24",
                segment_matcher,
                plugin_semantics=management_segment,
                attachment_model={
                    "interface_kind": "management",
                    "logical_interface_resource_id": "node-a/INTERFACE/fxp0",
                    "addresses": ["172.20.0.11/24"],
                },
                confidence_score=1.0,
                evidence=[{"kind": "interface_address", "value": "172.20.0.11/24"}],
            ),
            _segment_claim(
                "node-a/LOOPBACK/lo0",
                "loopback:global:10.255.0.1-32",
                segment_matcher,
                plugin_semantics=loopback_segment("PE-A loopback", "10.255.0.1/32"),
                attachment_model={
                    "interface_kind": "loopback",
                    "logical_interface_resource_id": "node-a/LOOPBACK/lo0",
                    "addresses": ["10.255.0.1/32"],
                },
                confidence_score=1.0,
                evidence=[{"kind": "loopback_address", "value": "10.255.0.1/32"}],
            ),
        ],
    )
    node_a_evpn = _projection(
        "evpn.overlay",
        "EVPN overlay intent",
        "evpn.control-state",
        [
            _resource("node-a/VTEP/10.0.0.1", "VTEP", "PE-A VTEP", "active"),
            _resource(
                "node-a/ETHERNET_SEGMENT/esi-01",
                "ETHERNET_SEGMENT",
                "ESI 0000:...:0001",
                "active",
                changes=withdraw,
                properties={"esi": "0000:0000:0000:0000:0001"},
            ),
        ],
        [
            {
                "link_id": "node-a:es-to-vtep",
                "link_type": "evpn.advertised_by",
                "source_resource_id": "node-a/ETHERNET_SEGMENT/esi-01",
                "target_resource_id": "node-a/VTEP/10.0.0.1",
                "directed": True,
            }
        ],
        [
            _claim(
                "node-a/VTEP/10.0.0.1",
                "evpn:blue:pe-pair",
                "evpn-overlay-peer",
                overlay_matcher,
                route_trace_role="overlay",
            )
        ],
        segment_claims=[
            _segment_claim(
                "node-a/VTEP/10.0.0.1",
                "vpn:blue:ipv4:10.20.0.0-24",
                segment_matcher,
                plugin_semantics=vpn_blue_segment,
                attachment_model={
                    "interface_kind": "vtep",
                    "logical_interface_resource_id": "node-a/VTEP/10.0.0.1",
                    "routing_scope": {"kind": "vrf", "id": "blue"},
                    "vni": 50120,
                    "route_targets": ["target:65000:120"],
                },
                confidence_score=0.98,
                inference_method="evpn_type5_and_vrf_state",
                inference_rule_id="evpn.blue.ip-prefix-domain",
                evidence=[
                    {"kind": "evpn_type5", "prefix": "10.20.0.0/24"},
                    {"kind": "vrf", "name": "blue", "vni": 50120},
                ],
            ),
            _segment_claim(
                "node-a/ETHERNET_SEGMENT/esi-01",
                "vpn:blue:esi-west",
                segment_matcher,
                plugin_semantics=vpn_es_west_segment,
                attachment_model={
                    "interface_kind": "ethernet_segment",
                    "logical_interface_resource_id": "node-a/ETHERNET_SEGMENT/esi-01",
                    "routing_scope": {"kind": "vrf", "id": "blue"},
                    "ethernet_segment_id": "0000:0000:0000:0000:0001",
                    "redundancy_mode": "all_active",
                },
                confidence_score=0.99,
                inference_method="evpn_type1_type4_and_df_state",
                inference_rule_id="evpn.blue.west-ethernet-segment",
                evidence=[
                    {"kind": "evpn_type1", "esi": "0000:0000:0000:0000:0001"},
                    {"kind": "evpn_type4", "esi": "0000:0000:0000:0000:0001"},
                ],
            ),
        ],
        watermark_lag_ns=11_000_000,
    )

    node_b_underlay = _projection(
        "beta.forwarding-links",
        "Beta ASIC forwarding connectivity",
        "beta.asic-observed",
        [
            _resource(
                "node-b/LOOPBACK/1",
                "LOOPBACK",
                "PE-B loopback",
                "up",
                properties={"address": "10.255.0.2/32"},
            ),
            _resource(
                "node-b/PORT/17",
                "PORT",
                "PE-B port 17",
                "programmed",
                changes=[
                    {"time_ns": failure_ns + 31_000_000, "status": "down"},
                    {"time_ns": restore_ns + 64_000_000, "status": "programmed"},
                ],
                properties={"opaque_port_id": 17, "vlan": 102},
            ),
            _resource(
                "node-b/PORT/18",
                "PORT",
                "PE-B port 18 to P2",
                "programmed",
                properties={"opaque_port_id": 18, "vlan": 202},
            ),
            _resource(
                "node-b/PORT/19",
                "PORT",
                "PE-B port 19 (bond17 member)",
                "programmed",
                properties={"opaque_port_id": 19, "lag_parent": 1700},
            ),
            _resource(
                "node-b/LAG/1700",
                "LAG",
                "PE-B bond17",
                "programmed",
                properties={"opaque_lag_id": 1700, "minimum_links": 1},
            ),
            _resource(
                "node-b/SUBINTERFACE/1700.102",
                "SUBINTERFACE",
                "PE-B bond17.102",
                "programmed",
                properties={"address": "192.0.2.10/29", "vlan_id": 102},
            ),
            _resource(
                "node-b/PORT/27",
                "PORT",
                "PE-B east ES member 1",
                "programmed",
                properties={"opaque_port_id": 27, "lag_parent": 3200},
            ),
            _resource(
                "node-b/PORT/29",
                "PORT",
                "PE-B east ES member 2",
                "programmed",
                properties={"opaque_port_id": 29, "lag_parent": 3200},
            ),
            _resource(
                "node-b/LAG/3200",
                "LAG",
                "PE-B east EVPN multihoming bundle",
                "programmed",
                properties={"opaque_lag_id": 3200, "minimum_links": 1},
            ),
            _resource(
                "node-b/SUBINTERFACE/3200.320",
                "SUBINTERFACE",
                "PE-B east access VLAN 320",
                "programmed",
                properties={"vlan_id": 320, "vrf": "blue"},
            ),
            _resource(
                "node-b/PORT/0",
                "MANAGEMENT_PORT",
                "PE-B management0",
                "programmed",
                properties={"address": "172.20.0.12/24"},
            ),
        ],
        [
            {
                "link_id": "node-b:loopback-to-port",
                "link_type": "beta.fib_egress",
                "source_resource_id": "node-b/LOOPBACK/1",
                "target_resource_id": "node-b/PORT/17",
                "directed": True,
            },
            {
                "link_id": "node-b:loopback-to-port-18",
                "link_type": "beta.ecmp_egress",
                "source_resource_id": "node-b/LOOPBACK/1",
                "target_resource_id": "node-b/PORT/18",
                "directed": True,
            },
            {
                "link_id": "node-b:port-17-member-of-1700",
                "link_type": "beta.lag_member",
                "source_resource_id": "node-b/PORT/17",
                "target_resource_id": "node-b/LAG/1700",
                "directed": True,
            },
            {
                "link_id": "node-b:port-19-member-of-1700",
                "link_type": "beta.lag_member",
                "source_resource_id": "node-b/PORT/19",
                "target_resource_id": "node-b/LAG/1700",
                "directed": True,
            },
            {
                "link_id": "node-b:lag-1700-to-subif-102",
                "link_type": "beta.subinterface_parent",
                "source_resource_id": "node-b/LAG/1700",
                "target_resource_id": "node-b/SUBINTERFACE/1700.102",
                "directed": True,
            },
            {
                "link_id": "node-b:port-27-member-of-3200",
                "link_type": "beta.lag_member",
                "source_resource_id": "node-b/PORT/27",
                "target_resource_id": "node-b/LAG/3200",
                "directed": True,
            },
            {
                "link_id": "node-b:port-29-member-of-3200",
                "link_type": "beta.lag_member",
                "source_resource_id": "node-b/PORT/29",
                "target_resource_id": "node-b/LAG/3200",
                "directed": True,
            },
            {
                "link_id": "node-b:lag-3200-to-subif-320",
                "link_type": "beta.subinterface_parent",
                "source_resource_id": "node-b/LAG/3200",
                "target_resource_id": "node-b/SUBINTERFACE/3200.320",
                "directed": True,
            },
        ],
        [
            _claim(
                "node-b/PORT/17",
                "underlay:circuit-102",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "node-b/PORT/18",
                "underlay:circuit-202",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "node-b/PORT/27",
                "access:east:node-b:member-1",
                "access-ethernet",
                connector_matcher,
            ),
            _claim(
                "node-b/PORT/29",
                "access:east:node-b:member-2",
                "access-ethernet",
                connector_matcher,
            ),
        ],
        segment_claims=[
            _segment_claim(
                "node-b/SUBINTERFACE/1700.102",
                "underlay:default:core-east:vlan-102",
                segment_matcher,
                plugin_semantics=core_east_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "node-b/SUBINTERFACE/1700.102",
                    "parent_interface_resource_id": "node-b/LAG/1700",
                    "lag_resource_id": "node-b/LAG/1700",
                    "physical_interface_resource_ids": [
                        "node-b/PORT/17",
                        "node-b/PORT/19",
                    ],
                    "vlan": {"id": 102, "encapsulation": "802.1Q"},
                    "addresses": ["192.0.2.10/29"],
                },
                component_resource_ids=[
                    "node-b/SUBINTERFACE/1700.102",
                    "node-b/LAG/1700",
                    "node-b/PORT/17",
                    "node-b/PORT/19",
                ],
                confidence_score=0.96,
                inference_method="asic_interface_route_neighbor_consensus",
                inference_rule_id="beta.connected-network-with-lag-and-fib",
                evidence=[
                    {"kind": "interface_address", "value": "192.0.2.10/29"},
                    {"kind": "connected_fib_entry", "value": "192.0.2.8/29"},
                    {"kind": "lag_members", "opaque_port_ids": [17, 19]},
                ],
            ),
            _segment_claim(
                "node-b/SUBINTERFACE/3200.320",
                "access:blue:esi-east:vlan-320",
                segment_matcher,
                plugin_semantics=access_east_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "node-b/SUBINTERFACE/3200.320",
                    "parent_interface_resource_id": "node-b/LAG/3200",
                    "lag_resource_id": "node-b/LAG/3200",
                    "physical_interface_resource_ids": [
                        "node-b/PORT/27",
                        "node-b/PORT/29",
                    ],
                    "vlan": {"id": 320, "encapsulation": "802.1Q"},
                    "routing_scope": {"kind": "vrf", "id": "blue"},
                },
                component_resource_ids=[
                    "node-b/SUBINTERFACE/3200.320",
                    "node-b/LAG/3200",
                    "node-b/PORT/27",
                    "node-b/PORT/29",
                ],
                confidence_score=0.97,
                inference_method="evpn_es_interface_lacp_consensus",
                inference_rule_id="beta.blue-east-ethernet-segment",
                evidence=[
                    {"kind": "vlan", "id": 320},
                    {"kind": "lag_members", "opaque_port_ids": [27, 29]},
                    {"kind": "evpn_esi", "value": "0000:0000:0000:0000:0002"},
                ],
            ),
            _segment_claim(
                "node-b/PORT/0",
                "management:oob:172.20.0.0-24",
                segment_matcher,
                plugin_semantics=management_segment,
                attachment_model={
                    "interface_kind": "management",
                    "logical_interface_resource_id": "node-b/PORT/0",
                    "addresses": ["172.20.0.12/24"],
                },
                confidence_score=1.0,
                evidence=[{"kind": "interface_address", "value": "172.20.0.12/24"}],
            ),
            _segment_claim(
                "node-b/LOOPBACK/1",
                "loopback:global:10.255.0.2-32",
                segment_matcher,
                plugin_semantics=loopback_segment("PE-B loopback", "10.255.0.2/32"),
                attachment_model={
                    "interface_kind": "loopback",
                    "logical_interface_resource_id": "node-b/LOOPBACK/1",
                    "addresses": ["10.255.0.2/32"],
                },
                confidence_score=1.0,
                evidence=[{"kind": "loopback_address", "value": "10.255.0.2/32"}],
            ),
        ],
        watermark_lag_ns=37_000_000,
    )
    node_b_evpn = _projection(
        "evpn.overlay",
        "EVPN overlay intent",
        "evpn.control-state",
        [
            _resource("node-b/VTEP/10.0.0.2", "VTEP", "PE-B VTEP", "active"),
            _resource(
                "node-b/ETHERNET_SEGMENT/esi-01",
                "ETHERNET_SEGMENT",
                "East ESI 0000:...:0002",
                "active",
                changes=[
                    {"time_ns": failure_ns + 45_000_000, "status": "withdrawn"},
                    {"time_ns": restore_ns + 80_000_000, "status": "active"},
                ],
                properties={"esi": "0000:0000:0000:0000:0002"},
            ),
        ],
        [
            {
                "link_id": "node-b:es-to-vtep",
                "link_type": "evpn.advertised_by",
                "source_resource_id": "node-b/ETHERNET_SEGMENT/esi-01",
                "target_resource_id": "node-b/VTEP/10.0.0.2",
                "directed": True,
            }
        ],
        [
            _claim(
                "node-b/VTEP/10.0.0.2",
                "evpn:blue:pe-pair",
                "evpn-overlay-peer",
                overlay_matcher,
                route_trace_role="overlay",
            )
        ],
        segment_claims=[
            _segment_claim(
                "node-b/VTEP/10.0.0.2",
                "vpn:blue:ipv4:10.20.0.0-24",
                segment_matcher,
                plugin_semantics=vpn_blue_segment,
                attachment_model={
                    "interface_kind": "vtep",
                    "logical_interface_resource_id": "node-b/VTEP/10.0.0.2",
                    "routing_scope": {"kind": "vrf", "id": "blue"},
                    "vni": 50120,
                    "route_targets": ["target:65000:120"],
                },
                confidence_score=0.96,
                inference_method="evpn_type5_and_vrf_state",
                inference_rule_id="evpn.blue.ip-prefix-domain",
                evidence=[
                    {"kind": "evpn_type5", "prefix": "10.20.0.0/24"},
                    {"kind": "vrf", "name": "blue", "vni": 50120},
                ],
            ),
            _segment_claim(
                "node-b/ETHERNET_SEGMENT/esi-01",
                "vpn:blue:esi-east",
                segment_matcher,
                plugin_semantics=vpn_es_east_segment,
                attachment_model={
                    "interface_kind": "ethernet_segment",
                    "logical_interface_resource_id": "node-b/ETHERNET_SEGMENT/esi-01",
                    "routing_scope": {"kind": "vrf", "id": "blue"},
                    "ethernet_segment_id": "0000:0000:0000:0000:0002",
                    "redundancy_mode": "single_active",
                },
                confidence_score=0.97,
                inference_method="evpn_type1_type4_and_df_state",
                inference_rule_id="evpn.blue.east-ethernet-segment",
                evidence=[
                    {"kind": "evpn_type1", "esi": "0000:0000:0000:0000:0002"},
                    {"kind": "evpn_type4", "esi": "0000:0000:0000:0000:0002"},
                ],
            ),
        ],
        watermark_lag_ns=53_000_000,
    )

    transit = _projection(
        "gamma.isis-links",
        "Gamma IS-IS adjacency topology",
        "gamma.isis-observed",
        [
            _resource(
                "transit-p-1/LOOPBACK/0",
                "LOOPBACK",
                "P1 router ID",
                "up",
                properties={"address": "10.255.0.11/32"},
            ),
            _resource(
                "transit-p-1/ADJACENCY/pe-a",
                "ISIS_ADJACENCY",
                "P1 to PE-A",
                "up",
                changes=[
                    {"time_ns": failure_ns + 12_000_000, "status": "down"},
                    {"time_ns": restore_ns + 48_000_000, "status": "up"},
                ],
            ),
            _resource(
                "transit-p-1/ADJACENCY/pe-b",
                "ISIS_ADJACENCY",
                "P1 to PE-B",
                "up",
                changes=[
                    {"time_ns": failure_ns + 39_000_000, "status": "down"},
                    {"time_ns": restore_ns + 72_000_000, "status": "up"},
                ],
            ),
            _resource(
                "transit-p-1/ADJACENCY/pe-a-candidate",
                "ISIS_ADJACENCY",
                "P1 alternate observation for PE-A",
                "up",
                properties={
                    "observation_role": "parallel_candidate",
                    "candidate_reason": "duplicate opaque connector claim",
                },
            ),
            _resource(
                "transit-p-1/ADJACENCY/p2",
                "ISIS_ADJACENCY",
                "P1 to P2 core adjacency",
                "up",
                properties={"metric": 15, "adj_sid": 16112},
            ),
            _resource(
                "transit-p-1/INTERFACE/et-0-0-0",
                "INTERFACE",
                "P1 et-0/0/0",
                "up",
                properties={"ifindex": 310},
            ),
            _resource(
                "transit-p-1/SUBINTERFACE/et-0-0-0.101",
                "SUBINTERFACE",
                "P1 et-0/0/0.101",
                "up",
                changes=[
                    {"time_ns": failure_ns + 12_000_000, "status": "down"},
                    {"time_ns": restore_ns + 48_000_000, "status": "up"},
                ],
                properties={"address": "192.0.2.2/29", "vlan_id": 101},
            ),
            _resource(
                "transit-p-1/INTERFACE/et-0-0-1",
                "INTERFACE",
                "P1 et-0/0/1",
                "up",
                properties={"ifindex": 311},
            ),
            _resource(
                "transit-p-1/SUBINTERFACE/et-0-0-1.102",
                "SUBINTERFACE",
                "P1 et-0/0/1.102",
                "up",
                changes=[
                    {"time_ns": failure_ns + 39_000_000, "status": "down"},
                    {"time_ns": restore_ns + 72_000_000, "status": "up"},
                ],
                properties={"address": "192.0.2.9/29", "vlan_id": 102},
            ),
            _resource(
                "transit-p-1/INTERFACE/et-0-0-2",
                "INTERFACE",
                "P1 route boundary to PE-D",
                "up",
                properties={"ifindex": 312, "neighbor": "node-d"},
            ),
            _resource(
                "transit-p-1/INTERFACE/et-0-0-3",
                "INTERFACE",
                "P1 route boundary to PE-E",
                "up",
                properties={"ifindex": 313, "neighbor": "node-e"},
            ),
            _resource(
                "transit-p-1/INTERFACE/em0",
                "MANAGEMENT_INTERFACE",
                "P1 em0",
                "up",
                properties={"address": "172.20.0.21/24"},
            ),
        ],
        [
            {
                "link_id": "p1:et-0-0-0-to-vlan-101",
                "link_type": "gamma.subinterface_parent",
                "source_resource_id": "transit-p-1/INTERFACE/et-0-0-0",
                "target_resource_id": "transit-p-1/SUBINTERFACE/et-0-0-0.101",
                "directed": True,
            },
            {
                "link_id": "p1:et-0-0-1-to-vlan-102",
                "link_type": "gamma.subinterface_parent",
                "source_resource_id": "transit-p-1/INTERFACE/et-0-0-1",
                "target_resource_id": "transit-p-1/SUBINTERFACE/et-0-0-1.102",
                "directed": True,
            },
        ],
        [
            _claim(
                "transit-p-1/ADJACENCY/pe-a",
                "underlay:circuit-101",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "transit-p-1/ADJACENCY/pe-b",
                "underlay:circuit-102",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "transit-p-1/ADJACENCY/pe-a-candidate",
                "underlay:circuit-101",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "transit-p-1/ADJACENCY/p2",
                "underlay:core-p1-p2",
                "underlay-core-adjacency",
                connector_matcher,
            ),
            _claim(
                "transit-p-1/INTERFACE/et-0-0-2",
                "underlay:circuit-301",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "transit-p-1/INTERFACE/et-0-0-3",
                "underlay:circuit-401",
                "underlay-adjacency",
                connector_matcher,
            ),
        ],
        segment_claims=[
            _segment_claim(
                "transit-p-1/SUBINTERFACE/et-0-0-0.101",
                "underlay:default:core-west:vlan-101",
                segment_matcher,
                plugin_semantics=core_west_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "transit-p-1/SUBINTERFACE/et-0-0-0.101",
                    "parent_interface_resource_id": "transit-p-1/INTERFACE/et-0-0-0",
                    "physical_interface_resource_ids": ["transit-p-1/INTERFACE/et-0-0-0"],
                    "vlan": {"id": 101, "encapsulation": "802.1Q"},
                    "addresses": ["192.0.2.2/29"],
                },
                component_resource_ids=[
                    "transit-p-1/SUBINTERFACE/et-0-0-0.101",
                    "transit-p-1/INTERFACE/et-0-0-0",
                ],
                confidence_score=0.97,
                inference_method="isis_interface_and_connected_route",
                inference_rule_id="gamma.isis.multi-access-network",
                evidence=[
                    {"kind": "interface_address", "value": "192.0.2.2/29"},
                    {"kind": "isis_lan_adjacencies", "neighbors": ["PE-A", "P2"]},
                ],
            ),
            _segment_claim(
                "transit-p-1/SUBINTERFACE/et-0-0-1.102",
                "underlay:default:core-east:vlan-102",
                segment_matcher,
                plugin_semantics=core_east_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "transit-p-1/SUBINTERFACE/et-0-0-1.102",
                    "parent_interface_resource_id": "transit-p-1/INTERFACE/et-0-0-1",
                    "physical_interface_resource_ids": ["transit-p-1/INTERFACE/et-0-0-1"],
                    "vlan": {"id": 102, "encapsulation": "802.1Q"},
                    "addresses": ["192.0.2.9/29"],
                },
                component_resource_ids=[
                    "transit-p-1/SUBINTERFACE/et-0-0-1.102",
                    "transit-p-1/INTERFACE/et-0-0-1",
                ],
                confidence_score=0.97,
                inference_method="isis_interface_and_connected_route",
                inference_rule_id="gamma.isis.multi-access-network",
                evidence=[
                    {"kind": "interface_address", "value": "192.0.2.9/29"},
                    {"kind": "isis_lan_adjacencies", "neighbors": ["PE-B", "P2"]},
                ],
            ),
            _segment_claim(
                "transit-p-1/INTERFACE/em0",
                "management:oob:172.20.0.0-24",
                segment_matcher,
                plugin_semantics=management_segment,
                attachment_model={
                    "interface_kind": "management",
                    "logical_interface_resource_id": "transit-p-1/INTERFACE/em0",
                    "addresses": ["172.20.0.21/24"],
                },
                confidence_score=1.0,
                evidence=[{"kind": "interface_address", "value": "172.20.0.21/24"}],
            ),
            _segment_claim(
                "transit-p-1/LOOPBACK/0",
                "loopback:global:10.255.0.11-32",
                segment_matcher,
                plugin_semantics=loopback_segment("P1 router ID", "10.255.0.11/32"),
                attachment_model={
                    "interface_kind": "loopback",
                    "logical_interface_resource_id": "transit-p-1/LOOPBACK/0",
                    "addresses": ["10.255.0.11/32"],
                },
                confidence_score=1.0,
                evidence=[{"kind": "isis_router_id", "value": "10.255.0.11/32"}],
            ),
        ],
        watermark_lag_ns=23_000_000,
    )
    transit_p2 = _projection(
        "delta.sr-isis-links",
        "Delta SR-aware IS-IS topology",
        "delta.sr-observed",
        [
            _resource(
                "transit-p-2/ROUTER_ID/10.255.0.12",
                "ROUTER_ID",
                "P2 router ID",
                "up",
                properties={"address": "10.255.0.12/32"},
            ),
            _resource(
                "transit-p-2/ADJACENCY/pe-a",
                "ISIS_ADJACENCY",
                "P2 to PE-A",
                "up",
                properties={"metric": 12, "adj_sid": 16201},
            ),
            _resource(
                "transit-p-2/ADJACENCY/pe-b",
                "ISIS_ADJACENCY",
                "P2 to PE-B",
                "up",
                properties={"metric": 11, "adj_sid": 16202},
            ),
            _resource(
                "transit-p-2/ADJACENCY/pe-c",
                "ISIS_ADJACENCY",
                "P2 to PE-C",
                "up",
                properties={"metric": 8, "adj_sid": 16203},
            ),
            _resource(
                "transit-p-2/ADJACENCY/p1",
                "ISIS_ADJACENCY",
                "P2 to P1 core adjacency",
                "up",
                properties={"metric": 15, "adj_sid": 16212},
            ),
            _resource(
                "transit-p-2/INTERFACE/TenGig0-0-0",
                "INTERFACE",
                "P2 TenGig0/0/0 (Bundle-Ether10 member)",
                "up",
                properties={"ifindex": 420, "lag_parent": "Bundle-Ether10"},
            ),
            _resource(
                "transit-p-2/INTERFACE/TenGig0-0-1",
                "INTERFACE",
                "P2 TenGig0/0/1 (Bundle-Ether10 member)",
                "up",
                properties={"ifindex": 421, "lag_parent": "Bundle-Ether10"},
            ),
            _resource(
                "transit-p-2/LAG/Bundle-Ether10",
                "LAG",
                "P2 Bundle-Ether10",
                "up",
                properties={"lacp_mode": "active", "minimum_links": 1},
            ),
            _resource(
                "transit-p-2/SUBINTERFACE/Bundle-Ether10.101",
                "SUBINTERFACE",
                "P2 Bundle-Ether10.101",
                "up",
                properties={"address": "192.0.2.3/29", "vlan_id": 101},
            ),
            _resource(
                "transit-p-2/SUBINTERFACE/Bundle-Ether10.102",
                "SUBINTERFACE",
                "P2 Bundle-Ether10.102",
                "up",
                properties={"address": "192.0.2.11/29", "vlan_id": 102},
            ),
            _resource(
                "transit-p-2/INTERFACE/TenGig0-0-4",
                "INTERFACE",
                "P2 independent TenGig0/0/4",
                "up",
                properties={"ifindex": 424},
            ),
            _resource(
                "transit-p-2/SUBINTERFACE/TenGig0-0-4.101",
                "SUBINTERFACE",
                "P2 independent TenGig0/0/4.101",
                "up",
                properties={"address": "192.0.2.4/29", "vlan_id": 101},
            ),
            _resource(
                "transit-p-2/INTERFACE/TenGig0-0-3",
                "INTERFACE",
                "P2 TenGig0/0/3",
                "up",
                properties={"ifindex": 423},
            ),
            _resource(
                "transit-p-2/SUBINTERFACE/TenGig0-0-3.203",
                "SUBINTERFACE",
                "P2 TenGig0/0/3.203 to PE-C",
                "up",
                properties={"address": "192.0.2.17/30", "vlan_id": 203},
            ),
            _resource(
                "transit-p-2/INTERFACE/TenGig0-0-5",
                "INTERFACE",
                "P2 route boundary to PE-D",
                "up",
                properties={"ifindex": 425, "neighbor": "node-d"},
            ),
            _resource(
                "transit-p-2/INTERFACE/TenGig0-0-6",
                "INTERFACE",
                "P2 route boundary to PE-E",
                "up",
                properties={"ifindex": 426, "neighbor": "node-e"},
            ),
            _resource(
                "transit-p-2/INTERFACE/Management0",
                "MANAGEMENT_INTERFACE",
                "P2 Management0",
                "up",
                properties={"address": "172.20.0.22/24"},
            ),
        ],
        [
            {
                "link_id": "p2:te-0-0-0-member-of-be10",
                "link_type": "delta.lag_member",
                "source_resource_id": "transit-p-2/INTERFACE/TenGig0-0-0",
                "target_resource_id": "transit-p-2/LAG/Bundle-Ether10",
                "directed": True,
            },
            {
                "link_id": "p2:te-0-0-1-member-of-be10",
                "link_type": "delta.lag_member",
                "source_resource_id": "transit-p-2/INTERFACE/TenGig0-0-1",
                "target_resource_id": "transit-p-2/LAG/Bundle-Ether10",
                "directed": True,
            },
            {
                "link_id": "p2:be10-to-vlan-101",
                "link_type": "delta.subinterface_parent",
                "source_resource_id": "transit-p-2/LAG/Bundle-Ether10",
                "target_resource_id": "transit-p-2/SUBINTERFACE/Bundle-Ether10.101",
                "directed": True,
            },
            {
                "link_id": "p2:be10-to-vlan-102",
                "link_type": "delta.subinterface_parent",
                "source_resource_id": "transit-p-2/LAG/Bundle-Ether10",
                "target_resource_id": "transit-p-2/SUBINTERFACE/Bundle-Ether10.102",
                "directed": True,
            },
        ],
        [
            _claim(
                "transit-p-2/ADJACENCY/pe-a",
                "underlay:circuit-201",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "transit-p-2/ADJACENCY/pe-b",
                "underlay:circuit-202",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "transit-p-2/ADJACENCY/pe-c",
                "underlay:circuit-203",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "transit-p-2/ADJACENCY/p1",
                "underlay:core-p1-p2",
                "underlay-core-adjacency",
                connector_matcher,
            ),
            _claim(
                "transit-p-2/INTERFACE/TenGig0-0-5",
                "underlay:circuit-302",
                "underlay-adjacency",
                connector_matcher,
            ),
            _claim(
                "transit-p-2/INTERFACE/TenGig0-0-6",
                "underlay:circuit-402",
                "underlay-adjacency",
                connector_matcher,
            ),
        ],
        segment_claims=[
            _segment_claim(
                "transit-p-2/SUBINTERFACE/Bundle-Ether10.101",
                "underlay:default:core-west:vlan-101",
                segment_matcher,
                plugin_semantics=core_west_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "transit-p-2/SUBINTERFACE/Bundle-Ether10.101",
                    "parent_interface_resource_id": "transit-p-2/LAG/Bundle-Ether10",
                    "lag_resource_id": "transit-p-2/LAG/Bundle-Ether10",
                    "physical_interface_resource_ids": [
                        "transit-p-2/INTERFACE/TenGig0-0-0",
                        "transit-p-2/INTERFACE/TenGig0-0-1",
                    ],
                    "vlan": {"id": 101, "encapsulation": "802.1Q"},
                    "addresses": ["192.0.2.3/29"],
                },
                component_resource_ids=[
                    "transit-p-2/SUBINTERFACE/Bundle-Ether10.101",
                    "transit-p-2/LAG/Bundle-Ether10",
                    "transit-p-2/INTERFACE/TenGig0-0-0",
                    "transit-p-2/INTERFACE/TenGig0-0-1",
                ],
                confidence_score=0.94,
                inference_method="sr_isis_interface_neighbor_consensus",
                inference_rule_id="delta.sr.multi-access-domain",
                evidence=[
                    {"kind": "interface_address", "value": "192.0.2.3/29"},
                    {"kind": "isis_lan_adjacencies", "neighbors": ["PE-A", "P1"]},
                    {"kind": "lacp_members", "count": 2},
                ],
            ),
            _segment_claim(
                "transit-p-2/SUBINTERFACE/TenGig0-0-4.101",
                "underlay:default:core-west:vlan-101",
                segment_matcher,
                plugin_semantics=core_west_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "transit-p-2/SUBINTERFACE/TenGig0-0-4.101",
                    "parent_interface_resource_id": "transit-p-2/INTERFACE/TenGig0-0-4",
                    "physical_interface_resource_ids": ["transit-p-2/INTERFACE/TenGig0-0-4"],
                    "vlan": {"id": 101, "encapsulation": "802.1Q"},
                    "addresses": ["192.0.2.4/29"],
                    "attachment_role": "independent_parallel_interface",
                },
                component_resource_ids=[
                    "transit-p-2/SUBINTERFACE/TenGig0-0-4.101",
                    "transit-p-2/INTERFACE/TenGig0-0-4",
                ],
                confidence_score=0.86,
                inference_method="interface_route_without_complete_neighbor_inventory",
                inference_rule_id="delta.route-and-interface-subnet-candidate",
                evidence=[
                    {"kind": "interface_address", "value": "192.0.2.4/29"},
                    {"kind": "connected_route", "value": "192.0.2.0/29"},
                    {"kind": "neighbor_inventory", "status": "partial"},
                ],
                valid_from_ns=failure_ns + 100_000_000,
                valid_to_ns=capture_ns + 500_000_000,
            ),
            _segment_claim(
                "transit-p-2/SUBINTERFACE/Bundle-Ether10.102",
                "underlay:default:core-east:vlan-102",
                segment_matcher,
                plugin_semantics=core_east_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "transit-p-2/SUBINTERFACE/Bundle-Ether10.102",
                    "parent_interface_resource_id": "transit-p-2/LAG/Bundle-Ether10",
                    "lag_resource_id": "transit-p-2/LAG/Bundle-Ether10",
                    "physical_interface_resource_ids": [
                        "transit-p-2/INTERFACE/TenGig0-0-0",
                        "transit-p-2/INTERFACE/TenGig0-0-1",
                    ],
                    "vlan": {"id": 102, "encapsulation": "802.1Q"},
                    "addresses": ["192.0.2.11/29"],
                },
                component_resource_ids=[
                    "transit-p-2/SUBINTERFACE/Bundle-Ether10.102",
                    "transit-p-2/LAG/Bundle-Ether10",
                    "transit-p-2/INTERFACE/TenGig0-0-0",
                    "transit-p-2/INTERFACE/TenGig0-0-1",
                ],
                confidence_score=0.94,
                inference_method="sr_isis_interface_neighbor_consensus",
                inference_rule_id="delta.sr.multi-access-domain",
                evidence=[
                    {"kind": "interface_address", "value": "192.0.2.11/29"},
                    {"kind": "isis_lan_adjacencies", "neighbors": ["PE-B", "P1"]},
                ],
            ),
            _segment_claim(
                "transit-p-2/SUBINTERFACE/TenGig0-0-3.203",
                "underlay:default:edge-east:vlan-203",
                segment_matcher,
                plugin_semantics=edge_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "transit-p-2/SUBINTERFACE/TenGig0-0-3.203",
                    "physical_interface_resource_ids": ["transit-p-2/INTERFACE/TenGig0-0-3"],
                    "vlan": {"id": 203, "encapsulation": "802.1Q"},
                    "addresses": ["192.0.2.17/30"],
                },
                component_resource_ids=[
                    "transit-p-2/SUBINTERFACE/TenGig0-0-3.203",
                    "transit-p-2/INTERFACE/TenGig0-0-3",
                ],
                confidence_score=0.98,
                inference_method="sr_isis_interface_neighbor_consensus",
                inference_rule_id="delta.sr.point-to-point-domain",
                evidence=[
                    {"kind": "interface_address", "value": "192.0.2.17/30"},
                    {"kind": "isis_neighbor", "neighbor": "PE-C"},
                ],
            ),
            _segment_claim(
                "transit-p-2/INTERFACE/Management0",
                "management:oob:172.20.0.0-24",
                segment_matcher,
                plugin_semantics=management_segment,
                attachment_model={
                    "interface_kind": "management",
                    "logical_interface_resource_id": "transit-p-2/INTERFACE/Management0",
                    "addresses": ["172.20.0.22/24"],
                },
                confidence_score=1.0,
                evidence=[{"kind": "interface_address", "value": "172.20.0.22/24"}],
            ),
            _segment_claim(
                "transit-p-2/ROUTER_ID/10.255.0.12",
                "loopback:global:10.255.0.12-32",
                segment_matcher,
                plugin_semantics=loopback_segment("P2 router ID", "10.255.0.12/32"),
                attachment_model={
                    "interface_kind": "loopback",
                    "logical_interface_resource_id": "transit-p-2/ROUTER_ID/10.255.0.12",
                    "addresses": ["10.255.0.12/32"],
                },
                confidence_score=1.0,
                evidence=[{"kind": "isis_router_id", "value": "10.255.0.12/32"}],
            ),
        ],
        watermark_lag_ns=29_000_000,
    )
    node_c_underlay = _projection(
        "epsilon.forwarding-links",
        "Epsilon edge forwarding",
        "epsilon.dataplane-observed",
        [
            _resource(
                "node-c/LOOPBACK/100",
                "LOOPBACK",
                "PE-C service loopback",
                "up",
                properties={"address": "10.0.0.3/32"},
            ),
            _resource(
                "node-c/PORT/7",
                "PORT",
                "PE-C port 7 to P2",
                "programmed",
                properties={"opaque_port_id": 7, "srv6_capable": True},
            ),
            _resource(
                "node-c/SUBINTERFACE/7.203",
                "SUBINTERFACE",
                "PE-C port 7.203",
                "programmed",
                properties={"address": "192.0.2.18/30", "vlan_id": 203},
            ),
            _resource(
                "node-c/PORT/8",
                "PORT",
                "PE-C external service port 8",
                "programmed",
                properties={"opaque_port_id": 8, "address": "198.51.100.1/24"},
            ),
            _resource(
                "node-c/PORT/0",
                "MANAGEMENT_PORT",
                "PE-C management0",
                "programmed",
                properties={"opaque_port_id": 0, "address": "172.20.0.13/24"},
            ),
        ],
        [
            {
                "link_id": "node-c:loopback-to-port-7",
                "link_type": "epsilon.route_egress",
                "source_resource_id": "node-c/LOOPBACK/100",
                "target_resource_id": "node-c/PORT/7",
                "directed": True,
            },
            {
                "link_id": "node-c:port-7-to-vlan-203",
                "link_type": "epsilon.subinterface_parent",
                "source_resource_id": "node-c/PORT/7",
                "target_resource_id": "node-c/SUBINTERFACE/7.203",
                "directed": True,
            },
        ],
        [
            _claim(
                "node-c/PORT/7",
                "underlay:circuit-203",
                "underlay-adjacency",
                connector_matcher,
            )
        ],
        segment_claims=[
            _segment_claim(
                "node-c/SUBINTERFACE/7.203",
                "underlay:default:edge-east:vlan-203",
                segment_matcher,
                plugin_semantics=edge_segment,
                attachment_model={
                    "interface_kind": "subinterface",
                    "logical_interface_resource_id": "node-c/SUBINTERFACE/7.203",
                    "parent_interface_resource_id": "node-c/PORT/7",
                    "physical_interface_resource_ids": ["node-c/PORT/7"],
                    "vlan": {"id": 203, "encapsulation": "802.1Q"},
                    "addresses": ["192.0.2.18/30"],
                },
                component_resource_ids=[
                    "node-c/SUBINTERFACE/7.203",
                    "node-c/PORT/7",
                ],
                confidence_score=0.96,
                inference_method="interface_route_and_srv6_neighbor",
                inference_rule_id="epsilon.connected-domain-with-neighbor",
                evidence=[
                    {"kind": "interface_address", "value": "192.0.2.18/30"},
                    {"kind": "isis_neighbor", "neighbor": "P2"},
                ],
            ),
            _segment_claim(
                "node-c/PORT/8",
                "external:default:customer-services:198.51.100.0-24",
                segment_matcher,
                plugin_semantics=external_segment,
                attachment_model={
                    "interface_kind": "physical",
                    "logical_interface_resource_id": "node-c/PORT/8",
                    "physical_interface_resource_ids": ["node-c/PORT/8"],
                    "addresses": ["198.51.100.1/24"],
                },
                confidence_score=0.78,
                inference_method="connected_route_without_selected_remote_node",
                inference_rule_id="epsilon.external-from-role-route-and-coverage",
                evidence=[
                    {"kind": "interface_address", "value": "198.51.100.1/24"},
                    {"kind": "connected_route", "value": "198.51.100.0/24"},
                    {"kind": "interface_role", "value": "external_services"},
                    {"kind": "selected_capture_coverage", "complete": True},
                ],
            ),
            _segment_claim(
                "node-c/PORT/0",
                "management:oob:172.20.0.0-24",
                segment_matcher,
                plugin_semantics=management_segment,
                attachment_model={
                    "interface_kind": "management",
                    "logical_interface_resource_id": "node-c/PORT/0",
                    "addresses": ["172.20.0.13/24"],
                },
                confidence_score=1.0,
                evidence=[{"kind": "interface_address", "value": "172.20.0.13/24"}],
            ),
            _segment_claim(
                "node-c/LOOPBACK/100",
                "loopback:global:10.0.0.3-32",
                segment_matcher,
                plugin_semantics=loopback_segment("PE-C service loopback", "10.0.0.3/32"),
                attachment_model={
                    "interface_kind": "loopback",
                    "logical_interface_resource_id": "node-c/LOOPBACK/100",
                    "addresses": ["10.0.0.3/32"],
                },
                confidence_score=1.0,
                evidence=[{"kind": "loopback_address", "value": "10.0.0.3/32"}],
            ),
        ],
        watermark_lag_ns=41_000_000,
    )
    node_d_underlay = pe_underlay_projection(
        {
            "node_id": "node-d",
            "display": "PE-D",
            "projection_id": "zeta.fabric-links",
            "projection_label": "Zeta programmed fabric and access links",
            "perspective_id": "zeta.hardware-observed",
            "rule_prefix": "zeta",
            "loopback_id": "node-d/LOOPBACK/lo0",
            "loopback_address": "10.255.0.4/32",
            "loopback_segment_key": "loopback:global:10.255.0.4-32",
            "core_member_ids": [
                "node-d/INTERFACE/Ethernet1-1",
                "node-d/INTERFACE/Ethernet1-2",
            ],
            "core_lag_id": "node-d/LAG/Port-Channel10",
            "subif_101_id": "node-d/SUBINTERFACE/Port-Channel10.101",
            "subif_102_id": "node-d/SUBINTERFACE/Port-Channel10.102",
            "address_101": "192.0.2.5/29",
            "address_102": "192.0.2.12/29",
            "boundary_keys": ["underlay:circuit-301", "underlay:circuit-302"],
            "access_member_ids": [
                "node-d/INTERFACE/Ethernet1-10",
                "node-d/INTERFACE/Ethernet1-11",
            ],
            "access_lag_id": "node-d/LAG/Port-Channel310",
            "access_subif_id": "node-d/SUBINTERFACE/Port-Channel310.310",
            "access_vlan": 310,
            "access_segment_key": "access:blue:esi-west:vlan-310",
            "access_semantics": access_west_segment,
            "access_connector_keys": [
                "access:west:node-d:member-1",
                "access:west:node-d:member-2",
            ],
            "esi": "0000:0000:0000:0000:0001",
            "management_id": "node-d/INTERFACE/Management0",
            "management_address": "172.20.0.14/24",
            "watermark_lag_ns": 31_000_000,
        }
    )
    node_d_evpn = pe_evpn_projection(
        {
            "node_id": "node-d",
            "display": "PE-D",
            "site": "west",
            "vtep_id": "node-d/VTEP/10.0.0.4",
            "es_id": "node-d/ETHERNET_SEGMENT/esi-west",
            "red_vrf_id": "node-d/VRF/red",
            "esi": "0000:0000:0000:0000:0001",
            "redundancy_mode": "all_active",
            "es_segment_key": "vpn:blue:esi-west",
            "es_semantics": vpn_es_west_segment,
            "es_changes": [
                {"time_ns": failure_ns + 70_000_000, "status": "withdrawn"},
                {"time_ns": restore_ns + 120_000_000, "status": "active"},
            ],
            "watermark_lag_ns": 43_000_000,
        }
    )
    node_e_underlay = pe_underlay_projection(
        {
            "node_id": "node-e",
            "display": "PE-E",
            "projection_id": "eta.border-links",
            "projection_label": "Eta border forwarding and access links",
            "perspective_id": "eta.forwarding-observed",
            "rule_prefix": "eta",
            "loopback_id": "node-e/LOOPBACK/lo0",
            "loopback_address": "10.255.0.5/32",
            "loopback_segment_key": "loopback:global:10.255.0.5-32",
            "core_member_ids": [
                "node-e/INTERFACE/et-0-0-0",
                "node-e/INTERFACE/et-0-0-1",
            ],
            "core_lag_id": "node-e/LAG/ae10",
            "subif_101_id": "node-e/SUBINTERFACE/ae10.101",
            "subif_102_id": "node-e/SUBINTERFACE/ae10.102",
            "address_101": "192.0.2.6/29",
            "address_102": "192.0.2.13/29",
            "boundary_keys": ["underlay:circuit-401", "underlay:circuit-402"],
            "access_member_ids": [
                "node-e/INTERFACE/et-0-0-10",
                "node-e/INTERFACE/et-0-0-11",
            ],
            "access_lag_id": "node-e/LAG/ae320",
            "access_subif_id": "node-e/SUBINTERFACE/ae320.320",
            "access_vlan": 320,
            "access_segment_key": "access:blue:esi-east:vlan-320",
            "access_semantics": access_east_segment,
            "access_connector_keys": [
                "access:east:node-e:member-1",
                "access:east:node-e:member-2",
            ],
            "esi": "0000:0000:0000:0000:0002",
            "management_id": "node-e/INTERFACE/fxp0",
            "management_address": "172.20.0.15/24",
            "external": {
                "resource_id": "node-e/INTERFACE/et-0-0-20",
                "label": "PE-E Internet handoff",
                "address": "203.0.113.1/24",
                "prefix": "203.0.113.0/24",
                "segment_key": "external:default:internet:203.0.113.0-24",
                "semantics": external_network_segment(
                    "PE-E Internet handoff", "203.0.113.0/24"
                ),
                "confidence": 0.96,
            },
            "watermark_lag_ns": 47_000_000,
        }
    )
    node_e_evpn = pe_evpn_projection(
        {
            "node_id": "node-e",
            "display": "PE-E",
            "site": "east",
            "vtep_id": "node-e/VTEP/10.0.0.5",
            "es_id": "node-e/ETHERNET_SEGMENT/esi-east",
            "red_vrf_id": "node-e/VRF/red",
            "esi": "0000:0000:0000:0000:0002",
            "redundancy_mode": "single_active",
            "es_segment_key": "vpn:blue:esi-east",
            "es_semantics": vpn_es_east_segment,
            "es_changes": [
                {"time_ns": failure_ns + 95_000_000, "status": "withdrawn"},
                {"time_ns": restore_ns + 150_000_000, "status": "active"},
            ],
            "watermark_lag_ns": 59_000_000,
        }
    )
    ce_west_projection = ce_access_projection(
        {
            "node_id": "ce-west",
            "display": "CE-West",
            "projection_id": "ce-west.access-links",
            "projection_label": "CE-West multihomed access",
            "perspective_id": "ce-west.interface-observed",
            "rule_prefix": "ce-west",
            "member_ids": [
                "ce-west/INTERFACE/Ethernet0",
                "ce-west/INTERFACE/Ethernet1",
                "ce-west/INTERFACE/Ethernet2",
                "ce-west/INTERFACE/Ethernet3",
            ],
            "connector_keys": [
                "access:west:node-a:member-1",
                "access:west:node-a:member-2",
                "access:west:node-d:member-1",
                "access:west:node-d:member-2",
            ],
            "neighbors": ["node-a", "node-a", "node-d", "node-d"],
            "lag_id": "ce-west/LAG/bond0",
            "subinterface_id": "ce-west/SUBINTERFACE/bond0.310",
            "vlan": 310,
            "access_segment_key": "access:blue:esi-west:vlan-310",
            "access_semantics": access_west_segment,
            "loopback_id": "ce-west/LOOPBACK/0",
            "loopback_address": "10.255.1.10/32",
            "loopback_segment_key": "loopback:global:10.255.1.10-32",
            "management_id": "ce-west/INTERFACE/Management0",
            "management_address": "172.20.0.31/24",
            "external_id": "ce-west/INTERFACE/Ethernet10",
            "external_address": "10.100.10.1/24",
            "external_prefix": "10.100.10.0/24",
            "external_segment_key": "external:blue:ce-west:10.100.10.0-24",
            "watermark_lag_ns": 67_000_000,
        }
    )
    ce_east_projection = ce_access_projection(
        {
            "node_id": "ce-east",
            "display": "CE-East",
            "projection_id": "ce-east.access-links",
            "projection_label": "CE-East multihomed access",
            "perspective_id": "ce-east.interface-observed",
            "rule_prefix": "ce-east",
            "member_ids": [
                "ce-east/INTERFACE/Ethernet0",
                "ce-east/INTERFACE/Ethernet1",
                "ce-east/INTERFACE/Ethernet2",
                "ce-east/INTERFACE/Ethernet3",
            ],
            "connector_keys": [
                "access:east:node-b:member-1",
                "access:east:node-b:member-2",
                "access:east:node-e:member-1",
                "access:east:node-e:member-2",
            ],
            "neighbors": ["node-b", "node-b", "node-e", "node-e"],
            "lag_id": "ce-east/LAG/bond0",
            "subinterface_id": "ce-east/SUBINTERFACE/bond0.320",
            "vlan": 320,
            "access_segment_key": "access:blue:esi-east:vlan-320",
            "access_semantics": access_east_segment,
            "loopback_id": "ce-east/LOOPBACK/0",
            "loopback_address": "10.255.1.20/32",
            "loopback_segment_key": "loopback:global:10.255.1.20-32",
            "management_id": "ce-east/INTERFACE/Management0",
            "management_address": "172.20.0.32/24",
            "external_id": "ce-east/INTERFACE/Ethernet10",
            "external_address": "10.100.20.1/24",
            "external_prefix": "10.100.20.0/24",
            "external_segment_key": "external:blue:ce-east:10.100.20.0-24",
            "watermark_lag_ns": 71_000_000,
        }
    )
    unavailable_projection = _projection(
        "delta.legacy-links",
        "Unavailable legacy discovery",
        "delta.driver-observed",
        [],
        [],
        [],
    )

    def plugin(
        plugin_id: str,
        instance_id: str,
        version: str,
        projections: list[dict[str, Any]],
        *,
        available: bool = True,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "plugin_id": plugin_id,
            "plugin_instance_id": instance_id,
            "plugin_run_id": f"run:{instance_id}:{version}",
            "version": version,
            "api_version": "1.0",
            "installed": True,
            "active": True,
            "available": available,
            "unavailable_reason": reason,
            "roles": ["resource_status", "topology_projection"],
            "projections": projections,
        }

    nodes = [
        {
            "node_id": "node-a",
            "label": "PE-A / Alpha NOS",
            "revision_id": revision_id,
            "device_family": "alpha-pe",
            "site": "toronto-west",
            "roles": ["provider_edge", "service_ingress", "evpn_leaf"],
            "available": True,
            "optional": False,
            "default_selected": True,
            "active_plugin_set_id": "node-a.alpha-evpn.v1",
            "clock": {
                "clock_domain": "node-a-data-bridge-raw",
                "local_minus_absolute_ns": -9_000_000,
                "uncertainty_ns": 5_000_000,
                "mapping_method": "synthetic_piecewise_clock_anchors",
                "mapping_quality": "best_effort",
            },
            "plugin_sets": [
                {
                    "plugin_set_id": "node-a.alpha-evpn.v1",
                    "label": "Alpha platform + common EVPN",
                    "active": True,
                    "plugins": [
                        plugin(
                            "demo.alpha.platform",
                            "node-a/alpha-platform",
                            "2.4.0",
                            [node_a_underlay],
                        ),
                        plugin(
                            "demo.evpn.control",
                            "node-a/evpn-control",
                            "1.3.0",
                            [node_a_evpn],
                        ),
                    ],
                }
            ],
        },
        {
            "node_id": "node-b",
            "label": "PE-B / Beta NOS",
            "revision_id": "synthetic-node-b-revision",
            "device_family": "beta-pe",
            "site": "montreal-east",
            "roles": ["provider_edge", "service_egress", "evpn_leaf"],
            "available": True,
            "optional": False,
            "default_selected": True,
            "active_plugin_set_id": "node-b.beta-evpn.v2",
            "clock": {
                "clock_domain": "node-b-driver-raw",
                "local_minus_absolute_ns": -50_000_000,
                "uncertainty_ns": 9_000_000,
                "mapping_method": "synthetic_ntp_anchor_interpolation",
                "mapping_quality": "best_effort",
            },
            "plugin_sets": [
                {
                    "plugin_set_id": "node-b.beta-evpn.v2",
                    "label": "Beta route DB + EVPN compatibility adapter",
                    "active": True,
                    "plugins": [
                        plugin(
                            "demo.beta.forwarding",
                            "node-b/beta-forwarding",
                            "5.1.2",
                            [node_b_underlay],
                        ),
                        plugin(
                            "demo.evpn.control",
                            "node-b/evpn-control",
                            "1.2.7",
                            [node_b_evpn],
                        ),
                    ],
                }
            ],
        },
        {
            "node_id": "node-d",
            "label": "PE-D / Zeta EVPN NOS",
            "revision_id": "synthetic-node-d-revision",
            "device_family": "zeta-evpn-pe",
            "site": "toronto-west",
            "roles": [
                "provider_edge",
                "service_ingress",
                "evpn_leaf",
                "mpls_endpoint",
            ],
            "available": True,
            "optional": False,
            "default_selected": True,
            "active_plugin_set_id": "node-d.zeta-evpn.v1",
            "clock": {
                "clock_domain": "node-d-forwarding-raw",
                "local_minus_absolute_ns": -14_000_000,
                "uncertainty_ns": 6_000_000,
                "mapping_method": "synthetic_ptp_anchor_interpolation",
                "mapping_quality": "best_effort",
            },
            "plugin_sets": [
                {
                    "plugin_set_id": "node-d.zeta-evpn.v1",
                    "label": "Zeta fabric + common EVPN",
                    "active": True,
                    "plugins": [
                        plugin(
                            "demo.zeta.fabric",
                            "node-d/zeta-fabric",
                            "6.2.1",
                            [node_d_underlay],
                        ),
                        plugin(
                            "demo.evpn.control",
                            "node-d/evpn-control",
                            "1.4.0",
                            [node_d_evpn],
                        ),
                    ],
                }
            ],
        },
        {
            "node_id": "node-e",
            "label": "PE-E / Eta border NOS",
            "revision_id": "synthetic-node-e-revision",
            "device_family": "eta-border-pe",
            "site": "montreal-east",
            "roles": [
                "provider_edge",
                "service_egress",
                "evpn_leaf",
                "srv6_endpoint",
                "internet_border",
            ],
            "available": True,
            "optional": False,
            "default_selected": True,
            "active_plugin_set_id": "node-e.eta-evpn.v1",
            "clock": {
                "clock_domain": "node-e-border-raw",
                "local_minus_absolute_ns": 24_000_000,
                "uncertainty_ns": 8_000_000,
                "mapping_method": "synthetic_ntp_anchor_interpolation",
                "mapping_quality": "best_effort",
            },
            "plugin_sets": [
                {
                    "plugin_set_id": "node-e.eta-evpn.v1",
                    "label": "Eta border forwarding + common EVPN",
                    "active": True,
                    "plugins": [
                        plugin(
                            "demo.eta.border",
                            "node-e/eta-border",
                            "8.3.2",
                            [node_e_underlay],
                        ),
                        plugin(
                            "demo.evpn.control",
                            "node-e/evpn-control",
                            "1.4.0",
                            [node_e_evpn],
                        ),
                    ],
                }
            ],
        },
        {
            "node_id": "transit-p-1",
            "label": "P1 / Gamma routing daemon",
            "revision_id": "synthetic-transit-p-1-revision",
            "device_family": "gamma-p-router",
            "site": "core-west",
            "roles": ["core_transit", "mpls_lsr"],
            "available": True,
            "optional": False,
            "default_selected": True,
            "active_plugin_set_id": "transit-p-1.gamma.v1",
            "clock": {
                "clock_domain": "transit-p-1-routing-raw",
                "local_minus_absolute_ns": 33_000_000,
                "uncertainty_ns": 3_000_000,
                "mapping_method": "synthetic_ptp_anchor_interpolation",
                "mapping_quality": "best_effort",
            },
            "plugin_sets": [
                {
                    "plugin_set_id": "transit-p-1.gamma.v1",
                    "label": "Gamma protocol state",
                    "active": True,
                    "plugins": [
                        plugin(
                            "demo.gamma.isis",
                            "transit-p-1/gamma-isis",
                            "3.0.1",
                            [transit],
                        )
                    ],
                }
            ],
        },
        {
            "node_id": "transit-p-2",
            "label": "P2 / Delta SR routing stack",
            "revision_id": "synthetic-transit-p-2-revision",
            "device_family": "delta-sr-p-router",
            "site": "core-east",
            "roles": ["core_transit", "segment_routing"],
            "available": True,
            "optional": False,
            "default_selected": True,
            "active_plugin_set_id": "transit-p-2.delta-sr.v1",
            "clock": {
                "clock_domain": "transit-p-2-sr-raw",
                "local_minus_absolute_ns": 17_000_000,
                "uncertainty_ns": 4_000_000,
                "mapping_method": "synthetic_ptp_anchor_interpolation",
                "mapping_quality": "best_effort",
            },
            "plugin_sets": [
                {
                    "plugin_set_id": "transit-p-2.delta-sr.v1",
                    "label": "Delta SR-aware protocol state",
                    "active": True,
                    "plugins": [
                        plugin(
                            "demo.delta.sr-isis",
                            "transit-p-2/delta-sr-isis",
                            "4.2.0",
                            [transit_p2],
                        )
                    ],
                }
            ],
        },
        {
            "node_id": "node-c",
            "label": "PE-C / Epsilon edge NOS",
            "revision_id": "synthetic-node-c-revision",
            "device_family": "epsilon-service-edge",
            "site": "ottawa-edge",
            "roles": ["provider_edge", "service_termination", "srv6_endpoint"],
            "available": True,
            "optional": False,
            "default_selected": True,
            "active_plugin_set_id": "node-c.epsilon-edge.v1",
            "clock": {
                "clock_domain": "node-c-forwarding-raw",
                "local_minus_absolute_ns": -21_000_000,
                "uncertainty_ns": 7_000_000,
                "mapping_method": "synthetic_ntp_anchor_interpolation",
                "mapping_quality": "best_effort",
            },
            "plugin_sets": [
                {
                    "plugin_set_id": "node-c.epsilon-edge.v1",
                    "label": "Epsilon forwarding adapter",
                    "active": True,
                    "plugins": [
                        plugin(
                            "demo.epsilon.forwarding",
                            "node-c/epsilon-forwarding",
                            "7.0.3",
                            [node_c_underlay],
                        )
                    ],
                }
            ],
        },
        {
            "node_id": "ce-west",
            "label": "CE-West / dual-homed customer edge",
            "revision_id": "synthetic-ce-west-revision",
            "device_family": "generic-customer-edge",
            "site": "toronto-west-access",
            "roles": ["customer_edge", "evpn_multihomed_endpoint"],
            "available": True,
            "optional": False,
            "default_selected": True,
            "active_plugin_set_id": "ce-west.access.v1",
            "clock": {
                "clock_domain": "ce-west-interface-raw",
                "local_minus_absolute_ns": -32_000_000,
                "uncertainty_ns": 12_000_000,
                "mapping_method": "synthetic_ntp_anchor_interpolation",
                "mapping_quality": "best_effort",
            },
            "plugin_sets": [
                {
                    "plugin_set_id": "ce-west.access.v1",
                    "label": "CE-West interface and LACP state",
                    "active": True,
                    "plugins": [
                        plugin(
                            "demo.ce-west.access",
                            "ce-west/access",
                            "1.0.0",
                            [ce_west_projection],
                        )
                    ],
                }
            ],
        },
        {
            "node_id": "ce-east",
            "label": "CE-East / dual-homed customer edge",
            "revision_id": "synthetic-ce-east-revision",
            "device_family": "generic-customer-edge",
            "site": "montreal-east-access",
            "roles": ["customer_edge", "evpn_multihomed_endpoint"],
            "available": True,
            "optional": False,
            "default_selected": True,
            "active_plugin_set_id": "ce-east.access.v1",
            "clock": {
                "clock_domain": "ce-east-interface-raw",
                "local_minus_absolute_ns": 41_000_000,
                "uncertainty_ns": 14_000_000,
                "mapping_method": "synthetic_ntp_anchor_interpolation",
                "mapping_quality": "best_effort",
            },
            "plugin_sets": [
                {
                    "plugin_set_id": "ce-east.access.v1",
                    "label": "CE-East interface and LACP state",
                    "active": True,
                    "plugins": [
                        plugin(
                            "demo.ce-east.access",
                            "ce-east/access",
                            "1.0.0",
                            [ce_east_projection],
                        )
                    ],
                }
            ],
        },
        {
            "node_id": "edge-c",
            "label": "Edge-C / unavailable optional capture",
            "revision_id": "synthetic-edge-c-revision",
            "device_family": "delta-legacy-edge",
            "site": "lab-legacy",
            "roles": ["optional_legacy_edge"],
            "available": False,
            "optional": True,
            "default_selected": False,
            "unavailable_reason": "analysis_revision_not_loaded",
            "active_plugin_set_id": "edge-c.delta.v1",
            "clock": None,
            "plugin_sets": [
                {
                    "plugin_set_id": "edge-c.delta.v1",
                    "label": "Delta legacy adapter (load failed)",
                    "active": True,
                    "plugins": [
                        plugin(
                            "demo.delta.legacy",
                            "edge-c/delta-legacy",
                            "0.9.4",
                            [unavailable_projection],
                            available=False,
                            reason="plugin_dependency_unavailable",
                        )
                    ],
                }
            ],
        },
    ]
    for node in nodes:
        node["member_id"] = f"member:{node['node_id']}"
    federation_plugin = {
        "plugin_id": "demo.fabric.federation-linker",
        "plugin_instance_id": "assembly/demo-fabric-linker",
        "plugin_run_id": "run:assembly:demo-fabric-linker:v1",
        "plugin_version": "1.0.0",
        "api_version": "1.0",
        "role": "inter_node_connector_resolution",
    }
    return {
        "nodes": nodes,
        "federation_plugin": federation_plugin,
        "inter_node_matchers": [
            {
                "matcher_id": connector_matcher,
                "owner_plugin_id": "demo.gamma.isis",
                "description": (
                    "Exact opaque connector-key equality emitted by device plug-ins."
                ),
                "combination_policy": "all_claims_usable",
            },
            {
                "matcher_id": overlay_matcher,
                "owner_plugin_id": "demo.evpn.control",
                "description": "Exact EVPN peer-key equality emitted by the EVPN plug-in.",
                "combination_policy": "all_claims_usable",
            },
        ],
        "network_segment_matchers": [
            {
                "matcher_id": segment_matcher,
                "contract_version": "1.0",
                "match_semantics": "exact_token",
                "result_shape": "connectivity_domain",
                "owner_plugin_id": "demo.fabric.federation-linker",
                "description": (
                    "Exact equality of a plug-in-declared opaque connectivity-domain "
                    "key. Prefixes, VLANs, VRFs, labels, and resource kinds are never "
                    "used as implicit federation keys."
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
                "status_combination_policy": "all_existing_attachments_usable",
                "external_classification_policy": (
                    "plugin_role_external_and_complete_projection_coverage"
                ),
            }
        ],
    }
