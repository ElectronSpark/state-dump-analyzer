"""Generic cross-node route tracing over injected normalized projections.

Node plug-ins provide local route-resolution decisions and
their explanatory strings; the federation linker provides inter-node boundary
identity.  The core aligns time, evaluates exact typed candidate constraints,
performs bounded traversal and cycle detection, orders the opaque explanatory
steps, retains every candidate, and records uncertainty or best-effort joins.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from itertools import pairwise
from typing import Any

from router_dump_analyzer.plugin_api import (
    Evidence,
    ForwardingCandidateConstraint,
    ForwardingPacketLayer,
    ForwardingPacketState,
    ForwardingPacketTransition,
    ForwardingPolicyScope,
    ForwardingPolicyVerdict,
    ForwardingTraversalStateKey,
    KeyAtom,
    ResourceKey,
    StatusPerspectiveRef,
    TopologyEndpointReference,
)
from router_dump_analyzer.route_trace_core import (
    EndpointReachabilityPairEvaluation,
    ForwardingPacketTraceEvaluation,
    ForwardingPacketTransitionEvaluation,
    ForwardingPolicyEvaluation,
    RouteTraceContractError,
    evaluate_endpoint_reachability_pair,
    evaluate_forwarding_packet_trace,
    evaluate_forwarding_policy,
    evaluate_forwarding_traversal,
)
from router_dump_analyzer.topology_core import (
    resolve_connectivity_domain_reference,
)
from router_dump_analyzer.value_core import parse_decimal_integer

from .canonical import CanonicalValueError, packet_value_json
from .multi_node_topology import (
    MultiNodeTopologyRequestError,
    MultiNodeTopologyService,
)


class MultiNodeRouteRequestError(MultiNodeTopologyRequestError):
    """A route-trace request cannot be executed by the advertised resolvers."""


PacketTransitionBuilder = Callable[..., tuple[Any, list[Any]]]


@dataclass(frozen=True)
class RouteProjectionSet:
    """Normalized node projections and coverage supplied by a plug-in."""

    projections_by_node: Mapping[str, Mapping[str, Any]]
    revision_ids_by_node: Mapping[str, str]
    coverage: Mapping[str, Any]


@dataclass(frozen=True)
class RouteServicePolicy:
    """Plug-in-owned semantics consumed by the generic route coordinator."""

    scenarios: Mapping[str, dict[str, Any]]
    default_scenario_id: str
    steering_profiles: tuple[dict[str, Any], ...]
    packet_transition_builder: PacketTransitionBuilder
    endpoint_profiles: Mapping[str, Mapping[str, Any]]
    route_type_profiles: Mapping[str, Mapping[str, Any]]
    route_family_presentations: Mapping[str, Mapping[str, Any]]
    vrf_aliases: Mapping[str, str]
    router_value_aliases: Mapping[str, str]
    route_table_schema_version: str
    packet_trace_schema_version: str
    node_matcher_id: str
    topology_link_matcher_id: str
    connectivity_domain_matcher_id: str
    data_disclosure: str = ""


class MultiNodeRouteService:
    """Compose plug-in-owned local decisions into bounded cross-node paths."""

    MAX_CANDIDATE_PATHS = 64
    MAX_SEGMENTS_PER_PATH = 128

    def __init__(
        self,
        topology: MultiNodeTopologyService,
        *,
        projections: RouteProjectionSet,
        policy: RouteServicePolicy,
    ) -> None:
        self.topology = topology
        self.policy = policy
        if policy.default_scenario_id not in policy.scenarios:
            raise MultiNodeRouteRequestError(
                "route policy default_scenario_id is not declared"
            )
        invalid_scenario_keys = [
            scenario_id
            for scenario_id, scenario in policy.scenarios.items()
            if scenario.get("scenario_id") != scenario_id
        ]
        if invalid_scenario_keys:
            raise MultiNodeRouteRequestError(
                "route policy scenario keys must match scenario_id: "
                + ", ".join(sorted(invalid_scenario_keys))
            )
        self._route_table_contexts: dict[str, dict[str, Any]] = {}
        self._generated_route_rows: list[dict[str, Any]] = []
        self._generated_forwarding_rows: list[dict[str, Any]] = []
        self._generated_packet_cases: list[dict[str, Any]] = []
        self._generated_coverage_by_id: dict[str, dict[str, Any]] = {}
        self._generated_coverage_registry_id: str | None = None
        self._generated_revision_by_node: dict[str, str] = {}
        self._generated_provider_by_node: dict[str, dict[str, Any]] = {}
        self._generated_resource_owner_by_id: dict[str, str] = {}
        for node_id, raw_projection in projections.projections_by_node.items():
            if node_id not in topology.nodes_by_id:
                raise MultiNodeRouteRequestError(
                    f"route projection names unknown topology node: {node_id}"
                )
            revision_id = projections.revision_ids_by_node.get(node_id)
            if not isinstance(revision_id, str) or not revision_id:
                raise MultiNodeRouteRequestError(
                    f"route projection lacks a revision ID for {node_id}"
                )
            projection = dict(raw_projection)
            manifest = projection.get("manifest", {})
            if not isinstance(manifest, dict):
                raise MultiNodeRouteRequestError(
                    f"route projection for {node_id} "
                    "lacks its plug-in manifest"
                )
            node_descriptor = topology.nodes_by_id.get(
                node_id,
                {},
            )
            plugin_descriptors = [
                plugin
                for plugin_set in node_descriptor.get("plugin_sets", [])
                if isinstance(plugin_set, dict)
                for plugin in plugin_set.get("plugins", [])
                if isinstance(plugin, dict)
                and plugin.get("plugin_id") == manifest.get("plugin_id")
            ]
            plugin_descriptor = (
                plugin_descriptors[0] if plugin_descriptors else {}
            )
            projection_descriptors = [
                projection
                for projection in plugin_descriptor.get("projections", [])
                if isinstance(projection, dict)
            ]
            projection_descriptor = (
                projection_descriptors[0]
                if projection_descriptors
                else {}
            )
            self._generated_revision_by_node[node_id] = revision_id
            self._generated_provider_by_node[node_id] = {
                key: manifest[key]
                for key in (
                    "plugin_id",
                    "plugin_version",
                    "projection_policy_id",
                    "semantic_owner",
                )
                if manifest.get(key) is not None
            } | {
                "node_id": node_id,
                "revision_id": revision_id,
                "data_source": "plugin_projection",
                "plugin_instance_id": plugin_descriptor.get(
                    "plugin_instance_id"
                ),
                "plugin_run_id": plugin_descriptor.get("plugin_run_id"),
                "status_perspective_id": projection_descriptor.get(
                    "default_status_perspective_id"
                ),
            }
            route_rows = [
                dict(item) for item in projection.get("routes", [])
            ]
            forwarding_rows = [
                dict(item) for item in projection.get("forwarding", [])
            ]
            self._generated_route_rows.extend(route_rows)
            self._generated_forwarding_rows.extend(forwarding_rows)
            topology_projection = projection.get("topology", {})
            topology_resources = (
                topology_projection.get("resources", [])
                if isinstance(topology_projection, dict)
                else []
            )
            # Ownership comes from the generated resource inventory.  Route
            # evidence is intentionally allowed to reference resources owned
            # by another node, so treating every evidence id as a local
            # ownership claim makes valid cross-node continuation rows
            # conflict with their real owner.
            owned_resource_ids = {
                str(item["resource_id"])
                for item in topology_resources
                if isinstance(item, dict) and item.get("resource_id")
            }
            # A route row is emitted in the owning node projection and its
            # evidence ids identify that node's independent resource records.
            # Forwarding continuation rows are different: they describe a
            # path and may cite evidence from any visited node, so they must
            # remain references rather than ownership claims.
            owned_resource_ids.update(
                str(resource_id)
                for row in route_rows
                if row.get("node_id") == node_id
                for resource_id in row.get("evidence_resource_ids", [])
                if resource_id
            )
            for resource_id in owned_resource_ids:
                previous_owner = self._generated_resource_owner_by_id.get(
                    resource_id
                )
                if (
                    previous_owner is not None
                    and previous_owner != node_id
                ):
                    raise MultiNodeRouteRequestError(
                        "resource identity is claimed by multiple "
                        f"nodes: {resource_id}"
                    )
                self._generated_resource_owner_by_id[resource_id] = (
                    node_id
                )
            packet_payload = projection.get("packet_cases", {})
            if isinstance(packet_payload, dict):
                self._generated_packet_cases.extend(
                    {
                        **dict(item),
                        "_projection_node_id": node_id,
                        "_projection_revision_id": revision_id,
                        "_projection_semantic_owner": packet_payload.get(
                            "semantic_owner"
                        ),
                    }
                    for item in packet_payload.get("cases", [])
                    if isinstance(item, dict)
                )
        coverage = projections.coverage
        if isinstance(coverage, dict):
            self._generated_coverage_registry_id = str(
                coverage.get("registry_id") or ""
            )
            self._generated_coverage_by_id = {
                str(item["case_id"]): dict(item)
                for item in coverage.get("cases", [])
                if isinstance(item, dict) and item.get("case_id")
            }
        self._advertised_scenarios = self._generated_scenario_descriptors()
        self._advertised_scenario_by_id = {
            str(item["scenario_id"]): item
            for item in self._advertised_scenarios
        }
        self._route_types = self._generated_route_type_descriptors()
        self._route_families = self._generated_route_family_descriptors()
        self._vrfs = self._generated_vrf_descriptors()
        self._routers_by_id = self._generated_router_descriptors()
        self._routers = tuple(self._routers_by_id.values())
        executor_ids = {
            str(item["scenario_id"])
            for item in self.policy.scenarios.values()
        }
        unsupported = (
            self._advertised_scenario_by_id.keys() - executor_ids
        )
        if unsupported:
            raise MultiNodeRouteRequestError(
                "the projection set advertises route scenarios without "
                "an installed plug-in executor: "
                + ", ".join(sorted(unsupported))
            )
        if (
            self.policy.default_scenario_id
            not in self._advertised_scenario_by_id
        ):
            raise MultiNodeRouteRequestError(
                "route policy default scenario is not advertised by the "
                "projection set"
            )

    @staticmethod
    def _public_generated_projection_row(
        row: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            key: value
            for key, value in row.items()
            if not str(key).startswith("_projection_")
        }

    def _generated_scenario_descriptors(
        self,
    ) -> tuple[dict[str, Any], ...]:
        """Project advertised scenarios solely from generated coverage."""

        descriptors: list[dict[str, Any]] = []
        for case in self._generated_coverage_by_id.values():
            required_capabilities = [
                str(item)
                for item in case.get("required_capabilities", [])
                if item
            ]
            if (
                "route_resolution" not in required_capabilities
                or case.get("generated") is not True
            ):
                continue
            source = (
                dict(case["source"])
                if isinstance(case.get("source"), dict)
                else {}
            )
            destination = (
                dict(case["destination"])
                if isinstance(case.get("destination"), dict)
                else {}
            )
            candidate_paths = [
                item
                for item in case.get("candidate_paths", [])
                if isinstance(item, dict)
            ]
            active_forward = [
                item
                for item in candidate_paths
                if item.get("direction") == "forward"
                and item.get("selected_active") is True
                and isinstance(item.get("node_sequence"), list)
                and item["node_sequence"]
            ]
            trace_start_nodes = {
                str(item["node_sequence"][0]) for item in active_forward
            }
            # Flow endpoint identity comes from the generated coverage
            # declaration. Candidate paths may intentionally terminate early,
            # repeat a node, or select another multihomed attachment.
            source_node = str(source.get("node_id") or "")
            destination_node = str(destination.get("node_id") or "")
            trace_start_node = (
                next(iter(trace_start_nodes))
                if len(trace_start_nodes) == 1
                else source_node
            )
            if source_node:
                if str(source.get("node_id") or "") != source_node:
                    source["endpoint_id"] = f"source:{source_node}"
                source["node_id"] = source_node
                source.setdefault("endpoint_id", f"source:{source_node}")
            if destination_node:
                if (
                    str(destination.get("node_id") or "")
                    != destination_node
                ):
                    destination["endpoint_id"] = (
                        f"destination:{destination_node}"
                    )
                destination["node_id"] = destination_node
                destination.setdefault(
                    "endpoint_id",
                    f"destination:{destination_node}",
                )
            scenario_id = str(case["case_id"])
            semantics = self.policy.scenarios.get(scenario_id)
            if semantics is None:
                raise MultiNodeRouteRequestError(
                    "the projection set advertises a route scenario without "
                    f"installed plug-in semantics: {scenario_id}"
                )
            canonical_context = self._scenario_routing_context(
                semantics,
                "forward",
            )
            declared_vrf = case.get("vrf") or case.get("vrf_id")
            if not isinstance(declared_vrf, str) or not declared_vrf:
                raise MultiNodeRouteRequestError(
                    "generated coverage must declare its VRF explicitly "
                    f"for {scenario_id}"
                )
            vrf = declared_vrf
            generated_context = {
                "route_type": str(case.get("route_type") or ""),
                "route_family": str(case.get("route_family") or ""),
                "address_family": str(
                    case.get("address_family") or ""
                ),
                "vrf_id": vrf,
            }
            if generated_context != canonical_context:
                raise MultiNodeRouteRequestError(
                    "generated coverage routing context disagrees with "
                    f"installed plug-in semantics for {scenario_id}"
                )
            title = str(
                semantics.get("label")
                or case.get("title")
                or scenario_id
            )
            descriptors.append(
                {
                    # Scenario behavior is declared once by the example
                    # plug-in's semantic registry. Generated coverage proves
                    # that the installed assembly has evidence for that
                    # behavior; it must not replace or narrow the semantics.
                    **dict(semantics),
                    "scenario_id": scenario_id,
                    "label": title,
                    "description": str(
                        semantics.get("description") or title
                    ),
                    "coverage_category": str(
                        case.get("category") or "route"
                    ),
                    **generated_context,
                    "vrf_id": vrf,
                    "vrf": vrf,
                    "source": source,
                    "destination": destination,
                    "default_source": source.get("endpoint_id"),
                    "default_destination": destination.get("endpoint_id"),
                    "default_start": (
                        f"start:{trace_start_node}"
                        if trace_start_node
                        else None
                    ),
                    "involved_node_ids": [
                        str(item)
                        for item in case.get("involved_nodes", [])
                        if item
                    ],
                    "expected_outcome": case.get("expected_outcome"),
                    "required_capabilities": required_capabilities,
                    "packet_profile_id": case.get("packet_profile_id"),
                    "coverage_registry_id": (
                        self._generated_coverage_registry_id
                    ),
                    "descriptor_source": "generated_coverage_registry",
                }
            )
        if not descriptors:
            raise MultiNodeRouteRequestError(
                "the projection set advertises no executable route scenarios"
            )
        return tuple(descriptors)

    def _generated_projection_for_scenario(
        self,
        scenario_id: str,
        direction: str,
        *,
        resolution_mode: str,
        steering_profile_id: str,
    ) -> dict[str, Any] | None:
        """Validate and select the plug-in projection for one coverage case.

        The assembly must prove that every involved node emitted a
        contemporaneous route and forwarding decision before the coordinator
        executes that scenario.
        """

        coverage = self._generated_coverage_by_id.get(scenario_id)
        if coverage is None:
            raise MultiNodeRouteRequestError(
                f"the projection set lacks coverage case {scenario_id}"
            )
        if coverage.get("generated") is not True:
            missing = ", ".join(
                str(item) for item in coverage.get("missing_nodes", [])
            )
            raise MultiNodeRouteRequestError(
                f"generated coverage case {scenario_id} is incomplete"
                + (f"; missing nodes: {missing}" if missing else "")
            )
        candidate_paths = coverage.get("candidate_paths")
        if (
            not isinstance(candidate_paths, list)
            or not candidate_paths
            or any(not isinstance(item, dict) for item in candidate_paths)
        ):
            raise MultiNodeRouteRequestError(
                f"generated coverage case {scenario_id} lacks candidate_paths"
            )
        candidates_by_id: dict[str, dict[str, Any]] = {}
        paths_by_id: dict[str, dict[str, Any]] = {}
        for candidate in candidate_paths:
            candidate_id = candidate.get("candidate_id")
            path_id = candidate.get("path_id")
            node_sequence = candidate.get("node_sequence")
            if (
                not isinstance(candidate_id, str)
                or not candidate_id
                or candidate_id in candidates_by_id
                or not isinstance(path_id, str)
                or not path_id
                or path_id in paths_by_id
                or candidate.get("direction") not in {"forward", "reverse"}
                or not isinstance(node_sequence, list)
                or not node_sequence
                or any(
                    not isinstance(node_id, str) or not node_id
                    for node_id in node_sequence
                )
                or not isinstance(candidate.get("selected_active"), bool)
                or not isinstance(candidate.get("primary"), bool)
                or not isinstance(
                    candidate.get("alternative_state"),
                    str,
                )
                or (
                    candidate.get("steering_profile_id") is not None
                    and (
                        not isinstance(
                            candidate["steering_profile_id"],
                            str,
                        )
                        or not candidate["steering_profile_id"]
                    )
                )
                or (
                    candidate.get("resolution_modes") is not None
                    and (
                        not isinstance(
                            candidate["resolution_modes"],
                            list,
                        )
                        or not candidate["resolution_modes"]
                        or any(
                            mode not in {"strict", "best_effort"}
                            for mode in candidate["resolution_modes"]
                        )
                    )
                )
            ):
                raise MultiNodeRouteRequestError(
                    f"generated coverage case {scenario_id} has an invalid "
                    "candidate path declaration"
                )
            candidates_by_id[candidate_id] = candidate
            paths_by_id[path_id] = candidate
        mode_compatible_paths = [
            dict(item)
            for item in candidate_paths
            if item["direction"] == direction
            and (
                not item.get("resolution_modes")
                or resolution_mode in item["resolution_modes"]
            )
        ]
        exact_steering_paths = [
            item
            for item in mode_compatible_paths
            if item.get("steering_profile_id") == steering_profile_id
        ]
        unscoped_paths = [
            item
            for item in mode_compatible_paths
            if item.get("steering_profile_id") is None
        ]
        if steering_profile_id == "observed":
            directional_paths = [
                *unscoped_paths,
                *exact_steering_paths,
            ]
        elif exact_steering_paths:
            # An exact declaration overrides the observed route geometry. Any
            # unscoped declaration remains applicable to every steering mode.
            directional_paths = [
                *unscoped_paths,
                *exact_steering_paths,
            ]
        else:
            # Some steering rules change only packet state (for example an
            # extra wrapper) and deliberately leave route geometry untouched.
            # Reuse the explicitly observed geometry when the plug-in did not
            # declare a path override for the requested profile.
            directional_paths = [
                *unscoped_paths,
                *(
                    item
                    for item in mode_compatible_paths
                    if item.get("steering_profile_id") == "observed"
                ),
            ]
        if not directional_paths:
            raise MultiNodeRouteRequestError(
                f"generated coverage case {scenario_id} has no "
                f"{direction} candidate paths"
            )
        if len(directional_paths) > self.MAX_CANDIDATE_PATHS:
            raise MultiNodeRouteRequestError(
                f"generated coverage case {scenario_id} exceeds the "
                f"{self.MAX_CANDIDATE_PATHS}-candidate trace limit"
            )
        if any(
            2 * len(item["node_sequence"]) - 1
            > self.MAX_SEGMENTS_PER_PATH
            for item in directional_paths
        ):
            raise MultiNodeRouteRequestError(
                f"generated coverage case {scenario_id} exceeds the "
                f"{self.MAX_SEGMENTS_PER_PATH}-segment path limit"
            )
        involved_nodes = coverage.get("involved_nodes")
        if (
            not isinstance(involved_nodes, list)
            or not involved_nodes
            or any(
                not isinstance(node_id, str) or not node_id
                for node_id in involved_nodes
            )
            or len(set(involved_nodes)) != len(involved_nodes)
        ):
            raise MultiNodeRouteRequestError(
                f"generated coverage case {scenario_id} has invalid involved_nodes"
            )
        evidence_refs = coverage.get("evidence_refs")
        if not isinstance(evidence_refs, list):
            raise MultiNodeRouteRequestError(
                f"generated coverage case {scenario_id} has invalid evidence_refs"
            )
        expected_projection_nodes = list(
            dict.fromkeys(
                str(item["node_id"])
                for item in evidence_refs
                if isinstance(item, dict)
                and isinstance(item.get("node_id"), str)
                and item["node_id"]
            )
        )
        if not expected_projection_nodes:
            raise MultiNodeRouteRequestError(
                f"generated coverage case {scenario_id} declares no evidence nodes"
            )
        if any(
            node_id not in involved_nodes
            for node_id in expected_projection_nodes
        ):
            raise MultiNodeRouteRequestError(
                f"generated coverage case {scenario_id} has evidence outside "
                "its involved_nodes"
            )

        forwarding_rows: list[dict[str, Any]] = []
        for node_id in expected_projection_nodes:
            candidates = [
                row
                for row in self._generated_forwarding_rows
                if row.get("scenario_id") == scenario_id
                and row.get("node_id") == node_id
            ]
            if len(candidates) != 1:
                raise MultiNodeRouteRequestError(
                    f"generated forwarding projection for {scenario_id} "
                    "requires exactly one row from coverage evidence node "
                    f"{node_id}"
                )
            row = candidates[0]
            expected_revision = self._generated_revision_by_node.get(node_id)
            required_strings = (
                "forwarding_id",
                "revision_id",
                "route_id",
                "observed_at_ns",
                "action",
                "disposition",
            )
            if any(
                not isinstance(row.get(field), str) or not row.get(field)
                for field in required_strings
            ):
                raise MultiNodeRouteRequestError(
                    f"generated forwarding row for {scenario_id}/{node_id} "
                    "lacks required identity or decision fields"
                )
            if row["revision_id"] != expected_revision:
                raise MultiNodeRouteRequestError(
                    f"generated forwarding row for {scenario_id}/{node_id} "
                    "has the wrong revision"
                )
            if row.get("semantic_owner") != "plugin":
                raise MultiNodeRouteRequestError(
                    f"generated forwarding row for {scenario_id}/{node_id} "
                    "must be owned by the node plugin"
                )
            next_nodes = row.get("next_nodes")
            next_hops = row.get("next_hops")
            directional_decisions = row.get("directional_decisions")
            evidence_ids = row.get("evidence_resource_ids")
            if (
                not isinstance(next_nodes, list)
                or any(
                    not isinstance(candidate, str) or not candidate
                    for candidate in next_nodes
                )
                or len(set(next_nodes)) != len(next_nodes)
            ):
                raise MultiNodeRouteRequestError(
                    f"generated forwarding row for {scenario_id}/{node_id} "
                    "has invalid next_nodes"
                )
            if (
                not isinstance(next_hops, list)
                or len(next_hops) != len(next_nodes)
                or any(not isinstance(item, dict) for item in next_hops)
                or {
                    str(item.get("node_id", ""))
                    for item in next_hops
                }
                != set(next_nodes)
            ):
                raise MultiNodeRouteRequestError(
                    f"generated forwarding row for {scenario_id}/{node_id} "
                    "has invalid next_hops"
                )
            for next_hop in next_hops:
                topology_references = next_hop.get(
                    "topology_references"
                )
                if (
                    not isinstance(
                        next_hop.get("interface_resource_id"),
                        str,
                    )
                    or not next_hop["interface_resource_id"]
                    or not isinstance(
                        next_hop.get("remote_interface_resource_id"),
                        str,
                    )
                    or not next_hop["remote_interface_resource_id"]
                    or not isinstance(topology_references, list)
                    or len(topology_references) != 1
                    or not isinstance(topology_references[0], dict)
                ):
                    raise MultiNodeRouteRequestError(
                        f"generated forwarding row for "
                        f"{scenario_id}/{node_id} has incomplete "
                        "next-hop topology evidence"
                    )
                reference = topology_references[0]
                match = reference.get("match")
                arguments = (
                    match.get("arguments")
                    if isinstance(match, dict)
                    else None
                )
                if (
                    reference.get("reference_kind")
                    != "connectivity_domain"
                    or not isinstance(match, dict)
                    or not isinstance(match.get("matcher_id"), str)
                    or not match["matcher_id"]
                    or not isinstance(arguments, dict)
                    or "segment_key" not in arguments
                ):
                    raise MultiNodeRouteRequestError(
                        f"generated forwarding row for "
                        f"{scenario_id}/{node_id} has an invalid "
                        "exact topology reference"
                    )
            if (
                not isinstance(directional_decisions, dict)
                or not isinstance(
                    directional_decisions.get("forward"),
                    list,
                )
                or not isinstance(
                    directional_decisions.get("reverse"),
                    list,
                )
            ):
                raise MultiNodeRouteRequestError(
                    f"generated forwarding row for {scenario_id}/{node_id} "
                    "lacks directional candidate decisions"
                )
            expected_occurrences = {
                (
                    path["candidate_id"],
                    visit_index,
                    (
                        path["node_sequence"][visit_index + 1]
                        if visit_index + 1
                        < len(path["node_sequence"])
                        else None
                    ),
                )
                for path in candidate_paths
                for visit_index, candidate_node_id in enumerate(
                    path["node_sequence"]
                )
                if candidate_node_id == node_id
            }
            actual_occurrences: set[tuple[str, int, str | None]] = set()
            for decision_direction in ("forward", "reverse"):
                for decision in directional_decisions[
                    decision_direction
                ]:
                    if not isinstance(decision, dict):
                        raise MultiNodeRouteRequestError(
                            f"generated forwarding row for "
                            f"{scenario_id}/{node_id} has a malformed "
                            "directional decision"
                        )
                    candidate_id = decision.get("candidate_id")
                    visit_index = decision.get("visit_index")
                    next_node_id = decision.get("next_node_id")
                    if (
                        not isinstance(candidate_id, str)
                        or candidate_id not in candidates_by_id
                        or not isinstance(visit_index, int)
                        or isinstance(visit_index, bool)
                        or visit_index < 0
                        or (
                            next_node_id is not None
                            and (
                                not isinstance(next_node_id, str)
                                or not next_node_id
                            )
                        )
                    ):
                        raise MultiNodeRouteRequestError(
                            f"generated forwarding row for "
                            f"{scenario_id}/{node_id} has an invalid "
                            "directional decision identity"
                        )
                    candidate_path = candidates_by_id[candidate_id]
                    sequence = candidate_path["node_sequence"]
                    expected_next_node_id = (
                        sequence[visit_index + 1]
                        if visit_index + 1 < len(sequence)
                        else None
                    )
                    if (
                        candidate_path["direction"]
                        != decision_direction
                        or visit_index >= len(sequence)
                        or sequence[visit_index] != node_id
                        or next_node_id != expected_next_node_id
                        or decision.get("selected_active")
                        != candidate_path["selected_active"]
                        or decision.get("primary")
                        != candidate_path["primary"]
                        or decision.get("alternative_state")
                        != candidate_path["alternative_state"]
                        or not isinstance(decision.get("disposition"), str)
                        or not decision["disposition"]
                        or not isinstance(
                            decision.get("resolution_text"),
                            str,
                        )
                        or not decision["resolution_text"]
                    ):
                        raise MultiNodeRouteRequestError(
                            f"generated forwarding row for "
                            f"{scenario_id}/{node_id} disagrees with its "
                            "candidate path declaration"
                        )
                    next_hop = decision.get("next_hop")
                    if (
                        next_node_id is not None
                        and next_node_id != node_id
                        and (
                            not isinstance(next_hop, dict)
                            or str(next_hop.get("node_id", ""))
                            != next_node_id
                        )
                    ):
                        raise MultiNodeRouteRequestError(
                            f"generated forwarding row for "
                            f"{scenario_id}/{node_id} does not bind its "
                            "directional next hop"
                        )
                    if next_node_id is None or next_node_id == node_id:
                        if next_hop is not None:
                            raise MultiNodeRouteRequestError(
                                f"generated forwarding row for "
                                f"{scenario_id}/{node_id} declares a "
                                "topology hop for a local or terminal step"
                            )
                    else:
                        topology_references = next_hop.get(
                            "topology_references"
                        )
                        reference = (
                            topology_references[0]
                            if isinstance(topology_references, list)
                            and len(topology_references) == 1
                            and isinstance(
                                topology_references[0],
                                dict,
                            )
                            else None
                        )
                        match = (
                            reference.get("match")
                            if isinstance(reference, dict)
                            else None
                        )
                        arguments = (
                            match.get("arguments")
                            if isinstance(match, dict)
                            else None
                        )
                        if (
                            not isinstance(
                                next_hop.get("interface_resource_id"),
                                str,
                            )
                            or not next_hop["interface_resource_id"]
                            or not isinstance(
                                next_hop.get(
                                    "remote_interface_resource_id"
                                ),
                                str,
                            )
                            or not next_hop[
                                "remote_interface_resource_id"
                            ]
                            or not isinstance(reference, dict)
                            or reference.get("reference_kind")
                            != "connectivity_domain"
                            or not isinstance(match, dict)
                            or not isinstance(
                                match.get("matcher_id"),
                                str,
                            )
                            or not match["matcher_id"]
                            or not isinstance(arguments, dict)
                            or "segment_key" not in arguments
                        ):
                            raise MultiNodeRouteRequestError(
                                f"generated forwarding row for "
                                f"{scenario_id}/{node_id} has incomplete "
                                "directional topology evidence"
                            )
                    actual_occurrences.add(
                        (candidate_id, visit_index, next_node_id)
                    )
            if actual_occurrences != expected_occurrences:
                raise MultiNodeRouteRequestError(
                    f"generated forwarding row for {scenario_id}/{node_id} "
                    "does not cover every declared path occurrence"
                )
            if (
                not isinstance(evidence_ids, list)
                or not evidence_ids
                or any(
                    not isinstance(evidence_id, str) or not evidence_id
                    for evidence_id in evidence_ids
                )
            ):
                raise MultiNodeRouteRequestError(
                    f"generated forwarding row for {scenario_id}/{node_id} "
                    "has invalid evidence_resource_ids"
                )
            if row.get("expected_outcome") != coverage.get(
                "expected_outcome"
            ):
                raise MultiNodeRouteRequestError(
                    f"generated forwarding outcome for {scenario_id}/{node_id} "
                    "does not match coverage"
                )
            if row.get("packet_profile_id") != coverage.get(
                "packet_profile_id"
            ):
                raise MultiNodeRouteRequestError(
                    f"generated forwarding packet profile for "
                    f"{scenario_id}/{node_id} does not match coverage"
                )
            linked_routes = [
                route
                for route in self._generated_route_rows
                if route.get("scenario_id") == scenario_id
                and route.get("node_id") == node_id
            ]
            route_context = row.get("route_context")
            if not isinstance(route_context, dict):
                route_context = {}
            if (
                len(linked_routes) != 1
                or linked_routes[0].get("route_id") != row["route_id"]
                or linked_routes[0].get("revision_id") != expected_revision
                or linked_routes[0].get("route_type")
                != route_context.get(
                    "route_type",
                    coverage.get("route_type"),
                )
                or linked_routes[0].get("route_family")
                != route_context.get(
                    "route_family",
                    coverage.get("route_family"),
                )
                or linked_routes[0].get("address_family")
                != route_context.get(
                    "address_family",
                    coverage.get("address_family"),
                )
                or linked_routes[0].get("vrf")
                != route_context.get("vrf_id", coverage.get("vrf"))
                or linked_routes[0].get("semantic_owner") != "plugin"
            ):
                raise MultiNodeRouteRequestError(
                    f"generated forwarding row for {scenario_id}/{node_id} "
                    "does not reference its matching generated route decision"
                )
            forwarding_rows.append(
                self._public_generated_projection_row(row)
            )

        declared_packet_profile = coverage.get("packet_profile_id")
        packet_case: dict[str, Any] | None = None
        if declared_packet_profile is not None:
            packet_cases: list[dict[str, Any]] = []
            for node_id in expected_projection_nodes:
                candidates = [
                    item
                    for item in self._generated_packet_cases
                    if item.get("scenario_id") == scenario_id
                    and item.get("_projection_node_id") == node_id
                ]
                if len(candidates) != 1:
                    raise MultiNodeRouteRequestError(
                        f"generated packet projection for {scenario_id} "
                        "requires exactly one declaration from coverage "
                        f"evidence node {node_id}"
                    )
                candidate = candidates[0]
                if (
                    candidate.get("_projection_revision_id")
                    != self._generated_revision_by_node.get(node_id)
                ):
                    raise MultiNodeRouteRequestError(
                        f"generated packet declaration for "
                        f"{scenario_id}/{node_id} has the wrong revision"
                    )
                if candidate.get("_projection_semantic_owner") != "plugin":
                    raise MultiNodeRouteRequestError(
                        f"generated packet declaration for "
                        f"{scenario_id}/{node_id} must be owned by the node plugin"
                    )
                packet_cases.append(
                    self._public_generated_projection_row(candidate)
                )
            canonical = json.dumps(
                packet_cases[0],
                sort_keys=True,
                separators=(",", ":"),
            )
            if any(
                json.dumps(
                    candidate,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                != canonical
                for candidate in packet_cases[1:]
            ):
                raise MultiNodeRouteRequestError(
                    f"generated packet declarations disagree for {scenario_id}"
                )
            packet_case = packet_cases[0]
            initial_layers = packet_case.get("initial_layers")
            expected_actions = packet_case.get("expected_actions")
            if packet_case.get("packet_profile_id") != declared_packet_profile:
                raise MultiNodeRouteRequestError(
                    f"generated packet profile for {scenario_id} "
                    "does not match coverage"
                )
            executor_profile_id = packet_case.get("executor_profile_id")
            scenario = next(
                (
                    item
                    for item in self.policy.scenarios.values()
                    if item["scenario_id"] == scenario_id
                ),
                None,
            )
            expected_executor_profile_id = (
                str(scenario["packet_profile_id"])
                if scenario is not None
                and scenario.get("packet_profile_id") is not None
                else None
            )
            if (
                not isinstance(executor_profile_id, str)
                or not executor_profile_id
                or executor_profile_id != expected_executor_profile_id
            ):
                raise MultiNodeRouteRequestError(
                    f"generated packet executor profile for {scenario_id} "
                    "does not match the installed plug-in executor"
                )
            if (
                not isinstance(initial_layers, list)
                or not initial_layers
                or any(
                    not isinstance(layer, dict)
                    or not isinstance(layer.get("kind"), str)
                    or not layer.get("kind")
                    for layer in initial_layers
                )
            ):
                raise MultiNodeRouteRequestError(
                    f"generated packet declaration for {scenario_id} "
                    "has invalid initial_layers"
                )
            if (
                not isinstance(expected_actions, list)
                or not expected_actions
                or any(
                    not isinstance(action, str) or not action
                    for action in expected_actions
                )
            ):
                raise MultiNodeRouteRequestError(
                    f"generated packet declaration for {scenario_id} "
                    "has invalid expected_actions"
                )
            for field in ("packet_size_bytes", "egress_mtu_bytes"):
                value = packet_case.get(field)
                if value is not None and (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value <= 0
                ):
                    raise MultiNodeRouteRequestError(
                        f"generated packet declaration for {scenario_id} "
                        f"has invalid {field}"
                    )
            packet_case = {
                **packet_case,
                "declared_by_node_ids": list(expected_projection_nodes),
            }
        elif any(
            item.get("scenario_id") == scenario_id
            for item in self._generated_packet_cases
        ):
            raise MultiNodeRouteRequestError(
                f"generated scenario {scenario_id} unexpectedly declares "
                "packet evolution"
            )

        raw_findings = coverage.get("consistency_findings", [])
        if not isinstance(raw_findings, list) or any(
            not isinstance(item, dict)
            or not isinstance(item.get("finding_id"), str)
            or not item["finding_id"]
            or not isinstance(item.get("finding_type"), str)
            or not item["finding_type"]
            or not isinstance(item.get("summary"), str)
            or not item["summary"]
            or not isinstance(item.get("candidate_ids"), list)
            or not isinstance(item.get("path_ids"), list)
            or any(
                candidate_id not in candidates_by_id
                for candidate_id in item.get("candidate_ids", [])
            )
            or any(
                path_id not in paths_by_id
                for path_id in item.get("path_ids", [])
            )
            for item in raw_findings
        ):
            raise MultiNodeRouteRequestError(
                f"generated coverage case {scenario_id} has invalid "
                "consistency_findings"
            )

        return {
            "source": "generated_plugin_projection",
            "coverage_case_id": scenario_id,
            "coverage_registry_id": self._generated_coverage_registry_id,
            "involved_node_ids": list(involved_nodes),
            "evidence_node_ids": list(expected_projection_nodes),
            "expected_outcome": coverage.get("expected_outcome"),
            "candidate_paths": directional_paths,
            "forwarding_decisions": forwarding_rows,
            "consistency_findings": [
                dict(item) for item in raw_findings
            ],
            "packet_case": packet_case,
            "validation": {
                "forwarding": "validated",
                "packet": (
                    "validated" if packet_case is not None else "not_applicable"
                ),
            },
            "semantic_owner": "node_plugins",
            "selection_and_identity_validation_owner": "core",
        }

    @staticmethod
    def _generated_candidate_for_path(
        path: dict[str, Any],
        projection: dict[str, Any],
        *,
        direction: str,
    ) -> dict[str, Any]:
        node_sequence = [
            str(item) for item in path.get("node_sequence", []) if item
        ]
        candidates = [
            item
            for item in projection["candidate_paths"]
            if item.get("direction") == direction
            and item.get("node_sequence") == node_sequence
        ]
        if len(candidates) > 1:
            exact_role = [
                item
                for item in candidates
                if item.get("primary") == bool(path.get("primary"))
                and item.get("alternative_state")
                == path.get("alternative_state")
            ]
            if len(exact_role) == 1:
                candidates = exact_role
        if len(candidates) != 1:
            raise MultiNodeRouteRequestError(
                "generated route projection must declare exactly one "
                f"{direction} candidate for rendered sequence "
                f"{node_sequence}; found {len(candidates)}"
            )
        return dict(candidates[0])

    @staticmethod
    def _generated_directional_decision(
        decisions: dict[str, dict[str, Any]],
        *,
        node_id: str,
        direction: str,
        candidate_id: str,
        visit_index: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        row = decisions.get(node_id)
        if row is None:
            raise MultiNodeRouteRequestError(
                "generated route candidate has no forwarding projection "
                f"for node {node_id}"
            )
        matches = [
            item
            for item in row["directional_decisions"][direction]
            if item.get("candidate_id") == candidate_id
            and item.get("visit_index") == visit_index
        ]
        if len(matches) != 1:
            raise MultiNodeRouteRequestError(
                "generated route candidate must have exactly one "
                f"{direction} forwarding decision for {node_id} visit "
                f"{visit_index}; found {len(matches)}"
            )
        return row, dict(matches[0])

    @classmethod
    def _attach_generated_forwarding_projection(
        cls,
        paths: list[dict[str, Any]],
        projection: dict[str, Any] | None,
        *,
        direction: str,
        requested_direction: str | None = None,
        steering_profile_id: str,
    ) -> None:
        if projection is None:
            return
        decisions = {
            str(item["node_id"]): item
            for item in projection["forwarding_decisions"]
        }
        for path in paths:
            candidate = cls._generated_candidate_for_path(
                path,
                projection,
                direction=direction,
            )
            candidate_id = str(candidate["candidate_id"])
            counterfactual = steering_profile_id != "observed"
            path["generated_candidate_id"] = candidate_id
            path["generated_candidate_declaration"] = candidate
            if not counterfactual:
                path["selected_active_by_plugin"] = bool(
                    candidate["selected_active"]
                )
                path["primary"] = bool(candidate["primary"])
                path["alternative_state"] = str(
                    candidate["alternative_state"]
                )
            node_sequence = [
                str(item) for item in path.get("node_sequence", [])
            ]
            local_segments = [
                segment
                for segment in sorted(
                    path.get("segments", []),
                    key=lambda item: item["ordinal"],
                )
                if segment.get("segment_kind") == "node_resolution"
            ]
            path_evidence: list[dict[str, Any]] = []
            for index, node_id in enumerate(node_sequence):
                segment = (
                    local_segments[index]
                    if index < len(local_segments)
                    else None
                )
                if segment is not None:
                    # Node identity comes from the validated route candidate,
                    # not from parsing a resource ID. Some executor-only packet
                    # steps are intentionally outside the coverage evidence set.
                    segment["node_id"] = node_id
                    segment["node_ids"] = [node_id]
                decision, directional_decision = (
                    cls._generated_directional_decision(
                        decisions,
                        node_id=node_id,
                        direction=direction,
                        candidate_id=candidate_id,
                        visit_index=index,
                    )
                )
                next_node_id = (
                    node_sequence[index + 1]
                    if index + 1 < len(node_sequence)
                    else None
                )
                evidence = {
                    **decision,
                    "directional_scope": direction,
                    "requested_direction": (
                        requested_direction or direction
                    ),
                    "generated_candidate_id": candidate_id,
                    "visit_index": index,
                    "selected_next_node_id": next_node_id,
                    "matches_rendered_candidate": (
                        directional_decision.get("next_node_id")
                        == next_node_id
                    ),
                    "directional_decision": directional_decision,
                    "counterfactual": counterfactual,
                }
                path_evidence.append(evidence)
                if segment is None:
                    continue
                # The validated forwarding row is the node-local
                # identity/evidence for this route-resolution step.
                segment["node_id"] = node_id
                segment["node_ids"] = [node_id]
                segment["generated_forwarding_decision"] = evidence
                segment["route_resolution"][
                    "generated_forwarding_decision"
                ] = evidence
            path["generated_forwarding_decisions"] = path_evidence
            path["generated_forwarding_projection"] = {
                "coverage_case_id": projection["coverage_case_id"],
                "generated_candidate_id": candidate_id,
                "directional_scope": direction,
                "requested_direction": requested_direction or direction,
                "decision_count": len(path_evidence),
                "all_rendered_candidates_match": bool(path_evidence)
                and all(
                    item["matches_rendered_candidate"]
                    for item in path_evidence
                ),
                "counterfactual": counterfactual,
            }

    def _generated_plugin_provider(self, node_id: str) -> dict[str, Any]:
        provider = self._generated_provider_by_node.get(node_id)
        if provider is None:
            raise MultiNodeRouteRequestError(
                f"generated route projection lacks provider identity for {node_id}"
            )
        return {
            "ownership": "node_plugin",
            **provider,
        }

    def _reconcile_generated_route_evidence(
        self,
        paths: list[dict[str, Any]],
        projection: dict[str, Any] | None,
        route_evidence: dict[str, Any],
        resources: dict[str, dict[str, Any]],
        targets: dict[str, dict[str, Any]],
        *,
        direction: str,
        resolution_mode: str,
    ) -> None:
        """Bind a path skeleton to generated plug-in and topology evidence.

        Only exact plug-in forwarding declarations and the contemporaneous
        normalized topology snapshot may make a route segment complete.
        """

        if projection is None:
            return
        decisions = {
            str(item["node_id"]): item
            for item in projection["forwarding_decisions"]
        }
        for path in paths:
            candidate_id = str(path.get("generated_candidate_id") or "")
            if not candidate_id:
                raise MultiNodeRouteRequestError(
                    "generated route path lacks its validated candidate identity"
                )
            node_sequence = [
                str(item) for item in path.get("node_sequence", []) if item
            ]
            ordered_segments = sorted(
                path.get("segments", []),
                key=lambda item: item["ordinal"],
            )
            local_segments = [
                item
                for item in ordered_segments
                if item.get("segment_kind") == "node_resolution"
            ]
            boundary_segments = [
                item
                for item in ordered_segments
                if item.get("segment_kind") == "inter_node_boundary"
            ]

            for index, node_id in enumerate(node_sequence):
                if index >= len(local_segments):
                    continue
                segment = local_segments[index]
                decision, directional_decision = (
                    self._generated_directional_decision(
                        decisions,
                        node_id=node_id,
                        direction=direction,
                        candidate_id=candidate_id,
                        visit_index=index,
                    )
                )
                next_node_id = (
                    node_sequence[index + 1]
                    if index + 1 < len(node_sequence)
                    else None
                )
                next_hop = directional_decision.get("next_hop")
                matches = bool(
                    directional_decision.get("next_node_id")
                    == next_node_id
                    and (
                        next_hop is not None
                        if next_node_id is not None
                        and next_node_id != node_id
                        else next_hop is None
                    )
                )
                evidence_ids = [
                    str(item)
                    for item in decision.get(
                        "evidence_resource_ids",
                        [],
                    )
                ]
                evidence_records = [
                    resources[item]
                    for item in evidence_ids
                    if item in resources
                ]
                member_id = (
                    str(evidence_records[0]["member_id"])
                    if evidence_records
                    else f"member:{node_id}"
                )
                resource_refs = [
                    dict(item["resource_ref"])
                    for item in evidence_records
                ]
                if not resource_refs:
                    revision_id = self._generated_revision_by_node.get(
                        node_id,
                        "",
                    )
                    resource_refs = [
                        {
                            "member_id": member_id,
                            "node_id": node_id,
                            "revision_id": revision_id,
                            "local_resource_id": resource_id,
                        }
                        for resource_id in evidence_ids
                    ]
                resource_target_ids = [
                    self._resource_target(item, targets)
                    for item in evidence_records
                ]
                node_target_id = self._node_target(
                    node_id,
                    member_id,
                    targets,
                )
                provider = self._generated_plugin_provider(node_id)
                disposition = str(
                    directional_decision.get(
                        "disposition",
                        decision.get("disposition", "unresolved"),
                    )
                )
                complete = matches and disposition != "unresolved"
                segment["resource_refs"] = resource_refs
                segment["node_id"] = node_id
                segment["node_ids"] = [node_id]
                segment["member_id"] = member_id
                segment["member_ids"] = [member_id]
                segment["interaction_target_ids"] = resource_target_ids
                segment["highlight_target_ids"] = [node_target_id]
                segment["plugin_provenance"] = self._dedupe_provenance(
                    [
                        *(
                            item.get("plugin_provenance", {})
                            for item in evidence_records
                        ),
                        provider,
                    ]
                )
                text = str(
                    directional_decision.get("resolution_text")
                    or decision.get("resolution_text")
                    or "The generated node plug-in did not declare this route step."
                )
                segment["route_resolution_text"] = text
                segment["route_resolution"].update(
                    {
                        "text": text,
                        "text_source": "plugin_provided",
                        "provided_by": provider,
                        "interaction_target_ids": resource_target_ids,
                        "highlight_target_ids": [node_target_id],
                    }
                )
                segment["route_resolution"]["parts"] = [
                    {
                        "part_id": (
                            f"{segment['segment_id']}:"
                            "part:generated-decision"
                        ),
                        "text": text,
                        "interactive": True,
                        "interaction_target_ids": resource_target_ids,
                        "highlight_target_ids": [node_target_id],
                    }
                ]
                segment["completeness"] = {
                    "state": "complete" if complete else "unresolved",
                    "end_to_end_resolved": complete,
                    "observed": complete,
                }
                existing_state = segment.get("state", {})
                explicitly_terminal = bool(existing_state.get("terminal"))
                explicitly_unusable = (
                    existing_state.get("operational") == "unusable"
                )
                decision_state = str(
                    directional_decision.get("state") or "unknown"
                )
                existing_state["plugin_decision_state"] = decision_state
                existing_state["plugin_disposition"] = disposition
                plugin_reason_code = str(
                    directional_decision.get("reason_code")
                    or decision.get("reason_code")
                    or "plugin_reason_not_declared"
                )
                existing_state["reason_code"] = plugin_reason_code
                segment["generated_forwarding_state"] = {
                    "state": decision_state,
                    "disposition": disposition,
                    "reason_code": plugin_reason_code,
                    "candidate_id": candidate_id,
                    "direction": direction,
                    "visit_index": index,
                }
                terminal_dispositions = {
                    "drop": (
                        "dropped",
                        "dropped",
                        "terminal_drop",
                    ),
                    "split_horizon_block": (
                        "split_horizon_block",
                        "policy_blocked",
                        "policy_block",
                    ),
                    "loop": (
                        "forwarding_loop",
                        "cycle",
                        "forwarding_cycle",
                    ),
                    "unusable": (
                        "unusable",
                        "unusable",
                        "unusable_forwarding",
                    ),
                    "withdrawn": (
                        "withdrawn",
                        "unusable",
                        "withdrawn_candidate",
                    ),
                }
                terminal_semantics = terminal_dispositions.get(
                    disposition
                )
                if terminal_semantics is not None:
                    terminal, terminal_disposition, classification = (
                        terminal_semantics
                    )
                    existing_state.update(
                        {
                            "active": False,
                            "operational": "unusable",
                            "terminal": terminal,
                            "terminal_disposition": (
                                terminal_disposition
                            ),
                            "reason_code": plugin_reason_code,
                            "core_terminal_classification": classification,
                        }
                    )
                    segment["completeness"] = {
                        "state": "terminal_observed",
                        "end_to_end_resolved": False,
                        "observed": True,
                    }
                    explicitly_terminal = True
                    explicitly_unusable = True
                elif disposition == "best_effort_inferred":
                    segment["completeness"] = {
                        "state": "best_effort_inferred",
                        "end_to_end_resolved": True,
                        "observed": False,
                    }
                    segment["segment_kind"] = "best_effort_bridge"
                    segment["inference"] = {
                        "performed_by": "core",
                        "method": (
                            "join_topology_with_contemporaneous_"
                            "resource_status"
                        ),
                        "trigger_reason_code": plugin_reason_code,
                    }
                    segment["confidence"] = min(
                        float(segment.get("confidence", 1.0)),
                        0.62,
                    )
                elif (
                    disposition == "unresolved"
                    and resolution_mode == "best_effort"
                ):
                    complete = True
                    segment["segment_kind"] = "best_effort_bridge"
                    segment["completeness"] = {
                        "state": "best_effort_inferred",
                        "end_to_end_resolved": True,
                        "observed": False,
                    }
                    segment["inference"] = {
                        "performed_by": "core",
                        "method": (
                            "join_topology_with_contemporaneous_"
                            "resource_status"
                        ),
                        "trigger_reason_code": plugin_reason_code,
                    }
                    segment["confidence"] = min(
                        float(segment.get("confidence", 1.0)),
                        0.62,
                    )
                elif disposition == "unresolved":
                    segment["segment_kind"] = "unresolved"
                if not explicitly_terminal and not explicitly_unusable:
                    existing_state["operational"] = (
                        "usable" if complete else "unknown"
                    )
                existing_state["selected_active_by_plugin"] = bool(
                    path.get("selected_active_by_plugin")
                )
                segment["state"] = existing_state
                segment["active"] = bool(
                    path.get("selected_active_by_plugin")
                    and complete
                    and existing_state.get("operational") != "unusable"
                    and not explicitly_terminal
                )

            for index, boundary in enumerate(boundary_segments):
                if index + 1 >= len(node_sequence):
                    continue
                source_node_id = node_sequence[index]
                target_node_id = node_sequence[index + 1]
                _, directional_decision = (
                    self._generated_directional_decision(
                        decisions,
                        node_id=source_node_id,
                        direction=direction,
                        candidate_id=candidate_id,
                        visit_index=index,
                    )
                )
                next_hop = directional_decision.get("next_hop")
                boundary["topology_link_id"] = None
                if (
                    next_hop is None
                    or directional_decision.get("next_node_id")
                    != target_node_id
                ):
                    boundary["generated_connectivity_binding"] = {
                        "state": "unresolved",
                        "reason_code": (
                            "next_hop_topology_reference_not_declared"
                        ),
                        "network_segment_id": None,
                        "source_attachment_id": None,
                        "target_attachment_id": None,
                        "candidate_domain_ids": [],
                    }
                    boundary["network_segment_id"] = None
                    boundary["network_segment_attachment_ids"] = []
                    boundary["resource_refs"] = []
                    boundary["interaction_target_ids"] = []
                    boundary["highlight_target_ids"] = []
                    boundary["completeness"] = {
                        "state": "unresolved",
                        "end_to_end_resolved": False,
                        "observed": False,
                    }
                    boundary["state"]["operational"] = "unknown"
                    boundary["active"] = False
                    continue
                reference = next_hop["topology_references"][0]
                binding = resolve_connectivity_domain_reference(
                    route_evidence,
                    reference,
                    source_node_id=source_node_id,
                    target_node_id=target_node_id,
                    source_resource_id=str(
                        next_hop["interface_resource_id"]
                    ),
                    target_resource_id=str(
                        next_hop["remote_interface_resource_id"]
                    ),
                )
                boundary["generated_connectivity_binding"] = (
                    binding.as_dict()
                )
                boundary["topology_reference"] = reference
                if not binding.resolved:
                    boundary["network_segment_id"] = None
                    boundary["network_segment_attachment_ids"] = []
                    boundary["resource_refs"] = []
                    boundary["interaction_target_ids"] = []
                    boundary["highlight_target_ids"] = []
                    boundary["completeness"] = {
                        "state": "unresolved",
                        "end_to_end_resolved": False,
                        "observed": False,
                    }
                    boundary["state"]["operational"] = "unknown"
                    boundary["active"] = False
                    continue

                domain = dict(binding.domain or {})
                source_attachment = dict(
                    binding.source_attachment or {}
                )
                target_attachment = dict(
                    binding.target_attachment or {}
                )
                domain_target_id = self._network_segment_target(
                    domain,
                    source_attachment,
                    target_attachment,
                    targets,
                )
                attachment_records = [
                    resources[resource_id]
                    for resource_id in (
                        source_attachment.get("resource_id"),
                        target_attachment.get("resource_id"),
                    )
                    if resource_id in resources
                ]
                attachment_target_ids = [
                    self._resource_target(item, targets)
                    for item in attachment_records
                ]
                target_ids = [
                    domain_target_id,
                    *attachment_target_ids,
                ]
                network_segment_id = str(domain["segment_id"])
                attachment_ids = [
                    str(source_attachment["attachment_id"]),
                    str(target_attachment["attachment_id"]),
                ]
                boundary["network_segment_id"] = network_segment_id
                boundary["network_segment_attachment_ids"] = attachment_ids
                boundary["resource_refs"] = [
                    dict(source_attachment["resource_ref"]),
                    dict(target_attachment["resource_ref"]),
                ]
                boundary["node_id"] = None
                boundary["node_ids"] = [
                    source_node_id,
                    target_node_id,
                ]
                boundary["member_id"] = None
                boundary["member_ids"] = [
                    str(source_attachment["member_id"]),
                    str(target_attachment["member_id"]),
                ]
                boundary["interaction_target_ids"] = target_ids
                boundary["highlight_target_ids"] = [domain_target_id]
                boundary["plugin_provenance"] = self._dedupe_provenance(
                    [
                        *domain.get("plugin_provenance", []),
                        source_attachment.get("plugin_provenance"),
                        target_attachment.get("plugin_provenance"),
                    ]
                )
                boundary["completeness"] = {
                    "state": "complete",
                    "end_to_end_resolved": True,
                    "observed": True,
                }
                existing_state = boundary.get("state", {})
                explicitly_terminal = bool(existing_state.get("terminal"))
                explicitly_unusable = (
                    existing_state.get("operational") == "unusable"
                )
                if not explicitly_terminal and not explicitly_unusable:
                    existing_state["operational"] = "usable"
                existing_state["selected_active_by_plugin"] = bool(
                    path.get("selected_active_by_plugin")
                )
                boundary["state"] = existing_state
                boundary["active"] = bool(
                    path.get("selected_active_by_plugin")
                    and existing_state.get("operational") != "unusable"
                    and not explicitly_terminal
                )
                domain_label = str(
                    domain.get("label") or network_segment_id
                )
                text = (
                    f"Core exact-joins the plug-in-declared {domain_label} "
                    f"domain between {source_node_id} and {target_node_id}."
                )
                boundary["route_resolution_text"] = text
                boundary["route_resolution"].update(
                    {
                        "text": text,
                        "text_source": "core_exact_join_summary",
                        "core_role": (
                            "validates_plugin_match_and_current_attachments"
                        ),
                        "interaction_target_ids": target_ids,
                        "highlight_target_ids": [domain_target_id],
                    }
                )
                boundary["route_resolution"]["parts"] = [
                    {
                        "part_id": (
                            f"{boundary['segment_id']}:"
                            "part:connectivity-domain"
                        ),
                        "text": text,
                        "interactive": True,
                        "interaction_target_ids": target_ids,
                        "highlight_target_ids": [domain_target_id],
                    }
                ]
                boundary["graph_presentation"] = {
                    "role": "outer-boundary",
                    "label": domain_label,
                    "detail": text,
                    "semantic_owner": "plugin",
                    "core_presentation": "domain_traversal",
                }

            path["active"] = bool(path.get("selected_active_by_plugin"))
            self._refresh_path(path)

    @staticmethod
    def _declared_resource_key(
        declaration: Mapping[str, Any],
        *,
        label: str,
    ) -> ResourceKey:
        """Decode one plug-in-canonicalized opaque resource identity."""

        raw_parts = declaration.get("parts")
        if isinstance(raw_parts, Mapping):
            parts = tuple(
                (str(name), value) for name, value in raw_parts.items()
            )
        elif isinstance(raw_parts, list):
            parsed_parts: list[tuple[str, Any]] = []
            for item in raw_parts:
                if (
                    not isinstance(item, Mapping)
                    or not isinstance(item.get("name"), str)
                    or not item["name"]
                    or "value" not in item
                ):
                    raise MultiNodeRouteRequestError(
                        f"{label} has malformed typed key parts"
                    )
                parsed_parts.append((str(item["name"]), item["value"]))
            parts = tuple(parsed_parts)
        else:
            raise MultiNodeRouteRequestError(
                f"{label} must declare typed key parts"
            )
        required = ("namespace", "node", "layer", "kind")
        if any(
            not isinstance(declaration.get(field), str)
            or not declaration[field]
            for field in required
        ):
            raise MultiNodeRouteRequestError(
                f"{label} lacks its typed resource-key identity"
            )
        try:
            return ResourceKey(
                namespace=str(declaration["namespace"]),
                node=str(declaration["node"]),
                layer=str(declaration["layer"]),
                kind=str(declaration["kind"]),
                parts=parts,
            )
        except ValueError as error:
            raise MultiNodeRouteRequestError(
                f"{label} is not a valid typed resource key"
            ) from error

    @staticmethod
    def _declared_policy_scope(
        declaration: Mapping[str, Any],
        *,
        label: str,
    ) -> ForwardingPolicyScope:
        """Decode an opaque plug-in scope for exact core comparison."""

        raw_arguments = declaration.get("arguments")
        if isinstance(raw_arguments, list):
            parsed: list[tuple[str, Any]] = []
            for item in raw_arguments:
                if (
                    not isinstance(item, Mapping)
                    or not isinstance(item.get("name"), str)
                    or not item["name"]
                    or "value" not in item
                ):
                    raise MultiNodeRouteRequestError(
                        f"{label} has malformed scope arguments"
                    )
                parsed.append((str(item["name"]), item["value"]))
            arguments = tuple(parsed)
        else:
            raise MultiNodeRouteRequestError(
                f"{label} must declare ordered scope arguments as a "
                "list of name/value objects"
            )
        contract_id = declaration.get("contract_id")
        if not isinstance(contract_id, str) or not contract_id:
            raise MultiNodeRouteRequestError(
                f"{label} lacks a scope contract_id"
            )
        try:
            return ForwardingPolicyScope(
                contract_id=contract_id,
                arguments=arguments,
            )
        except ValueError as error:
            raise MultiNodeRouteRequestError(
                f"{label} is not a valid forwarding scope"
            ) from error

    @classmethod
    def _project_candidate_policy_decisions(
        cls,
        path: dict[str, Any],
        candidate: Mapping[str, Any],
    ) -> None:
        """Evaluate typed plug-in constraints and retain their explanations."""

        declarations = candidate.get("policy_decisions", [])
        if declarations in (None, []):
            path["policy_decisions"] = []
            return
        if not isinstance(declarations, list) or any(
            not isinstance(item, Mapping) for item in declarations
        ):
            raise MultiNodeRouteRequestError(
                "candidate policy_decisions must be a list of objects"
            )

        public_decisions: list[dict[str, Any]] = []
        for declaration_index, declaration in enumerate(declarations):
            candidate_key = cls._declared_resource_key(
                declaration.get("candidate", {}),
                label=(
                    "candidate policy decision "
                    f"{declaration_index + 1} candidate"
                ),
            )
            raw_constraints = declaration.get("constraints")
            raw_ingress_scopes = declaration.get("ingress_scopes")
            if (
                not isinstance(raw_constraints, list)
                or not raw_constraints
                or any(
                    not isinstance(item, Mapping)
                    for item in raw_constraints
                )
                or not isinstance(raw_ingress_scopes, list)
                or any(
                    not isinstance(item, Mapping)
                    for item in raw_ingress_scopes
                )
            ):
                raise MultiNodeRouteRequestError(
                    "candidate policy decision must declare constraints "
                    "and ingress_scopes"
                )
            constraints: list[ForwardingCandidateConstraint] = []
            for constraint_index, raw_constraint in enumerate(
                raw_constraints
            ):
                candidate_scope = cls._declared_policy_scope(
                    raw_constraint.get("candidate_scope", {}),
                    label=(
                        "candidate policy constraint "
                        f"{constraint_index + 1}"
                    ),
                )
                constraint_id = raw_constraint.get("constraint_id")
                kind = raw_constraint.get("kind")
                traffic_classes = raw_constraint.get(
                    "traffic_classes", []
                )
                if (
                    not isinstance(constraint_id, str)
                    or not constraint_id
                    or not isinstance(kind, str)
                    or not kind
                    or not isinstance(traffic_classes, list)
                    or any(
                        not isinstance(item, str) or not item
                        for item in traffic_classes
                    )
                ):
                    raise MultiNodeRouteRequestError(
                        "candidate policy constraint has invalid identity "
                        "or traffic classes"
                    )
                try:
                    constraints.append(
                        ForwardingCandidateConstraint(
                            constraint_id=constraint_id,
                            kind=kind,
                            candidate_scope=candidate_scope,
                            traffic_classes=frozenset(traffic_classes),
                        )
                    )
                except ValueError as error:
                    raise MultiNodeRouteRequestError(
                        "candidate policy constraint is invalid"
                    ) from error
            ingress_scopes = frozenset(
                cls._declared_policy_scope(
                    item,
                    label="candidate policy ingress scope",
                )
                for item in raw_ingress_scopes
            )
            ingress_scopes_complete = declaration.get(
                "ingress_scopes_complete"
            )
            if not isinstance(ingress_scopes_complete, bool):
                raise MultiNodeRouteRequestError(
                    "candidate policy ingress_scopes_complete must be "
                    "a boolean"
                )
            traffic_class = declaration.get("traffic_class")
            if traffic_class is not None and (
                not isinstance(traffic_class, str) or not traffic_class
            ):
                raise MultiNodeRouteRequestError(
                    "candidate policy traffic_class must be a non-empty "
                    "string or null"
                )
            try:
                evaluation: ForwardingPolicyEvaluation = (
                    evaluate_forwarding_policy(
                        candidate=candidate_key,
                        constraints=tuple(constraints),
                        ingress_scopes=ingress_scopes,
                        traffic_class=traffic_class,
                        ingress_scopes_complete=(
                            ingress_scopes_complete
                        ),
                    )
                )
            except (RouteTraceContractError, ValueError) as error:
                raise MultiNodeRouteRequestError(
                    "candidate policy declaration cannot be evaluated"
                ) from error

            verdict_to_outcome = {
                ForwardingPolicyVerdict.BLOCKED: "reject",
                ForwardingPolicyVerdict.PERMITTED: "permit",
                ForwardingPolicyVerdict.NOT_APPLICABLE: "not_applicable",
                ForwardingPolicyVerdict.UNKNOWN: "unknown",
            }
            for decision in evaluation.decisions:
                public_decisions.append(
                    {
                        "decision_id": str(
                            declaration.get("decision_id")
                            or (
                                f"{path['path_id']}:policy:"
                                f"{len(public_decisions) + 1}"
                            )
                        ),
                        "outcome": verdict_to_outcome[
                            decision.verdict
                        ],
                        "verdict": decision.verdict.value,
                        "policy_kind": str(
                            declaration.get("policy_kind")
                            or decision.constraint.kind.value
                        ),
                        "constraint_id": (
                            decision.constraint.constraint_id
                        ),
                        "traffic_class": decision.traffic_class,
                        "ingress_scopes_complete": (
                            decision.ingress_scopes_complete
                        ),
                        "scope_refs": [
                            dict(item)
                            for item in declaration.get(
                                "scope_refs", []
                            )
                            if isinstance(item, Mapping)
                        ],
                        "evidence": [
                            dict(item)
                            for item in declaration.get("evidence", [])
                            if isinstance(item, Mapping)
                        ],
                        "provided_by": dict(
                            declaration.get("provided_by", {})
                        ),
                        "evaluation_owner": "core_exact_scope_match",
                        "semantic_owner": "plugin",
                    }
                )
        path["policy_decisions"] = public_decisions

    @classmethod
    def _project_candidate_traversal(
        cls,
        path: dict[str, Any],
        candidate: Mapping[str, Any],
        *,
        max_hops: int,
        max_recursion: int,
    ) -> None:
        """Apply typed cycle and traversal budgets to one declared path."""

        declarations = candidate.get("traversal_states")
        node_sequence = [
            str(item) for item in path.get("node_sequence", [])
        ]
        if not isinstance(declarations, list) or len(
            declarations
        ) != len(node_sequence) or any(
            not isinstance(item, Mapping) for item in declarations
        ):
            raise MultiNodeRouteRequestError(
                "candidate traversal_states must provide one object per "
                "node occurrence"
            )

        typed_states: list[ForwardingTraversalStateKey] = []
        hop_indices: list[int] = []
        recursion_depths: list[int] = []
        occurrences: list[dict[str, Any]] = []
        first_occurrence_by_state: dict[
            ForwardingTraversalStateKey, str
        ] = {}
        for visit_index, (node_id, declaration) in enumerate(
            zip(node_sequence, declarations)
        ):
            declared_visit_index = declaration.get("visit_index")
            declared_node_id = declaration.get("node_id")
            cycle_key = declaration.get("cycle_key")
            identity_complete = declaration.get("identity_complete", False)
            if (
                declared_visit_index != visit_index
                or declared_node_id != node_id
                or not isinstance(cycle_key, str)
                or not cycle_key
                or not isinstance(identity_complete, bool)
            ):
                raise MultiNodeRouteRequestError(
                    "candidate traversal state identity disagrees with "
                    "its node occurrence"
                )
            state = ForwardingTraversalStateKey(
                member_id=f"member:{node_id}",
                status_perspective=StatusPerspectiveRef(
                    perspective_id="normalized.forwarding",
                ),
                forwarding_object=ResourceKey(
                    namespace="plugin",
                    node=node_id,
                    layer="forwarding",
                    kind="OPAQUE_TRAVERSAL_STATE",
                    parts=(("canonical_state", cycle_key),),
                ),
                # The generic traversal evaluator already refuses to prove a
                # cycle when the declared policy-scope envelope is incomplete.
                # Generated executors currently project one opaque canonical
                # key, so conservatively carry their whole-identity
                # completeness through that existing proof gate.
                policy_scopes_complete=identity_complete,
            )
            hop_index = visit_index
            recursion_depth = (
                recursion_depths[-1] + 1
                if visit_index > 0
                and node_sequence[visit_index - 1] == node_id
                else 0
            )
            declared_hop_index = declaration.get("hop_index")
            declared_recursion_depth = declaration.get(
                "recursion_depth"
            )
            if (
                declared_hop_index is not None
                and (
                    not isinstance(declared_hop_index, int)
                    or isinstance(declared_hop_index, bool)
                    or declared_hop_index != hop_index
                )
            ) or (
                declared_recursion_depth is not None
                and (
                    not isinstance(declared_recursion_depth, int)
                    or isinstance(declared_recursion_depth, bool)
                    or declared_recursion_depth != recursion_depth
                )
            ):
                raise MultiNodeRouteRequestError(
                    "candidate traversal counters disagree with the "
                    "core-derived hop or recursion position"
                )
            occurrence_id = (
                f"{path['path_id']}:node-occurrence:{visit_index + 1}"
            )
            repeated_occurrence_id = (
                first_occurrence_by_state.get(state)
                if identity_complete
                else None
            )
            occurrence = {
                "occurrence_id": occurrence_id,
                "node_id": node_id,
                "visit_index": visit_index,
                "step": visit_index + 1,
                "occurrence_index": int(
                    declaration.get("occurrence_index", 0)
                ),
                "repeated": repeated_occurrence_id is not None,
                "repeats_occurrence_id": repeated_occurrence_id,
                "canonical_identity_complete": identity_complete,
            }
            if identity_complete and repeated_occurrence_id is None:
                first_occurrence_by_state[state] = occurrence_id
            typed_states.append(state)
            hop_indices.append(hop_index)
            recursion_depths.append(recursion_depth)
            occurrences.append(occurrence)

        terminal_semantics = candidate.get("terminal_semantics", {})
        declared_cycle_reason = (
            terminal_semantics.get("reason_code")
            if isinstance(terminal_semantics, Mapping)
            else None
        )
        cycle_reason = (
            declared_cycle_reason.strip()
            if isinstance(declared_cycle_reason, str)
            and declared_cycle_reason.strip()
            else "forwarding_cycle"
        )
        try:
            evaluation = evaluate_forwarding_traversal(
                tuple(typed_states),
                max_hops=max_hops,
                max_recursion=max_recursion,
                hop_indices=tuple(hop_indices),
                recursion_depths=tuple(recursion_depths),
                cycle_reason=cycle_reason,
            )
        except RouteTraceContractError as error:
            raise MultiNodeRouteRequestError(
                "candidate traversal declaration cannot be evaluated"
            ) from error

        path["node_occurrences"] = occurrences
        local_by_visit = {
            int(state["visit_index"]): segment
            for segment in path.get("segments", [])
            if isinstance(
                state := segment.get("generated_forwarding_state"),
                Mapping,
            )
            and isinstance(state.get("visit_index"), int)
        }
        for visit_index, occurrence in enumerate(occurrences):
            segment = local_by_visit.get(visit_index)
            if segment is not None:
                segment["node_occurrence_id"] = occurrence[
                    "occurrence_id"
                ]
        boundaries = [
            item
            for item in sorted(
                path.get("segments", []),
                key=lambda item: item["ordinal"],
            )
            if item.get("segment_kind") == "inter_node_boundary"
        ]
        for transition_index, boundary in enumerate(boundaries):
            if transition_index + 1 >= len(occurrences):
                break
            boundary["source_occurrence_id"] = occurrences[
                transition_index
            ]["occurrence_id"]
            boundary["target_occurrence_id"] = occurrences[
                transition_index + 1
            ]["occurrence_id"]

        if evaluation.outcome == "cycle" and evaluation.cycle is not None:
            first_step = evaluation.cycle.first_seen_step
            closing_step = evaluation.cycle.repeated_at_step
            path["cycle"] = {
                "first_step": first_step + 1,
                "closing_step": closing_step + 1,
                "first_occurrence_id": occurrences[first_step][
                    "occurrence_id"
                ],
                "closing_occurrence_id": occurrences[closing_step][
                    "occurrence_id"
                ],
                "state_count": len(evaluation.cycle.cycle_states),
                "reason": evaluation.terminal_reason,
                "identity_comparison": "exact_typed_state",
            }
            terminal = local_by_visit.get(closing_step)
            if terminal is not None:
                terminal["segment_kind"] = "cycle_detection"
                terminal["active"] = False
                terminal["state"].update(
                    {
                        "active": False,
                        "operational": "loop_detected",
                        "terminal": "cycle",
                        "terminal_disposition": "cycle",
                        "reason_code": cycle_reason,
                        "core_terminal_classification": (
                            "exact_typed_state_cycle"
                        ),
                    }
                )
                terminal["completeness"] = {
                    "state": "terminal_observed",
                    "end_to_end_resolved": False,
                    "observed": True,
                }
                stop_ordinal = int(terminal["ordinal"])
                path["declared_node_sequence"] = list(
                    path.get("node_sequence", [])
                )
                path["declared_node_occurrences"] = list(occurrences)
                path["node_sequence"] = list(
                    path["declared_node_sequence"][: closing_step + 1]
                )
                path["node_occurrences"] = list(
                    occurrences[: closing_step + 1]
                )
                path["segments"] = [
                    segment
                    for segment in path.get("segments", [])
                    if int(segment["ordinal"]) <= stop_ordinal
                ]
        elif evaluation.budget_kind is not None:
            path.pop("cycle", None)
            path["resolution_budget"] = {
                "kind": evaluation.budget_kind,
                "limit": evaluation.budget_limit,
                "observed": evaluation.budget_observed,
            }
            terminal = local_by_visit.get(evaluation.stop_step)
            if terminal is None and path.get("segments"):
                terminal = path["segments"][-1]
            if terminal is not None:
                for segment in path.get("segments", []):
                    if isinstance(segment.get("state"), dict):
                        segment["state"].pop("terminal", None)
                        segment["state"].pop(
                            "terminal_disposition", None
                        )
                terminal["segment_kind"] = "resolution_budget"
                terminal["active"] = False
                terminal["state"].update(
                    {
                        "active": False,
                        "operational": "budget_exhausted",
                        "terminal": evaluation.outcome,
                        "terminal_disposition": evaluation.outcome,
                        "reason_code": evaluation.terminal_reason,
                    }
                )
                terminal["completeness"] = {
                    "state": "terminal_observed",
                    "end_to_end_resolved": False,
                    "observed": True,
                }
                stop_ordinal = int(terminal["ordinal"])
                path["declared_node_sequence"] = list(
                    path.get("node_sequence", [])
                )
                path["declared_node_occurrences"] = list(occurrences)
                path["node_sequence"] = list(
                    path["declared_node_sequence"][
                        : evaluation.stop_step + 1
                    ]
                )
                path["node_occurrences"] = list(
                    occurrences[: evaluation.stop_step + 1]
                )
                path["segments"] = [
                    segment
                    for segment in path.get("segments", [])
                    if int(segment["ordinal"]) <= stop_ordinal
                ]

    @classmethod
    def _apply_generated_candidate_semantics(
        cls,
        paths: list[dict[str, Any]],
        *,
        max_hops: int,
        max_recursion: int,
    ) -> None:
        """Apply generic presentation and traversal semantics."""

        for path in paths:
            candidate = path.get("generated_candidate_declaration", {})
            alternative_state = str(
                candidate.get("alternative_state")
                or path.get("alternative_state")
                or ""
            )
            decisions = [
                item.get("directional_decision", {})
                for item in path.get(
                    "generated_forwarding_decisions",
                    [],
                )
            ]
            dispositions = {
                str(item.get("disposition") or "")
                for item in decisions
            }

            # Copy plug-in-owned content first. Normalized generic roles below
            # are presentation guarantees and therefore take precedence.
            if candidate.get("label"):
                path["label"] = str(candidate["label"])
            declared_encapsulation = candidate.get("encapsulation")
            if isinstance(declared_encapsulation, dict):
                path["encapsulation"] = dict(declared_encapsulation)
            for field in (
                "perspective",
                "forwarding_capable",
                "egress_resource_id",
                "protocol_chain",
            ):
                if candidate.get(field) is not None:
                    path[field] = candidate[field]
            if candidate.get("inferred") is True:
                path["inference"] = {
                    "declared_candidate": True,
                    "performed_by": "core",
                    "method": (
                        "join_topology_with_contemporaneous_resource_status"
                    ),
                    "does_not_override_observed_drop": True,
                    "semantic_owner": "plugin",
                }

            if alternative_state == "ecmp_member":
                path["label"] = f"ECMP member · {path['label']}"
            elif alternative_state == "eligible_standby":
                path["label"] = f"Eligible standby · {path['label']}"
            elif alternative_state == "control_expected_not_observed":
                path["label"] = (
                    f"Control-plane expectation · {path['label']}"
                )
                path["perspective"] = "control_expected"
                path["forwarding_capable"] = False
            if "control_only" in dispositions:
                path["perspective"] = "control_expected"
                path["forwarding_capable"] = False
            else:
                path.setdefault("forwarding_capable", True)

            terminal_kind_by_disposition = {
                "drop": "directional_drop",
                "split_horizon_block": "policy_decision",
                "loop": "cycle_detection",
                "unusable": "unusable_forwarding",
                "withdrawn": "withdrawn_candidate",
            }
            for segment, decision in zip(
                [
                    item
                    for item in sorted(
                        path.get("segments", []),
                        key=lambda item: item["ordinal"],
                    )
                    if item.get("segment_kind")
                    not in {"inter_node_boundary"}
                ],
                decisions,
            ):
                disposition = str(
                    decision.get("disposition") or ""
                )
                terminal_kind = terminal_kind_by_disposition.get(
                    disposition
                )
                if terminal_kind is not None:
                    segment["segment_kind"] = terminal_kind
                if disposition == "split_horizon_block":
                    segment["state"]["operational"] = "policy_blocked"

            cls._project_candidate_policy_decisions(path, candidate)
            cls._project_candidate_traversal(
                path,
                candidate,
                max_hops=max_hops,
                max_recursion=max_recursion,
            )
            cls._refresh_path(path)

    @staticmethod
    def _materialize_generated_findings(
        paths: list[dict[str, Any]],
        projection: Mapping[str, Any],
        issues: list[dict[str, Any]],
    ) -> None:
        """Bind opaque plug-in findings to the returned candidate paths."""

        paths_by_candidate = {
            str(
                path.get("generated_candidate_id")
                or path.get("candidate_id")
                or ""
            ): path
            for path in paths
        }
        for finding in projection.get("consistency_findings", []):
            candidate_ids = [
                str(item)
                for item in finding.get("candidate_ids", [])
                if str(item) in paths_by_candidate
            ]
            finding_paths = [
                paths_by_candidate[item] for item in candidate_ids
            ]
            if not finding_paths:
                continue
            issue_id = str(
                finding.get("issue_id")
                or f"issue:plugin:{finding['finding_id']}"
            )
            path_refs = [
                str(path["path_id"]) for path in finding_paths
            ]
            route_entry_refs = list(
                {
                    str(reference["route_entry_id"]): reference
                    for path in finding_paths
                    for reference in path.get("route_entry_refs", [])
                    if isinstance(reference, dict)
                    and reference.get("route_entry_id")
                }.values()
            )
            segment_refs = [
                str(segment["segment_id"])
                for path in finding_paths
                for segment in path.get("segments", [])
            ]
            interaction_target_ids = list(
                dict.fromkeys(
                    str(target_id)
                    for path in finding_paths
                    for target_id in path.get(
                        "interaction_target_ids", []
                    )
                )
            )
            issue = {
                "issue_id": issue_id,
                "category": str(
                    finding.get("category") or "cross_layer"
                ),
                "severity": str(
                    finding.get("severity") or "warning"
                ),
                "finding_type": str(finding["finding_type"]),
                "summary": str(finding["summary"]),
                "detail": str(
                    finding.get("detail") or finding["summary"]
                ),
                "candidate_refs": candidate_ids,
                "path_refs": path_refs,
                "segment_refs": segment_refs,
                "route_entry_refs": route_entry_refs,
                "interaction_target_ids": interaction_target_ids,
                "affects_consistency": bool(
                    finding.get("affects_consistency", True)
                ),
                "semantic_owner": "plugin",
                "binding_owner": "core",
            }
            issues.append(issue)
            for path in finding_paths:
                path["issue_refs"] = list(
                    dict.fromkeys(
                        [*path.get("issue_refs", []), issue_id]
                    )
                )
                for segment in path.get("segments", []):
                    segment["issue_refs"] = list(
                        dict.fromkeys(
                            [
                                *segment.get("issue_refs", []),
                                issue_id,
                            ]
                        )
                    )

    @staticmethod
    def _materialize_control_plane_only_issue(
        paths: list[dict[str, Any]],
        issues: list[dict[str, Any]],
    ) -> bool:
        """Report a complete control-only answer without claiming forwarding."""

        control_paths = [
            path
            for path in paths
            if path.get("alternative_state") == "control_plane_only"
            and path.get("forwarding_capable") is False
        ]
        if not control_paths or any(
            path.get("forwarding_capable") is not False
            for path in paths
        ):
            return False
        route_entry_refs = list(
            {
                str(reference["route_entry_id"]): reference
                for path in control_paths
                for reference in path.get("route_entry_refs", [])
                if isinstance(reference, dict)
                and reference.get("route_entry_id")
            }.values()
        )
        issue_id = (
            "issue:control-plane-only:"
            + hashlib.sha256(
                ":".join(
                    str(path["path_id"]) for path in control_paths
                ).encode("utf-8")
            ).hexdigest()[:16]
        )
        issue = {
            "issue_id": issue_id,
            "category": "forwarding",
            "severity": "warning",
            "finding_type": "control_plane_only",
            "summary": (
                "The selected route exists in control state but has no "
                "installed forwarding candidate."
            ),
            "detail": (
                "The node plug-in explicitly classified this route as "
                "control-plane-only. Core retains the route evidence and "
                "does not promote it to forwarding reachability."
            ),
            "path_refs": [
                str(path["path_id"]) for path in control_paths
            ],
            "segment_refs": [
                str(segment["segment_id"])
                for path in control_paths
                for segment in path.get("segments", [])
            ],
            "route_entry_refs": route_entry_refs,
            "interaction_target_ids": list(
                dict.fromkeys(
                    str(target_id)
                    for path in control_paths
                    for target_id in path.get(
                        "interaction_target_ids", []
                    )
                )
            ),
            "affects_consistency": True,
            "semantic_owner": "plugin",
            "binding_owner": "core",
        }
        issues.append(issue)
        for path in control_paths:
            path["issue_refs"] = list(
                dict.fromkeys(
                    [*path.get("issue_refs", []), issue_id]
                )
            )
        return True

    def _generated_router_descriptors(
        self,
    ) -> dict[str, dict[str, Any]]:
        """Build route-participant identities from normalized projections.

        These descriptors project node metadata and plug-in route evidence.
        They are not a second router catalog.
        """

        routed_nodes = self._generated_routed_nodes()
        inventory_by_node: dict[str, dict[str, Any]] = {}
        for row in self._generated_route_rows:
            if row.get("node_id") and not row.get("scenario_id"):
                inventory_by_node.setdefault(str(row["node_id"]), row)
        result: dict[str, dict[str, Any]] = {}
        for node in routed_nodes:
            node_id = str(node["node_id"])
            inventory = inventory_by_node.get(node_id, {})
            evidence_ids = [
                str(item)
                for item in inventory.get("evidence_resource_ids", [])
                if item
            ]
            if not evidence_ids:
                raise MultiNodeRouteRequestError(
                    "routed node projection lacks a plug-in-declared "
                    f"endpoint resource identity: {node_id}"
                )
            declared_values = [
                str(alias)
                for alias, alias_node_id
                in self.policy.router_value_aliases.items()
                if alias_node_id == node_id
            ]
            role = next(
                (
                    str(item)
                    for item in node.get("roles", [])
                    if item
                ),
                "routed_node",
            )
            result[node_id] = {
                "node_id": node_id,
                "source_id": f"source:{node_id}",
                "destination_id": f"destination:{node_id}",
                "label": str(node.get("label") or node_id),
                "site": str(node.get("site") or "unspecified"),
                "role": role,
                "loopback_resource_id": evidence_ids[0],
                "prefix": str(
                    declared_values[0]
                    if declared_values
                    else node_id
                ),
                "descriptor_source": "generated_plugin_projection",
            }
        return result

    def _scenario_resource_id(
        self,
        scenario_id: str,
        node_id: str,
    ) -> str:
        """Return plug-in evidence anchoring one scenario endpoint."""

        coverage = self._generated_coverage_by_id.get(scenario_id, {})
        resource_ids = [
            str(item["resource_id"])
            for item in coverage.get("evidence_refs", [])
            if isinstance(item, dict)
            and item.get("node_id") == node_id
            and item.get("resource_id")
        ]
        if resource_ids:
            return resource_ids[0]
        return self._router(node_id)["loopback_resource_id"]

    def _generated_destination_attachment_node_ids(
        self,
        scenario_id: str,
    ) -> list[str]:
        """Return every declared destination attachment node."""

        return [
            str(item["node_id"])
            for item in self._generated_destination_attachment_specs(
                scenario_id
            )
        ]

    def _generated_destination_attachment_specs(
        self,
        scenario_id: str,
    ) -> list[dict[str, Any]]:
        """Project typed attachment availability from forward candidates."""

        coverage = self._generated_coverage_by_id.get(scenario_id, {})
        by_node: dict[str, dict[str, Any]] = {}
        state_rank = {"withdrawn": 0, "unavailable": 1, "available": 2}
        for candidate in coverage.get("candidate_paths", []):
            if (
                not isinstance(candidate, dict)
                or candidate.get("direction") != "forward"
                or not isinstance(
                    node_sequence := candidate.get("node_sequence"),
                    list,
                )
                or not node_sequence
            ):
                continue
            node_id = str(node_sequence[-1])
            terminal = candidate.get("terminal_semantics")
            disposition = (
                str(terminal.get("disposition") or "")
                if isinstance(terminal, Mapping)
                else ""
            )
            declared_state = candidate.get(
                "terminal_attachment_state"
            )
            if declared_state is not None and declared_state not in {
                "available",
                "withdrawn",
                "unavailable",
            }:
                raise MultiNodeRouteRequestError(
                    "terminal_attachment_state must be available, "
                    "withdrawn, or unavailable"
                )
            alternative_state = str(
                candidate.get("alternative_state") or ""
            )
            state = (
                str(declared_state)
                if declared_state is not None
                else "withdrawn"
                if alternative_state == "withdrawn_dead"
                or disposition == "withdrawn"
                else "unavailable"
                if alternative_state in {
                    "ineligible_dead",
                    "unavailable",
                }
                else "available"
            )
            current = by_node.get(node_id)
            candidate_id = str(candidate.get("candidate_id") or "")
            if current is None:
                by_node[node_id] = {
                    "node_id": node_id,
                    "state": state,
                    "candidate_ids": (
                        [candidate_id] if candidate_id else []
                    ),
                }
                continue
            if candidate_id:
                current["candidate_ids"] = list(
                    dict.fromkeys(
                        [*current["candidate_ids"], candidate_id]
                    )
                )
            if state_rank[state] > state_rank[str(current["state"])]:
                current["state"] = state
        return list(by_node.values())

    def _router(self, node_id: str) -> dict[str, Any]:
        router = self._routers_by_id.get(node_id)
        if router is None:
            raise MultiNodeRouteRequestError(f"unknown routed node: {node_id}")
        return router

    def _generic_paths_from_generated_candidates(
        self,
        projection: dict[str, Any],
        route_type: str,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Materialize only plug-in-declared candidates for one direction.

        The generated projection supplied to this helper has already been
        filtered to the requested direction and validated against every
        node-local forwarding declaration. Core preserves the declared order
        and selection state; it does not infer a candidate from the topology.
        """

        paths: list[dict[str, Any]] = []
        candidates = projection["candidate_paths"]
        if len(candidates) > self.MAX_CANDIDATE_PATHS:
            raise MultiNodeRouteRequestError(
                "route projection exceeds the advertised "
                f"{self.MAX_CANDIDATE_PATHS}-candidate limit"
            )
        for candidate in candidates:
            node_sequence = [
                str(item) for item in candidate["node_sequence"]
            ]
            if not node_sequence:
                raise MultiNodeRouteRequestError(
                    "a generated routed candidate must contain at least "
                    "one node"
                )
            path = self._generic_path(
                    node_sequence,
                    route_type,
                    resources,
                    links,
                    targets,
                    active=bool(candidate["selected_active"]),
                    primary=bool(candidate["primary"]),
                    alternative_state=str(
                        candidate["alternative_state"]
                    ),
                    candidate_id=str(candidate["candidate_id"]),
                    allow_repeated_nodes=(
                        len(set(node_sequence)) != len(node_sequence)
                    ),
            )
            path["path_id"] = str(candidate["path_id"])
            if len(path.get("segments", [])) > self.MAX_SEGMENTS_PER_PATH:
                raise MultiNodeRouteRequestError(
                    f"route path {path['path_id']} exceeds the advertised "
                    f"{self.MAX_SEGMENTS_PER_PATH}-segment limit"
                )
            paths.append(path)
        return paths

    def _generated_inventory_projection(
        self,
        *,
        source_node_id: str,
        destination_node_id: str,
        routing_context: dict[str, Any],
        direction: str,
    ) -> dict[str, Any]:
        """Join one route-table decision to its exact forwarding evidence.

        Route rows own table selection and the stable ``route_id``/``path_id``
        pair.  Per-visit continuation state is a separate forwarding
        projection, including for transit nodes that do not expose the route
        as a local table row.  Keeping those responsibilities separate avoids
        manufacturing transit RIB rows merely to make a cross-node path.
        """

        context = {
            "route_type": str(routing_context["route_type"]),
            "route_family": str(routing_context["route_family"]),
            "address_family": str(routing_context["address_family"]),
            "vrf": str(routing_context["vrf_id"]),
        }
        inventory_scenario_ids = {
            scenario_id
            for scenario_id, scenario in self.policy.scenarios.items()
            if scenario.get("supports_arbitrary_endpoints")
        }
        if not inventory_scenario_ids:
            raise MultiNodeRouteRequestError(
                "route policy declares no arbitrary-endpoint scenario"
            )

        source_rows = [
            row
            for row in self._generated_route_rows
            if not row.get("scenario_id")
            and row.get("trace_scenario_id") in inventory_scenario_ids
            and row.get("table_visible") is not False
            and row.get("traceable") is True
            and str(row.get("node_id") or "") == source_node_id
            and str(row.get("destination_node_id") or "")
            == destination_node_id
            and all(
                str(row.get(field) or "") == value
                for field, value in context.items()
            )
        ]
        if not source_rows:
            raise MultiNodeRouteRequestError(
                "generated inventory must declare a traceable route for "
                f"{source_node_id} -> {destination_node_id} in "
                f"{context}"
            )
        if len(source_rows) > self.MAX_CANDIDATE_PATHS:
            raise MultiNodeRouteRequestError(
                "generated route inventory exceeds the advertised "
                f"{self.MAX_CANDIDATE_PATHS}-candidate limit"
            )
        trace_scenario_ids = {
            str(row["trace_scenario_id"]) for row in source_rows
        }
        if len(trace_scenario_ids) != 1:
            raise MultiNodeRouteRequestError(
                "route inventory rows select multiple arbitrary-endpoint "
                "scenario executors"
            )
        trace_scenario_id = next(iter(trace_scenario_ids))
        trace_semantics = self.policy.scenarios.get(
            trace_scenario_id,
            {},
        )
        path_ids = [str(row.get("path_id") or "") for row in source_rows]
        if any(not path_id for path_id in path_ids) or len(
            set(path_ids)
        ) != len(path_ids):
            raise MultiNodeRouteRequestError(
                "generated route inventory must declare a unique path_id "
                "for every traceable candidate"
            )

        selected_rows = [
            row
            for row in source_rows
            if self._declared_boolean(
                row,
                "selected",
                str(row.get("decision") or "") == "active",
            )
        ]
        multipath_mode = self._route_executor_multipath_mode(
            trace_semantics,
            selected_count=len(selected_rows),
        )
        if len(selected_rows) > 1 and multipath_mode != "all_active":
            raise MultiNodeRouteRequestError(
                "multiple selected route rows require an explicit "
                "all_active multipath mode"
            )
        declared_groups = {
            str(row["multipath_group"])
            for row in selected_rows
            if row.get("multipath_group") is not None
        }
        if len(declared_groups) > 1:
            raise MultiNodeRouteRequestError(
                "selected all-active route rows disagree on "
                "multipath_group"
            )
        multipath_group = (
            next(iter(declared_groups))
            if declared_groups
            else (
                f"scenario:{trace_scenario_id}"
                if multipath_mode == "all_active"
                else None
            )
        )
        candidate_paths: list[dict[str, Any]] = []
        forwarding_by_node: dict[str, dict[str, Any]] = {}
        involved_node_ids: list[str] = []
        for source_row in source_rows:
            route_id = str(source_row.get("route_id") or "")
            path_id = str(source_row["path_id"])
            node_sequence = [
                str(item)
                for item in source_row.get("node_sequence", [])
                if item
            ]
            if (
                not route_id
                or not node_sequence
                or node_sequence[0] != source_node_id
                or node_sequence[-1] != destination_node_id
                or 2 * len(node_sequence) - 1
                > self.MAX_SEGMENTS_PER_PATH
            ):
                raise MultiNodeRouteRequestError(
                    "generated inventory route has an invalid identity or "
                    "node_sequence"
                )

            continuation_rows = [
                row
                for row in self._generated_forwarding_rows
                if row.get("coverage_category")
                == "inventory_continuation"
                and str(row.get("route_id") or "") == route_id
                and str(row.get("path_id") or "") == path_id
            ]
            by_visit: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
            for row in continuation_rows:
                continuation = row.get("continuation")
                if not isinstance(continuation, dict):
                    raise MultiNodeRouteRequestError(
                        "generated inventory forwarding row lacks its "
                        "continuation declaration"
                    )
                visit_index = continuation.get("visit_index")
                if (
                    not isinstance(visit_index, int)
                    or isinstance(visit_index, bool)
                    or visit_index < 0
                    or visit_index in by_visit
                ):
                    raise MultiNodeRouteRequestError(
                        "generated inventory forwarding rows have invalid "
                        "or duplicate visit indexes"
                    )
                by_visit[visit_index] = (row, continuation)
            if set(by_visit) != set(range(len(node_sequence))):
                raise MultiNodeRouteRequestError(
                    "generated inventory forwarding evidence does not cover "
                    f"every visit of {path_id}"
                )

            selected = self._declared_boolean(
                source_row,
                "selected",
                str(source_row.get("decision") or "") == "active",
            )
            forwarding_capable = self._declared_boolean(
                source_row,
                "forwarding_capable",
                selected,
            )
            if selected and multipath_mode == "all_active":
                primary = False
                alternative_state = "ecmp_member"
            elif selected:
                primary = True
                alternative_state = "selected_primary"
            elif self._declared_boolean(
                source_row,
                "backup",
                False,
            ):
                primary = False
                alternative_state = "eligible_standby"
            elif not forwarding_capable:
                primary = False
                alternative_state = "control_plane_only"
            else:
                primary = False
                alternative_state = str(
                    source_row.get("alternative_state")
                    or "inactive_candidate"
                )
            candidate_id = str(
                source_row.get("trace_candidate_id")
                or f"inventory:{direction}:{path_id}"
            )
            candidate = {
                "candidate_id": candidate_id,
                "path_id": path_id,
                "direction": direction,
                "node_sequence": node_sequence,
                "selected_active": selected,
                "primary": primary,
                "alternative_state": alternative_state,
                "forwarding_capable": forwarding_capable,
                "multipath_mode": multipath_mode,
                "multipath_group": (
                    multipath_group if selected else None
                ),
                "resolution_layers": [
                    str(item)
                    for item in source_row.get(
                        "resolution_layers",
                        [],
                    )
                    if item
                ],
                "traversal_states": [
                    dict(by_visit[visit_index][1]["traversal_state"])
                    for visit_index in range(len(node_sequence))
                    if isinstance(
                        by_visit[visit_index][1].get(
                            "traversal_state"
                        ),
                        dict,
                    )
                ],
            }
            for field in (
                "perspective",
                "encapsulation",
                "remote_vtep",
                "connected_attachment",
                "terminal_segment_kind",
                "label",
            ):
                if source_row.get(field) is not None:
                    candidate[field] = source_row[field]
            candidate_paths.append(candidate)
            involved_node_ids.extend(node_sequence)

            for visit_index, node_id in enumerate(node_sequence):
                row, continuation = by_visit[visit_index]
                next_node_id = (
                    node_sequence[visit_index + 1]
                    if visit_index + 1 < len(node_sequence)
                    else None
                )
                if (
                    str(row.get("node_id") or "") != node_id
                    or str(continuation.get("node_id") or "") != node_id
                    or continuation.get("next_node_id") != next_node_id
                    or str(continuation.get("path_id") or "") != path_id
                    or row.get("semantic_owner") != "plugin"
                    or row.get("revision_id")
                    != self._generated_revision_by_node.get(node_id)
                ):
                    raise MultiNodeRouteRequestError(
                        "generated inventory continuation disagrees with "
                        f"the declared path at visit {visit_index}"
                    )
                next_hop = continuation.get("next_hop")
                if next_node_id is None:
                    if next_hop is not None:
                        raise MultiNodeRouteRequestError(
                            "generated terminal continuation must not "
                            "declare a next hop"
                        )
                elif (
                    not isinstance(next_hop, dict)
                    or str(next_hop.get("node_id") or "")
                    != next_node_id
                ):
                    raise MultiNodeRouteRequestError(
                        "generated inventory continuation does not bind its "
                        f"declared next node {node_id} -> {next_node_id}"
                    )
                resolution_text = str(row.get("resolution_text") or "")
                if not resolution_text:
                    raise MultiNodeRouteRequestError(
                        "generated inventory forwarding row lacks plug-in "
                        "resolution text"
                    )
                decision = {
                    "candidate_id": candidate_id,
                    "visit_index": visit_index,
                    "next_node_id": next_node_id,
                    "next_hop": (
                        dict(next_hop)
                        if isinstance(next_hop, dict)
                        else None
                    ),
                    "selected_active": selected,
                    "primary": primary,
                    "alternative_state": alternative_state,
                    "state": str(
                        continuation.get("state") or "unknown"
                    ),
                    "disposition": str(
                        continuation.get("disposition")
                        or row.get("disposition")
                        or "unresolved"
                    ),
                    "reason_code": str(
                        continuation.get("reason_code")
                        or row.get("reason_code")
                        or "plugin_reason_not_declared"
                    ),
                    "resolution_text": resolution_text,
                    "forwarding_actions": [
                        dict(item)
                        for item in continuation.get(
                            "forwarding_actions",
                            [],
                        )
                        if isinstance(item, dict)
                    ],
                    "resolution_layers": [
                        str(item)
                        for item in continuation.get(
                            "resolution_layers",
                            [],
                        )
                        if item
                    ],
                }
                public_row = self._public_generated_projection_row(row)
                grouped = forwarding_by_node.get(node_id)
                if grouped is None:
                    grouped = {
                        **public_row,
                        "evidence_resource_ids": [],
                        "directional_decisions": {
                            "forward": [],
                            "reverse": [],
                        },
                    }
                    forwarding_by_node[node_id] = grouped
                grouped["evidence_resource_ids"] = list(
                    dict.fromkeys(
                        [
                            *grouped["evidence_resource_ids"],
                            *[
                                str(item)
                                for item in row.get(
                                    "evidence_resource_ids",
                                    [],
                                )
                                if item
                            ],
                        ]
                    )
                )
                grouped["directional_decisions"][direction].append(
                    decision
                )
        return {
            "source": "generated_plugin_route_inventory",
            "coverage_case_id": trace_scenario_id,
            "coverage_registry_id": self._generated_coverage_registry_id,
            "involved_node_ids": list(dict.fromkeys(involved_node_ids)),
            "evidence_node_ids": list(forwarding_by_node),
            "expected_outcome": "resolved",
            "candidate_paths": candidate_paths,
            "forwarding_decisions": list(forwarding_by_node.values()),
            "packet_case": None,
            "validation": {
                "forwarding": "validated",
                "packet": "not_applicable",
            },
            "semantic_owner": "node_plugins",
            "selection_and_identity_validation_owner": "core",
        }

    @staticmethod
    def _router_endpoint_id(node_id: str) -> str:
        return f"endpoint:{node_id}:loopback"

    @staticmethod
    def _endpoint_attachment_id(
        endpoint_id: str,
        node_id: str,
        resource_id: str,
    ) -> str:
        """Return the plug-in-declared identity of one endpoint attachment."""

        material = json.dumps(
            [endpoint_id, node_id, resource_id],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        return "attachment1-" + hashlib.sha256(
            material.encode("utf-8")
        ).hexdigest()[:24]

    @classmethod
    def _endpoint_attachment(
        cls,
        *,
        endpoint_id: str,
        node_id: str,
        member_id: str,
        resource_id: str,
        state: str = "available",
        candidate_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        if state not in {"available", "withdrawn", "unavailable"}:
            raise MultiNodeRouteRequestError(
                "endpoint attachment state must be available, withdrawn, "
                "or unavailable"
            )
        available = state == "available"
        return {
            "attachment_id": cls._endpoint_attachment_id(
                endpoint_id,
                node_id,
                resource_id,
            ),
            "endpoint_id": endpoint_id,
            "node_id": node_id,
            "member_id": member_id,
            "resource_id": resource_id,
            "can_originate": available,
            "can_terminate": available,
            "state": state,
            "candidate_ids": list(candidate_ids or []),
            "semantic_owner": "node_plugin",
        }

    def _generated_route_type_descriptors(
        self,
    ) -> tuple[dict[str, Any], ...]:
        route_types = list(
            dict.fromkeys(
                str(item.get("route_type"))
                for item in (
                    *self._advertised_scenarios,
                    *self._generated_route_rows,
                )
                if item.get("route_type")
            )
        )
        return tuple(
            {
                "route_type": route_type,
                "label": route_type.replace("_", " ").upper(),
                "descriptor_source": "generated_plugin_projection",
            }
            for route_type in route_types
        )

    def _generated_route_family_descriptors(
        self,
    ) -> tuple[dict[str, Any], ...]:
        rows = (
            *self._advertised_scenarios,
            *self._generated_route_rows,
        )
        family_ids = list(
            dict.fromkeys(
                str(item.get("route_family"))
                for item in rows
                if item.get("route_family")
            )
        )
        result: list[dict[str, Any]] = []
        for route_family in family_ids:
            family_rows = [
                item
                for item in rows
                if item.get("route_family") == route_family
            ]
            address_families = list(
                dict.fromkeys(
                    str(item.get("address_family"))
                    for item in family_rows
                    if item.get("address_family")
                )
            )
            if len(address_families) != 1:
                raise MultiNodeRouteRequestError(
                    f"generated route_family {route_family} has ambiguous "
                    "address-family declarations"
                )
            presentation = self.policy.route_family_presentations.get(
                route_family,
                {},
            )
            result.append(
                {
                    "route_family": route_family,
                    "address_family": address_families[0],
                    "safi": str(presentation.get("safi") or "opaque"),
                    "label": str(
                        presentation.get("label")
                        or route_family.replace("_", " ").upper()
                    ),
                    "supported_route_types": list(
                        dict.fromkeys(
                            str(item.get("route_type"))
                            for item in family_rows
                            if item.get("route_type")
                        )
                    ),
                    "descriptor_source": "generated_plugin_projection",
                }
            )
        return tuple(result)

    def _generated_vrf_descriptors(
        self,
    ) -> tuple[dict[str, Any], ...]:
        rows = (
            *self._advertised_scenarios,
            *self._generated_route_rows,
        )
        vrf_ids = list(
            dict.fromkeys(
                str(item.get("vrf") or item.get("vrf_id"))
                for item in rows
                if item.get("vrf") or item.get("vrf_id")
            )
        )
        result: list[dict[str, Any]] = []
        for vrf_id in vrf_ids:
            vrf_rows = [
                item
                for item in rows
                if str(item.get("vrf") or item.get("vrf_id") or "")
                == vrf_id
            ]
            result.append(
                {
                    "vrf_id": vrf_id,
                    "vrf": vrf_id,
                    "label": vrf_id.replace("_", " ").upper(),
                    "description": (
                        "Generated plug-in route context."
                    ),
                    "route_families": list(
                        dict.fromkeys(
                            str(item.get("route_family"))
                            for item in vrf_rows
                            if item.get("route_family")
                        )
                    ),
                    "supported_route_types": list(
                        dict.fromkeys(
                            str(item.get("route_type"))
                            for item in vrf_rows
                            if item.get("route_type")
                        )
                    ),
                    "node_ids": list(
                        dict.fromkeys(
                            str(item.get("node_id"))
                            for item in vrf_rows
                            if item.get("node_id")
                        )
                    ),
                    "descriptor_source": "generated_plugin_projection",
                }
            )
        return tuple(result)

    def _family(self, route_family: str) -> dict[str, Any]:
        descriptor = next(
            (
                item
                for item in self._route_families
                if item["route_family"] == route_family
            ),
            None,
        )
        if descriptor is None:
            raise MultiNodeRouteRequestError(
                f"unknown route_family: {route_family}"
            )
        return descriptor

    def _vrf(self, vrf_id: str) -> dict[str, Any]:
        normalized = vrf_id.casefold()
        canonical = self.policy.vrf_aliases.get(normalized, normalized)
        descriptor = next(
            (
                item
                for item in self._vrfs
                if item["vrf_id"] == canonical
            ),
            None,
        )
        if descriptor is None:
            raise MultiNodeRouteRequestError(f"unknown vrf: {vrf_id}")
        return descriptor

    def _route_type_default_context(
        self,
        route_type: str,
    ) -> tuple[str, str]:
        candidates = [
            item
            for item in (
                *self._advertised_scenarios,
                *self._generated_route_rows,
            )
            if item.get("route_type") == route_type
            and item.get("route_family")
            and (item.get("vrf") or item.get("vrf_id"))
        ]
        if not candidates:
            raise MultiNodeRouteRequestError(
                f"unknown route_type: {route_type}"
            )
        selected = candidates[0]
        return (
            str(selected.get("vrf") or selected.get("vrf_id")),
            str(selected["route_family"]),
        )

    def _route_table_entries(self) -> list[dict[str, Any]]:
        """Return only rows emitted by the generated node projections."""

        return self._generated_route_table_entries()

    @staticmethod
    def _declared_boolean(
        row: dict[str, Any],
        field: str,
        fallback: bool,
    ) -> bool:
        value = row.get(field)
        return value if isinstance(value, bool) else fallback

    @staticmethod
    def _route_executor_multipath_mode(
        scenario: Mapping[str, Any],
        *,
        selected_count: int,
    ) -> str:
        """Resolve legacy single-path executors without inventing ECMP."""

        value = scenario.get("multipath_mode")
        if value in {"single_active", "all_active"}:
            return str(value)
        if value is None and selected_count <= 1:
            # Before the explicit group-mode field existed, one selected row
            # unambiguously meant the singular forwarding choice. Preserve
            # that executor compatibility without guessing when several rows
            # claim to forward concurrently.
            return "single_active"
        if value is None:
            raise MultiNodeRouteRequestError(
                "route executor contract v1 omits multipath_mode while "
                "declaring multiple selected candidates; declare "
                "single_active or all_active"
            )
        raise MultiNodeRouteRequestError(
            "route executor contract v1 multipath_mode must be "
            "single_active or all_active"
        )

    @staticmethod
    def _declared_trace_endpoint(
        trace_query: dict[str, Any],
        field: str,
    ) -> dict[str, Any]:
        endpoint = trace_query.get(field)
        return dict(endpoint) if isinstance(endpoint, dict) else {}

    def _generated_route_table_entry(
        self,
        row: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Map one plug-in row without re-deriving its route semantics.

        Inventory and scenario rows share one public adapter. The generator
        owns installation state, candidate endpoints, forwarding actions, and
        executable trace requests; this method adds only assembly identity,
        generic display fields, and correlation references.
        """

        if row.get("table_visible") is False:
            return None

        node_id = str(row.get("node_id") or "")
        route_type = str(row.get("route_type") or "")
        route_family = str(row.get("route_family") or "")
        declared_vrf = row.get("vrf") or row.get("vrf_id")
        if not isinstance(declared_vrf, str) or not declared_vrf:
            return None
        vrf_id = declared_vrf
        known_route_types = {
            str(item["route_type"]) for item in self._route_types
        }
        known_vrfs = {str(item["vrf_id"]) for item in self._vrfs}
        if (
            node_id not in self._routers_by_id
            or route_type not in known_route_types
            or not route_family
            or vrf_id not in known_vrfs
        ):
            return None
        try:
            family = self._family(route_family)
        except MultiNodeRouteRequestError:
            return None
        if str(row.get("address_family") or family["address_family"]) != str(
            family["address_family"]
        ):
            return None

        router = self._router(node_id)
        member_id = str(
            self.topology.nodes_by_id.get(node_id, {}).get("member_id")
            or f"member:{node_id}"
        )
        route_entry_id = str(
            row.get("route_id") or f"{node_id}/route/local"
        )
        table_id = str(
            row.get("table_id")
            or f"route-table:{node_id}:{vrf_id}:{route_family}"
        )
        route_entry_ref = {
            "assembly_id": self.topology.assembly_id,
            "node_id": node_id,
            "member_id": member_id,
            "plugin_id": self._generated_plugin_provider(node_id).get(
                "plugin_id"
            ),
            "table_id": table_id,
            "route_entry_id": route_entry_id,
        }
        evidence_ids = [
            str(item)
            for item in row.get("evidence_resource_ids", [])
            if item
        ]
        candidate_next_hops = [
            dict(item)
            for item in row.get("candidate_next_hops", [])
            if isinstance(item, dict)
        ]
        connected_attachment = row.get("connected_attachment")
        if (
            not candidate_next_hops
            and isinstance(connected_attachment, dict)
            and connected_attachment.get("resource_id")
        ):
            attachment_resource_id = str(
                row.get("egress_interface_resource_id")
                or connected_attachment["resource_id"]
            )
            candidate_next_hops.append(
                {
                    "next_hop_id": f"{route_entry_id}:connected-attachment",
                    "kind": "connected_attachment",
                    "value": str(
                        connected_attachment.get("subnet")
                        or attachment_resource_id
                    ),
                    "neighbor_node_id": None,
                    "interface_resource_id": attachment_resource_id,
                    "egress_interface_resource_id": attachment_resource_id,
                    "active": self._declared_boolean(
                        row,
                        "active",
                        self._declared_boolean(row, "selected", False),
                    ),
                    "backup": False,
                    "weight": 1,
                    "attachment": dict(connected_attachment),
                }
            )
        next_hops: list[dict[str, Any]] = []
        for index, candidate in enumerate(candidate_next_hops):
            active = self._declared_boolean(
                candidate,
                "active",
                False,
            )
            next_hop_id = str(
                candidate.get("next_hop_id")
                or f"{route_entry_id}:next-hop:{index}"
            )
            interface_resource_id = str(
                candidate.get("interface_resource_id")
                or candidate.get("egress_interface_resource_id")
                or ""
            )
            next_hops.append(
                {
                    **candidate,
                    "next_hop_id": next_hop_id,
                    "kind": str(
                        candidate.get("kind") or "neighbor_router"
                    ),
                    "value": str(
                        candidate.get("value")
                        or candidate.get("via")
                        or candidate.get("node_id")
                        or "unknown"
                    ),
                    "neighbor_node_id": candidate.get(
                        "neighbor_node_id",
                        candidate.get("node_id"),
                    ),
                    "egress_interface_resource_id": (
                        interface_resource_id or None
                    ),
                    "active": active,
                    "backup": self._declared_boolean(
                        candidate,
                        "backup",
                        not active,
                    ),
                    "weight": int(candidate.get("weight", 1)),
                }
            )

        forwarding_actions = [
            dict(item)
            for item in row.get("forwarding_actions", [])
            if isinstance(item, dict)
        ]

        raw_trace_query = row.get("trace_query")
        trace_query = (
            dict(raw_trace_query)
            if isinstance(raw_trace_query, dict) and raw_trace_query
            else {}
        )
        scenario_id = str(
            row.get("trace_scenario_id")
            or row.get("scenario_id")
            or ""
        )
        if trace_query:
            trace_query.setdefault("scenario_id", scenario_id)
            trace_query.setdefault("direction", "both")
            trace_query.setdefault("route_type", route_type)
            trace_query.setdefault("route_family", route_family)
            trace_query.setdefault(
                "address_family",
                family["address_family"],
            )
            trace_query.setdefault("vrf_id", vrf_id)
            trace_query.setdefault("vrf", vrf_id)
            trace_query["route_entry_ref"] = route_entry_ref
            if row.get("trace_candidate_id"):
                trace_query["trace_candidate_id"] = str(
                    row["trace_candidate_id"]
                )

        coverage = self._generated_coverage_by_id.get(
            str(row.get("scenario_id") or ""),
            {},
        )
        destination_request = self._declared_trace_endpoint(
            trace_query,
            "destination",
        )
        destination_node_id = str(
            row.get("destination_node_id")
            or destination_request.get("node_id")
            or (coverage.get("destination") or {}).get("node_id")
            or node_id
        )
        destination_id = str(
            destination_request.get("destination_id")
            or destination_request.get("endpoint_id")
            or trace_query.get("destination_id")
            or f"destination:{destination_node_id}"
        )
        destination_value = str(
            row.get("destination")
            or destination_request.get("value")
            or destination_id
        )
        destination_router = self._routers_by_id.get(destination_node_id)
        destination_label = (
            str(destination_router["label"])
            if destination_router is not None
            else destination_node_id
        )

        decision = str(row.get("decision") or "unknown")
        selected = self._declared_boolean(
            row,
            "selected",
            decision == "active",
        )
        installed = self._declared_boolean(
            row,
            "installed",
            selected,
        )
        active = self._declared_boolean(row, "active", selected)
        backup = self._declared_boolean(
            row,
            "backup",
            not active and bool(next_hops),
        )
        forwarding_capable = self._declared_boolean(
            row,
            "forwarding_capable",
            installed and active,
        )
        install_state = str(
            row.get("install_state")
            or ("installed" if installed else decision)
        )
        egress_resource_id = str(
            row.get("egress_interface_resource_id")
            or row.get("interface_resource_id")
            or (
                connected_attachment.get("resource_id")
                if isinstance(connected_attachment, dict)
                else ""
            )
            or (
                next_hops[0].get("egress_interface_resource_id")
                if next_hops
                else ""
            )
            or (evidence_ids[0] if evidence_ids else "")
            or f"{node_id}/control-plane/IP_ROUTING/{vrf_id}"
        )
        provider = {
            **self._generated_plugin_provider(node_id),
            "decision_owner": "node_route_plugin",
            "data_kind": "generated_route_table_row",
        }
        trace_candidate_id = (
            str(row["trace_candidate_id"])
            if row.get("trace_candidate_id")
            else None
        )
        catalog_id = str(
            row.get("inventory_context_id")
            or row.get("scenario_id")
            or "inventory"
        )
        traceable = bool(trace_query)
        return {
            "route_entry_id": route_entry_id,
            "row_id": route_entry_id,
            "route_entry_ref": route_entry_ref,
            "node_id": node_id,
            "member_id": member_id,
            "node_label": router["label"],
            "table_id": table_id,
            "vrf_id": vrf_id,
            "vrf": vrf_id,
            "address_family": family["address_family"],
            "safi": family["safi"],
            "route_family": route_family,
            "route_type": route_type,
            "prefix": destination_value,
            "destination": {
                **destination_request,
                "destination_id": destination_id,
                "node_id": destination_node_id,
                "kind": str(
                    destination_request.get("kind") or "plugin_owned"
                ),
                "value": str(
                    destination_request.get("value")
                    or destination_value
                ),
                "label": str(
                    destination_request.get("label")
                    or destination_label
                ),
            },
            "source": str(row.get("protocol") or "unknown"),
            "source_protocol": str(
                row.get("protocol") or "unknown"
            ),
            "protocol": str(row.get("protocol") or "unknown"),
            "owner": "node_route_plugin",
            "next_hops": next_hops,
            "forwarding_actions": forwarding_actions,
            "egress_interface": {
                "resource_id": egress_resource_id,
                "name": egress_resource_id.rsplit("/", 1)[-1],
                "node_id": node_id,
            },
            "metric": int(row.get("metric", 0)),
            "preference": row.get("preference"),
            "selected": selected,
            "installed": installed,
            "active": active,
            "backup": backup,
            "status": decision,
            "install_state": install_state,
            "forwarding_capable": forwarding_capable,
            "path_id": row.get("path_id"),
            "trace_candidate_id": trace_candidate_id,
            "candidate_path_ids": [
                str(item)
                for item in row.get("candidate_path_ids", [])
                if item
            ],
            "route_catalog_id": f"generated-route:{catalog_id}",
            "correlation_ids": [
                f"generated-route:{catalog_id}",
                route_entry_id,
            ],
            "resource_refs": [
                {
                    "member_id": member_id,
                    "node_id": node_id,
                    "local_resource_id": evidence_id,
                }
                for evidence_id in evidence_ids
            ],
            "traceable": traceable,
            "trace_unavailable_reason": (
                None
                if traceable
                else "The plug-in did not declare an executable trace action."
            ),
            "trace_query": trace_query,
            "status_perspective_id": row.get(
                "status_perspective_id"
            ),
            "plugin_provenance": provider,
            "attributes": dict(row),
            "plugin_details": dict(row),
            "valid_from_ns": str(row.get("observed_at_ns")),
            "valid_to_ns": row.get("valid_to_ns"),
        }

    def _generated_route_table_entries(self) -> list[dict[str, Any]]:
        """Project generated plug-in rows into the generic route-table shape."""

        result = [
            entry
            for row in self._generated_route_rows
            if (entry := self._generated_route_table_entry(row))
            is not None
        ]
        result.sort(
            key=lambda item: (
                item["node_id"],
                item["vrf_id"],
                item["route_family"],
                item["route_entry_id"],
            )
        )
        return result

    def _route_catalog(self) -> list[dict[str, Any]]:
        rows = [
            {
                "route_id": str(item["route_id"]),
                "scenario_id": (
                    str(item["scenario_id"])
                    if item.get("scenario_id")
                    else None
                ),
                "route_type": item.get("route_type"),
                "route_family": item.get("route_family"),
                "address_family": item.get("address_family"),
                "vrf": item.get("vrf"),
                "source_node_id": str(item["node_id"]),
                "revision_id": str(item["revision_id"]),
                "destination": item.get("destination"),
                "decision": item.get("decision"),
                "observed_at_ns": item.get("observed_at_ns"),
                "candidate_next_hops": [
                    dict(candidate)
                    for candidate in item.get(
                        "candidate_next_hops",
                        [],
                    )
                    if isinstance(candidate, dict)
                ],
                "decision_owner": "node_route_plugin",
                "descriptor_source": "generated_plugin_projection",
                "plugin_provenance": dict(
                    self._generated_provider_by_node.get(
                        str(item["node_id"]),
                        {},
                    )
                ),
            }
            for item in self._generated_route_rows
            if item.get("route_id")
            and item.get("node_id")
            and item.get("revision_id")
            and (
                not item.get("scenario_id")
                or str(item["scenario_id"])
                in self._advertised_scenario_by_id
            )
        ]
        rows.sort(
            key=lambda item: (
                item["source_node_id"],
                str(item["scenario_id"] or ""),
                item["route_id"],
            )
        )
        return rows

    def _generated_route_resolvers(self) -> list[dict[str, Any]]:
        """Return exact providers carried by generated projection manifests."""

        route_nodes = {
            str(item.get("node_id"))
            for item in self._generated_route_rows
            if item.get("node_id")
        }
        forwarding_nodes = {
            str(item.get("node_id"))
            for item in self._generated_forwarding_rows
            if item.get("node_id")
        }
        return [
            {
                "node_id": node_id,
                "member_id": f"member:{node_id}",
                "revision_id": self._generated_revision_by_node[node_id],
                **dict(provider),
                "roles": [
                    *(
                        ["local_resolution"]
                        if node_id in route_nodes
                        else []
                    ),
                    *(
                        ["forwarding_observation"]
                        if node_id in forwarding_nodes
                        else []
                    ),
                ],
                "descriptor_source": "generated_projection_manifest",
            }
            for node_id, provider in self._generated_provider_by_node.items()
        ]

    def _generated_routed_nodes(self) -> list[dict[str, Any]]:
        """Return route participants from normalized node metadata."""

        route_node_ids = {
            str(row["node_id"])
            for row in self._generated_route_rows
            if row.get("node_id")
        }
        result: list[dict[str, Any]] = []
        for node in self.topology.contract["nodes"]:
            roles = [str(item) for item in node.get("roles", []) if item]
            node_id = str(node["node_id"])
            if node_id not in route_node_ids:
                continue
            provider = self._generated_provider_by_node.get(node_id)
            if provider is None:
                continue
            result.append(
                {
                    "node_id": node_id,
                    "member_id": str(
                        node.get("member_id") or f"member:{node_id}"
                    ),
                    "revision_id": str(node["revision_id"]),
                    "label": str(node.get("label") or node_id),
                    "site": str(node.get("site") or "unspecified"),
                    "roles": roles,
                    "plugin_provenance": dict(provider),
                    "descriptor_source": "generated_assembly_catalog",
                }
            )
        if not result:
            raise MultiNodeRouteRequestError(
                "the projection set advertises no routed node participants"
            )
        return result

    def _generated_route_endpoints(
        self,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
    ]:
        """Build capability endpoints from generated nodes and coverage."""

        nodes = self._generated_routed_nodes()

        def scenario_ids(node_id: str) -> list[str]:
            return [
                str(item["scenario_id"])
                for item in self._advertised_scenarios
                if node_id
                in {
                    str(item.get("source", {}).get("node_id") or ""),
                    str(item.get("destination", {}).get("node_id") or ""),
                    *{
                        str(value)
                        for value in item.get("involved_node_ids", [])
                    },
                }
            ]

        sources = [
            {
                **node,
                "endpoint_id": f"source:{node['node_id']}",
                "source_id": f"source:{node['node_id']}",
                "route_participant": True,
                "supported_scenario_ids": scenario_ids(node["node_id"]),
            }
            for node in nodes
        ]
        start_points = [
            {
                **node,
                "start_id": f"start:{node['node_id']}",
                "semantic_role": "traversal_seed",
                "route_participant": True,
                "supported_scenario_ids": scenario_ids(node["node_id"]),
            }
            for node in nodes
        ]
        destinations = [
            {
                **node,
                "endpoint_id": f"destination:{node['node_id']}",
                "destination_id": f"destination:{node['node_id']}",
                "kind": "router_node",
                "value": node["node_id"],
                "route_participant": True,
                "supported_scenario_ids": scenario_ids(node["node_id"]),
            }
            for node in nodes
        ]
        return sources, start_points, destinations

    def _generated_directional_pairs(self) -> list[dict[str, Any]]:
        """Derive endpoint pairs from generated coverage, never fixture globals."""

        pairs: list[dict[str, Any]] = []
        for scenario in self._advertised_scenarios:
            source = scenario.get("source")
            destination = scenario.get("destination")
            if not isinstance(source, dict) or not isinstance(
                destination,
                dict,
            ):
                continue
            source_node = str(source.get("node_id") or "")
            destination_node = str(destination.get("node_id") or "")
            source_id = str(
                scenario.get("default_source")
                or source.get("endpoint_id")
                or ""
            )
            destination_id = str(
                scenario.get("default_destination")
                or destination.get("endpoint_id")
                or ""
            )
            if not all(
                (
                    source_node,
                    destination_node,
                    source_id,
                    destination_id,
                )
            ):
                continue
            route_context = {
                key: scenario[key]
                for key in (
                    "route_type",
                    "route_family",
                    "address_family",
                )
                if scenario.get(key)
            }
            pairs.append(
                {
                    "pair_id": (
                        f"generated-pair:{scenario['scenario_id']}"
                    ),
                    "label": str(
                        scenario.get("label")
                        or scenario["scenario_id"]
                    ),
                    "scenario_id": str(scenario["scenario_id"]),
                    "forward": {
                        "source_id": source_id,
                        "destination_id": destination_id,
                        **route_context,
                    },
                    "reverse": {
                        "source_id": f"source:{destination_node}",
                        "destination_id": f"destination:{source_node}",
                        **route_context,
                    },
                    "expected_comparison": str(
                        scenario.get("expected_outcome")
                        or "unspecified"
                    ),
                    "descriptor_source": "generated_coverage_registry",
                }
            )
        return pairs

    def _generated_network_model(self) -> dict[str, Any]:
        routed_nodes = self._generated_routed_nodes()
        return {
            "router_count": len(routed_nodes),
            "assembly_node_count": len(self.topology.contract["nodes"]),
            "physical_topology": "generated_plugin_projection",
            "physical_connectivity_source": (
                "generated_topology_segment_claims"
            ),
            "network_segment_matchers": [
                dict(item)
                for item in self.topology.contract[
                    "network_segment_matchers"
                ]
            ],
            "routed_node_ids": [
                str(item["node_id"]) for item in routed_nodes
            ],
            "descriptor_source": "generated_assembly_catalog",
        }

    def capabilities(self) -> dict[str, Any]:
        topology_capabilities = self.topology.capabilities()
        generated_endpoints = self._generated_route_endpoints()
        default_request: dict[str, Any] = {
            "direction": "forward",
            "resolution_mode": "best_effort",
            "steering_profile_id": "observed",
            "max_hops": 64,
            "max_recursion": 16,
            "clock_policy": "best_effort",
            "basis": {"kind": "relative_to_watermark", "offset_ns": "0"},
        }
        if generated_endpoints:
            scenarios = list(self._advertised_scenarios)
            sources_by_id = {
                str(item["source_id"]): item
                for item in generated_endpoints[0]
            }
            starts_by_id = {
                str(item["start_id"]): item
                for item in generated_endpoints[1]
            }
            destinations_by_id = {
                str(item["destination_id"]): item
                for item in generated_endpoints[2]
            }
            executable_defaults = [
                item
                for item in scenarios
                if str(item.get("default_source") or "")
                in sources_by_id
                and str(item.get("default_destination") or "")
                in destinations_by_id
                and str(item.get("default_start") or "")
                in starts_by_id
            ]
            if not executable_defaults:
                raise MultiNodeRouteRequestError(
                    "the projection set advertises no catalog-resolvable "
                    "default route request"
                )
            default_scenario = next(
                (
                    item
                    for item in executable_defaults
                    if item.get("scenario_id")
                    == self.policy.default_scenario_id
                ),
                None,
            )
            if default_scenario is None:
                raise MultiNodeRouteRequestError(
                    "route policy default scenario is not executable in the "
                    "the projection set"
                )
            source_id = str(default_scenario["default_source"])
            destination_id = str(
                default_scenario["default_destination"]
            )
            start_id = str(default_scenario["default_start"])
            source = dict(sources_by_id[source_id])
            destination = dict(destinations_by_id[destination_id])
            ingress = dict(starts_by_id[start_id])
            default_request.update(
                {
                    "scenario_id": str(
                        default_scenario["scenario_id"]
                    ),
                    "route_type": str(
                        default_scenario.get("route_type") or ""
                    ),
                    "route_family": str(
                        default_scenario.get("route_family") or ""
                    ),
                    "address_family": str(
                        default_scenario.get("address_family") or ""
                    ),
                    "vrf": str(default_scenario["vrf"]),
                    "vrf_id": str(default_scenario["vrf_id"]),
                    "source_id": source_id,
                    "destination_id": destination_id,
                    "source": source,
                    "destination": destination,
                    "flow": {
                        "source": dict(source),
                        "destination": dict(destination),
                    },
                    "ingress": ingress,
                }
            )
        return {
            "api_version": "v1",
            "assembly_id": self.topology.assembly_id,
            "topology_id": self.topology.topology_id,
            "label": "Heterogeneous cross-node route trace",
            "description": (
                "Retains active and inactive candidates, cross-layer disagreements, "
                "exact-state cycles, policy exclusions, and explicitly sourced "
                "best-effort continuations."
            ),
            "default_request": default_request,
            "sources": generated_endpoints[0],
            "start_points": generated_endpoints[1],
            "destinations": generated_endpoints[2],
            "route_types": [dict(item) for item in self._route_types],
            "route_families": [
                dict(item) for item in self._route_families
            ],
            "vrfs": [
                {
                    **item,
                    "node_ids": list(item["node_ids"]),
                }
                for item in self._vrfs
            ],
            "route_tables": {
                "schema_version": self.policy.route_table_schema_version,
                "state_location": "time_bound_query_only",
                "available_node_ids": [
                    item["node_id"]
                    for item in self._generated_routed_nodes()
                ],
                "entry_count_at_snapshot": len(self._route_table_entries()),
                "columns": [
                    "node_id",
                    "vrf_id",
                    "address_family",
                    "route_family",
                    "prefix",
                    "route_type",
                    "source_protocol",
                    "next_hops",
                    "forwarding_actions",
                    "egress_interface",
                    "metric",
                    "preference",
                    "active",
                    "backup",
                    "install_state",
                    "plugin_provenance",
                ],
                "query_href": (
                    f"/v1/topology-assemblies/{self.topology.assembly_id}/"
                    "routes/tables/query"
                ),
                "alias_query_href": "/v1/topologies/routes/tables/query",
                "max_page_size": 500,
            },
            "network_model": self._generated_network_model(),
            "route_catalog": self._route_catalog(),
            "directional_pairs": self._generated_directional_pairs(),
            "resolution_modes": [
                {
                    "mode": "strict",
                    "semantics": "Do not cross a missing node-local or boundary decision.",
                },
                {
                    "mode": "best_effort",
                    "semantics": (
                        "Core may join plug-in output through the reconstructed topology "
                        "and contemporaneous node status, with explicit provenance and "
                        "reduced confidence."
                    ),
                },
            ],
            "scenarios": [
                dict(item) for item in self._advertised_scenarios
            ],
            "packet_trace": {
                "schema_version": self.policy.packet_trace_schema_version,
                "layer_order": "outermost_to_innermost",
                "maximum_layers": 256,
                "maximum_transitions": 256,
                "continuity_owner": "core",
                "packet_action_owner": "node_plugins",
                "mtu_semantics_owner": "node_plugins",
                "mtu_comparison_owner": "core_exact_basis_only",
                "federation_boundary_behavior": (
                    "preserve_or_explicitly_map_packet_contract"
                ),
                "user_forced_results_are_counterfactual": True,
                "steering_profiles": [
                    dict(item) for item in self.policy.steering_profiles
                ],
            },
            "steering_profiles": [
                dict(item) for item in self.policy.steering_profiles
            ],
            "route_resolvers": self._generated_route_resolvers(),
            "federation_resolver": topology_capabilities["federation_plugin"],
            "request_contract": {
                "scenario_id": "one advertised scenario_id",
                "flow": (
                    "immutable traffic source and destination endpoints; "
                    "top-level source/destination remain compatibility aliases"
                ),
                "ingress": (
                    "forward traversal/observation start, independent from the "
                    "traffic source"
                ),
                "trace_starts": (
                    "optional per-direction start points; reverse otherwise "
                    "starts from a destination endpoint attachment"
                ),
                "resolution_mode": "strict or best_effort",
                "resolution_policy": "compatibility alias for resolution_mode",
                "completeness_policy": "documentation compatibility alias for resolution_mode",
                "destination_id": "one advertised destinations[].destination_id",
                "source_id": "one advertised sources[].source_id",
                "direction": "forward, reverse, or both",
                "route_type": "one advertised route_types[].route_type",
                "route_family": (
                    "one advertised route_families[].route_family; address_family "
                    "is a compatibility selector"
                ),
                "vrf_id": (
                    "one advertised vrfs[].vrf_id; vrf is a compatibility alias"
                ),
                "routing_context": (
                    "structured form of vrf_id, route_family/address_family, "
                    "route_type, table_id, and opaque constraints"
                ),
                "route_entry_ref": (
                    "optional opaque reference returned by the route-table query"
                ),
                "focus_path_id": (
                    "optional stable path_id; inactive and inconsistent candidates are valid"
                ),
                "max_hops": (
                    "bounded maximum inter-node transitions, integer 1 through 128"
                ),
                "max_recursion": (
                    "bounded maximum recursive lookup depth, integer 0 through 64"
                ),
                "basis": topology_capabilities["time_bases"],
                "clock_policy": topology_capabilities["clock_policies"],
                "node_queries": (
                    "optional heterogeneous per-node selections accepted by topology query"
                ),
                "bidirectional_criterion": (
                    "forward reaches the traffic destination and reverse reaches "
                    "the traffic source; reverse need not revisit forward ingress"
                ),
            },
            "response_contract": {
                "paths": "all candidate paths, never only the selected or active path",
                "route_resolution_sequence": (
                    "ordered plug-in-provided text objects for the focused path"
                ),
                "interaction_targets": (
                    "stable bidirectional targets shared by text parts and topology objects"
                ),
                "highlight_target_ids": (
                    "exact typed topology-node or topology-link targets selected by plug-ins; "
                    "the core preserves the IDs without interpreting route text"
                ),
                "path_graph_target_ids": (
                    "ordered exact graph targets aggregated from each path's structured segments"
                ),
                "path_outcome": (
                    "normalized role, result, eligibility, and terminal_reason on "
                    "every candidate, including cycle and policy_blocked"
                ),
                "cycle": (
                    "typed repeated canonical traversal state with first and closing steps"
                ),
                "policy_decisions": (
                    "core-evaluated verdicts retaining plug-in constraints, scope "
                    "completeness, reasons, and evidence on each candidate"
                ),
                "node_occurrences": (
                    "ordered path-local router occurrences; repeated nodes are not deduplicated"
                ),
                "issues": "cross-layer, boundary, incompleteness, and inference findings",
                "endpoint_reachability": (
                    "typed terminal endpoint matching for each direction"
                ),
                "path_relation": (
                    "symmetric, asymmetric, or not_comparable descriptive path "
                    "shape; it does not determine consistency"
                ),
            },
            "semantic_ownership": {
                "core": [
                    "time alignment",
                    "ordering and joining plug-in-provided resolution steps",
                    "candidate retention and focus selection",
                    "bounded traversal and canonical-state cycle detection",
                    (
                        "exact typed policy comparison, decision validation, "
                        "and aggregate verdict handling"
                    ),
                    "uncertainty, completeness, and best-effort evidence accounting",
                    (
                        "immutable flow direction, endpoint-goal matching, and "
                        "bidirectional reachability aggregation"
                    ),
                ],
                "node_plugins": [
                    "local route resolution and candidate activity",
                    "route_resolution text and resource references",
                    "layer-specific reachability and forwarding semantics",
                    "route-table keys, VRF/family semantics, preference, and next hops",
                    (
                        "policy constraints, scope construction/completeness, "
                        "reasons, and evidence"
                    ),
                    "endpoint attachment and local terminal/delivery classification",
                ],
                "federation_linker": [
                    "inter-node endpoint identity and boundary candidates"
                ],
            },
            "limits": {
                "max_candidate_paths": self.MAX_CANDIDATE_PATHS,
                "max_segments_per_path": self.MAX_SEGMENTS_PER_PATH,
                "default_max_hops": 64,
                "maximum_max_hops": 128,
                "default_max_recursion": 16,
                "maximum_max_recursion": 64,
            },
            "topology_capabilities_href": (
                f"/v1/topology-assemblies/{self.topology.assembly_id}/capabilities"
            ),
            "trace_href": (
                f"/v1/topology-assemblies/{self.topology.assembly_id}/routes/trace"
            ),
            "route_table_query_href": (
                f"/v1/topology-assemblies/{self.topology.assembly_id}/"
                "routes/tables/query"
            ),
            "data_disclosure": self.policy.data_disclosure,
        }

    def route_tables(self, body: dict[str, Any]) -> dict[str, Any]:
        """Federate opaque plug-in route rows at one topology time context."""

        if not isinstance(body, dict):
            raise MultiNodeRouteRequestError("request body must be an object")
        context_aliases = {
            str(body[field])
            for field in ("topology_context_id", "context_id")
            if body.get(field) is not None
        }
        if len(context_aliases) > 1:
            raise MultiNodeRouteRequestError(
                "context_id and topology_context_id disagree"
            )
        requested_context_id = next(iter(context_aliases), None)
        if requested_context_id is not None:
            snapshot = self.topology._contexts.get(requested_context_id)
            if snapshot is None:
                raise MultiNodeRouteRequestError(
                    "unknown or expired topology context"
                )
            effective_basis = snapshot["resolved_basis"]["requested"]
            effective_clock_policy = snapshot["resolved_basis"]["clock_policy"]
            if (
                body.get("basis") is not None
                and self.topology.normalize_basis(body["basis"])
                != self.topology.normalize_basis(effective_basis)
            ):
                raise MultiNodeRouteRequestError(
                    "basis disagrees with the selected topology context"
                )
            if (
                body.get("clock_policy") is not None
                and str(body["clock_policy"]) != effective_clock_policy
            ):
                raise MultiNodeRouteRequestError(
                    "clock_policy disagrees with the selected topology context"
                )
            self._validate_context_node_selection(body, snapshot)
        else:
            requested_basis = (
                self.topology.normalize_basis(body["basis"])
                if body.get("basis") is not None
                else {"kind": "relative_to_watermark", "offset_ns": "0"}
            )
            topology_request: dict[str, Any] = {
                "basis": requested_basis,
                "clock_policy": body.get("clock_policy", "best_effort"),
                "resource_limit": 500,
                "inter_node_link_limit": 1000,
            }
            selected_nodes = body.get("node_ids")
            if selected_nodes is None and "node_queries" not in body:
                selected_nodes = list(self._routers_by_id)
            if selected_nodes is not None:
                topology_request["node_ids"] = selected_nodes
            if "node_queries" in body:
                topology_request["node_queries"] = body["node_queries"]
            snapshot = self.topology.query(topology_request)
            effective_basis = snapshot["resolved_basis"]["requested"]
            effective_clock_policy = snapshot["resolved_basis"]["clock_policy"]

        filters = self._optional_object(body, "filters")
        page_request = self._optional_object(body, "page")
        limit = self._bounded_page_integer(
            page_request.get("limit", body.get("limit", 250)),
            "page.limit",
            minimum=1,
            maximum=500,
        )
        cursor = page_request.get("cursor")
        if cursor is None:
            offset = self._bounded_page_integer(
                page_request.get("offset", body.get("offset", 0)),
                "page.offset",
                minimum=0,
                maximum=100_000,
            )
        else:
            # Decoded only after the query-bound route-table context digest is
            # known.  A cursor can never be reused against another filter set.
            offset = 0

        selected_node_ids = {
            str(item["node_id"])
            for item in snapshot["nodes"]
            if item.get("available", True)
        }
        node_filter = self._filter_values(
            filters,
            plural=("node_ids",),
            singular=("node_id",),
        )
        if node_filter:
            unknown = node_filter - set(self._routers_by_id)
            if unknown:
                raise MultiNodeRouteRequestError(
                    f"unknown route-table node_ids: {sorted(unknown)}"
                )
            selected_node_ids &= node_filter
        vrf_filter = self._filter_values(
            filters,
            plural=("vrf_ids", "vrfs"),
            singular=("vrf_id", "vrf"),
        )
        vrf_filter = {
            self._vrf(value)["vrf_id"] for value in vrf_filter
        }
        family_filter = self._filter_values(
            filters,
            plural=("route_families",),
            singular=("route_family",),
        )
        for value in family_filter:
            self._family(value)
        address_filter = self._filter_values(
            filters,
            plural=("address_families",),
            singular=("address_family",),
        )
        known_address_families = {
            item["address_family"] for item in self._route_families
        }
        unknown_addresses = address_filter - known_address_families
        if unknown_addresses:
            raise MultiNodeRouteRequestError(
                f"unknown address_families: {sorted(unknown_addresses)}"
            )
        type_filter = self._filter_values(
            filters,
            plural=("route_types",),
            singular=("route_type",),
        )
        known_types = {item["route_type"] for item in self._route_types}
        unknown_types = type_filter - known_types
        if unknown_types:
            raise MultiNodeRouteRequestError(
                f"unknown route_types: {sorted(unknown_types)}"
            )
        protocol_filter = self._filter_values(
            filters,
            plural=("protocols",),
            singular=("protocol", "source_protocol"),
        )
        active_filter = self._optional_boolean(filters, "active")
        installed_filter = self._optional_boolean(filters, "installed")
        text_filter = str(filters.get("text", "")).strip().casefold()
        destination_filter = filters.get("destination")
        if destination_filter is not None and not isinstance(
            destination_filter, (str, dict)
        ):
            raise MultiNodeRouteRequestError(
                "filters.destination must be a string or object"
            )
        destination_value = (
            str(destination_filter.get("value", "")).strip()
            if isinstance(destination_filter, dict)
            else str(destination_filter or "").strip()
        )
        destination_match = (
            str(destination_filter.get("match", "exact"))
            if isinstance(destination_filter, dict)
            else "exact"
        )
        if destination_match not in {"exact", "text"}:
            raise MultiNodeRouteRequestError(
                "filters.destination.match must be exact or text; prefix-match "
                "semantics belong to the node plug-in"
            )

        nodes_by_id = {str(item["node_id"]): item for item in snapshot["nodes"]}
        rows: list[dict[str, Any]] = []
        for row in self._route_table_entries():
            if row["node_id"] not in selected_node_ids:
                continue
            if vrf_filter and row["vrf_id"] not in vrf_filter:
                continue
            if family_filter and row["route_family"] not in family_filter:
                continue
            if address_filter and row["address_family"] not in address_filter:
                continue
            if type_filter and row["route_type"] not in type_filter:
                continue
            if protocol_filter and row["source_protocol"] not in protocol_filter:
                continue
            if active_filter is not None and row["active"] is not active_filter:
                continue
            if installed_filter is not None and row["installed"] is not installed_filter:
                continue
            if destination_value:
                candidate_values = {
                    str(row["prefix"]),
                    str(row["destination"]["value"]),
                    str(row["destination"]["destination_id"]),
                    str(row["destination"]["node_id"]),
                }
                matches = (
                    destination_value in candidate_values
                    if destination_match == "exact"
                    else any(
                        destination_value.casefold() in value.casefold()
                        for value in candidate_values
                    )
                )
                if not matches:
                    continue
            if text_filter and text_filter not in json.dumps(
                row, sort_keys=True, default=str
            ).casefold():
                continue
            node = nodes_by_id[row["node_id"]]
            resolved_time = node.get("resolved_time") or {}
            basis_time_ns = resolved_time.get("query_time_ns")
            if basis_time_ns is not None:
                timestamp_ns = int(basis_time_ns)
                if timestamp_ns < self.topology.start_ns:
                    continue
            rows.append(
                {
                    **row,
                    "basis_time_ns": basis_time_ns,
                    "quality": (
                        "exact"
                        if resolved_time.get("resolution") == "exact"
                        else "best_effort"
                    ),
                    "resolved_time": resolved_time,
                    "topology_context_id": snapshot["context_id"],
                }
            )

        rows.sort(
            key=lambda item: (
                item["node_id"],
                item["vrf_id"],
                item["route_family"],
                item["prefix"],
                item["route_type"],
                item["backup"],
            )
        )
        context_material = {
            "topology_context_id": snapshot["context_id"],
            "filters": filters,
            "route_entry_ids": [item["route_entry_id"] for item in rows],
        }
        context_digest = hashlib.sha256(
            json.dumps(
                context_material,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        ).hexdigest()[:24]
        route_table_context_id = f"rtctx1-{context_digest}"
        if cursor is not None:
            offset = self._decode_route_table_cursor(
                cursor, route_table_context_id
            )
        for row in rows:
            row["route_table_context_id"] = route_table_context_id
            if row["traceable"]:
                row["trace_query"] = {
                    **row["trace_query"],
                    "topology_context_id": snapshot["context_id"],
                    "route_table_context_id": route_table_context_id,
                }
        total = len(rows)
        returned = rows[offset : offset + limit]
        next_offset = offset + len(returned)
        truncated = next_offset < total
        next_cursor = (
            self._encode_route_table_cursor(
                route_table_context_id, next_offset
            )
            if truncated
            else None
        )
        returned_ids = {item["route_entry_id"] for item in returned}
        node_summaries = []
        for node in snapshot["nodes"]:
            node_rows = [item for item in rows if item["node_id"] == node["node_id"]]
            node_summaries.append(
                {
                    "node_id": node["node_id"],
                    "member_id": node["member_id"],
                    "label": node["label"],
                    "plugin_set_id": node["plugin_set_id"],
                    "resolved_time": node.get("resolved_time"),
                    "available": node.get("available", True),
                    "complete": node.get("complete", False),
                    "entry_count": len(node_rows),
                    "returned_count": sum(
                        item["route_entry_id"] in returned_ids for item in node_rows
                    ),
                    "plugin_provenance": dict(
                        self._generated_provider_by_node.get(
                            str(node["node_id"]),
                            {},
                        )
                    ),
                }
            )
        response = {
            "api_version": "v1",
            "assembly_id": self.topology.assembly_id,
            "topology_id": self.topology.topology_id,
            "schema_version": self.policy.route_table_schema_version,
            "route_table_context_id": route_table_context_id,
            "topology_context_id": snapshot["context_id"],
            "request": {
                "topology_context_id": requested_context_id,
                "basis": effective_basis,
                "clock_policy": effective_clock_policy,
                "filters": filters,
                "page": {"limit": limit, "cursor": cursor, "offset": offset},
            },
            "resolved_basis": snapshot["resolved_basis"],
            "capture_vector": [
                {
                    "node_id": item["node_id"],
                    "member_id": item["member_id"],
                    "resolved_time": item.get("resolved_time"),
                    "complete": item.get("complete", False),
                }
                for item in snapshot["nodes"]
            ],
            "items": returned,
            "node_summaries": node_summaries,
            "counts": {
                "total": total,
                "returned": len(returned),
                "nodes": len({item["node_id"] for item in rows}),
            },
            "facets": {
                "node_ids": self._facet_counts(rows, "node_id"),
                "vrf_ids": self._facet_counts(rows, "vrf_id"),
                "route_families": self._facet_counts(rows, "route_family"),
                "route_types": self._facet_counts(rows, "route_type"),
                "protocols": self._facet_counts(rows, "source_protocol"),
            },
            "page": {
                "offset": offset,
                "limit": limit,
                "returned": len(returned),
                "total": total,
                "truncated": truncated,
                "next_cursor": next_cursor,
            },
            "completeness": {
                "complete": snapshot["complete"] and not truncated,
                "topology_complete": snapshot["complete"],
                "rows_truncated": truncated,
                "clock_alignment": snapshot["completeness"]["clock_alignment"],
                "simultaneity": snapshot["resolved_basis"]["simultaneity"],
                "relative_capture_vector_is_not_simultaneous": (
                    snapshot["resolved_basis"]["simultaneity"] == "not_implied"
                ),
            },
            "semantic_ownership": {
                "route_rows_and_keys": "node_plugins",
                "prefix_match_and_preference": "node_plugins",
                "vrf_family_and_next_hop_semantics": "node_plugins",
                "time_context_filtering_and_pagination": "core",
                "opaque_row_trace_correlation": "core",
            },
        }
        self._route_table_contexts[route_table_context_id] = {
            "topology_context_id": snapshot["context_id"],
            "route_entry_ids": {item["route_entry_id"] for item in rows},
        }
        while len(self._route_table_contexts) > 32:
            self._route_table_contexts.pop(next(iter(self._route_table_contexts)))
        return response

    @staticmethod
    def _bounded_page_integer(
        value: Any,
        field: str,
        *,
        minimum: int,
        maximum: int,
    ) -> int:
        try:
            parsed = parse_decimal_integer(value, field)
        except ValueError as error:
            raise MultiNodeRouteRequestError(
                f"{field} must be an integer"
            ) from error
        if parsed < minimum or parsed > maximum:
            raise MultiNodeRouteRequestError(
                f"{field} must be between {minimum} and {maximum}"
            )
        return parsed

    def _validate_context_node_selection(
        self,
        body: dict[str, Any],
        snapshot: dict[str, Any],
    ) -> None:
        """Reject a route request that reinterprets a cached topology context."""

        has_node_ids = "node_ids" in body
        has_node_queries = "node_queries" in body
        if not has_node_ids and not has_node_queries:
            return
        selection_body = {
            field: body[field]
            for field in ("node_ids", "node_queries")
            if field in body
        }
        requested = self.topology._node_queries(selection_body)
        cached_nodes = {
            str(item["node_id"]): item for item in snapshot.get("nodes", [])
        }
        requested_ids = [str(item["node_id"]) for item in requested]
        if set(requested_ids) != set(cached_nodes):
            raise MultiNodeRouteRequestError(
                "node selection disagrees with the selected topology context"
            )

        # node_ids only selects scope. Projection identity is explicit only in
        # node_queries, so do not reinterpret a custom context as defaults when
        # a caller merely repeats its node membership.
        if not has_node_queries:
            return

        for request in requested:
            node_id = str(request["node_id"])
            cached = cached_nodes[node_id]
            node = self.topology._node(node_id)
            for field in ("member_id", "revision_id"):
                if (
                    request.get(field) is not None
                    and str(request[field]) != str(cached.get(field))
                ):
                    raise MultiNodeRouteRequestError(
                        f"{field} for node {node_id} disagrees with the selected "
                        "topology context"
                    )

            plugin_set_id = str(
                request.get("plugin_set_id", node["active_plugin_set_id"])
            )
            if plugin_set_id != str(cached.get("plugin_set_id")):
                raise MultiNodeRouteRequestError(
                    f"plugin_set_id for node {node_id} disagrees with the selected "
                    "topology context"
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
                raise MultiNodeRouteRequestError(
                    f"unknown plugin_set_id {plugin_set_id} for node {node_id}"
                )
            requested_selections = self.topology._projection_selections(
                node,
                plugin_set,
                request,
            )
            requested_projection_ids = [
                (
                    str(item["plugin"]["plugin_id"]),
                    str(item["projection"]["projection_id"]),
                    str(item["status_perspective_id"]),
                )
                for item in requested_selections
            ]
            cached_projection_ids = [
                (
                    str(item["plugin_id"]),
                    str(item["projection_id"]),
                    str(item["status_perspective_id"]),
                )
                for item in cached.get("selected_plugins", [])
            ]
            if requested_projection_ids != cached_projection_ids:
                raise MultiNodeRouteRequestError(
                    f"projection selection for node {node_id} disagrees with the "
                    "selected topology context"
                )

            if "basis" not in request:
                continue
            requested_basis = self.topology.normalize_basis(
                request["basis"],
                f"basis for node {node_id}",
            )
            resolved_times = cached.get("resolved_times", [])
            if requested_basis["kind"] == "absolute_time":
                comparable_times = [
                    item
                    for item in resolved_times
                    if item.get("query_time_ns") is not None
                ]
                agrees = all(
                    str(item.get("query_time_ns"))
                    == str(requested_basis["time_ns"])
                    for item in comparable_times
                )
            else:
                comparable_times = [
                    item
                    for item in resolved_times
                    if item.get("relative_offset_ns") is not None
                ]
                agrees = all(
                    str(item.get("relative_offset_ns"))
                    == str(requested_basis["offset_ns"])
                    for item in comparable_times
                )
            if not agrees:
                raise MultiNodeRouteRequestError(
                    f"basis for node {node_id} disagrees with the selected "
                    "topology context"
                )

    @staticmethod
    def _filter_values(
        filters: dict[str, Any],
        *,
        plural: tuple[str, ...],
        singular: tuple[str, ...],
    ) -> set[str]:
        values: list[Any] = []
        for field in plural:
            if field not in filters:
                continue
            supplied = filters[field]
            if not isinstance(supplied, list):
                raise MultiNodeRouteRequestError(f"filters.{field} must be an array")
            values.extend(supplied)
        for field in singular:
            if filters.get(field) is not None:
                values.append(filters[field])
        return {str(value) for value in values}

    @staticmethod
    def _optional_boolean(filters: dict[str, Any], field: str) -> bool | None:
        if field not in filters:
            return None
        value = filters[field]
        if not isinstance(value, bool):
            raise MultiNodeRouteRequestError(f"filters.{field} must be boolean")
        return value

    @staticmethod
    def _facet_counts(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
        values: dict[str, int] = {}
        for row in rows:
            value = str(row[field])
            values[value] = values.get(value, 0) + 1
        return [
            {"value": value, "count": count}
            for value, count in sorted(values.items())
        ]

    @staticmethod
    def _optional_object(
        container: dict[str, Any], field: str, *, label: str | None = None
    ) -> dict[str, Any]:
        if field not in container or container[field] is None:
            return {}
        value = container[field]
        if not isinstance(value, dict):
            raise MultiNodeRouteRequestError(
                f"{label or field} must be an object"
            )
        return value

    @staticmethod
    def _scenario_routing_context(
        scenario: dict[str, Any], direction: str
    ) -> dict[str, str]:
        directional = scenario.get("directional_routing_contexts", {}).get(
            direction, {}
        )
        return {
            field: str(directional.get(field, scenario[field]))
            for field in (
                "route_type",
                "vrf_id",
                "route_family",
                "address_family",
            )
        }

    @staticmethod
    def _encode_route_table_cursor(
        route_table_context_id: str, offset: int
    ) -> str:
        material = json.dumps(
            {"context": route_table_context_id, "offset": offset},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        token = base64.urlsafe_b64encode(material).decode("ascii").rstrip("=")
        return f"rtcursor2-{token}"

    def _decode_route_table_cursor(
        self, cursor: Any, route_table_context_id: str
    ) -> int:
        cursor_text = str(cursor)
        if not cursor_text.startswith("rtcursor2-"):
            raise MultiNodeRouteRequestError("invalid route-table cursor")
        token = cursor_text.removeprefix("rtcursor2-")
        try:
            padding = "=" * (-len(token) % 4)
            decoded = json.loads(
                base64.urlsafe_b64decode(token + padding).decode("utf-8")
            )
        except (
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            binascii.Error,
        ) as error:
            raise MultiNodeRouteRequestError(
                "invalid route-table cursor"
            ) from error
        if not isinstance(decoded, dict) or set(decoded) != {"context", "offset"}:
            raise MultiNodeRouteRequestError("invalid route-table cursor")
        if decoded["context"] != route_table_context_id:
            raise MultiNodeRouteRequestError(
                "route-table cursor belongs to a different query or context"
            )
        return self._bounded_page_integer(
            decoded["offset"],
            "page.cursor",
            minimum=0,
            maximum=100_000,
        )

    def _resolve_routing_context(
        self,
        body: dict[str, Any],
        scenario: dict[str, Any],
        direction: str,
    ) -> tuple[str, dict[str, Any], dict[str, Any] | None]:
        routing = self._optional_object(body, "routing_context")
        route_entry_ref = (
            body["route_entry_ref"]
            if body.get("route_entry_ref") is not None
            else routing.get("route_entry_ref")
        )
        referenced_row: dict[str, Any] | None = None
        if route_entry_ref is not None:
            if not isinstance(route_entry_ref, dict):
                raise MultiNodeRouteRequestError(
                    "route_entry_ref must be an object"
                )
            entry_id = route_entry_ref.get("route_entry_id")
            if not entry_id:
                raise MultiNodeRouteRequestError(
                    "route_entry_ref requires route_entry_id"
                )
            referenced_row = next(
                (
                    item
                    for item in self._route_table_entries()
                    if item["route_entry_id"] == str(entry_id)
                ),
                None,
            )
            if referenced_row is None:
                raise MultiNodeRouteRequestError(
                    f"unknown route_entry_ref: {entry_id}"
                )
            for field in ("node_id", "member_id", "plugin_id", "table_id"):
                expected = referenced_row["route_entry_ref"].get(field)
                supplied = route_entry_ref.get(field)
                if supplied is not None and str(supplied) != str(expected):
                    raise MultiNodeRouteRequestError(
                        f"route_entry_ref.{field} does not match the advertised row"
                    )

        route_table_context_id = body.get("route_table_context_id") or routing.get(
            "route_table_context_id"
        )
        if route_table_context_id is not None:
            route_table_context_id = str(route_table_context_id)
            table_context = self._route_table_contexts.get(route_table_context_id)
            if table_context is None:
                raise MultiNodeRouteRequestError(
                    "unknown or expired route_table_context_id"
                )
            if referenced_row and referenced_row["route_entry_id"] not in table_context[
                "route_entry_ids"
            ]:
                raise MultiNodeRouteRequestError(
                    "route_entry_ref is not present in the selected route-table context"
                )
            topology_context_values = {
                str(value)
                for value in (
                    body.get("topology_context_id"),
                    body.get("context_id"),
                )
                if value is not None
            }
            if len(topology_context_values) > 1:
                raise MultiNodeRouteRequestError(
                    "context_id and topology_context_id disagree"
                )
            if topology_context_values and next(
                iter(topology_context_values)
            ) != table_context["topology_context_id"]:
                raise MultiNodeRouteRequestError(
                    "route_table_context_id belongs to a different topology context"
                )

        type_values = {
            str(value)
            for value in (
                body.get("route_type"),
                routing.get("route_type"),
                referenced_row.get("route_type") if referenced_row else None,
            )
            if value is not None
        }
        if len(type_values) > 1:
            raise MultiNodeRouteRequestError(
                "route_type and the selected route-table row disagree"
            )
        explicit_route_type = next(iter(type_values), None)

        family_values = {
            str(value)
            for value in (
                body.get("route_family"),
                routing.get("route_family"),
                referenced_row.get("route_family") if referenced_row else None,
            )
            if value is not None
        }
        if len(family_values) > 1:
            raise MultiNodeRouteRequestError(
                "route_family and the selected route-table row disagree"
            )
        requested_family = next(iter(family_values), None)
        if requested_family is not None:
            family = self._family(requested_family)
        else:
            family = None

        address_values = {
            str(value)
            for value in (
                body.get("address_family"),
                routing.get("address_family"),
                referenced_row.get("address_family") if referenced_row else None,
            )
            if value is not None
        }
        if len(address_values) > 1:
            raise MultiNodeRouteRequestError(
                "address_family and the selected route-table row disagree"
            )
        requested_address = next(iter(address_values), None)

        scenario_context = self._scenario_routing_context(scenario, direction)
        fixed_context = not bool(scenario.get("supports_arbitrary_endpoints"))
        default_type = scenario_context["route_type"]
        if fixed_context and explicit_route_type not in {None, default_type}:
            raise MultiNodeRouteRequestError(
                f"scenario {scenario['scenario_id']} requires route_type "
                f"{default_type} for {direction} direction"
            )
        if (
            fixed_context
            and requested_family not in {None, scenario_context["route_family"]}
        ):
            raise MultiNodeRouteRequestError(
                f"scenario {scenario['scenario_id']} requires route_family "
                f"{scenario_context['route_family']} for {direction} direction"
            )
        if explicit_route_type is not None:
            route_type = explicit_route_type
        elif family is not None and default_type not in family["supported_route_types"]:
            route_type = str(family["supported_route_types"][0])
        else:
            route_type = default_type
        known_types = {item["route_type"] for item in self._route_types}
        if route_type not in known_types:
            raise MultiNodeRouteRequestError(f"unknown route_type: {route_type}")
        default_vrf_id, derived_family_id = (
            self._route_type_default_context(route_type)
        )
        if family is None:
            family = self._family(
                scenario_context["route_family"]
                if fixed_context
                else derived_family_id
            )
        if route_type not in family["supported_route_types"]:
            raise MultiNodeRouteRequestError(
                f"route_type {route_type} is incompatible with route_family "
                f"{family['route_family']}"
            )
        if requested_address is not None:
            address_family_id = requested_address
            if requested_address in {
                item["route_family"] for item in self._route_families
            }:
                address_family_id = self._family(requested_address)[
                    "address_family"
                ]
            if address_family_id != family["address_family"]:
                raise MultiNodeRouteRequestError(
                    f"address_family {requested_address} is incompatible with "
                    f"route_family {family['route_family']}"
                )
            if (
                fixed_context
                and address_family_id != scenario_context["address_family"]
            ):
                raise MultiNodeRouteRequestError(
                    f"scenario {scenario['scenario_id']} requires address_family "
                    f"{scenario_context['address_family']} for {direction} direction"
                )

        source_request = body.get("source") or {}
        destination_request = body.get("destination") or {}
        vrf_values = {
            str(value)
            for value in (
                body.get("vrf_id"),
                body.get("vrf"),
                routing.get("vrf_id"),
                routing.get("vrf"),
                source_request.get("vrf_id") if isinstance(source_request, dict) else None,
                source_request.get("vrf") if isinstance(source_request, dict) else None,
                destination_request.get("vrf_id")
                if isinstance(destination_request, dict)
                else None,
                destination_request.get("vrf")
                if isinstance(destination_request, dict)
                else None,
                referenced_row.get("vrf_id") if referenced_row else None,
            )
            if value is not None
        }
        canonical_vrfs = {self._vrf(value)["vrf_id"] for value in vrf_values}
        if len(canonical_vrfs) > 1:
            raise MultiNodeRouteRequestError(
                "VRF selectors and the selected route-table row disagree"
            )
        expected_vrf_id = (
            scenario_context["vrf_id"] if fixed_context else default_vrf_id
        )
        vrf = self._vrf(next(iter(canonical_vrfs), expected_vrf_id))
        if fixed_context and vrf["vrf_id"] != scenario_context["vrf_id"]:
            raise MultiNodeRouteRequestError(
                f"scenario {scenario['scenario_id']} requires VRF "
                f"{scenario_context['vrf_id']} for {direction} direction"
            )
        if family["route_family"] not in vrf["route_families"]:
            raise MultiNodeRouteRequestError(
                f"route_family {family['route_family']} is not available in VRF "
                f"{vrf['vrf_id']}"
            )
        if route_type not in vrf["supported_route_types"]:
            raise MultiNodeRouteRequestError(
                f"route_type {route_type} is not available in VRF {vrf['vrf_id']}"
            )

        table_values = {
            str(value)
            for value in (
                body.get("table_id"),
                routing.get("table_id"),
                referenced_row.get("table_id") if referenced_row else None,
            )
            if value is not None
        }
        if len(table_values) > 1:
            raise MultiNodeRouteRequestError(
                "table_id and the selected route-table row disagree"
            )
        constraints = self._optional_object(
            routing, "constraints", label="routing_context.constraints"
        )
        context = {
            "vrf_id": vrf["vrf_id"],
            "vrf": vrf["vrf"],
            "route_family": family["route_family"],
            "address_family": family["address_family"],
            "safi": family["safi"],
            "route_type": route_type,
            "table_id": next(iter(table_values), None),
            "constraints": constraints,
            "route_table_context_id": route_table_context_id,
            "route_entry_ref": (
                referenced_row["route_entry_ref"] if referenced_row else None
            ),
            "semantic_owner": "node_route_plugins",
        }
        return route_type, context, referenced_row

    def trace(self, body: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise MultiNodeRouteRequestError("request body must be an object")
        scenario_id = str(
            body.get("scenario_id", self.policy.default_scenario_id)
        )
        if scenario_id not in self._advertised_scenario_by_id:
            raise MultiNodeRouteRequestError(
                f"unknown scenario_id: {scenario_id}"
            )
        scenario = self.policy.scenarios.get(scenario_id)
        if scenario is None:
            raise MultiNodeRouteRequestError(
                f"scenario {scenario_id} has no installed plug-in executor"
            )
        supplied_policies = {
            str(body[field])
            for field in ("resolution_mode", "resolution_policy", "completeness_policy")
            if body.get(field) is not None
        }
        if len(supplied_policies) > 1:
            raise MultiNodeRouteRequestError(
                "resolution_mode, resolution_policy, and completeness_policy disagree"
            )
        resolution_mode = next(iter(supplied_policies), "best_effort")
        if resolution_mode not in {"strict", "best_effort"}:
            raise MultiNodeRouteRequestError(
                "resolution_mode must be strict or best_effort"
            )
        steering_profile_id = str(
            body.get("steering_profile_id", "observed")
        )
        advertised_steering_ids = {
            str(item["profile_id"])
            for item in self.policy.steering_profiles
        }
        if steering_profile_id not in advertised_steering_ids:
            raise MultiNodeRouteRequestError(
                f"unknown steering_profile_id: {steering_profile_id}"
            )
        scenario_steering_ids = {
            str(item)
            for item in scenario.get("steering_profiles", ("observed",))
        }
        if steering_profile_id not in scenario_steering_ids:
            raise MultiNodeRouteRequestError(
                f"scenario {scenario_id} does not support steering profile "
                f"{steering_profile_id}"
            )
        direction = str(body.get("direction", "forward"))
        if direction not in {"forward", "reverse", "both"}:
            raise MultiNodeRouteRequestError(
                "direction must be forward, reverse, or both"
            )
        max_hops = self._bounded_page_integer(
            body.get("max_hops", 64),
            "max_hops",
            minimum=1,
            maximum=128,
        )
        max_recursion = self._bounded_page_integer(
            body.get("max_recursion", 16),
            "max_recursion",
            minimum=0,
            maximum=64,
        )
        normalized_body = dict(body)
        flow = self._optional_object(body, "flow")
        for field in ("source", "destination"):
            flow_endpoint = flow.get(field)
            if flow_endpoint is not None and not isinstance(
                flow_endpoint, (dict, str)
            ):
                raise MultiNodeRouteRequestError(
                    f"flow.{field} must be an object or advertised value"
                )
            if (
                flow_endpoint is not None
                and field in normalized_body
                and normalized_body[field] not in (None, {}, flow_endpoint)
            ):
                raise MultiNodeRouteRequestError(
                    f"flow.{field} and top-level {field} disagree"
                )
            if flow_endpoint is not None:
                normalized_body[field] = flow_endpoint
        for field in ("source", "destination"):
            endpoint = normalized_body.get(field)
            if endpoint is None:
                normalized_body[field] = {}
            elif isinstance(endpoint, str):
                normalized_body[field] = {"value": endpoint}
            elif not isinstance(endpoint, dict):
                raise MultiNodeRouteRequestError(
                    f"{field} must be an object or advertised value"
                )
        route_type, routing_context, referenced_row = self._resolve_routing_context(
            normalized_body, scenario, direction
        )
        if referenced_row is not None:
            declared_query = referenced_row.get("trace_query", {})
            if not isinstance(declared_query, dict) or not declared_query:
                raise MultiNodeRouteRequestError(
                    "selected route-table row has no plug-in-declared "
                    "trace action"
                )
            # The row's plug-in owns its traffic endpoints and any explicit
            # traversal seed. Never reinterpret an intermediate row as an
            # ingress merely because it owns the table entry.
            for field in (
                "source_id",
                "destination_id",
                "source",
                "destination",
                "flow",
                "ingress",
                "starting_point",
                "trace_starts",
            ):
                if declared_query.get(field) is not None:
                    normalized_body.setdefault(
                        field,
                        declared_query[field],
                    )
        flow_source, flow_destination = self._resolve_endpoints(
            normalized_body,
            scenario_id,
            "forward",
        )
        scenario_direction = self._scenario_direction_for_flow(
            scenario_id,
            flow_source,
            flow_destination,
            "forward" if direction == "both" else direction,
        )
        if scenario_direction != direction:
            (
                route_type,
                routing_context,
                remapped_referenced_row,
            ) = self._resolve_routing_context(
                normalized_body,
                scenario,
                scenario_direction,
            )
            if (
                referenced_row is not None
                and remapped_referenced_row is not None
                and remapped_referenced_row.get("route_entry_id")
                != referenced_row.get("route_entry_id")
            ):
                raise MultiNodeRouteRequestError(
                    "route_entry_ref resolves to a different row after "
                    "fixed-scenario direction mapping"
                )
            referenced_row = remapped_referenced_row
        if direction == "both":
            forward_request = dict(normalized_body)
            reverse_request = dict(normalized_body)
            forward_request["direction"] = "forward"
            reverse_request["direction"] = "reverse"
            if body.get("directional_routing_contexts") is not None:
                directional_contexts = body["directional_routing_contexts"]
            else:
                directional_contexts = scenario.get(
                    "directional_routing_contexts", {}
                )
            if not isinstance(directional_contexts, dict):
                raise MultiNodeRouteRequestError(
                    "directional_routing_contexts must be an object"
                )
            for requested_direction, request in (
                ("forward", forward_request),
                ("reverse", reverse_request),
            ):
                directional_context = directional_contexts.get(
                    requested_direction
                )
                if directional_context is None:
                    continue
                if not isinstance(directional_context, dict):
                    raise MultiNodeRouteRequestError(
                        "each directional routing context must be an object"
                    )
                for field in (
                    "route_type",
                    "route_family",
                    "address_family",
                    "vrf",
                    "vrf_id",
                ):
                    request.pop(field, None)
                nested_context = dict(request.get("routing_context") or {})
                for field in (
                    "route_type",
                    "route_family",
                    "address_family",
                    "vrf",
                    "vrf_id",
                ):
                    nested_context.pop(field, None)
                nested_context.update(directional_context)
                request["routing_context"] = nested_context
            forward_request.pop("focus_path_id", None)
            reverse_request.pop("focus_path_id", None)
            # A route-entry reference identifies the forward source RIB row. The
            # reverse trace resolves and reports its own contemporaneous rows.
            reverse_request.pop("route_entry_ref", None)
            if isinstance(reverse_request.get("routing_context"), dict):
                reverse_request["routing_context"] = {
                    key: value
                    for key, value in reverse_request["routing_context"].items()
                    if key != "route_entry_ref"
                }
            forward = self.trace(forward_request)
            reverse = self.trace(reverse_request)
            self._validate_pair_reverse_start(
                forward["flow"]["destination"],
                reverse["trace_start"],
            )
            return self._bidirectional_response(
                scenario, route_type, resolution_mode, forward, reverse
            )
        source, destination = self._resolve_endpoints(
            normalized_body, scenario_id, direction
        )
        effective_direction = scenario_direction
        referenced_attributes = (
            referenced_row.get("attributes", {})
            if isinstance(referenced_row, dict)
            else {}
        )
        referenced_scenario_id = (
            referenced_attributes.get("scenario_id")
            if isinstance(referenced_attributes, dict)
            else None
        )
        generated_projection = (
            self._generated_inventory_projection(
                source_node_id=source["node_id"],
                destination_node_id=destination["node_id"],
                routing_context=routing_context,
                direction=effective_direction,
            )
            if scenario.get("supports_arbitrary_endpoints")
            and referenced_scenario_id != scenario_id
            else self._generated_projection_for_scenario(
                scenario_id,
                effective_direction,
                resolution_mode=resolution_mode,
                steering_profile_id=steering_profile_id,
            )
        )
        trace_start = self._resolve_trace_start(
            normalized_body,
            scenario,
            direction,
            flow_source if direction == "forward" else flow_destination,
            scenario_direction=effective_direction,
        )
        if (
            scenario.get("supports_explicit_start")
            and not any(
                isinstance(candidate.get("node_sequence"), list)
                and candidate["node_sequence"]
                and str(candidate["node_sequence"][0])
                == trace_start["node_id"]
                for candidate in generated_projection["candidate_paths"]
            )
        ):
            generated_projection = self._generated_inventory_projection(
                source_node_id=trace_start["node_id"],
                destination_node_id=destination["node_id"],
                routing_context=routing_context,
                direction=effective_direction,
            )
        # Reachability is always evaluated against this trace's actual
        # directional destination.  That differs from the immutable base-flow
        # endpoint when a fixed scenario is requested in the opposite
        # orientation and its return trace resolves a presented service.
        target_endpoint = destination
        vrf_node_ids = set(self._vrf(routing_context["vrf_id"])["node_ids"])
        outside_vrf = [
            endpoint["node_id"]
            for endpoint in (source, destination, trace_start)
            if endpoint["node_id"] not in vrf_node_ids
        ]
        if outside_vrf:
            raise MultiNodeRouteRequestError(
                f"source, destination, and trace start must belong to VRF "
                f"{routing_context['vrf_id']}; outside scope: "
                f"{sorted(set(outside_vrf))}"
            )
        self._validate_referenced_route_row(
            referenced_row, trace_start, destination, routing_context
        )
        source_id = source["source_id"]
        destination_id = destination["destination_id"]
        context_aliases = {
            str(body[field])
            for field in ("context_id", "topology_context_id")
            if body.get(field) is not None
        }
        if len(context_aliases) > 1:
            raise MultiNodeRouteRequestError(
                "context_id and topology_context_id disagree"
            )
        requested_context_id = next(iter(context_aliases), None)
        if requested_context_id and not requested_context_id.startswith("tctx1-"):
            raise MultiNodeRouteRequestError("invalid topology context identifier")

        requested_basis = (
            self.topology.normalize_basis(body["basis"])
            if body.get("basis") is not None
            else {"kind": "relative_to_watermark", "offset_ns": "0"}
        )
        topology_request = {
            "basis": requested_basis,
            "clock_policy": body.get("clock_policy", "best_effort"),
            "resource_limit": 500,
            "inter_node_link_limit": 1000,
            "network_segment_limit": 500,
            "segment_attachment_limit": 4000,
        }
        for field in ("node_queries", "node_ids"):
            if field in body:
                topology_request[field] = body[field]
        if requested_context_id:
            snapshot = self.topology._contexts.get(requested_context_id)
            if snapshot is None:
                raise MultiNodeRouteRequestError(
                    "unknown or expired topology context"
                )
            cached_basis = snapshot["resolved_basis"]["requested"]
            cached_clock_policy = snapshot["resolved_basis"]["clock_policy"]
            if (
                body.get("basis") is not None
                and self.topology.normalize_basis(body["basis"])
                != self.topology.normalize_basis(cached_basis)
            ):
                raise MultiNodeRouteRequestError(
                    "basis disagrees with the selected topology context"
                )
            if (
                body.get("clock_policy") is not None
                and str(body["clock_policy"]) != cached_clock_policy
            ):
                raise MultiNodeRouteRequestError(
                    "clock_policy disagrees with the selected topology context"
                )
            self._validate_context_node_selection(body, snapshot)
            topology_request["basis"] = cached_basis
            topology_request["clock_policy"] = cached_clock_policy
        else:
            snapshot = self.topology.query(topology_request)

        # The selected topology snapshot remains the trace's authoritative context.
        # Route resolvers can, however, require evidence from another default-enabled
        # projection in the same installed plug-in set (for example another
        # protocol/control-state projection)
        # when the visible topology is filtered to underlay only).  Re-run the same
        # selected nodes, basis, and clock policy without projection filters.  This is
        # an auxiliary evidence snapshot, not a replacement topology context.
        requested_node_queries = {
            str(item["node_id"]): item
            for item in body.get("node_queries", [])
            if isinstance(item, dict) and item.get("node_id")
        }
        route_node_queries: list[dict[str, Any]] = []
        for node in snapshot["nodes"]:
            original = requested_node_queries.get(str(node["node_id"]), {})
            route_node_query = {
                "node_id": node["node_id"],
                "plugin_set_id": node["plugin_set_id"],
            }
            if "basis" in original:
                route_node_query["basis"] = original["basis"]
            route_node_queries.append(route_node_query)
        route_evidence_request = {
            "basis": topology_request["basis"],
            "clock_policy": topology_request["clock_policy"],
            "resource_limit": topology_request["resource_limit"],
            "inter_node_link_limit": topology_request["inter_node_link_limit"],
            "network_segment_limit": topology_request[
                "network_segment_limit"
            ],
            "segment_attachment_limit": topology_request[
                "segment_attachment_limit"
            ],
            "node_queries": route_node_queries,
        }
        route_evidence = self.topology.query(route_evidence_request)
        resources = {
            item["resource_id"]: item
            for node in route_evidence["nodes"]
            for item in node.get("resources", [])
        }
        links: dict[str, list[dict[str, Any]]] = {}
        for link in route_evidence.get("inter_node_links", []):
            links.setdefault(str(link["link_id"]), []).append(link)

        targets: dict[str, dict[str, Any]] = {}
        issues: list[dict[str, Any]] = []
        paths = self._generic_paths_from_generated_candidates(
            generated_projection,
            route_type,
            resources,
            links,
            targets,
        )
        consistency_state = (
            "consistent_counterfactual_user_forced"
            if steering_profile_id != "observed"
            else "consistent_with_selected_observations"
        )
        packet_case = generated_projection.get("packet_case")
        packet_executor_profile_id = (
            str(packet_case["executor_profile_id"])
            if packet_case is not None
            else None
        )

        self._attach_generated_forwarding_projection(
            paths,
            generated_projection,
            direction=effective_direction,
            requested_direction=direction,
            steering_profile_id=steering_profile_id,
        )
        self._reconcile_generated_route_evidence(
            paths,
            generated_projection,
            route_evidence,
            resources,
            targets,
            direction=effective_direction,
            resolution_mode=resolution_mode,
        )
        self._apply_generated_candidate_semantics(
            paths,
            max_hops=max_hops,
            max_recursion=max_recursion,
        )
        if generated_projection is not None:
            generated_outcome = str(
                generated_projection.get("expected_outcome") or ""
            )
            if generated_outcome == "inconsistent":
                consistency_state = "inconsistent"
            elif (
                generated_outcome == "one_way_drop"
                and effective_direction == "reverse"
            ):
                consistency_state = "inconsistent_one_way_drop"
            elif generated_outcome == "policy_blocked":
                consistency_state = "consistent_policy_blocked"
            elif generated_outcome == "loop":
                consistency_state = "consistent_cycle_detected"
            elif generated_outcome == "failed_over":
                consistency_state = "consistent_after_failover"
            elif generated_outcome == "incomplete":
                consistency_state = (
                    "best_effort_with_gap"
                    if resolution_mode == "best_effort"
                    else "incomplete"
                )
        if packet_executor_profile_id is not None:
            self._attach_packet_trace(
                paths[0],
                profile_id=packet_executor_profile_id,
                direction=effective_direction,
                steering_profile_id=steering_profile_id,
                issues=issues,
                declared_case=(
                    generated_projection.get("packet_case")
                    if generated_projection is not None
                    else None
                ),
            )
        self._declare_plugin_terminal_evidence(paths, target_endpoint)
        endpoint_reachability = self._annotate_endpoint_reachability(
            paths,
            target_endpoint,
            trace_start,
        )
        route_entry_refs = self._attach_route_entry_refs(
            paths,
            destination,
            routing_context,
            referenced_row,
            targets,
            scenario_id=scenario_id,
        )
        self._materialize_generated_findings(
            paths,
            generated_projection,
            issues,
        )
        if self._materialize_control_plane_only_issue(paths, issues):
            consistency_state = "control_plane_only_not_forwarding"
        self._decorate_route_presentations(paths, routing_context)
        route_entry_correlations = list(
            {
                item["route_entry_id"]: item
                for path in paths
                for item in path.get("route_entry_correlations", [])
            }.values()
        )
        path_ids = {item["path_id"] for item in paths}
        requested_focus = body.get("focus_path_id")
        trace_candidate_id = body.get("trace_candidate_id")
        if requested_focus is None and trace_candidate_id is not None:
            candidate_matches = [
                item
                for item in paths
                if str(
                    item.get("generated_candidate_id")
                    or item.get("candidate_id")
                    or ""
                )
                == str(trace_candidate_id)
            ]
            if len(candidate_matches) != 1:
                raise MultiNodeRouteRequestError(
                    "trace_candidate_id does not identify exactly one "
                    f"returned candidate: {trace_candidate_id}"
                )
            requested_focus = candidate_matches[0]["path_id"]
        if requested_focus is None and referenced_row is not None:
            row_focus = referenced_row.get("path_id")
            # A node-local route row can name its own candidate without knowing
            # the assembly-level path ID produced after cross-node composition.
            # Treat it as a focus hint only when it exactly matches a returned
            # path; never reject an otherwise valid generated row.
            if row_focus in path_ids:
                requested_focus = row_focus
        if requested_focus is not None and str(requested_focus) not in path_ids:
            raise MultiNodeRouteRequestError(
                f"focus_path_id is not a candidate in this trace: {requested_focus}"
            )
        focused_path_id = str(requested_focus) if requested_focus else self._default_focus(paths)
        for path in paths:
            path["focused"] = path["path_id"] == focused_path_id

        focused = next(item for item in paths if item["path_id"] == focused_path_id)
        issue_by_id = {item["issue_id"]: item for item in issues}
        active_paths = [item for item in paths if item["active"]]
        primary = next((item for item in paths if item["primary"]), None)
        multipath_mode = self._route_executor_multipath_mode(
            scenario,
            selected_count=sum(
                1
                for item in paths
                if bool(
                    item.get(
                        "selected_active_by_plugin",
                        item.get("active"),
                    )
                )
            ),
        )
        trace_material = {
            "context_id": snapshot["context_id"],
            "route_evidence_context_id": route_evidence["context_id"],
            "scenario_id": scenario_id,
            "resolution_mode": resolution_mode,
            "steering_profile_id": steering_profile_id,
            "direction": direction,
            "route_type": route_type,
            "max_hops": max_hops,
            "max_recursion": max_recursion,
            "flow_source_endpoint_id": flow_source["endpoint_id"],
            "flow_destination_endpoint_id": flow_destination["endpoint_id"],
            "trace_start_node_id": trace_start["node_id"],
            "source_node_id": source["node_id"],
            "destination_node_id": destination["node_id"],
            "source_id": source_id,
            "destination_id": destination_id,
            "routing_context": routing_context,
            "requested_context_id": requested_context_id,
        }
        trace_id = "rtrace1-" + hashlib.sha256(
            json.dumps(trace_material, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:24]
        all_end_to_end = all(
            item["completeness"]["end_to_end_resolved"] for item in paths
        )
        exact = all(
            item["completeness"]["state"] == "complete" for item in paths
        )
        reachable = endpoint_reachability["reaches_target"] is True
        directional_pair = self._directional_pair(
            scenario_id, direction, flow_source, flow_destination
        )
        counterpart_direction = (
            "reverse" if direction == "forward" else "forward"
        )
        counterpart_effective_direction = self._opposite_trace_direction(
            effective_direction
        )
        counterpart_context = self._scenario_routing_context(
            scenario, counterpart_effective_direction
        )
        if scenario.get("supports_arbitrary_endpoints"):
            counterpart_source_id = self._router(
                directional_pair["base_source_node_id"]
            )["source_id"]
            counterpart_destination_id = self._router(
                directional_pair["base_destination_node_id"]
            )["destination_id"]
            counterpart_context = {
                "route_type": route_type,
                "route_family": routing_context["route_family"],
                "address_family": routing_context["address_family"],
                "vrf_id": routing_context["vrf_id"],
            }
        else:
            # Keep these selectors aligned with the caller's base flow.  A
            # fixed scenario may be exercised with its advertised endpoint
            # pair reversed, in which case the executor direction changes but
            # the public forward/reverse vocabulary does not.
            counterpart_source_id = flow_source["source_id"]
            counterpart_destination_id = flow_destination["destination_id"]
        return {
            "api_version": "v1",
            "assembly_id": self.topology.assembly_id,
            "topology_id": self.topology.topology_id,
            "trace_id": trace_id,
            "trace_mode": "single_direction",
            "direction": direction,
            "steering_profile_id": steering_profile_id,
            "counterfactual": steering_profile_id != "observed",
            "direction_id": (
                f"direction:{direction}:{trace_start['node_id']}:"
                f"{target_endpoint['endpoint_id']}"
            ),
            "route_type": route_type,
            "route_family": routing_context["route_family"],
            "address_family": routing_context["address_family"],
            "vrf": routing_context["vrf"],
            "vrf_id": routing_context["vrf_id"],
            "routing_context": routing_context,
            "source": source,
            "destination": destination,
            "flow": {
                "source": flow_source,
                "destination": flow_destination,
            },
            "traffic_endpoints": {
                "source": flow_source,
                "destination": flow_destination,
            },
            "trace_start": trace_start,
            "starting_point": trace_start,
            "target_endpoint": target_endpoint,
            "goal_endpoint": target_endpoint,
            "endpoint_reachability": endpoint_reachability,
            "directional_pair": directional_pair,
            "reachable": reachable,
            "context_id": snapshot["context_id"],
            "topology_context_id": snapshot["context_id"],
            "requested_context_id": requested_context_id,
            "context_consistency": {
                "state": (
                    "not_supplied"
                    if requested_context_id is None
                    else "same_reconstruction"
                    if requested_context_id == snapshot["context_id"]
                    else "derived_from_valid_context"
                ),
                "requested_context_id": requested_context_id,
                "resolved_context_id": snapshot["context_id"],
                "validated": requested_context_id is None
                or requested_context_id == snapshot["context_id"]
                or requested_context_id in self.topology._contexts,
            },
            "scenario": dict(scenario),
            "generated_projection": generated_projection,
            "request": {
                "scenario_id": scenario_id,
                "direction": direction,
                "route_type": route_type,
                "route_family": routing_context["route_family"],
                "address_family": routing_context["address_family"],
                "vrf": routing_context["vrf"],
                "vrf_id": routing_context["vrf_id"],
                "routing_context": routing_context,
                "source_id": source_id,
                "resolution_mode": resolution_mode,
                "resolution_policy": resolution_mode,
                "completeness_policy": resolution_mode,
                "steering_profile_id": steering_profile_id,
                "max_hops": max_hops,
                "max_recursion": max_recursion,
                "destination_id": destination_id,
                "route_table_context_id": routing_context[
                    "route_table_context_id"
                ],
                "route_entry_ref": routing_context["route_entry_ref"],
                "clock_policy": topology_request["clock_policy"],
                "basis": topology_request["basis"],
                "source": source,
                "destination": destination,
                "flow": {
                    "source": flow_source,
                    "destination": flow_destination,
                },
                "trace_starts": {direction: trace_start},
            },
            "counterpart_request": {
                "scenario_id": scenario_id,
                "direction": counterpart_direction,
                "source_id": counterpart_source_id,
                "destination_id": counterpart_destination_id,
                "route_type": counterpart_context["route_type"],
                "route_family": counterpart_context["route_family"],
                "address_family": counterpart_context["address_family"],
                "vrf": counterpart_context["vrf_id"],
                "vrf_id": counterpart_context["vrf_id"],
                "resolution_mode": resolution_mode,
                "steering_profile_id": steering_profile_id,
                "max_hops": max_hops,
                "max_recursion": max_recursion,
                "basis": topology_request["basis"],
                "clock_policy": topology_request["clock_policy"],
                "flow": {
                    "source": flow_source,
                    "destination": flow_destination,
                },
            },
            "resolution_mode": resolution_mode,
            "resolution_policy": resolution_mode,
            "completeness_policy": resolution_mode,
            "max_hops": max_hops,
            "max_recursion": max_recursion,
            "resolved_basis": snapshot["resolved_basis"],
            "multipath": {
                "mode": multipath_mode,
                "selection_owner": "node_plugins",
                "candidate_count": len(paths),
                "active_path_count": len(active_paths),
                "active_path_ids": [item["path_id"] for item in active_paths],
                "primary_path_id": primary["path_id"] if primary else None,
                "all_candidates_retained": True,
            },
            "paths": paths,
            "route_table_entry_refs": route_entry_refs,
            "matched_route_entry_refs": route_entry_refs,
            "route_table_entry_correlations": route_entry_correlations,
            "route_table_entry_ids": [
                item["route_entry_id"] for item in route_entry_refs
            ],
            "focused_path_id": focused_path_id,
            "focus": {
                "path_id": focused_path_id,
                "active": focused["active"],
                "primary": focused["primary"],
                "alternative_state": focused["alternative_state"],
                "role": focused["role"],
                "result": focused["result"],
                "eligibility": focused["eligibility"],
                "terminal_reason": focused["terminal_reason"],
                "graph_target_ids": focused["graph_target_ids"],
            },
            "route_resolution_sequence": focused["route_resolution_sequence"],
            "interaction_targets": list(targets.values()),
            "issues": issues,
            "consistency": {
                "state": consistency_state,
                "consistent": consistency_state.startswith("consistent"),
                "issue_refs": [
                    item["issue_id"]
                    for item in issues
                    if item["category"]
                    in {"cross_layer", "boundary", "directional", "forwarding"}
                    and item.get("affects_consistency", True) is not False
                ],
                "compared_status_perspectives": sorted(
                    {
                        provider.get("status_perspective_id")
                        for path in paths
                        for provider in path["plugin_provenance"]
                        if provider.get("status_perspective_id")
                    }
                ),
            },
            "complete": all_end_to_end,
            "completeness": {
                "end_to_end_resolved": all_end_to_end,
                "reachable": reachable,
                "endpoint_reachability_state": endpoint_reachability["state"],
                "observationally_complete": exact,
                "state": "complete" if exact else "partial",
                "inferred_segment_count": sum(
                    1
                    for path in paths
                    for segment in path["segments"]
                    if segment["completeness"]["state"] == "best_effort_inferred"
                ),
                "unresolved_segment_count": sum(
                    1
                    for path in paths
                    for segment in path["segments"]
                    if segment["completeness"]["state"] == "unresolved"
                ),
            },
            "topology_snapshot": {
                "context_id": snapshot["context_id"],
                "resolved_basis": snapshot["resolved_basis"],
                "node_count": snapshot["counts"]["nodes"],
                "inter_node_link_count": snapshot["counts"]["inter_node_links"],
                "complete": snapshot["complete"],
                "deep_link": snapshot["deep_links"]["self"],
            },
            "route_resolution_evidence": {
                "context_id": route_evidence["context_id"],
                "topology_context_id": snapshot["context_id"],
                "scope": "default_enabled_projections_for_selected_node_plugin_sets",
                "auxiliary": True,
                "replaces_topology_context": False,
                "explicit_projection_filters_removed": any(
                    "projections" in item
                    or any(
                        field in item
                        for field in (
                            "plugin_id",
                            "projection_id",
                            "status_perspective_id",
                        )
                    )
                    for item in requested_node_queries.values()
                ),
                "node_queries": route_node_queries,
                "resolved_basis": route_evidence["resolved_basis"],
            },
            "issue_index": issue_by_id,
            "semantic_ownership": {
                "route_resolution_text": "node_or_federation_plugin",
                "local_resolution": "node_plugin",
                "boundary_resolution": "federation_linker_plugin",
                "route_presentation_roles_and_content": "node_or_federation_plugin",
                "presentation_reference_validation_and_rendering": "core",
                "route_table_rows_and_selection": "node_plugin",
                "route_table_time_context_and_correlation": "core",
                "time_path_join_and_uncertainty": "core",
                "flow_endpoint_identity_and_direction_swap": "core",
                "trace_start_selection": "caller_and_core",
                "terminal_endpoint_classification": "node_plugin",
                "terminal_endpoint_exact_match_and_pair_aggregation": "core",
                "reverse_must_revisit_forward_start": False,
                "core_does_not_interpret_route_resolution_text": True,
                "core_does_not_infer_overlay_from_protocol_or_address_fields": True,
            },
            "deep_links": {
                "topology": snapshot["deep_links"]["self"],
                "individual_nodes": snapshot["deep_links"]["individual_nodes"],
            },
        }

    @staticmethod
    def _attachment_identity(
        attachment: dict[str, Any],
        *,
        label: str,
    ) -> tuple[str, str, str, str]:
        values = tuple(
            attachment.get(field)
            for field in (
                "attachment_id",
                "node_id",
                "member_id",
                "resource_id",
            )
        )
        if any(not isinstance(value, str) or not value for value in values):
            raise MultiNodeRouteRequestError(
                f"{label} must declare non-empty attachment_id, node_id, "
                "member_id, and resource_id"
            )
        return values  # type: ignore[return-value]

    @staticmethod
    def _packet_value_json(value: Any) -> Any:
        """Serialize one already-validated opaque forwarding value."""

        try:
            return packet_value_json(value, key_atom_type=KeyAtom)
        except CanonicalValueError as error:
            raise MultiNodeRouteRequestError(str(error)) from error

    @classmethod
    def _packet_resource_key_json(
        cls,
        resource: ResourceKey,
    ) -> dict[str, Any]:
        """Preserve one typed resource identity without interpreting its parts."""

        return {
            "namespace": resource.namespace,
            "node": resource.node,
            "layer": resource.layer,
            "kind": resource.kind,
            "parts": [
                {
                    "name": name,
                    "value": cls._packet_value_json(value),
                }
                for name, value in resource.parts
            ],
        }

    @classmethod
    def _packet_topology_reference_json(
        cls,
        reference: TopologyEndpointReference,
    ) -> dict[str, Any]:
        """Serialize the exact resource-or-matcher topology reference."""

        if reference.resource is not None:
            return {
                "resource": cls._packet_resource_key_json(reference.resource),
            }
        assert reference.match is not None
        return {
            "match": {
                "matcher_id": reference.match.matcher_id,
                "arguments": {
                    name: cls._packet_value_json(value)
                    for name, value in reference.match.arguments.items()
                },
                "resolved_candidates": [
                    cls._packet_resource_key_json(candidate)
                    for candidate in reference.match.resolved_candidates
                ],
            },
        }

    @staticmethod
    def _packet_evidence_json(evidence: Evidence) -> dict[str, Any]:
        """Serialize retained evidence without exposing any undeclared payload."""

        return {
            "artifact_id": str(evidence.artifact_id),
            "locator": evidence.locator,
            "raw_timestamp_ns": evidence.raw_timestamp_ns,
            "clock_domain": evidence.clock_domain,
            "excerpt_sha256": evidence.excerpt_sha256,
        }

    @staticmethod
    def _packet_boundary_continuity(
        expected: ForwardingPacketState,
        actual: ForwardingPacketState,
    ) -> bool | None:
        """Return exact boundary continuity, or unknown for incomplete identity."""

        if not expected.identity_complete or not actual.identity_complete:
            return None
        return expected == actual

    @classmethod
    def _packet_layer_json(
        cls,
        layer: ForwardingPacketLayer,
    ) -> dict[str, Any]:
        return {
            "layer_id": layer.layer_id,
            "contract_id": layer.contract_id,
            "label": layer.label,
            "fields": {
                name: cls._packet_value_json(value)
                for name, value in layer.fields
            },
            "size_bytes": layer.size_bytes,
            "complete": layer.complete,
        }

    @classmethod
    def _packet_state_json(
        cls,
        state: ForwardingPacketState,
    ) -> dict[str, Any]:
        return {
            "layers": [
                cls._packet_layer_json(layer) for layer in state.layers
            ],
            "size": (
                {
                    "basis_contract_id": state.size.basis_contract_id,
                    "size_bytes": state.size.size_bytes,
                    "complete": state.size.complete,
                }
                if state.size is not None
                else None
            ),
            "complete": state.complete,
            "identity_complete": state.identity_complete,
        }

    @classmethod
    def _packet_transition_json(
        cls,
        evaluation: ForwardingPacketTransitionEvaluation,
        *,
        segment: dict[str, Any],
    ) -> dict[str, Any]:
        transition = evaluation.transition
        mtu_constraint = transition.mtu
        return {
            "transition": {
                "transition_id": transition.transition_id,
                "step_id": transition.step_id,
                "before": cls._packet_state_json(transition.before),
                "after": cls._packet_state_json(transition.after),
                "action_contract_id": transition.action_contract_id,
                "action_label": transition.action_label,
                "disposition": transition.disposition.value,
                "origin": transition.origin.value,
                "actor_id": transition.actor_id,
                "forced_rule_id": transition.forced_rule_id,
                "mtu_constraint": (
                    {
                        "basis_contract_id": (
                            mtu_constraint.basis_contract_id
                        ),
                        "limit_bytes": mtu_constraint.limit_bytes,
                        "complete": mtu_constraint.complete,
                        "resource": (
                            cls._packet_resource_key_json(
                                mtu_constraint.resource
                            )
                            if mtu_constraint.resource is not None
                            else None
                        ),
                    }
                    if mtu_constraint is not None
                    else None
                ),
                "contributions": [
                    {
                        "phase": item.phase,
                        "text": item.text,
                        "quality": item.quality.value,
                        "resource_references": [
                            cls._packet_resource_key_json(reference)
                            for reference in item.resource_references
                        ],
                        "topology_references": [
                            cls._packet_topology_reference_json(reference)
                            for reference in item.topology_references
                        ],
                        "evidence": [
                            cls._packet_evidence_json(evidence)
                            for evidence in item.evidence
                        ],
                    }
                    for item in transition.contributions
                ],
            },
            "diff": {
                "added_layer_ids": list(evaluation.diff.added_layer_ids),
                "removed_layer_ids": list(
                    evaluation.diff.removed_layer_ids
                ),
                "changed_layer_ids": list(
                    evaluation.diff.changed_layer_ids
                ),
                "moved_layer_ids": list(evaluation.diff.moved_layer_ids),
                "complete": evaluation.diff.complete,
            },
            "mtu": {
                "outcome": evaluation.mtu.outcome,
                "size_bytes": evaluation.mtu.size_bytes,
                "limit_bytes": evaluation.mtu.limit_bytes,
                "excess_bytes": evaluation.mtu.excess_bytes,
                "basis_contract_id": evaluation.mtu.basis_contract_id,
            },
            "counterfactual": evaluation.counterfactual,
            "segment_id": segment["segment_id"],
            "node_id": segment.get("node_id"),
            "highlight_target_ids": list(
                segment.get("highlight_target_ids", [])
            ),
            "interaction_target_ids": list(
                segment.get("interaction_target_ids", [])
            ),
        }

    def _attach_packet_trace(
        self,
        path: dict[str, Any],
        *,
        profile_id: str,
        direction: str,
        steering_profile_id: str,
        issues: list[dict[str, Any]],
        declared_case: dict[str, Any] | None = None,
    ) -> None:
        """Validate declared plug-in transitions and attach protocol-neutral JSON."""

        local_segments = [
            item
            for item in sorted(
                path["segments"], key=lambda candidate: candidate["ordinal"]
            )
            if item["segment_kind"] == "node_resolution"
        ]
        initial_state, transitions = self.policy.packet_transition_builder(
            profile_id=profile_id,
            step_ids=[
                str(item["segment_id"]) for item in local_segments
            ],
            node_ids=[str(item["node_id"]) for item in local_segments],
            direction=direction,
            steering_profile_id=steering_profile_id,
        )
        declared_actions: list[str] = []
        if declared_case is not None:
            initial_state, transitions = self._bind_generated_packet_declaration(
                initial_state,
                transitions,
                declared_case=declared_case,
                direction=direction,
            )
            declared_actions = [
                str(item) for item in declared_case["expected_actions"]
            ]
        trace: ForwardingPacketTraceEvaluation = (
            evaluate_forwarding_packet_trace(
                initial_state,
                transitions,
                max_steps=256,
            )
        )
        segment_by_id = {
            str(item["segment_id"]): item for item in local_segments
        }
        serialized_transitions: list[dict[str, Any]] = []
        expected_packet_state = initial_state
        declared_action_buckets = (
            self._partition_declared_packet_actions(
                declared_actions,
                len(trace.transitions),
            )
            if declared_case is not None
            else []
        )
        for transition_index, evaluation in enumerate(trace.transitions):
            segment = segment_by_id[evaluation.transition.step_id]
            serialized = self._packet_transition_json(
                evaluation,
                segment=segment,
            )
            if declared_case is not None:
                serialized["declared_actions"] = list(
                    declared_action_buckets[transition_index]
                )
            serialized["continuity_valid"] = (
                self._packet_boundary_continuity(
                    expected_packet_state,
                    evaluation.transition.before,
                )
            )
            serialized_transitions.append(serialized)
            segment["packet_transition"] = serialized
            segment["route_resolution"]["packet_transition"] = serialized
            expected_packet_state = evaluation.transition.after

        counterfactual = any(
            item.counterfactual for item in trace.transitions
        )
        declared_profile_id = (
            str(declared_case["packet_profile_id"])
            if declared_case is not None
            else profile_id
        )
        path["packet_profile_id"] = declared_profile_id
        path["packet_executor_profile_id"] = profile_id
        path["counterfactual"] = counterfactual
        path["observed"] = not counterfactual
        path["packet_trace"] = {
            "schema_version": self.policy.packet_trace_schema_version,
            "layer_order": "outermost_to_innermost",
            "initial_state": self._packet_state_json(initial_state),
            "outcome": trace.outcome,
            "stop_step": trace.stop_step,
            "continuity": trace.continuity,
            "continuity_complete": trace.continuity == "complete",
            "terminal_disposition": (
                trace.terminal_disposition.value
                if trace.terminal_disposition is not None
                else None
            ),
            "counterfactual": counterfactual,
            "steering_profile_id": steering_profile_id,
            "transitions": serialized_transitions,
            "generated_declaration": (
                {
                    **declared_case,
                    "executor_profile_id": profile_id,
                    "initial_state_binding": (
                        "declared_fields_over_executor_layers"
                    ),
                    "action_plan_binding": (
                        "declared_transition_contracts_over_executor_semantics"
                    ),
                }
                if declared_case is not None
                else None
            ),
            "declared_initial_layers": (
                list(declared_case["initial_layers"])
                if declared_case is not None
                else None
            ),
            "declared_action_plan": (
                declared_actions if declared_case is not None else None
            ),
            "validation_owner": "core",
            "semantics_owner": "node_plugins",
        }

        if trace.outcome != "drop" or not trace.transitions:
            return
        dropped = trace.transitions[-1]
        terminal = segment_by_id[dropped.transition.step_id]
        drop_index = path["segments"].index(terminal)
        terminal.update(
            {
                "segment_kind": "packet_mtu_drop",
                "active": False,
                "confidence": 1.0,
                "completeness": {
                    "state": "terminal_drop",
                    "end_to_end_resolved": False,
                    "observed": True,
                },
            }
        )
        terminal["state"].update(
            {
                "active": False,
                "selected_active_by_plugin": True,
                "operational": "unusable",
                "terminal": "mtu_exceeded",
                "reason_code": "mtu_exceeded_after_encapsulation",
                "terminal_disposition": "dropped",
            }
        )
        terminal["route_resolution"]["phase"] = "packet_mtu_decision"
        terminal["phase"] = "packet_mtu_decision"
        for suffix in path["segments"][drop_index + 1 :]:
            suffix["active"] = False
            suffix["completeness"] = {
                "state": "not_traversed",
                "end_to_end_resolved": False,
                "observed": False,
            }
            suffix["state"].update(
                {
                    "active": False,
                    "operational": "not_traversed",
                    "reason_code": "upstream_terminal_drop",
                }
            )
        issue_id = (
            f"issue:packet-mtu:{direction}:{terminal['segment_id']}"
        )
        terminal["issue_refs"] = list(
            dict.fromkeys([*terminal.get("issue_refs", []), issue_id])
        )
        path["issue_refs"] = list(
            dict.fromkeys([*path.get("issue_refs", []), issue_id])
        )
        issues.append(
            {
                "issue_id": issue_id,
                "category": "forwarding",
                "severity": "error",
                "summary": "Plug-in-declared MTU policy drops the packet",
                "detail": (
                    "Core confirmed that the plug-in-declared packet size "
                    "exceeds an exactly comparable MTU. The node plug-in, not "
                    "core, declared the DF/drop disposition."
                ),
                "path_refs": [path["path_id"]],
                "segment_refs": [terminal["segment_id"]],
                "interaction_target_ids": list(
                    terminal.get("interaction_target_ids", [])
                ),
                "ownership": (
                    "core_size_comparison_node_plugin_disposition"
                ),
            }
        )
        self._refresh_path(path)

    def _declare_plugin_terminal_evidence(
        self,
        paths: list[dict[str, Any]],
        target_endpoint: dict[str, Any],
    ) -> None:
        """Project plug-in delivery decisions before core exact matching.

        This method stands in for the participating node plug-ins.  The core
        annotator below consumes only this normalized declaration; it does not
        infer endpoint delivery from a path's final node.
        """

        declared_attachments_by_node = {
            str(item["node_id"]): dict(item)
            for item in target_endpoint.get("attachments", [])
            if item.get("node_id")
        }
        attachments_by_node = {
            str(item["node_id"]): dict(item)
            for item in target_endpoint.get("attachments", [])
            if item.get("can_terminate", True)
            and item.get("state") not in {"withdrawn", "unavailable"}
            and item.get("node_id")
        }
        for path in paths:
            sequence = [
                str(item) for item in path.get("node_sequence", []) if item
            ]
            terminal_node_id = sequence[-1] if sequence else None
            target_attachment = attachments_by_node.get(
                str(terminal_node_id)
            )
            declared_attachment = declared_attachments_by_node.get(
                str(terminal_node_id)
            )
            resolved = bool(
                path.get("completeness", {}).get("end_to_end_resolved")
            )
            forwarding_capable = path.get("forwarding_capable", True) is not False
            result = str(path.get("result", "unknown"))
            if (
                resolved
                and forwarding_capable
                and result == "resolved"
                and target_attachment is not None
            ):
                declaration = {
                    "classification": "delivered",
                    "classification_complete": True,
                    "endpoint_id": target_endpoint["endpoint_id"],
                    "attachment": target_attachment,
                }
            elif (
                resolved
                and forwarding_capable
                and result == "resolved"
                and declared_attachment is not None
                and (
                    declared_attachment.get("can_terminate") is False
                    or declared_attachment.get("state")
                    in {"withdrawn", "unavailable"}
                )
            ):
                declaration = {
                    "classification": "not_delivered",
                    "classification_complete": True,
                    "endpoint_id": target_endpoint["endpoint_id"],
                    "attachment": declared_attachment,
                }
            elif result in {
                "dropped",
                "discarded",
                "unusable",
                "cycle",
                "policy_blocked",
                "hop_limit_exceeded",
                "recursion_limit_exceeded",
            } or not forwarding_capable or (
                resolved
                and forwarding_capable
                and result == "resolved"
                and target_endpoint.get("attachments_complete") is True
            ):
                declaration = {
                    "classification": "not_delivered",
                    "classification_complete": True,
                    "endpoint_id": None,
                    "attachment": None,
                }
            else:
                declaration = {
                    "classification": "unknown",
                    "classification_complete": False,
                    "endpoint_id": None,
                    "attachment": None,
                }
            declaration.update(
                {
                    "terminal_node_id": terminal_node_id,
                    "semantic_owner": "node_plugin",
                    "evidence_kind": "normalized_terminal_attachment",
                }
            )
            path["plugin_terminal"] = declaration

    @classmethod
    def _annotate_endpoint_reachability(
        cls,
        paths: list[dict[str, Any]],
        target_endpoint: dict[str, Any],
        trace_start: dict[str, Any],
    ) -> dict[str, Any]:
        """Match plug-in-declared path terminals to the requested endpoint."""

        target_endpoint_id = target_endpoint.get("endpoint_id")
        if not isinstance(target_endpoint_id, str) or not target_endpoint_id:
            raise MultiNodeRouteRequestError(
                "target endpoint must declare a non-empty endpoint_id"
            )
        target_attachments = [
            dict(item)
            for item in target_endpoint.get("attachments", [])
            if item.get("can_terminate", True)
            and item.get("state") not in {"withdrawn", "unavailable"}
        ]
        target_attachment_identities = {
            cls._attachment_identity(
                item,
                label="target endpoint attachment",
            )
            for item in target_attachments
        }
        attachments_complete = target_endpoint.get(
            "attachments_complete", False
        )
        if not isinstance(attachments_complete, bool):
            raise MultiNodeRouteRequestError(
                "target endpoint attachments_complete must be a boolean"
            )
        active_branch_count = 0
        reached_active_branch_count = 0
        unresolved_active_branch_count = 0
        failed_active_branch_count = 0
        selected_results: list[bool | None] = []
        for path in paths:
            sequence = [
                str(item) for item in path.get("node_sequence", []) if item
            ]
            if not sequence or sequence[0] != str(trace_start.get("node_id")):
                raise MultiNodeRouteRequestError(
                    "plug-in route path must begin at the declared trace_start"
                )
            terminal_node_id = sequence[-1] if sequence else None
            end_to_end_resolved = bool(
                path.get("completeness", {}).get("end_to_end_resolved")
            )
            declaration = path.get("plugin_terminal")
            if not isinstance(declaration, dict):
                raise MultiNodeRouteRequestError(
                    "plug-in route path must declare plugin_terminal evidence"
                )
            classification = declaration.get("classification")
            if classification not in {"delivered", "not_delivered", "unknown"}:
                raise MultiNodeRouteRequestError(
                    "plugin_terminal.classification must be delivered, "
                    "not_delivered, or unknown"
                )
            classification_complete = declaration.get(
                "classification_complete"
            )
            if not isinstance(classification_complete, bool):
                raise MultiNodeRouteRequestError(
                    "plugin_terminal.classification_complete must be a boolean"
                )
            terminal_attachment = declaration.get("attachment")
            if terminal_attachment is not None and not isinstance(
                terminal_attachment, dict
            ):
                raise MultiNodeRouteRequestError(
                    "plugin_terminal.attachment must be an object or null"
                )
            terminal_attachment_identity = (
                cls._attachment_identity(
                    terminal_attachment,
                    label="plug-in terminal attachment",
                )
                if terminal_attachment is not None
                else None
            )
            endpoint_matches = (
                declaration.get("endpoint_id") == target_endpoint_id
            )
            attachment_matches = (
                terminal_attachment_identity
                in target_attachment_identities
                if terminal_attachment_identity is not None
                else False
            )
            exact_match = endpoint_matches and attachment_matches
            if classification == "delivered":
                if exact_match and end_to_end_resolved:
                    reaches_target: bool | None = True
                elif classification_complete and attachments_complete:
                    reaches_target = False
                else:
                    reaches_target = None
            elif classification == "not_delivered":
                reaches_target = False if classification_complete else None
            else:
                reaches_target = None
            state = (
                "reached"
                if reaches_target is True
                else "not_reached"
                if reaches_target is False
                else "unknown"
            )
            path["target_endpoint_id"] = target_endpoint_id
            path["terminal_endpoint_id"] = declaration.get("endpoint_id")
            path["terminal_reachability"] = {
                "state": state,
                "reached": reaches_target,
                "target_endpoint_id": target_endpoint_id,
                "terminal_endpoint_id": declaration.get("endpoint_id"),
                "terminal_node_id": terminal_node_id,
                "terminal_attachment": terminal_attachment,
                "exact_endpoint_match": endpoint_matches,
                "exact_attachment_match": attachment_matches,
                "exact_match": exact_match,
                "classification_complete": classification_complete,
                "end_to_end_resolved": end_to_end_resolved,
                "classification_owner": "node_plugin",
                "exact_match_owner": "core",
            }
            selected_active = bool(
                path.get(
                    "selected_active_by_plugin",
                    path.get("active"),
                )
            )
            if selected_active:
                active_branch_count += 1
                selected_results.append(reaches_target)
                if reaches_target is True:
                    reached_active_branch_count += 1
                elif reaches_target is None:
                    unresolved_active_branch_count += 1
                else:
                    failed_active_branch_count += 1

        no_selected_active_path = not selected_results
        explicitly_nonforwarding = bool(paths) and all(
            item["plugin_terminal"]["classification"] == "not_delivered"
            and item["plugin_terminal"]["classification_complete"] is True
            for item in paths
        )
        if no_selected_active_path and explicitly_nonforwarding:
            state = "not_reached"
            reaches_target: bool | None = False
        elif no_selected_active_path:
            # Standby, rejected, or merely retained candidates are not
            # forwarding truth.  Do not promote the primary or first row.
            state = "unknown_no_selected_active_path"
            reaches_target = None
        elif all(item is True for item in selected_results):
            state = "reached"
            reaches_target = True
        elif any(item is None for item in selected_results):
            state = "unknown"
            reaches_target = None
        elif any(item is True for item in selected_results):
            state = "partial_active_reachability"
            reaches_target = None
        else:
            state = "not_reached"
            reaches_target = False
        all_active_branches_reach: bool | None = (
            None
            if not selected_results or any(
                item is None for item in selected_results
            )
            else all(item is True for item in selected_results)
        )
        return {
            "state": state,
            "reaches_target": reaches_target,
            "target_endpoint_id": target_endpoint_id,
            "target_attachment_ids": sorted(
                item[0] for item in target_attachment_identities
            ),
            "target_attachment_node_ids": sorted(
                item[1] for item in target_attachment_identities
            ),
            "attachments_complete": attachments_complete,
            "trace_start_node_id": trace_start["node_id"],
            "active_branch_count": active_branch_count,
            "reached_active_branch_count": reached_active_branch_count,
            "unresolved_active_branch_count": unresolved_active_branch_count,
            "failed_active_branch_count": failed_active_branch_count,
            "all_active_branches_reach": all_active_branches_reach,
            "selection_complete": not no_selected_active_path
            or explicitly_nonforwarding,
            "no_selected_active_path": no_selected_active_path,
            "criterion": "exact_normalized_endpoint_attachment",
            "terminal_classification_owner": "node_plugin",
            "aggregation_owner": "core",
        }

    @staticmethod
    def _validate_referenced_route_row(
        row: dict[str, Any] | None,
        trace_start: dict[str, Any],
        destination: dict[str, Any],
        routing_context: dict[str, Any],
    ) -> None:
        if row is None:
            return
        expected = {
            "node_id": trace_start["node_id"],
            "destination_node_id": destination["node_id"],
            "vrf_id": routing_context["vrf_id"],
            "route_family": routing_context["route_family"],
            "route_type": routing_context["route_type"],
        }
        actual = {
            "node_id": row["node_id"],
            "destination_node_id": row["destination"]["node_id"],
            "vrf_id": row["vrf_id"],
            "route_family": row["route_family"],
            "route_type": row["route_type"],
        }
        if actual != expected:
            raise MultiNodeRouteRequestError(
                "route_entry_ref does not match the requested trace start, destination, "
                "VRF, family, and route type"
            )

    def _decorate_route_presentations(
        self,
        paths: list[dict[str, Any]],
        routing_context: dict[str, Any],
    ) -> None:
        """Attach plug-in-declared graph context without changing path geometry.

        These descriptors deliberately use protocol-neutral roles.  The
        plug-in decides which route types represent a tenant service; the core
        renderer must not infer that from a VRF name, VNI, label, SID, or text.
        """

        def node_topology_reference(node_id: str) -> dict[str, Any]:
            return {
                "match": {
                    "matcher_id": self.policy.node_matcher_id,
                    "arguments": {"node_id": node_id},
                }
            }

        def target_topology_reference(
            target: dict[str, Any],
        ) -> dict[str, Any] | None:
            if target.get("kind") == "topology_link" and target.get("topology_link_id"):
                return {
                    "match": {
                        "matcher_id": self.policy.topology_link_matcher_id,
                        "arguments": {"topology_link_id": target["topology_link_id"]},
                    }
                }
            if target.get("kind") == "topology_match" and target.get("matcher_id"):
                return {
                    "match": {
                        "matcher_id": target["matcher_id"],
                        "arguments": {"match_key": target.get("match_key")},
                    }
                }
            return None

        for path in paths:
            path_id = str(path["path_id"])
            node_sequence = [str(item) for item in path.get("node_sequence", [])]
            endpoint_refs = [
                {"node_id": node_id}
                for node_id in (
                    [node_sequence[0], node_sequence[-1]]
                    if len(node_sequence) >= 2
                    else node_sequence
                )
            ]
            topology_references = [
                node_topology_reference(item["node_id"])
                for item in endpoint_refs
            ]
            provenance = [dict(item) for item in path.get("plugin_provenance", [])]
            provided_by = next(
                (
                    item
                    for item in provenance
                    if item.get("ownership") == "node_plugin"
                    or item.get("decision_owner") == "node_route_plugin"
                ),
                provenance[0] if provenance else {"plugin_id": "unknown-plugin"},
            )
            boundary_segments = [
                item
                for item in path.get("segments", [])
                if item.get("segment_kind") == "inter_node_boundary"
                and item.get("participates_in_forwarding_geometry", True)
            ]
            principal = {
                "presentation_id": f"presentation:{path_id}:outer-l1-l3",
                "role": "principal",
                "scope": "path",
                "style": "path",
                "label": "Outer L1-L3 forwarding",
                "description": (
                    "Device cards are L3 resolution points; arrows are the "
                    "plug-in-resolved outer L1/L2 boundaries between them."
                ),
                "geometry_role": "forwarding",
                "participates_in_forwarding_geometry": True,
                "topology_references": topology_references,
                "anchor_resources": [],
                "segment_ids": [item["segment_id"] for item in boundary_segments],
                "topology_link_ids": [
                    item["topology_link_id"]
                    for item in boundary_segments
                    if item.get("topology_link_id")
                ],
                "facts": {
                    "layers": ["L1", "L2", "L3"],
                    "physical_boundaries": len(boundary_segments),
                },
                "semantic_owner": "plugin",
                "provided_by": dict(provided_by),
                "plugin_provenance": provenance,
            }
            layers = [principal]
            route_type = str(path.get("route_type") or routing_context.get("route_type") or "")
            route_profile = self.policy.route_type_profiles.get(
                route_type,
                {},
            )
            service = route_profile.get("service_presentation")
            encapsulation = dict(path.get("encapsulation") or {})
            if isinstance(service, Mapping):
                declared_vrf = routing_context.get(
                    "vrf_id"
                ) or routing_context.get("vrf")
                vrf_id = (
                    str(declared_vrf)
                    if declared_vrf is not None
                    else None
                )
                facts: dict[str, Any] = {
                    "routing_context": vrf_id,
                    "route_family": routing_context.get("route_family"),
                    "protocol_chain": list(path.get("protocol_chain") or []),
                    "encapsulation": encapsulation,
                }
                fact_fields = service.get("fact_fields", {})
                if not isinstance(fact_fields, Mapping):
                    raise MultiNodeRouteRequestError(
                        "service presentation fact_fields must be an object"
                    )
                for source_field, public_field in fact_fields.items():
                    value = path.get(source_field)
                    if value not in (None, [], {}):
                        facts[str(public_field)] = value
                topology_targets = list(path.get("presentation_topology_targets") or [])
                domain_keys = service.get("connectivity_domain_keys", {})
                if not isinstance(domain_keys, Mapping):
                    raise MultiNodeRouteRequestError(
                        "service presentation connectivity_domain_keys "
                        "must be an object"
                    )
                segment_key = domain_keys.get(vrf_id)
                if segment_key:
                    interaction_target_id = next(
                        (
                            str(item)
                            for item in path.get(
                                "interaction_target_ids",
                                [],
                            )
                            if item
                        ),
                        None,
                    )
                    topology_targets.append(
                        {
                            "kind": "topology_match",
                            "matcher_id": (
                                self.policy.connectivity_domain_matcher_id
                            ),
                            "match_key": segment_key,
                            "interaction_target_id": (
                                interaction_target_id
                            ),
                            "semantic_owner": "topology_plugin",
                        }
                    )
                alternative_state = str(path.get("alternative_state") or "")
                status = (
                    "withdrawn"
                    if alternative_state == "withdrawn_dead"
                    else "expected"
                    if alternative_state == "control_expected_not_observed"
                    else "active"
                    if path.get("active")
                    else "inactive"
                )
                overlay_topology_references = list(topology_references)
                overlay_topology_references.extend(
                    reference
                    for item in topology_targets
                    if (reference := target_topology_reference(item)) is not None
                )
                layers.append(
                    {
                        "presentation_id": f"presentation:{path_id}:service-overlay",
                        "group_id": (
                            f"service:{vrf_id}:{routing_context.get('route_family', route_type)}"
                        ),
                        "role": "overlay",
                        "scope": "path",
                        "style": "band",
                        "label": str(service["label"]).format(
                            vrf=vrf_id,
                            technology=service.get("technology", ""),
                        ),
                        "description": str(service["description"]),
                        "geometry_role": "context",
                        "participates_in_forwarding_geometry": False,
                        "topology_references": overlay_topology_references,
                        "anchor_resources": [],
                        "topology_targets": topology_targets,
                        "interaction_target_ids": [
                            item["interaction_target_id"]
                            for item in topology_targets
                            if isinstance(item, dict) and item.get("interaction_target_id")
                        ],
                        "facts": {
                            key: value
                            for key, value in facts.items()
                            if value not in (None, [], {})
                        },
                        "status": status,
                        "semantic_owner": "plugin",
                        "provided_by": dict(provided_by),
                        "plugin_provenance": provenance,
                    }
                )
            elif encapsulation:
                layers.append(
                    {
                        "presentation_id": f"presentation:{path_id}:encapsulation",
                        "role": "annotation",
                        "scope": "path",
                        "style": "badge",
                        "label": "Encapsulation context",
                        "description": "Plug-in-declared encapsulation applied to the outer path.",
                        "geometry_role": "context",
                        "participates_in_forwarding_geometry": False,
                        "topology_references": topology_references,
                        "anchor_resources": [],
                        "facts": {"encapsulation": encapsulation},
                        "semantic_owner": "plugin",
                        "provided_by": dict(provided_by),
                        "plugin_provenance": provenance,
                    }
                )
            path["presentations"] = layers

    def _attach_route_entry_refs(
        self,
        paths: list[dict[str, Any]],
        destination: dict[str, Any],
        routing_context: dict[str, Any],
        referenced_row: dict[str, Any] | None,
        targets: dict[str, dict[str, Any]],
        *,
        scenario_id: str,
    ) -> list[dict[str, Any]]:
        entries = self._route_table_entries()
        all_refs: dict[str, dict[str, Any]] = {}
        for path in paths:
            sequence = list(path.get("node_sequence") or [])
            path_destination_node_id = str(
                path.get("destination_node_id") or destination["node_id"]
            )
            local_rows: list[dict[str, Any]] = []
            resolution_nodes = sequence if len(sequence) == 1 else sequence[:-1]
            for node_index, node_id in enumerate(resolution_nodes):
                candidates = [
                    item
                    for item in entries
                    if item["node_id"] == node_id
                    and item["destination"]["node_id"]
                    == path_destination_node_id
                    and item["vrf_id"] == routing_context["vrf_id"]
                    and item["route_family"] == routing_context["route_family"]
                    and item["route_type"] == path.get("route_type")
                ]
                generated_candidates = any(
                    item.get("plugin_provenance", {}).get("data_kind")
                    == "generated_route_table_row"
                    for item in candidates
                )
                if generated_candidates:
                    candidates = [
                        item
                        for item in candidates
                        if item.get("trace_query", {}).get("scenario_id")
                        == scenario_id
                    ]
                    next_node_id = (
                        sequence[node_index + 1]
                        if node_index + 1 < len(sequence)
                        else None
                    )
                    if next_node_id is not None:
                        candidates = [
                            item
                            for item in candidates
                            if any(
                                next_hop.get("neighbor_node_id")
                                == next_node_id
                                for next_hop in item.get("next_hops", [])
                            )
                        ]
                else:
                    candidates = [
                        item for item in candidates if item["installed"]
                    ]
                if (
                    node_id == sequence[0]
                    and referenced_row is not None
                    and (
                        referenced_row["path_id"] == path.get("path_id")
                        or any(
                            item["route_entry_id"]
                            == referenced_row["route_entry_id"]
                            for item in candidates
                        )
                    )
                ):
                    candidates = [referenced_row]
                elif candidates:
                    exact = next(
                        (
                            item
                            for item in candidates
                            if item["path_id"] == path.get("path_id")
                        ),
                        None,
                    )
                    candidates = [exact or candidates[0]]
                local_rows.extend(candidates[:1])
            refs = [item["route_entry_ref"] for item in local_rows]
            correlations = [
                {
                    "route_entry_ref": item["route_entry_ref"],
                    "route_entry_id": item["route_entry_id"],
                    "install_state": item["install_state"],
                    "installed": item["installed"],
                    "correlation_role": (
                        "control_plane_evidence"
                        if item["install_state"] == "control_plane_only"
                        else "forwarding_route"
                    ),
                }
                for item in local_rows
            ]
            path["route_entry_refs"] = refs
            path["matched_route_entry_refs"] = refs
            path["route_entry_correlations"] = correlations
            for row in local_rows:
                entry_id = row["route_entry_id"]
                all_refs[entry_id] = row["route_entry_ref"]
                target_id = self._target_id("route_table_row", entry_id)
                targets.setdefault(
                    target_id,
                    {
                        "target_id": target_id,
                        "kind": "route_table_row",
                        "label": (
                            f"{row['node_label']} {row['vrf_id']} "
                            f"{row['prefix']}"
                        ),
                        "node_id": row["node_id"],
                        "member_id": row["member_id"],
                        "route_entry_id": entry_id,
                        "route_entry_ref": row["route_entry_ref"],
                        "installed": row["installed"],
                        "install_state": row["install_state"],
                        "correlation_role": (
                            "control_plane_evidence"
                            if row["install_state"] == "control_plane_only"
                            else "forwarding_route"
                        ),
                        "trace_query": row["trace_query"],
                    },
                )
            refs_by_node = {
                item["node_id"]: item["route_entry_ref"] for item in local_rows
            }
            correlations_by_node = {
                item["node_id"]: correlation
                for item, correlation in zip(local_rows, correlations)
            }
            for segment in path.get("segments", []):
                node_id = segment.get("node_id")
                segment_refs = [refs_by_node[node_id]] if node_id in refs_by_node else []
                segment["route_entry_refs"] = segment_refs
                segment["route_entry_correlations"] = (
                    [correlations_by_node[node_id]]
                    if node_id in correlations_by_node
                    else []
                )
        return list(all_refs.values())

    def _resolve_trace_start(
        self,
        body: dict[str, Any],
        scenario: dict[str, Any],
        direction: str,
        directional_source: dict[str, Any],
        *,
        scenario_direction: str | None = None,
    ) -> dict[str, Any]:
        """Resolve a traversal seed without changing the packet source.

        ``ingress`` is the forward observation point.  The reverse direction
        deliberately ignores it and defaults to the destination-side endpoint
        attachment unless ``trace_starts.reverse``/``reverse_ingress`` is
        explicitly supplied.
        """

        trace_starts = self._optional_object(body, "trace_starts")
        candidates: list[tuple[str, Any]] = []
        if trace_starts.get(direction) is not None:
            candidates.append((f"trace_starts.{direction}", trace_starts[direction]))
        if direction == "forward":
            for field in ("ingress", "starting_point", "start"):
                if body.get(field) is not None:
                    candidates.append((field, body[field]))
            if body.get("start_id") is not None:
                candidates.append(("start_id", body["start_id"]))
        elif body.get("reverse_ingress") is not None:
            candidates.append(("reverse_ingress", body["reverse_ingress"]))
        normalized_candidates = [
            (
                label,
                {"start_id": value} if isinstance(value, str) else value,
            )
            for label, value in candidates
        ]
        if any(not isinstance(value, dict) for _label, value in normalized_candidates):
            label = next(
                label
                for label, value in normalized_candidates
                if not isinstance(value, dict)
            )
            raise MultiNodeRouteRequestError(f"{label} must be an object or start ID")
        if len(normalized_candidates) > 1:
            encoded = {
                json.dumps(value, sort_keys=True, default=str)
                for _label, value in normalized_candidates
            }
            if len(encoded) > 1:
                raise MultiNodeRouteRequestError(
                    "trace start selectors for the requested direction disagree"
                )
        request = (
            dict(normalized_candidates[0][1])
            if normalized_candidates
            else {}
        )
        if (
            not request
            and (scenario_direction or direction) == "forward"
            and scenario.get("default_start")
        ):
            request = {"start_id": scenario["default_start"]}

        derivation = str(
            request.get("derivation")
            or (
                "explicit_observation"
                if request
                else "source_endpoint_attachment"
                if direction == "forward"
                else "destination_endpoint_attachment"
            )
        )
        available_attachments = [
            dict(item)
            for item in directional_source.get("attachments", [])
            if item.get("state") not in {"withdrawn", "unavailable"}
            and item.get("can_originate", True)
        ]
        selected_attachment: dict[str, Any] | None = None
        if not request:
            router = self._router(str(directional_source["node_id"]))
            matching_attachments = [
                item
                for item in available_attachments
                if str(item.get("node_id")) == router["node_id"]
            ]
            if len(matching_attachments) == 1:
                selected_attachment = matching_attachments[0]
        else:
            ingress_ref = request.get("ingress_resource_ref")
            if ingress_ref is not None and not isinstance(ingress_ref, dict):
                raise MultiNodeRouteRequestError(
                    "ingress_resource_ref must be an object"
                )
            resource_id = request.get("resource_id") or (
                ingress_ref.get("resource_id") if ingress_ref else None
            )
            start_id = request.get("start_id")
            node_selectors = {
                str(value)
                for value in (
                    request.get("node_id"),
                    str(request["member_id"]).removeprefix("member:")
                    if request.get("member_id")
                    else None,
                    str(start_id).removeprefix("start:")
                    if start_id
                    else None,
                )
                if value is not None
            }
            if resource_id is not None:
                endpoint_attachment = next(
                    (
                        item
                        for item in available_attachments
                        if str(item.get("resource_id")) == str(resource_id)
                    ),
                    None,
                )
                resource_router = (
                    self._router(str(endpoint_attachment["node_id"]))
                    if endpoint_attachment is not None
                    else self._router(
                        self._generated_resource_owner_by_id[
                            str(resource_id)
                        ]
                    )
                    if str(resource_id)
                    in self._generated_resource_owner_by_id
                        else next(
                            (
                                item
                                for item in self._routers
                                if item["loopback_resource_id"]
                                == str(resource_id)
                            ),
                            None,
                        )
                    )
                if resource_router is None:
                    raise MultiNodeRouteRequestError(
                        f"unknown trace start resource_id: {resource_id}"
                    )
                node_selectors.add(resource_router["node_id"])
            # Labels are plug-in-owned presentation text, not an identity
            # selector.  A generated catalog may use a human label that is
            # intentionally different from this executor's router label.
            # Resolve only an explicit value; exact IDs above remain the
            # canonical, constant-time path.
            value = request.get("value")
            if value is not None:
                normalized = str(value).strip().casefold()
                matches = [
                    item
                    for item in self._routers
                    if normalized
                    in {
                        item["node_id"].casefold(),
                        item["label"].casefold(),
                        item["prefix"].casefold(),
                    }
                ]
                if len(matches) != 1:
                    raise MultiNodeRouteRequestError(
                        f"unknown or ambiguous trace start value: {value}"
                    )
                node_selectors.add(matches[0]["node_id"])
            if not node_selectors:
                raise MultiNodeRouteRequestError(
                    "trace start requires start_id, node_id, member_id, "
                    "resource_id, or value"
                )
            if len(node_selectors) != 1:
                raise MultiNodeRouteRequestError(
                    "trace start identifiers disagree"
                )
            router = self._router(next(iter(node_selectors)))
            matching_attachments = [
                item
                for item in available_attachments
                if str(item.get("node_id")) == router["node_id"]
                and (
                    resource_id is None
                    or str(item.get("resource_id")) == str(resource_id)
                )
            ]
            if len(matching_attachments) == 1:
                selected_attachment = matching_attachments[0]
            elif len(matching_attachments) > 1:
                raise MultiNodeRouteRequestError(
                    "trace start matches multiple endpoint attachments; "
                    "supply resource_id"
                )

        if (
            router["node_id"] != directional_source["node_id"]
            and not scenario.get("supports_explicit_start")
            and not scenario.get("supports_arbitrary_endpoints")
        ):
            raise MultiNodeRouteRequestError(
                f"scenario {scenario['scenario_id']} does not advertise a "
                "transit trace start"
            )
        return {
            "start_id": f"start:{router['node_id']}",
            "node_id": router["node_id"],
            "member_id": (
                selected_attachment.get("member_id")
                if selected_attachment is not None
                else f"member:{router['node_id']}"
            ),
            "resource_id": (
                selected_attachment.get("resource_id")
                if selected_attachment is not None
                else request.get("resource_id") or router["loopback_resource_id"]
            ),
            "attachment_id": (
                selected_attachment.get("attachment_id")
                if selected_attachment is not None
                else None
            ),
            "label": router["label"],
            "site": router["site"],
            "role": router["role"],
            "derivation": derivation,
            "semantic_role": "traversal_seed",
        }

    @staticmethod
    def _opposite_trace_direction(direction: str) -> str:
        if direction == "forward":
            return "reverse"
        if direction == "reverse":
            return "forward"
        raise MultiNodeRouteRequestError(
            "an endpoint pair can map only forward or reverse direction"
        )

    def _scenario_direction_for_flow(
        self,
        scenario_id: str,
        flow_source: Mapping[str, Any],
        flow_destination: Mapping[str, Any],
        requested_direction: str,
    ) -> str:
        """Map a caller-oriented flow onto a fixed executor's declarations."""

        scenario = self.policy.scenarios[scenario_id]
        if scenario.get("supports_arbitrary_endpoints"):
            return requested_direction
        advertised = self._advertised_scenario_by_id[scenario_id]
        declared_pair = (
            str(advertised.get("source", {}).get("node_id") or ""),
            str(advertised.get("destination", {}).get("node_id") or ""),
        )
        supplied_pair = (
            str(flow_source.get("node_id") or ""),
            str(flow_destination.get("node_id") or ""),
        )
        if supplied_pair == declared_pair:
            return requested_direction
        if (
            declared_pair[0] != declared_pair[1]
            and supplied_pair == (declared_pair[1], declared_pair[0])
        ):
            return self._opposite_trace_direction(requested_direction)
        raise MultiNodeRouteRequestError(
            f"scenario {scenario_id} is scoped to "
            f"{declared_pair[0]}/{declared_pair[1]}"
        )

    def _resolve_endpoints(
        self, body: dict[str, Any], scenario_id: str, direction: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        source_request = self._optional_object(body, "source")
        destination_request = self._optional_object(body, "destination")
        scenario_semantics = self.policy.scenarios[scenario_id]
        advertised_scenario = self._advertised_scenario_by_id[scenario_id]
        destination_role = str(
            scenario_semantics.get("destination_role") or "router"
        )
        endpoint_profile = dict(
            self.policy.endpoint_profiles.get(destination_role, {})
        )
        if endpoint_profile:
            missing_endpoint_fields = {
                "endpoint_id",
                "destination_id",
                "kind",
                "label",
            } - endpoint_profile.keys()
            if missing_endpoint_fields:
                raise MultiNodeRouteRequestError(
                    "route endpoint profile is missing fields for "
                    f"{destination_role}: "
                    + ", ".join(sorted(missing_endpoint_fields))
                )
        elif destination_role != "router":
            raise MultiNodeRouteRequestError(
                "route scenario declares an endpoint role without an "
                f"installed profile: {destination_role}"
            )
        declared_destination_router = self._router(
            str(advertised_scenario["destination"]["node_id"])
        )
        destination_endpoint_ids = {
            str(item)
            for item in scenario_semantics.get(
                "destination_endpoint_ids",
                (),
            )
        }
        destination_values = {
            str(item).casefold()
            for item in scenario_semantics.get("destination_values", ())
        }
        routers_by_source = {
            item["source_id"]: item for item in self._routers
        }
        routers_by_source.update(
            {
                self._router_endpoint_id(item["node_id"]): item
                for item in self._routers
            }
        )
        routers_by_source.update(
            {
                f"source:{item['node_id']}": item
                for item in self._routers
            }
        )
        routers_by_destination = {
            item["destination_id"]: item for item in self._routers
        }
        routers_by_destination.update(
            {
                self._router_endpoint_id(item["node_id"]): item
                for item in self._routers
            }
        )
        routers_by_destination.update(
            {
                f"destination:{item['node_id']}": item
                for item in self._routers
            }
        )
        routers_by_destination.update(
            {
                endpoint_id: declared_destination_router
                for endpoint_id in destination_endpoint_ids
            }
        )
        routers_by_resource = {
            item["loopback_resource_id"]: item for item in self._routers
        }
        routers_by_resource.update(
            {
                resource_id: self._router(node_id)
                for resource_id, node_id
                in self._generated_resource_owner_by_id.items()
                if node_id in self._routers_by_id
            }
        )

        def router_from_value(value: Any, field: str) -> dict[str, Any] | None:
            if value is None:
                return None
            text = str(value).strip()
            normalized = text.casefold()
            if text in routers_by_resource:
                return routers_by_resource[text]
            candidates = [
                item
                for item in self._routers
                if normalized
                in {
                    item["node_id"].casefold(),
                    item["label"].casefold(),
                    item["prefix"].casefold(),
                }
            ]
            alias_node_id = self.policy.router_value_aliases.get(normalized)
            if alias_node_id is not None:
                candidates = [self._router(alias_node_id)]
            if normalized in destination_values:
                if field != "destination":
                    raise MultiNodeRouteRequestError(
                        f"ambiguous {field} value: {value}"
                    )
                candidates = [declared_destination_router]
            if not candidates:
                raise MultiNodeRouteRequestError(
                    f"unknown {field} value: {value}"
                )
            if len(candidates) > 1:
                raise MultiNodeRouteRequestError(
                    f"ambiguous {field} value: {value}"
                )
            return candidates[0]

        source_id = (
            body.get("source_id")
            or source_request.get("source_id")
            or source_request.get("endpoint_id")
        )
        source_node_id = source_request.get("node_id")
        source_value = body.get("source_value") or source_request.get("value")
        if source_value is not None:
            value_router = router_from_value(source_value, "source")
            if source_node_id and value_router["node_id"] != str(source_node_id):
                raise MultiNodeRouteRequestError(
                    "source value and source.node_id disagree"
                )
            source_node_id = value_router["node_id"]
        if source_request.get("resource_id"):
            record = routers_by_resource.get(str(source_request["resource_id"]))
            if record is None:
                raise MultiNodeRouteRequestError(
                    f"unknown source resource_id: {source_request['resource_id']}"
                )
            if source_node_id and record["node_id"] != str(source_node_id):
                raise MultiNodeRouteRequestError(
                    "source.resource_id and source.node_id disagree"
                )
            source_node_id = record["node_id"]
        if source_id is not None:
            source_router = routers_by_source.get(str(source_id))
            if source_router is None:
                source_router = router_from_value(source_id, "source")
            if source_node_id and source_router["node_id"] != str(source_node_id):
                raise MultiNodeRouteRequestError("source_id and source.node_id disagree")
            source_node_id = source_router["node_id"]

        destination_id = (
            body.get("destination_id")
            or destination_request.get("destination_id")
            or destination_request.get("endpoint_id")
        )
        destination_node_id = destination_request.get("node_id")
        if destination_request.get("resource_id"):
            record = routers_by_resource.get(
                str(destination_request["resource_id"])
            )
            if record is None:
                raise MultiNodeRouteRequestError(
                    "unknown destination resource_id: "
                    f"{destination_request['resource_id']}"
                )
            if destination_node_id and record["node_id"] != str(
                destination_node_id
            ):
                raise MultiNodeRouteRequestError(
                    "destination.resource_id and destination.node_id disagree"
                )
            destination_node_id = record["node_id"]
        destination_value = body.get("destination_value") or destination_request.get(
            "value"
        )
        destination_value_text = str(destination_value or "").casefold()
        destination_is_presented_endpoint = bool(
            endpoint_profile
            and destination_value_text in destination_values
        )
        if destination_value is not None:
            value_router = router_from_value(destination_value, "destination")
            if (
                destination_node_id
                and value_router["node_id"] != str(destination_node_id)
            ):
                raise MultiNodeRouteRequestError(
                    "destination value and destination.node_id disagree"
                )
            destination_node_id = value_router["node_id"]
        if destination_id is not None:
            destination_id_text = str(destination_id)
            allowed_destination_ids = {
                str(scenario_semantics["default_destination"]),
                *destination_endpoint_ids,
            }
            advertised_scenario = self._advertised_scenario_by_id.get(
                scenario_id,
                {},
            )
            generated_destination_id = advertised_scenario.get(
                "destination",
                {},
            ).get("endpoint_id")
            if generated_destination_id:
                allowed_destination_ids.add(
                    str(generated_destination_id)
                )
            advertised_source_node_id = str(
                advertised_scenario.get("source", {}).get("node_id") or ""
            )
            if (
                advertised_source_node_id
                and not scenario_semantics.get("supports_arbitrary_endpoints")
            ):
                # Fixed scenarios explicitly allow their advertised pair in
                # either orientation.  Accept the opposite router's normal
                # destination selector so a generated counterpart request for
                # that reversed base flow is round-trippable.
                allowed_destination_ids.add(
                    str(
                        self._router(advertised_source_node_id)[
                            "destination_id"
                        ]
                    )
                )
            if (
                destination_id_text.startswith("destination:")
                and destination_id_text not in allowed_destination_ids
                and not self.policy.scenarios[scenario_id].get(
                    "supports_arbitrary_endpoints"
                )
            ):
                raise MultiNodeRouteRequestError(
                    f"destination_id {destination_id_text} is not supported by "
                    f"scenario {scenario_id}"
                )
            destination_router = routers_by_destination.get(str(destination_id))
            if destination_router is None:
                destination_router = router_from_value(
                    destination_id, "destination"
                )
            destination_is_presented_endpoint = (
                destination_is_presented_endpoint
                or destination_id_text in destination_endpoint_ids
            )
            if (
                destination_node_id
                and destination_router["node_id"] != str(destination_node_id)
            ):
                raise MultiNodeRouteRequestError(
                    "destination_id and destination.node_id disagree"
                )
            destination_node_id = destination_router["node_id"]

        declared_source_node = str(
            advertised_scenario.get("source", {}).get("node_id") or ""
        )
        declared_destination_node = str(
            advertised_scenario.get("destination", {}).get("node_id") or ""
        )
        if not scenario_semantics.get("supports_arbitrary_endpoints"):
            base_source = declared_source_node
            base_destination = declared_destination_node
            supplied_pair = (
                str(source_node_id or base_source),
                str(destination_node_id or base_destination),
            )
            allowed_pairs = {(base_source, base_destination)}
            if base_source != base_destination:
                allowed_pairs.add((base_destination, base_source))
            if supplied_pair not in allowed_pairs:
                raise MultiNodeRouteRequestError(
                    f"scenario {scenario_id} is scoped to "
                    f"{base_source}/{base_destination}"
                )
            pair_reversed = (
                base_source != base_destination
                and supplied_pair == (base_destination, base_source)
            )
            if pair_reversed and endpoint_profile.get("multi_attachment"):
                raise MultiNodeRouteRequestError(
                    "a fixed scenario with a multi-attachment destination "
                    "cannot reverse its endpoint pair without an explicit "
                    "source-attachment contract"
                )
            base_source, base_destination = supplied_pair
        else:
            base_source = str(source_node_id or declared_source_node)
            base_destination = str(
                destination_node_id or declared_destination_node
            )
            pair_reversed = False
            self._router(base_source)
            self._router(base_destination)
        scenario_direction = (
            self._opposite_trace_direction(direction)
            if pair_reversed
            else direction
        )
        actual_source, actual_destination = (
            (base_destination, base_source)
            if direction == "reverse"
            else (base_source, base_destination)
        )
        if (
            actual_source == actual_destination
            and not endpoint_profile.get("allow_same_node")
        ):
            raise MultiNodeRouteRequestError(
                "source and destination must be different routers"
            )
        source_router = self._router(actual_source)
        destination_router = self._router(actual_destination)
        resolved_source = {
            "endpoint_id": self._router_endpoint_id(source_router["node_id"]),
            "source_id": source_router["source_id"],
            "node_id": source_router["node_id"],
            "member_id": f"member:{source_router['node_id']}",
            "resource_id": source_router["loopback_resource_id"],
            "label": source_router["label"],
            "site": source_router["site"],
            "role": source_router["role"],
        }
        use_presented_endpoint = bool(
            endpoint_profile
            and (
                scenario_direction == "forward"
                or actual_source == actual_destination
            )
        )
        if (
            scenario_direction == "reverse"
            and actual_source != actual_destination
        ):
            # Destination selectors describe the base forward pair.  In the
            # reverse trace the service/subnet is the source-side endpoint and
            # the resolved destination is the opposite router loopback.
            use_presented_endpoint = False
        if (
            destination_is_presented_endpoint
            and scenario_direction == "forward"
        ):
            use_presented_endpoint = True
        endpoint_resource_mode = str(
            endpoint_profile.get("resource_mode") or "router"
        )
        endpoint_resource_id = (
            self._scenario_resource_id(
                scenario_id,
                destination_router["node_id"],
            )
            if use_presented_endpoint
            and endpoint_resource_mode == "scenario"
            else destination_router["loopback_resource_id"]
        )
        resolved_destination = {
            "endpoint_id": (
                str(endpoint_profile["endpoint_id"])
                if use_presented_endpoint
                else self._router_endpoint_id(destination_router["node_id"])
            ),
            "destination_id": (
                str(endpoint_profile["destination_id"])
                if use_presented_endpoint
                else destination_router["destination_id"]
            ),
            "node_id": destination_router["node_id"],
            "member_id": f"member:{destination_router['node_id']}",
            "resource_id": endpoint_resource_id,
            "kind": (
                str(endpoint_profile["kind"])
                if use_presented_endpoint
                else "router_loopback"
            ),
            "value": (
                endpoint_profile.get("value")
                if use_presented_endpoint
                else destination_router["prefix"]
            ),
            "label": (
                str(endpoint_profile["label"])
                if use_presented_endpoint
                else destination_router["label"]
            ),
            "site": destination_router["site"],
            "role": destination_router["role"],
        }
        attachment_specs: list[dict[str, Any]]
        if (
            use_presented_endpoint
            and endpoint_profile.get("multi_attachment")
        ):
            attachment_specs = (
                self._generated_destination_attachment_specs(scenario_id)
            )
            resolved_destination["terminating_node_ids"] = [
                str(item["node_id"]) for item in attachment_specs
            ]
        else:
            attachment_specs = [
                {
                    "node_id": resolved_destination["node_id"],
                    "state": "available",
                    "candidate_ids": [],
                }
            ]
        resolved_destination["attachments"] = [
            self._endpoint_attachment(
                endpoint_id=resolved_destination["endpoint_id"],
                node_id=str(spec["node_id"]),
                member_id=f"member:{spec['node_id']}",
                resource_id=(
                    self._scenario_resource_id(
                        scenario_id,
                        str(spec["node_id"]),
                    )
                    if use_presented_endpoint
                    and endpoint_profile.get("multi_attachment")
                    else resolved_destination["resource_id"]
                ),
                state=str(spec["state"]),
                candidate_ids=[
                    str(item) for item in spec["candidate_ids"]
                ],
            )
            for spec in attachment_specs
        ]
        resolved_destination["attachments_complete"] = True
        resolved_destination["available_attachments_complete"] = all(
            item["state"] == "available"
            for item in resolved_destination["attachments"]
        )
        resolved_source["attachments"] = [
            self._endpoint_attachment(
                endpoint_id=resolved_source["endpoint_id"],
                node_id=resolved_source["node_id"],
                member_id=resolved_source["member_id"],
                resource_id=resolved_source["resource_id"],
            )
        ]
        resolved_source["attachments_complete"] = True
        return resolved_source, resolved_destination

    def _directional_pair(
        self,
        scenario_id: str,
        direction: str,
        source: dict[str, Any],
        destination: dict[str, Any],
    ) -> dict[str, Any]:
        scenario = self.policy.scenarios[scenario_id]
        base_source = source["node_id"]
        base_destination = destination["node_id"]
        pair_id = str(
            scenario.get("pair_id")
            or (
                f"pair:{source.get('endpoint_id', base_source)}:"
                f"{destination.get('endpoint_id', base_destination)}"
            )
        )
        return {
            "pair_id": pair_id,
            "scenario_id": scenario_id,
            "base_source_node_id": base_source,
            "base_destination_node_id": base_destination,
            "source_endpoint_id": source.get("endpoint_id"),
            "destination_endpoint_id": destination.get("endpoint_id"),
            "requested_direction": direction,
        }

    @classmethod
    def _validate_pair_reverse_start(
        cls,
        flow_destination: dict[str, Any],
        reverse_start: dict[str, Any],
    ) -> None:
        """Require a pair's return observation to start at its destination."""

        allowed = {
            cls._attachment_identity(
                item,
                label="traffic destination attachment",
            )
            for item in flow_destination.get("attachments", [])
            if item.get("can_originate", True)
            and item.get("state") not in {"withdrawn", "unavailable"}
        }
        observed = (
            reverse_start.get("attachment_id"),
            reverse_start.get("node_id"),
            reverse_start.get("member_id"),
            reverse_start.get("resource_id"),
        )
        if observed not in allowed:
            raise MultiNodeRouteRequestError(
                "bidirectional reverse trace start must resolve to an "
                "available attachment of flow.destination"
            )

    def _bidirectional_response(
        self,
        scenario: dict[str, Any],
        route_type: str,
        resolution_mode: str,
        forward: dict[str, Any],
        reverse: dict[str, Any],
    ) -> dict[str, Any]:
        forward_active_paths = [
            item for item in forward["paths"] if item.get("active")
        ]
        reverse_active_paths = [
            item for item in reverse["paths"] if item.get("active")
        ]
        forward_path = (
            forward_active_paths[0]
            if forward_active_paths
            else forward["paths"][0]
        )
        reverse_path = (
            reverse_active_paths[0]
            if reverse_active_paths
            else reverse["paths"][0]
        )
        forward_start_attachment = (
            forward["trace_start"].get("attachment_id"),
            forward["trace_start"].get("node_id"),
            forward["trace_start"].get("member_id"),
            forward["trace_start"].get("resource_id"),
        )
        forward_source_attachments = {
            self._attachment_identity(
                item,
                label="traffic source attachment",
            )
            for item in forward["flow"]["source"].get("attachments", [])
            if item.get("can_originate", True)
            and item.get("state") not in {"withdrawn", "unavailable"}
        }
        reverse_start_attachment = (
            reverse["trace_start"].get("attachment_id"),
            reverse["trace_start"].get("node_id"),
            reverse["trace_start"].get("member_id"),
            reverse["trace_start"].get("resource_id"),
        )
        reverse_destination_attachments = {
            self._attachment_identity(
                item,
                label="traffic destination attachment",
            )
            for item in forward["flow"]["destination"].get(
                "attachments", []
            )
            if item.get("can_originate", True)
            and item.get("state") not in {"withdrawn", "unavailable"}
        }
        forward_sequence = list(forward_path.get("node_sequence", []))
        reverse_sequence = list(reverse_path.get("node_sequence", []))
        multipath = (
            str(scenario.get("multipath_mode")) == "all_active"
            or len(forward_active_paths) > 1
            or len(reverse_active_paths) > 1
        )

        def directional_state(trace: dict[str, Any]) -> str:
            state = str(
                trace.get("endpoint_reachability", {}).get(
                    "state", "unknown"
                )
            )
            return (
                state
                if state
                in {
                    "reached",
                    "not_reached",
                    "unknown",
                    "partial_active_reachability",
                }
                else "unknown"
            )

        evaluation: EndpointReachabilityPairEvaluation = (
            evaluate_endpoint_reachability_pair(
                forward_reaches_destination=forward.get(
                    "endpoint_reachability", {}
                ).get("reaches_target"),
                reverse_reaches_source=reverse.get(
                    "endpoint_reachability", {}
                ).get("reaches_target"),
                forward_complete=bool(forward["complete"]),
                reverse_complete=bool(reverse["complete"]),
                forward_node_sequence=tuple(forward_sequence),
                reverse_node_sequence=tuple(reverse_sequence),
                forward_start_node_id=forward["trace_start"]["node_id"],
                traffic_source_node_id=forward["flow"]["source"]["node_id"],
                forward_starts_at_source_endpoint=(
                    forward_start_attachment in forward_source_attachments
                ),
                reverse_starts_at_destination_endpoint=(
                    reverse_start_attachment
                    in reverse_destination_attachments
                ),
                forward_reachability_state=directional_state(forward),
                reverse_reachability_state=directional_state(reverse),
                forward_branch_node_sequences=(
                    tuple(
                        tuple(str(node_id) for node_id in path["node_sequence"])
                        for path in forward_active_paths
                    )
                    if multipath
                    else None
                ),
                reverse_branch_node_sequences=(
                    tuple(
                        tuple(str(node_id) for node_id in path["node_sequence"])
                        for path in reverse_active_paths
                    )
                    if multipath
                    else None
                ),
                multipath=multipath,
            )
        )
        comparison = evaluation.comparison_state
        issue_refs = list(
            dict.fromkeys(
                item["issue_id"]
                for trace in (forward, reverse)
                for item in trace.get("issues", [])
            )
        )
        combined_issues = list(
            {
                item["issue_id"]: item
                for trace in (forward, reverse)
                for item in trace.get("issues", [])
            }.values()
        )
        directional_consistent = all(
            bool(trace.get("consistency", {}).get("consistent"))
            for trace in (forward, reverse)
        )
        endpoint_consistent = evaluation.consistent
        overall_consistent = directional_consistent and endpoint_consistent
        directional_inconsistent_state = next(
            (
                str(trace.get("consistency", {}).get("state"))
                for trace in (forward, reverse)
                if not trace.get("consistency", {}).get("consistent")
            ),
            None,
        )
        overall_consistency_state = (
            directional_inconsistent_state
            if directional_inconsistent_state
            else evaluation.endpoint_state
        )
        trace_id = "rtrace-pair1-" + hashlib.sha256(
            f"{forward['trace_id']}:{reverse['trace_id']}".encode()
        ).hexdigest()[:24]
        response = dict(forward)
        response.update(
            {
                "trace_id": trace_id,
                "trace_mode": "bidirectional",
                "direction": "both",
                "scenario": dict(scenario),
                "route_type": route_type,
                "resolution_mode": resolution_mode,
                "resolution_policy": resolution_mode,
                "completeness_policy": resolution_mode,
                "traces": {"forward": forward, "reverse": reverse},
                "directional_traces": {"forward": forward, "reverse": reverse},
                "forward_trace": forward,
                "reverse_trace": reverse,
                "routing_contexts": {
                    "forward": forward["routing_context"],
                    "reverse": reverse["routing_context"],
                },
                "bidirectional_validation": {
                    "state": comparison,
                    "criterion": "source_destination_endpoint_reachability",
                    "endpoint_state": evaluation.endpoint_state,
                    "consistent": evaluation.consistent,
                    "forward_reaches_destination": (
                        evaluation.forward_reaches_destination
                    ),
                    "reverse_reaches_source": evaluation.reverse_reaches_source,
                    "forward_reachability_state": (
                        evaluation.forward_reachability_state
                    ),
                    "reverse_reachability_state": (
                        evaluation.reverse_reachability_state
                    ),
                    # Compatibility aliases are endpoint-goal results, not
                    # merely continuous line/segment results.
                    "forward_reachable": evaluation.forward_reaches_destination,
                    "reverse_reachable": evaluation.reverse_reaches_source,
                    "one_way": evaluation.endpoint_state
                    == "one_way_reachable",
                    "symmetric_node_sequence": evaluation.path_relation
                    == "symmetric",
                    "forward_node_sequence": forward_sequence,
                    "reverse_node_sequence": reverse_sequence,
                    "path_relation": {
                        "state": evaluation.path_relation,
                        "reason": evaluation.path_relation_reason,
                        "basis": evaluation.path_relation_basis,
                        "comparison_affects_consistency": False,
                    },
                    "forward_start": forward["trace_start"],
                    "reverse_start": reverse["trace_start"],
                    "reverse_must_visit_forward_start": (
                        evaluation.reverse_must_visit_forward_start
                    ),
                    "reverse_visits_forward_start": (
                        evaluation.reverse_visits_forward_start
                    ),
                    "issue_refs": issue_refs,
                    "ownership": (
                        "core matches typed terminal endpoints and aggregates "
                        "directional goals; plugins own each next-hop and local "
                        "terminal classification"
                    ),
                },
                "endpoint_reachability": {
                    "criterion": "source_destination_endpoint_reachability",
                    "state": evaluation.endpoint_state,
                    "consistent": evaluation.consistent,
                    "forward_reaches_destination": (
                        evaluation.forward_reaches_destination
                    ),
                    "reverse_reaches_source": evaluation.reverse_reaches_source,
                    "forward_state": evaluation.forward_reachability_state,
                    "reverse_state": evaluation.reverse_reachability_state,
                    "flow": forward["flow"],
                    "reverse_must_visit_forward_start": False,
                },
                "path_relation": {
                    "state": evaluation.path_relation,
                    "reason": evaluation.path_relation_reason,
                    "basis": evaluation.path_relation_basis,
                    "forward_node_sequence": forward_sequence,
                    "reverse_node_sequence": reverse_sequence,
                    "reverse_visits_forward_start": (
                        evaluation.reverse_visits_forward_start
                    ),
                    "affects_consistency": False,
                },
                "issues": combined_issues,
                "issue_index": {
                    item["issue_id"]: item for item in combined_issues
                },
                "consistency": {
                    "state": overall_consistency_state,
                    "comparison_state": comparison,
                    "endpoint_state": evaluation.endpoint_state,
                    "criterion": (
                        "directional_findings_and_source_destination_"
                        "endpoint_reachability"
                    ),
                    "consistent": overall_consistent,
                    "endpoint_consistent": endpoint_consistent,
                    "directional_consistent": directional_consistent,
                    "issue_refs": issue_refs,
                    "directional": True,
                },
                "complete": forward["complete"] and reverse["complete"],
                "reachable": evaluation.consistent,
                "completeness": {
                    "state": (
                        "complete"
                        if forward["complete"] and reverse["complete"]
                        else "partial"
                    ),
                    "forward_complete": forward["complete"],
                    "reverse_complete": reverse["complete"],
                    "forward_reachable": forward["reachable"],
                    "reverse_reachable": reverse["reachable"],
                },
            }
        )
        return response

    def _bind_generated_packet_declaration(
        self,
        initial_state: ForwardingPacketState,
        transitions: tuple[ForwardingPacketTransition, ...],
        *,
        declared_case: dict[str, Any],
        direction: str,
    ) -> tuple[
        ForwardingPacketState,
        tuple[ForwardingPacketTransition, ...],
    ]:
        """Bind generated plug-in declarations to executor transitions.

        ``executor_profile_id`` selects the plug-in policy that knows protocol
        semantics. The generated declaration remains authoritative for the
        initial packet fields and the action contracts presented to core.
        Core still receives ordinary protocol-neutral before/after transitions.
        """

        declared_layers = list(declared_case["initial_layers"])
        if len(declared_layers) != len(initial_state.layers):
            raise MultiNodeRouteRequestError(
                "generated packet declaration initial_layers do not match "
                "the installed plug-in executor input shape"
            )

        declared_fields_by_layer: dict[str, dict[str, Any]] = {}
        for index, declaration in enumerate(declared_layers):
            executor_layer = initial_state.layers[index]
            declared_kind = str(declaration["kind"]).lower()
            executor_identity = (
                f"{executor_layer.layer_id} {executor_layer.contract_id}"
            ).lower()
            if declared_kind not in executor_identity:
                raise MultiNodeRouteRequestError(
                    "generated packet declaration initial layer "
                    f"{declared_kind} does not match executor layer "
                    f"{executor_layer.layer_id}"
                )
            declared_fields = {
                str(name): value
                for name, value in declaration.items()
                if name != "kind"
            }
            if direction == "reverse":
                source = declared_fields.get("source")
                destination = declared_fields.get("destination")
                if source is not None and destination is not None:
                    declared_fields["source"] = destination
                    declared_fields["destination"] = source
            declared_fields_by_layer[executor_layer.layer_id] = (
                declared_fields
            )

        declared_size = declared_case.get("packet_size_bytes")
        size_delta = (
            int(declared_size) - int(initial_state.size.size_bytes)
            if declared_size is not None and initial_state.size is not None
            else 0
        )

        def bind_state(state: ForwardingPacketState) -> ForwardingPacketState:
            def bind_layer(
                layer: ForwardingPacketLayer,
            ) -> ForwardingPacketLayer:
                declared_fields = declared_fields_by_layer.get(
                    layer.layer_id
                )
                if declared_fields is None:
                    return layer
                fields = dict(layer.fields)
                fields.update(declared_fields)
                return replace(layer, fields=tuple(fields.items()))

            return replace(
                state,
                layers=tuple(bind_layer(layer) for layer in state.layers),
                size=(
                    replace(
                        state.size,
                        size_bytes=state.size.size_bytes + size_delta,
                    )
                    if state.size is not None and size_delta
                    else state.size
                ),
            )

        bound_initial_state = bind_state(initial_state)
        bound_transitions = tuple(
            replace(
                transition,
                before=bind_state(transition.before),
                after=bind_state(transition.after),
                mtu=(
                    replace(
                        transition.mtu,
                        limit_bytes=int(
                            declared_case["egress_mtu_bytes"]
                        ),
                    )
                    if transition.mtu is not None
                    and declared_case.get("egress_mtu_bytes") is not None
                    else transition.mtu
                ),
            )
            for index, transition in enumerate(transitions)
        )
        return bound_initial_state, bound_transitions

    @staticmethod
    def _partition_declared_packet_actions(
        actions: list[str],
        transition_count: int,
    ) -> list[list[str]]:
        """Map an ordered action plan onto executor steps without dropping it."""

        if transition_count <= 0:
            raise MultiNodeRouteRequestError(
                "generated packet declaration has no executor transitions"
            )
        if len(actions) >= transition_count:
            buckets = []
            for index in range(transition_count):
                start = (index * len(actions)) // transition_count
                end = (
                    len(actions)
                    if index == transition_count - 1
                    else ((index + 1) * len(actions)) // transition_count
                )
                buckets.append(actions[start:max(start + 1, end)])
            return buckets
        return [
            [
                actions[
                    min(
                        (index * len(actions)) // transition_count,
                        len(actions) - 1,
                    )
                ]
            ]
            for index in range(transition_count)
        ]

    @staticmethod
    def _default_focus(paths: list[dict[str, Any]]) -> str:
        primary = next((item for item in paths if item["primary"]), None)
        if primary:
            return str(primary["path_id"])
        active = next((item for item in paths if item["active"]), None)
        return str((active or paths[0])["path_id"])

    def _boundary_descriptor(
        self,
        left: str,
        right: str,
    ) -> dict[str, Any]:
        """Return a temporary shell for a declared candidate transition.

        Exact attachment and connectivity-domain identities are taken from the
        generated next-hop declaration and normalized topology snapshot in
        ``_reconcile_generated_route_evidence``. This shell only lets the path
        renderer allocate an ordered boundary segment before that validation.
        """

        self._router(left)
        self._router(right)
        pair = sorted((left, right))
        return {
            "link_id": f"candidate-boundary:{pair[0]}:{pair[1]}",
            "resources": {
                left: f"{left}/candidate-boundary/{right}",
                right: f"{right}/candidate-boundary/{left}",
            },
            "descriptor_source": "generated_candidate_placeholder",
        }

    def _generic_path(
        self,
        node_sequence: list[str],
        route_type: str,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        *,
        active: bool,
        primary: bool,
        alternative_state: str,
        issue_refs: list[str] | None = None,
        candidate_id: str | None = None,
        allow_repeated_nodes: bool = False,
        destination_node_id: str | None = None,
        terminal_next_hop_node_id: str | None = None,
    ) -> dict[str, Any]:
        if not node_sequence:
            raise MultiNodeRouteRequestError(
                "plug-in route node_sequence must contain at least one router"
            )
        has_repeated_nodes = len(set(node_sequence)) != len(node_sequence)
        if has_repeated_nodes and not allow_repeated_nodes:
            raise MultiNodeRouteRequestError(
                "plug-in route node_sequence repeats a router without explicit "
                "diagnostic-loop retention"
            )
        issue_refs = list(issue_refs or [])
        destination = self._router(destination_node_id or node_sequence[-1])
        via = "-".join(node_sequence[1:-1]) or "direct"
        path_id = (
            f"route-path:{node_sequence[0]}:{destination['node_id']}:"
            f"{route_type}:via-{via}"
        )
        if candidate_id:
            path_id = f"{path_id}:candidate-{candidate_id}"
        segments: list[dict[str, Any]] = []
        ordinal = 1
        source_router = self._router(node_sequence[0])
        next_node_label = (
            node_sequence[1]
            if len(node_sequence) > 1
            else "the local attachment"
        )
        source_resource_ids = [source_router["loopback_resource_id"]]
        if len(node_sequence) > 1:
            first_boundary = self._boundary_descriptor(
                node_sequence[0], node_sequence[1]
            )
            source_resource_ids.append(
                first_boundary["resources"][node_sequence[0]]
            )
        segments.append(
            self._local_segment(
                f"segment:{path_id}:source",
                ordinal,
                node_sequence[0],
                source_resource_ids,
                (
                    f"The {node_sequence[0]} route plug-in resolves "
                    f"{destination['prefix']} as {route_type} toward "
                    f"{next_node_label}."
                ),
                resources,
                targets,
                active,
                primary,
                alternative_state,
                issue_refs,
            )
        )
        ordinal += 1
        for index, (left, right) in enumerate(pairwise(node_sequence)):
            boundary = self._boundary_descriptor(left, right)
            segments.append(
                self._boundary_segment(
                    f"segment:{path_id}:boundary:{index + 1}",
                    ordinal,
                    [
                        boundary["resources"][left],
                        boundary["resources"][right],
                    ],
                    boundary["link_id"],
                    (
                        f"The federation linker maps the plug-in-declared {left} "
                        f"egress to the {right} ingress without interpreting route semantics."
                    ),
                    resources,
                    links,
                    targets,
                    active,
                    primary,
                    alternative_state,
                    issue_refs,
                )
            )
            ordinal += 1
            at_last_occurrence = index == len(node_sequence) - 2
            if at_last_occurrence and terminal_next_hop_node_id is not None:
                next_boundary = self._boundary_descriptor(
                    right, terminal_next_hop_node_id
                )
                end_ids = [
                    boundary["resources"][right],
                    next_boundary["resources"][right],
                ]
                text = (
                    f"The {right} route plug-in resolves {destination['prefix']} "
                    f"from {left} back toward {terminal_next_hop_node_id} for "
                    f"{route_type}."
                )
            elif at_last_occurrence:
                end_ids = [
                    boundary["resources"][right],
                    destination["loopback_resource_id"],
                ]
                text = (
                    f"The {right} route plug-in terminates {route_type} resolution "
                    f"at {destination['prefix']}."
                )
            else:
                next_boundary = self._boundary_descriptor(
                    right, node_sequence[index + 2]
                )
                end_ids = [
                    boundary["resources"][right],
                    next_boundary["resources"][right],
                ]
                text = (
                    f"The {right} route plug-in resolves {destination['prefix']} "
                    f"from {left} toward {node_sequence[index + 2]} for {route_type}."
                )
            segments.append(
                self._local_segment(
                    (
                        f"segment:{path_id}:node:{index + 1}:{right}"
                        if has_repeated_nodes
                        else f"segment:{path_id}:node:{right}"
                    ),
                    ordinal,
                    right,
                    end_ids,
                    text,
                    resources,
                    targets,
                    active,
                    primary,
                    alternative_state,
                    issue_refs,
                )
            )
            ordinal += 1
        path = self._path(
            path_id,
            (
                f"{route_type.replace('_', ' ').upper()} "
                + (
                    f"via {' -> '.join(node_sequence[1:-1])}"
                    if node_sequence[1:-1]
                    else "direct"
                )
            ),
            segments,
            active,
            primary,
            alternative_state,
            "forwarding_observed",
            issue_refs,
        )
        path["node_sequence"] = list(node_sequence)
        path["destination_node_id"] = destination["node_id"]
        path["route_type"] = route_type
        path["candidate_id"] = candidate_id or path_id
        local_segments = [
            item for item in segments if item["segment_kind"] == "node_resolution"
        ]
        for index, segment in enumerate(local_segments):
            phase = (
                "local_lookup"
                if index == 0
                else "remote_ingress"
                if index == len(local_segments) - 1
                else "next_hop"
            )
            route_profile = self.policy.route_type_profiles.get(
                route_type,
                {},
            )
            recursive_phases = route_profile.get(
                "phase_by_visit_index",
                {},
            )
            if str(index) in recursive_phases:
                phase = str(recursive_phases[str(index)])
            segment["phase"] = phase
            segment["route_resolution"]["phase"] = phase
        for segment in segments:
            if segment["segment_kind"] == "inter_node_boundary":
                segment["phase"] = "federation_boundary"
                segment["route_resolution"]["phase"] = "federation_boundary"
        path_attributes = route_profile.get("path_attributes", {})
        if not isinstance(path_attributes, Mapping):
            raise MultiNodeRouteRequestError(
                "route type path_attributes must be an object: "
                f"{route_type}"
            )
        allowed_path_attributes = {
            "protocol_chain",
            "encapsulation",
            "service_attributes",
            "presentation_topology_targets",
        }
        unsupported_path_attributes = (
            set(path_attributes) - allowed_path_attributes
        )
        if unsupported_path_attributes:
            raise MultiNodeRouteRequestError(
                "route type profile attempts to override core path fields: "
                + ", ".join(sorted(unsupported_path_attributes))
            )
        path.update(dict(path_attributes))
        source_phase = str(
            route_profile.get("source_phase") or "local_lookup"
        )
        self._set_segment_resolution(
            local_segments[0],
            local_segments[0]["route_resolution_text"],
            source_phase,
        )
        path["resolution_phases"] = [
            segment["phase"] for segment in sorted(segments, key=lambda item: item["ordinal"])
        ]
        return path









    @staticmethod
    def _set_segment_resolution(
        segment: dict[str, Any], text: str, phase: str
    ) -> None:
        segment["phase"] = phase
        segment["route_resolution"]["phase"] = phase
        segment["route_resolution"]["text"] = text
        segment["route_resolution_text"] = text
        if segment.get("graph_presentation", {}).get("role") == "l3-resolution":
            segment["graph_presentation"]["detail"] = text
        if segment["route_resolution"].get("parts"):
            segment["route_resolution"]["parts"][-1]["text"] = text













    def _local_segment(
        self,
        segment_id: str,
        ordinal: int,
        node_id: str,
        resource_ids: list[str],
        text: str,
        resources: dict[str, dict[str, Any]],
        targets: dict[str, dict[str, Any]],
        active: bool,
        primary: bool,
        alternative_state: str,
        issue_refs: list[str],
    ) -> dict[str, Any]:
        records = [resources[item] for item in resource_ids if item in resources]
        provider = self._provider_for_records(records, node_id)
        target_ids = [self._resource_target(item, targets) for item in records]
        member_id = (
            str(records[0]["member_id"])
            if records
            else f"member:{node_id}"
        )
        node_target_id = self._node_target(node_id, member_id, targets)
        operational = self._resource_operational(records, len(resource_ids))
        confidence = 0.96 if operational == "usable" else 0.68
        segment = self._segment(
            segment_id,
            ordinal,
            "node_resolution",
            records,
            target_ids,
            text,
            provider,
            active,
            primary,
            alternative_state,
            operational,
            "complete" if len(records) == len(resource_ids) else "unresolved",
            confidence,
            issue_refs,
            highlight_target_ids=[node_target_id],
        )
        # Candidate node identity is declared by the generated plug-in. Exact
        # resource evidence is reconciled after the path skeleton is ordered.
        segment["node_id"] = node_id
        segment["node_ids"] = [node_id]
        segment["member_id"] = member_id
        segment["member_ids"] = [member_id]
        segment["graph_presentation"] = {
            "role": "l3-resolution",
            "label": "L3 resolution",
            "detail": text,
            "semantic_owner": "plugin",
            "provided_by": provider,
        }
        return segment

    def _boundary_segment(
        self,
        segment_id: str,
        ordinal: int,
        resource_ids: list[str],
        link_id: str,
        text: str,
        resources: dict[str, dict[str, Any]],
        links: dict[str, list[dict[str, Any]]],
        targets: dict[str, dict[str, Any]],
        active: bool,
        primary: bool,
        alternative_state: str,
        issue_refs: list[str],
    ) -> dict[str, Any]:
        records = [resources[item] for item in resource_ids if item in resources]
        link = self._matching_link(links.get(link_id, []), set(resource_ids))
        target_ids = [self._resource_target(item, targets) for item in records]
        link_target_id = None
        if link:
            link_target_id = self._link_target(link, targets)
            target_ids.append(link_target_id)
        linker = dict(self.topology.contract["federation_plugin"])
        provider = {
            "ownership": "federation_linker_plugin",
            "plugin_id": linker["plugin_id"],
            "plugin_run_id": linker["plugin_run_id"],
            "plugin_version": linker["plugin_version"],
        }
        operational = (
            str(link.get("operational_status", "unknown")) if link else "unknown"
        )
        segment = self._segment(
            segment_id,
            ordinal,
            "inter_node_boundary",
            records,
            target_ids,
            text,
            provider,
            active,
            primary,
            alternative_state,
            operational,
            "complete" if link else "unresolved",
            0.82 if link and link.get("resolution") == "ambiguous" else 0.95 if link else 0.35,
            issue_refs,
            topology_link_id=link_id,
            extra_provenance=(link.get("plugin_provenance", []) if link else []),
            highlight_target_ids=([link_target_id] if link_target_id else []),
        )
        attachment_labels = [
            str(item.get("label") or item["resource_id"]) for item in records
        ]
        segment["graph_presentation"] = {
            "role": "outer-boundary",
            "label": "L1/L2 boundary",
            "detail": " ↔ ".join(attachment_labels),
            "semantic_owner": "federation_linker_plugin",
            "provided_by": provider,
        }
        return segment

    def _segment(
        self,
        segment_id: str,
        ordinal: int,
        kind: str,
        records: list[dict[str, Any]],
        target_ids: list[str],
        text: str,
        provider: dict[str, Any],
        selected_active: bool,
        primary: bool,
        alternative_state: str,
        operational: str,
        completeness_state: str,
        confidence: float,
        issue_refs: list[str],
        *,
        topology_link_id: str | None = None,
        extra_provenance: list[dict[str, Any]] | None = None,
        highlight_target_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        plugin_provenance = self._dedupe_provenance(
            [
                *(item.get("plugin_provenance", {}) for item in records),
                *(extra_provenance or []),
                provider,
            ]
        )
        node_ids = list(dict.fromkeys(item["node_id"] for item in records))
        member_ids = list(dict.fromkeys(item["member_id"] for item in records))
        exact_highlight_target_ids = list(dict.fromkeys(highlight_target_ids or []))
        resolution_parts = []
        labels = [str(item.get("label", item["resource_id"])) for item in records]
        if labels:
            resolution_parts.append(
                {
                    "part_id": f"{segment_id}:part:resources",
                    "text": " / ".join(labels),
                    "interactive": True,
                    "interaction_target_ids": target_ids,
                    "highlight_target_ids": exact_highlight_target_ids,
                }
            )
        resolution_parts.append(
            {
                "part_id": f"{segment_id}:part:explanation",
                "text": text,
                "interactive": True,
                "interaction_target_ids": target_ids,
                "highlight_target_ids": exact_highlight_target_ids,
            }
        )
        end_to_end = completeness_state != "unresolved"
        active = selected_active and operational != "unusable" and end_to_end
        result = {
            "segment_id": segment_id,
            "ordinal": ordinal,
            "segment_kind": kind,
            "geometry_role": "forwarding",
            "participates_in_forwarding_geometry": True,
            "phase": (
                "federation_boundary"
                if kind == "inter_node_boundary"
                else "best_effort"
                if kind == "best_effort_bridge"
                else "unresolved"
                if kind == "unresolved"
                else "local_lookup"
            ),
            "node_id": node_ids[0] if len(node_ids) == 1 else None,
            "node_ids": node_ids,
            "member_id": member_ids[0] if len(member_ids) == 1 else None,
            "member_ids": member_ids,
            "plugin_provenance": plugin_provenance,
            "route_resolution": {
                "resolution_id": f"resolution:{segment_id}",
                "ordinal": ordinal,
                "phase": (
                    "federation_boundary"
                    if kind == "inter_node_boundary"
                    else "best_effort"
                    if kind == "best_effort_bridge"
                    else "unresolved"
                    if kind == "unresolved"
                    else "local_lookup"
                ),
                "text": text,
                "text_source": "plugin_provided",
                "provided_by": provider,
                "core_role": "orders_and_joins_plugin_steps_only",
                "parts": resolution_parts,
                "interaction_target_ids": target_ids,
                "highlight_target_ids": exact_highlight_target_ids,
            },
            "route_resolution_text": text,
            "resource_refs": [item["resource_ref"] for item in records],
            "topology_link_id": topology_link_id,
            "active": active,
            "primary": primary,
            "alternative_state": alternative_state,
            "state": {
                "active": active,
                "selected_active_by_plugin": selected_active,
                "primary": primary,
                "alternative_state": alternative_state,
                "operational": operational,
            },
            "completeness": {
                "state": completeness_state,
                "end_to_end_resolved": end_to_end,
                "observed": completeness_state == "complete",
            },
            "confidence": confidence,
            "issue_refs": list(issue_refs),
            "interaction_target_ids": target_ids,
            "highlight_target_ids": exact_highlight_target_ids,
        }
        return result

    def _path(
        self,
        path_id: str,
        label: str,
        segments: list[dict[str, Any]],
        selected_active: bool,
        primary: bool,
        alternative_state: str,
        perspective: str,
        issue_refs: list[str],
    ) -> dict[str, Any]:
        result = {
            "path_id": path_id,
            "label": label,
            "perspective": perspective,
            "selected_active_by_plugin": selected_active,
            "active": selected_active and all(item["active"] for item in segments),
            "primary": primary,
            "alternative_state": alternative_state,
            "segments": segments,
            "issue_refs": list(issue_refs),
        }
        self._refresh_path(result)
        return result

    @staticmethod
    def _refresh_path(path: dict[str, Any]) -> None:
        segments = path["segments"]
        path["active"] = bool(path.get("active")) and all(
            item["active"] for item in segments
        )
        path["confidence"] = round(
            min((item["confidence"] for item in segments), default=0.0), 3
        )
        unresolved = [
            item for item in segments if not item["completeness"]["end_to_end_resolved"]
        ]
        inferred = [
            item
            for item in segments
            if item["completeness"]["state"] == "best_effort_inferred"
        ]
        path["completeness"] = {
            "state": (
                "incomplete" if unresolved else "best_effort_resolved" if inferred else "complete"
            ),
            "end_to_end_resolved": not unresolved,
            "observationally_complete": not unresolved and not inferred,
            "inferred_segment_count": len(inferred),
            "unresolved_segment_count": len(unresolved),
        }
        alternative_state = str(path.get("alternative_state", ""))
        if path.get("primary") or alternative_state == "selected_primary":
            role = "primary"
        elif alternative_state == "ecmp_member":
            role = "ecmp"
        elif alternative_state == "eligible_standby":
            role = "standby"
        else:
            role = "alternative"

        terminal_segment = next(
            (
                item
                for item in segments
                if isinstance(item.get("state"), dict)
                and item["state"].get("terminal")
            ),
            None,
        )
        unusable_segment = next(
            (
                item
                for item in segments
                if isinstance(item.get("state"), dict)
                and item["state"].get("operational") == "unusable"
            ),
            None,
        )
        if terminal_segment is not None:
            terminal_state = terminal_segment["state"]
            raw_terminal_reason = (
                terminal_state.get("reason_code")
                or terminal_state.get("terminal")
            )
            terminal_reason = (
                raw_terminal_reason.strip()
                if isinstance(raw_terminal_reason, str)
                and raw_terminal_reason.strip()
                else "terminal_unusable"
            )
            declared_disposition = str(
                terminal_state.get("terminal_disposition") or "unusable"
            )
            result = (
                declared_disposition
                if declared_disposition
                in {
                    "dropped",
                    "discarded",
                    "unusable",
                    "cycle",
                    "policy_blocked",
                    "hop_limit_exceeded",
                    "recursion_limit_exceeded",
                }
                else "unusable"
            )
        elif unresolved:
            terminal_reason = "unresolved_resolution"
            result = "unresolved"
        elif unusable_segment is not None:
            terminal_reason = str(
                unusable_segment["state"].get("reason_code")
                or "resource_unusable"
            )
            result = "unusable"
        elif path["completeness"]["end_to_end_resolved"]:
            terminal_reason = None
            result = "resolved"
        else:
            terminal_reason = "incomplete_resolution"
            result = "incomplete"

        eligibility_by_alternative = {
            "eligible_standby": "eligible_standby",
            "best_effort_possible": "best_effort_candidate",
            "control_expected_not_observed": "comparison_only",
            "control_plane_only": "control_plane_only",
            "withdrawn_dead": "ineligible_dead",
            "policy_rejected": "ineligible_policy",
        }
        eligibility = eligibility_by_alternative.get(alternative_state)
        if result == "policy_blocked":
            eligibility = "ineligible_policy"
        if eligibility is None:
            eligibility = (
                "selected"
                if role in {"primary", "ecmp"} or path.get("active")
                else "inactive_candidate"
            )

        path["role"] = role
        path["result"] = result
        path["eligibility"] = eligibility
        path["terminal_reason"] = terminal_reason
        path["graph_target_ids"] = [
            str(target_id)
            for item in sorted(segments, key=lambda candidate: candidate["ordinal"])
            for target_id in item.get("highlight_target_ids", [])
        ]
        path["route_resolution_sequence"] = [
            {
                "sequence": item["ordinal"],
                "segment_id": item["segment_id"],
                "route_resolution": item["route_resolution"],
            }
            for item in segments
        ]
        path["interaction_target_ids"] = list(
            dict.fromkeys(
                target
                for item in segments
                for target in item["interaction_target_ids"]
            )
        )
        path["plugin_provenance"] = MultiNodeRouteService._dedupe_provenance(
            [
                provider
                for item in segments
                for provider in item["plugin_provenance"]
            ]
        )

    def _provider_for_records(
        self,
        records: list[dict[str, Any]],
        node_id: str,
    ) -> dict[str, Any]:
        if records:
            provider = dict(records[0].get("plugin_provenance", {}))
            provider["ownership"] = "node_plugin"
            return provider
        return {
            "ownership": "node_plugin",
            **self._generated_plugin_provider(node_id),
        }

    @staticmethod
    def _resource_operational(
        records: list[dict[str, Any]], expected_count: int
    ) -> str:
        if len(records) != expected_count:
            return "unknown"
        classes = {item.get("status_class") for item in records}
        if "unusable" in classes:
            return "unusable"
        if classes == {"usable"}:
            return "usable"
        return "unknown"

    @staticmethod
    def _matching_link(
        candidates: list[dict[str, Any]], required_resource_ids: set[str]
    ) -> dict[str, Any] | None:
        for item in candidates:
            endpoint_ids = {
                item["endpoint_a"]["resource_id"],
                item["endpoint_b"]["resource_id"],
            }
            if endpoint_ids == required_resource_ids:
                return item
        # A topology link identifier is not sufficient evidence when a
        # federation result contains several scoped candidates.  Choosing the
        # first candidate can silently attach a route segment to the wrong
        # endpoints; leave it unresolved unless the exact endpoint set matches.
        return None

    @staticmethod
    def _dedupe_provenance(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for raw in values:
            if not raw:
                continue
            item = dict(raw)
            key = (str(item.get("plugin_id")), str(item.get("plugin_run_id")))
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    @staticmethod
    def _target_id(kind: str, material: str) -> str:
        digest = hashlib.sha256(f"{kind}:{material}".encode()).hexdigest()[:16]
        return f"target:{kind}:{digest}"

    def _resource_target(
        self, resource: dict[str, Any], targets: dict[str, dict[str, Any]]
    ) -> str:
        ref = resource["resource_ref"]
        target_id = self._target_id(
            "resource",
            f"{ref['member_id']}:{ref['revision_id']}:{ref['local_resource_id']}",
        )
        targets.setdefault(
            target_id,
            {
                "target_id": target_id,
                "kind": "resource",
                "label": resource.get("label", resource["resource_id"]),
                "node_id": resource["node_id"],
                "member_id": resource["member_id"],
                "resource_ref": ref,
                "status": resource.get("status"),
                "status_class": resource.get("status_class"),
                "deep_link": resource.get("deep_link"),
            },
        )
        return target_id

    def _node_target(
        self,
        node_id: str,
        member_id: str,
        targets: dict[str, dict[str, Any]],
    ) -> str:
        """Register a stable graph-level target without folding in resource identity."""
        target_id = self._target_id("topology-node", f"{member_id}:{node_id}")
        router = self._routers_by_id.get(node_id)
        targets.setdefault(
            target_id,
            {
                "target_id": target_id,
                "kind": "topology_node",
                "label": (router or {}).get("label", node_id),
                "node_id": node_id,
                "member_id": member_id,
                "semantic_owner": "plugin",
            },
        )
        return target_id

    def _link_target(
        self, link: dict[str, Any], targets: dict[str, dict[str, Any]]
    ) -> str:
        target_id = self._target_id(
            "topology-link",
            f"{link['link_id']}:{link['endpoint_a']['resource_id']}:{link['endpoint_b']['resource_id']}",
        )
        targets.setdefault(
            target_id,
            {
                "target_id": target_id,
                "kind": "topology_link",
                "label": link["link_type"],
                "topology_link_id": link["link_id"],
                "resolution": link["resolution"],
                "operational_status": link["operational_status"],
                "endpoint_a": link["endpoint_a"],
                "endpoint_b": link["endpoint_b"],
                "deep_link": link.get("deep_links", {}).get("topology"),
            },
        )
        return target_id

    def _network_segment_target(
        self,
        domain: dict[str, Any],
        source_attachment: dict[str, Any],
        target_attachment: dict[str, Any],
        targets: dict[str, dict[str, Any]],
    ) -> str:
        """Register a generated connectivity domain without flattening it."""

        network_segment_id = str(domain["segment_id"])
        target_id = self._target_id(
            "network-segment",
            (
                f"{network_segment_id}:"
                f"{source_attachment['attachment_id']}:"
                f"{target_attachment['attachment_id']}"
            ),
        )
        targets.setdefault(
            target_id,
            {
                "target_id": target_id,
                "kind": "network_segment",
                "label": domain.get("label", network_segment_id),
                "network_segment_id": network_segment_id,
                "match": domain.get("match"),
                "operational_status": domain.get(
                    "operational_status"
                ),
                "source_attachment": source_attachment,
                "target_attachment": target_attachment,
                "semantic_owner": "plugin",
            },
        )
        return target_id
