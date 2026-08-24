"""Heterogeneous multi-node topology reconstruction.

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
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any
from urllib.parse import quote, urlencode
from uuid import UUID

from router_dump_analyzer.canonical import (
    CanonicalValueError,
    bounded_value_key,
    canonical_opaque_value,
    opaque_value_json,
)
from router_dump_analyzer.capability_router import (
    CapabilityProviderRef,
    RevisionSetCapabilityKey,
)
from router_dump_analyzer.contract_validation import (
    bounded_mapping,
    validate_bounded_json_value,
)
from router_dump_analyzer.corroboration import (
    CorroborationError,
    ExactMatchClaim,
    ExactMatchState,
    MatcherId,
    exact_match_claims,
)
from router_dump_analyzer.federation_executor import (
    FederationExecutionProvenance,
)
from router_dump_analyzer.normalized_data import contains_time
from router_dump_analyzer.plugin_api import (
    Evidence,
    FederationMatchState,
    GlobalResourceRef,
    InterNodeLinkPresentation,
    InterNodeRouteTraceRole,
    KeyAtom,
    Provenance,
    Quality,
    RelationDirection,
    RelationshipView,
    ResourceKey,
    ResourceStateView,
    StatusPerspectiveRef,
    TopologyDomainRole,
    TopologyEndpointRecord,
    TopologyLinkRecord,
    TopologyPluginSemanticsDescriptor,
    TopologyProjectionRequest,
    TopologyResourceRecord,
    TopologyTwoParticipantShape,
    TopologyUsability,
    WorldBasis,
    WorldBasisKind,
)
from router_dump_analyzer.temporal_core import (
    RESOURCE_CREATION_OPERATIONS,
    RESOURCE_DELETION_OPERATIONS,
    checked_temporal_add,
    checked_temporal_subtract,
    distinct_temporal_states,
    temporal_integer,
    temporal_order_key,
)
from router_dump_analyzer.topology_federation import (
    TopologyFederatedClaimContext,
    TopologyFederationAssembly,
    TopologyFederationCoordinator,
    TopologyFederationError,
    TopologyProjectionBasisSnapshot,
    TopologyProjectionInvocation,
    TopologyProjectionSelection,
)


class MultiNodeTopologyRequestError(ValueError):
    """A multi-node request cannot be executed by the advertised providers."""


type _TypedResourceScopeKey = tuple[GlobalResourceRef, str, str]


_FEDERATION_STATE_BY_EXACT_MATCH_STATE = {
    ExactMatchState.MATCHED: FederationMatchState.MATCHED,
    ExactMatchState.AMBIGUOUS: FederationMatchState.AMBIGUOUS,
    ExactMatchState.UNMATCHED: FederationMatchState.UNRESOLVED,
}


def _normalize_opaque_key(value: Any) -> dict[str, Any]:
    """Return a recursively type-tagged, JSON-safe exact-match key.

    Plug-ins own the meaning of every atom. The coordinator preserves atom and
    container types so, for example, a UUID never aliases its display string
    and binary bytes never alias a string that happens to look like ``repr``.
    """

    try:
        return opaque_value_json(value, key_atom_type=KeyAtom)
    except CanonicalValueError as error:
        raise MultiNodeTopologyRequestError(str(error)) from error


def _exact_nonempty_string(value: Any, label: str) -> str:
    """Validate one frozen coordinate without coercion or fallback."""

    if type(value) is not str or not value or len(value) > 256:
        raise MultiNodeTopologyRequestError(
            f"{label} must be an exact non-empty string of at most 256 characters"
        )
    return value


def _typed_json_value(value: Any) -> Any:
    """Detach a typed plug-in value into JSON without scalar aliasing."""

    value_type = type(value)
    if value is None or value_type in {bool, float, str}:
        return value
    if value_type is int:
        if -(2**53) + 1 <= value <= (2**53) - 1:
            return value
        return {"type": "int", "decimal": str(value)}
    if value_type is bytes:
        return {
            "type": "bytes",
            "base64": base64.b64encode(value).decode("ascii"),
        }
    if value_type is UUID:
        return {"type": "uuid", "value": str(value)}
    if value_type is tuple:
        return [_typed_json_value(item) for item in value]
    if isinstance(value, Mapping):
        return {
            _exact_nonempty_string(key, "typed property name"): _typed_json_value(
                item
            )
            for key, item in value.items()
        }
    raise MultiNodeTopologyRequestError(
        f"typed topology value has unsupported type {value_type.__name__}"
    )


def _typed_evidence(evidence: Evidence) -> dict[str, Any]:
    """Return all immutable evidence coordinates in a JSON-safe shape."""

    return {
        "artifact_id": str(evidence.artifact_id),
        "locator": evidence.locator,
        "raw_timestamp_ns": (
            None
            if evidence.raw_timestamp_ns is None
            else str(evidence.raw_timestamp_ns)
        ),
        "clock_domain": evidence.clock_domain,
        "excerpt_sha256": evidence.excerpt_sha256,
    }


def _canonical_opaque_key(value: Any) -> tuple[dict[str, Any], str]:
    try:
        return canonical_opaque_value(value, key_atom_type=KeyAtom)
    except CanonicalValueError as error:
        raise MultiNodeTopologyRequestError(str(error)) from error


def _semantic_comparison_key(
    value: Any,
    *,
    label: str,
) -> tuple[Any, ...]:
    """Return one bounded, type-preserving merge key or fail closed."""

    try:
        validate_bounded_json_value(value, label)
        return bounded_value_key(value)
    except (CanonicalValueError, ValueError) as error:
        raise MultiNodeTopologyRequestError(
            f"{label} is not safely comparable: {error}"
        ) from error


def _validated_topology_presentation(value: Any) -> dict[str, Any]:
    try:
        presentation = bounded_mapping(
            value,
            "topology_presentation",
            allow_none=True,
        )
        _semantic_comparison_key(
            presentation,
            label="topology_presentation",
        )
        shape = TopologyTwoParticipantShape(
            presentation.get(
                "two_participant_shape",
                TopologyTwoParticipantShape.DOMAIN_NODE,
            )
        )
    except (TypeError, ValueError) as error:
        raise MultiNodeTopologyRequestError(
            f"invalid topology_presentation: {error}"
        ) from error
    presentation["two_participant_shape"] = shape.value
    return presentation


def _validated_plugin_semantics(
    value: Any,
) -> tuple[
    dict[str, Any],
    tuple[Any, ...],
    TopologyPluginSemanticsDescriptor,
]:
    try:
        semantics = bounded_mapping(
            value,
            "plugin_semantics",
            allow_none=True,
        )
        comparison_key = _semantic_comparison_key(
            semantics,
            label="plugin_semantics",
        )
        descriptor = TopologyPluginSemanticsDescriptor(
            role=semantics.get("role"),
            coverage_complete=semantics.get("coverage_complete"),
        )
        _validated_topology_presentation(
            semantics.get("topology_presentation")
        )
    except (TypeError, ValueError) as error:
        if isinstance(error, MultiNodeTopologyRequestError):
            raise
        raise MultiNodeTopologyRequestError(
            f"invalid plugin_semantics: {error}"
        ) from error
    return semantics, comparison_key, descriptor


def _validated_inter_node_presentation(
    value: Any,
) -> tuple[dict[str, Any], InterNodeRouteTraceRole]:
    try:
        presentation = bounded_mapping(
            value,
            "inter-node presentation",
            allow_none=True,
        )
        _semantic_comparison_key(
            presentation,
            label="inter-node presentation",
        )
        descriptor = InterNodeLinkPresentation(
            route_trace=presentation.get(
                "route_trace",
                InterNodeRouteTraceRole.INCLUDE,
            )
        )
    except (TypeError, ValueError) as error:
        if isinstance(error, MultiNodeTopologyRequestError):
            raise
        raise MultiNodeTopologyRequestError(
            f"invalid inter-node presentation: {error}"
        ) from error
    presentation["route_trace"] = descriptor.route_trace.value
    return presentation, descriptor.route_trace


def _integer_ns(value: Any, field: str) -> int:
    try:
        return temporal_integer(value, field)
    except ValueError as error:
        raise MultiNodeTopologyRequestError(
            f"{field} must be an integer nanosecond value"
        ) from error


def _integer_ns_add(left: int, right: int, field: str) -> int:
    try:
        return checked_temporal_add(left, right, field)
    except ValueError as error:
        raise MultiNodeTopologyRequestError(
            f"{field} exceeds the signed 64-bit nanosecond range"
        ) from error


def _integer_ns_subtract(left: int, right: int, field: str) -> int:
    try:
        return checked_temporal_subtract(left, right, field)
    except ValueError as error:
        raise MultiNodeTopologyRequestError(
            f"{field} exceeds the signed 64-bit nanosecond range"
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


def _status_view_at(
    resource: dict[str, Any],
    timestamp_ns: int,
) -> dict[str, Any]:
    valid_from = resource.get("valid_from_ns")
    valid_to = resource.get("valid_to_ns")
    valid_from_value = (
        None
        if valid_from is None
        else _integer_ns(valid_from, "resource.valid_from_ns")
    )
    valid_to_value = (
        None
        if valid_to is None
        else _integer_ns(valid_to, "resource.valid_to_ns")
    )
    valid_at_timestamp = contains_time(
        timestamp_ns,
        valid_from_value,
        valid_to_value,
    )
    lifecycle_exists = True
    status = str(resource.get("initial_status", "unknown"))
    initial_state = resource.get("initial_state")
    state: Any = (
        dict(initial_state)
        if isinstance(initial_state, Mapping)
        else ({} if initial_state is None else initial_state)
    )
    changes = sorted(
        resource.get("changes", []),
        key=lambda item: temporal_order_key(
            item,
            time_field="time_ns",
            identifier_fields=("event_uid", "change_id"),
        ),
    )
    applied_time: int | None = None
    next_time: int | None = None
    for change in changes:
        change_time, _, _ = temporal_order_key(
            change,
            time_field="time_ns",
            identifier_fields=("event_uid", "change_id"),
        )
        if change.get("state_changed") is False:
            continue
        if timestamp_ns < change_time:
            next_time = change_time
            break
        applied_time = change_time
        explicit_exists = change.get("exists")
        if isinstance(explicit_exists, bool):
            lifecycle_exists = explicit_exists
        else:
            operation = str(change.get("operation", "")).casefold()
            if operation in RESOURCE_CREATION_OPERATIONS:
                lifecycle_exists = True
            elif operation in RESOURCE_DELETION_OPERATIONS:
                lifecycle_exists = False
        status = str(change.get("status", status))
        changed_state = change.get("state")
        if isinstance(state, dict) and isinstance(changed_state, Mapping):
            state.update(changed_state)
        elif changed_state is not None:
            state = changed_state
    exists = valid_at_timestamp and lifecycle_exists
    interval_start = valid_from_value
    if applied_time is not None:
        interval_start = (
            applied_time
            if interval_start is None
            else max(interval_start, applied_time)
        )
    interval_end = valid_to_value
    if next_time is not None:
        interval_end = (
            next_time
            if interval_end is None
            else min(interval_end, next_time)
        )
    if (
        valid_from_value is not None
        and timestamp_ns < valid_from_value
    ):
        interval_start = None
        interval_end = valid_from_value
    elif valid_to_value is not None and timestamp_ns >= valid_to_value:
        interval_start = valid_to_value
        interval_end = None
    return {
        "exists": exists,
        "status": status if exists else "absent",
        "state": state,
        "valid_from_ns": (
            None if interval_start is None else str(interval_start)
        ),
        "valid_to_ns": None if interval_end is None else str(interval_end),
    }


def _status_window_at(
    resource: dict[str, Any],
    *,
    center_ns: int,
    minimum_ns: int,
    maximum_ns: int,
) -> dict[str, Any]:
    """Evaluate every state boundary inside one mapped clock interval.

    A bounded clock mapping represents a set of possible absolute instants,
    not merely its center. Sampling both sides of each resource transition
    preserves the same uncertainty semantics as the single-node temporal
    query service.
    """

    sample_times = {minimum_ns, center_ns, maximum_ns}
    for change in resource.get("changes", []):
        change_time = _integer_ns(change.get("time_ns"), "change.time_ns")
        if minimum_ns <= change_time <= maximum_ns:
            sample_times.add(change_time)
            if change_time > minimum_ns:
                sample_times.add(change_time - 1)
    for boundary_name in ("valid_from_ns", "valid_to_ns"):
        boundary = resource.get(boundary_name)
        if boundary is None:
            continue
        boundary_time = _integer_ns(
            boundary,
            f"resource.{boundary_name}",
        )
        if minimum_ns <= boundary_time <= maximum_ns:
            sample_times.add(boundary_time)
            if boundary_time > minimum_ns:
                sample_times.add(boundary_time - 1)

    samples = [
        (sampled_at, _status_view_at(resource, sampled_at))
        for sampled_at in sorted(sample_times)
    ]
    unique, comparison_complete = distinct_temporal_states(samples)
    center = _status_view_at(resource, center_ns)
    if not comparison_complete:
        return {
            "exists": None,
            "status": "unknown",
            "state": None,
            "quality": "unknown",
            "temporal_resolution": "unknown",
            "possible_states": [],
            "unknown_fields": [
                {
                    "name": "*",
                    "reason_code": "state_comparison_unavailable",
                    "message": (
                        "The state could not be compared safely inside "
                        "the mapped clock interval."
                    ),
                }
            ],
        }
    if len(unique) == 1:
        return {
            "exists": center["exists"],
            "status": center["status"],
            "state": center["state"],
            "quality": (
                "exact"
                if minimum_ns == maximum_ns
                else "best_effort"
            ),
            "temporal_resolution": (
                "exact"
                if minimum_ns == maximum_ns
                else "stable_within_clock_window"
            ),
            "possible_states": [],
            "unknown_fields": [],
        }
    return {
        "exists": None,
        "status": "ambiguous",
        "state": None,
        "quality": "ambiguous",
        "temporal_resolution": "ambiguous",
        "possible_states": [
            {
                "sampled_at_ns": str(sampled_at),
                "exists": view["exists"],
                "status": view["status"],
                "state": view["state"],
                "valid_from_ns": view.get("valid_from_ns"),
                "valid_to_ns": view.get("valid_to_ns"),
            }
            for sampled_at, view in sorted(unique)
        ],
        "unknown_fields": [
            {
                "name": "*",
                "reason_code": "clock_window_crosses_state_transition",
                "message": (
                    "More than one state is possible inside the mapped "
                    "clock interval."
                ),
            }
        ],
    }


class _TopologyProjectionWorld:
    """Minimal core-owned world for a provider that emits self-contained facts."""

    def __init__(
        self,
        basis: WorldBasis,
        perspective_ref: StatusPerspectiveRef,
        states: Mapping[ResourceKey, ResourceStateView] | None = None,
    ) -> None:
        self._basis = basis
        self._perspective_ref = perspective_ref
        self._states = dict(states or {})

    @property
    def basis(self) -> WorldBasis:
        return self._basis

    @property
    def perspective_ref(self) -> StatusPerspectiveRef:
        return self._perspective_ref

    def state_of(self, resource: ResourceKey) -> ResourceStateView | None:
        return self._states.get(resource)

    def iter_states(
        self,
        layers: frozenset[str] | None = None,
        kinds: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[ResourceStateView]:
        selected = (
            state
            for state in self._states.values()
            if (layers is None or state.resource.layer in layers)
            and (kinds is None or state.resource.kind in kinds)
        )
        if limit is None:
            return tuple(selected)
        return tuple(selected)[:limit]

    def related(
        self,
        resource: ResourceKey,
        direction: RelationDirection = RelationDirection.OUTGOING,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        del resource, direction, relation_types, limit
        return ()

    def iter_relationships(
        self,
        relation_types: frozenset[str] | None = None,
        layers: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        del relation_types, layers, limit
        return ()


class MultiNodeTopologyService:
    """Coordinate independently selected plug-in projections across nodes."""

    def __init__(
        self,
        *,
        contract: dict[str, Any],
        topology_profiles: list[dict[str, Any]],
        topology_metadata: dict[str, Any],
        topology_federation: TopologyFederationCoordinator | None = None,
        topology_projection_state_provider: (
            Callable[
                [CapabilityProviderRef, str, Mapping[str, Any]],
                Mapping[ResourceKey, ResourceStateView],
            ]
            | None
        ) = None,
    ) -> None:
        if not isinstance(contract, dict) or not isinstance(
            contract.get("nodes"),
            list,
        ):
            raise MultiNodeTopologyRequestError(
                "the topology provider must supply a normalized contract"
            )
        if not topology_profiles:
            raise MultiNodeTopologyRequestError(
                "the topology provider must supply at least one profile"
            )
        topology_id = topology_metadata.get("topology_id")
        if not isinstance(topology_id, str) or not topology_id:
            raise MultiNodeTopologyRequestError(
                "topology_metadata.topology_id must be a non-empty string"
            )
        assembly_id = topology_metadata.get("assembly_id")
        revision_id = topology_metadata.get("revision_id")
        if not isinstance(assembly_id, str) or not assembly_id:
            raise MultiNodeTopologyRequestError(
                "topology_metadata.assembly_id must be a non-empty string"
            )
        if not isinstance(revision_id, str) or not revision_id:
            raise MultiNodeTopologyRequestError(
                "topology_metadata.revision_id must be a non-empty string"
            )
        self.assembly_id: str = assembly_id
        self.revision_id: str = revision_id
        try:
            self.capture_ns: int = _integer_ns(
                topology_metadata["capture_ns"],
                "topology_metadata.capture_ns",
            )
            self.start_ns: int = _integer_ns(
                topology_metadata["timeline_start_ns"],
                "topology_metadata.timeline_start_ns",
            )
            self.end_ns: int = _integer_ns(
                topology_metadata["timeline_end_ns"],
                "topology_metadata.timeline_end_ns",
            )
        except (KeyError, TypeError, ValueError) as error:
            raise MultiNodeTopologyRequestError(
                "topology metadata must provide integer capture and "
                "timeline bounds"
            ) from error
        self.contract: dict[str, Any] = contract
        self.topology_profiles: list[dict[str, Any]] = [
            dict(item) for item in topology_profiles
        ]
        self.topology_metadata: dict[str, Any] = dict(topology_metadata)
        self.topology_id: str = topology_id
        self.nodes_by_id: dict[str, Any] = {
            str(item["node_id"]): item for item in self.contract["nodes"]
        }
        self._node_order = {
            str(item["node_id"]): index
            for index, item in enumerate(self.contract["nodes"])
        }
        self._contexts: dict[str, dict[str, Any]] = {}
        if topology_federation is not None and type(
            topology_federation
        ) is not TopologyFederationCoordinator:
            raise TypeError(
                "topology_federation must be an exact TopologyFederationCoordinator"
            )
        if (
            topology_projection_state_provider is not None
            and not callable(topology_projection_state_provider)
        ):
            raise TypeError("topology_projection_state_provider must be callable")
        self._topology_federation = topology_federation
        self._topology_projection_state_provider = (
            topology_projection_state_provider
        )

    @staticmethod
    def normalize_basis(
        basis: Any,
        field: str = "basis",
    ) -> dict[str, Any]:
        """Return the canonical form used in contexts and cross-API comparisons."""

        return _canonical_topology_basis(basis, field)

    def capabilities(self) -> dict[str, Any]:
        profiles = [dict(item) for item in self.topology_profiles]
        default_profile_id = str(
            self.topology_metadata.get("default_profile_id")
            or profiles[0]["profile_id"]
        )
        return {
            "api_version": "v1",
            "topology_id": self.topology_id,
            "assembly_id": self.assembly_id,
            "label": str(
                self.topology_metadata.get("label")
                or self.topology_id
            ),
            "description": (
                str(self.topology_metadata.get("description") or "")
            ),
            "revision_id": self.revision_id,
            "defaults": {
                "basis": {
                    "kind": "relative_to_watermark",
                    "offset_ns": "0",
                },
                "clock_policy": "best_effort",
                "profile_id": default_profile_id,
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
            "default_profile_id": default_profile_id,
            "default_clock_policy": str(
                self.topology_metadata.get(
                    "default_clock_policy",
                    "best_effort",
                )
            ),
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
                    "href": f"/?topology_id={quote(self.topology_id)}",
                    "route": "/",
                }
            },
            "data_disclosure": str(
                self.topology_metadata.get("data_disclosure") or ""
            ),
        }

    def node_capabilities(self, node_id: str) -> dict[str, Any]:
        node = self._node(node_id)
        return {
            "api_version": "v1",
            "topology_id": self.topology_id,
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
            "assembly_id": self.assembly_id,
            "topology_id": self.topology_id,
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
            "assembly_id": self.assembly_id,
            "basis": global_basis,
            "clock_policy": clock_policy,
            "node_queries": node_queries,
            "resource_limit": resource_limit,
            "inter_node_link_limit": link_limit,
            "network_segment_limit": segment_limit,
            "segment_attachment_limit": attachment_limit,
        }
        _semantic_comparison_key(
            context_material,
            label="topology query context",
        )
        try:
            context_bytes = json.dumps(
                context_material,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise MultiNodeTopologyRequestError(
                "topology query context is not canonical JSON"
            ) from error
        context_digest = hashlib.sha256(
            context_bytes
        ).hexdigest()[:24]
        context_id = f"tctx1-{context_digest}"

        snapshots: list[dict[str, Any]] = []
        all_claims: list[dict[str, Any]] = []
        all_segment_claims: list[dict[str, Any]] = []
        typed_invocations: list[TopologyProjectionInvocation] = []
        typed_invocations_complete = True
        typed_resources: dict[
            _TypedResourceScopeKey, tuple[dict[str, Any], ...]
        ] = {}
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
            typed_invocations.extend(snapshot.pop("_typed_invocations", ()))
            typed_invocations_complete = bool(
                typed_invocations_complete
                and snapshot.pop("_typed_invocations_complete", True)
            )
            for scope, rows in snapshot.pop("_typed_resources", {}).items():
                typed_resources[scope] = typed_resources.get(scope, ()) + rows
            basis_kinds.update(
                item["basis_kind"] for item in snapshot["resolved_times"]
            )

        (
            inter_node_links,
            connector_resolutions,
            unmatched_claims,
            links_truncated,
        ) = self._join_claims(all_claims, link_limit, context_id)
        typed_assembly: TopologyFederationAssembly | None = None
        typed_unmatched_claims: list[dict[str, Any]] = []
        typed_federation_failures: list[dict[str, Any]] = []
        if self._topology_federation is not None and typed_invocations:
            try:
                typed_assembly = self._topology_federation.federate(
                    tuple(typed_invocations),
                    invocations_complete=typed_invocations_complete,
                )
            except TopologyFederationError:
                typed_federation_failures.append(
                    {
                        "reason_code": "typed_federation_input_rejected",
                        "scope": "selected_typed_projections",
                    }
                )
            if typed_assembly is not None:
                (
                    typed_links,
                    typed_resolutions,
                    typed_unmatched,
                    typed_links_truncated,
                ) = self._federated_claim_links(
                    typed_assembly,
                    typed_resources,
                    link_limit,
                    context_id,
                    global_basis,
                )
                available_link_slots = max(0, link_limit - len(inter_node_links))
                inter_node_links.extend(typed_links[:available_link_slots])
                connector_resolutions.extend(typed_resolutions)
                # UNRESOLVED is a complete typed federation outcome when a
                # selected scope intentionally has no compatible remote member.
                typed_unmatched_claims = typed_unmatched
                links_truncated = (
                    links_truncated
                    or typed_links_truncated
                    or len(typed_links) > available_link_slots
                )
                typed_federation_failures.extend(
                    {
                        "claim_contract_id": item.claim_contract_id,
                        "match_policy_id": item.policy_id,
                        "reason_code": item.reason_code,
                        "linker_plugin_id": item.linker_plugin_id,
                        "linker_plugin_version": item.linker_plugin_version,
                    }
                    for item in typed_assembly.failures
                )
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
            "topology_id": self.topology_id,
            "assembly_id": self.assembly_id,
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
                "topology_endpoints": sum(
                    len(item.get("topology_endpoints", [])) for item in snapshots
                ),
                "local_links": sum(len(item["local_links"]) for item in snapshots),
                "connector_claims": len(all_claims),
                "typed_connector_claims": (
                    len(typed_assembly.claims) if typed_assembly is not None else 0
                ),
                "inter_node_links": len(inter_node_links),
                "unmatched_connector_claims": len(unmatched_claims),
                "unresolved_typed_connector_claims": len(
                    typed_unmatched_claims
                ),
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
                and not typed_federation_failures
                and (typed_assembly is None or typed_assembly.complete)
            ),
            "completeness": {
                "complete": (
                    not incomplete_nodes
                    and not links_truncated
                    and not unmatched_claims
                    and not segments_truncated
                    and not attachments_truncated
                    and not unresolved_segment_claims
                    and not typed_federation_failures
                    and (typed_assembly is None or typed_assembly.complete)
                ),
                "incomplete_nodes": incomplete_nodes,
                "unmatched_connector_claims": unmatched_claims,
                "unresolved_typed_connector_claims": typed_unmatched_claims,
                "typed_federation_failures": typed_federation_failures,
                "inter_node_links_truncated": links_truncated,
                "network_segments_truncated": segments_truncated,
                "segment_attachments_truncated": attachments_truncated,
                "unresolved_network_segment_claims": unresolved_segment_claims,
                "typed_federation_complete": (
                    None if typed_assembly is None else typed_assembly.complete
                ),
                "typed_federation_truncated": (
                    False if typed_assembly is None else typed_assembly.truncated
                ),
                "inactive_typed_connector_claims": (
                    0
                    if typed_assembly is None
                    else typed_assembly.inactive_claim_count
                ),
                "unknown_basis_typed_connector_claims": (
                    0
                    if typed_assembly is None
                    else typed_assembly.temporal_basis_unknown_claim_count
                ),
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
                    "topology_id": self.topology_id,
                    "assembly_id": self.assembly_id,
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
        topology_endpoints: list[dict[str, Any]] = []
        local_links: list[dict[str, Any]] = []
        claims: list[dict[str, Any]] = []
        segment_claims: list[dict[str, Any]] = []
        typed_invocations: list[TopologyProjectionInvocation] = []
        typed_invocations_complete = True
        typed_resources: dict[
            _TypedResourceScopeKey, tuple[dict[str, Any], ...]
        ] = {}
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
                typed_invocations_complete = False
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
                typed_invocations_complete = False
                continue
            result = self._run_projection(
                node,
                plugin_set_id,
                plugin,
                projection,
                perspective_id,
                resolved_time,
                basis,
                max(0, resource_limit - len(resources)),
                context_id,
            )
            plugin_results.append(result)
            resources.extend(result["resources"])
            topology_endpoints.extend(result.get("topology_endpoints", []))
            local_links.extend(result["local_links"])
            claims.extend(result.pop("connector_claims"))
            segment_claims.extend(result.pop("network_segment_claims"))
            typed_invocations.extend(result.pop("_typed_invocations", ()))
            typed_invocations_complete = bool(
                typed_invocations_complete
                and result.pop("_typed_invocations_complete", True)
            )
            for scope, rows in result.pop("_typed_resources", {}).items():
                typed_resources[scope] = typed_resources.get(scope, ()) + rows
            if not result["complete"]:
                incomplete_reasons.append(
                    {
                        "plugin_id": plugin["plugin_id"],
                        "projection_id": projection["projection_id"],
                        "reason_code": result.get(
                            "incomplete_reason_code",
                            "projection_truncated",
                        ),
                    }
                )

        resource_totals = [
            item["counts"]["resources"]["total_count"]
            for item in plugin_results
        ]
        resource_total_count = (
            None
            if any(value is None for value in resource_totals)
            else sum(int(value) for value in resource_totals)
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
            "topology_endpoints": topology_endpoints,
            "local_links": local_links,
            "counts": {
                "plugin_results": len(plugin_results),
                "resources": len(resources),
                "resource_page": {
                    "total_count": resource_total_count,
                    "returned_count": len(resources),
                    "truncated": any(
                        bool(item["counts"]["resources"]["truncated"])
                        for item in plugin_results
                    ),
                },
                "topology_endpoints": len(topology_endpoints),
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
            "_typed_invocations": typed_invocations,
            "_typed_invocations_complete": typed_invocations_complete,
            "_typed_resources": typed_resources,
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
        scope = {
            "node_id": node["node_id"],
            "member_id": node["member_id"],
            "revision_id": node["revision_id"],
            "plugin_set_id": plugin_set_id,
            "plugin_id": plugin["plugin_id"],
            "plugin_run_id": plugin["plugin_run_id"],
            "projection_id": projection["projection_id"],
            "status_perspective_id": perspective_id,
        }
        common = dict(scope)
        query_time: int | None
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
            watermarks = node.get("watermarks", {})
            if not isinstance(watermarks, dict):
                raise MultiNodeTopologyRequestError(
                    f"watermarks for node {node['node_id']} must be an object"
                )
            perspective_watermarks = watermarks.get(
                perspective_id,
                {},
            )
            if not isinstance(perspective_watermarks, dict):
                raise MultiNodeTopologyRequestError(
                    "perspective watermarks must be an object for "
                    f"{node['node_id']}:{perspective_id}"
                )
            watermark = perspective_watermarks.get(
                projection["projection_id"]
            )
            if watermark is not None:
                if not isinstance(watermark, dict):
                    raise MultiNodeTopologyRequestError(
                        "projection watermark must be an object for "
                        f"{node['node_id']}:{plugin['plugin_id']}:"
                        f"{projection['projection_id']}:{perspective_id}"
                    )
                if watermark.get("complete") is False:
                    raise MultiNodeTopologyRequestError(
                        "projection watermark is explicitly incomplete for "
                        f"{node['node_id']}:{plugin['plugin_id']}:"
                        f"{projection['projection_id']}:{perspective_id}"
                    )
                local_watermark = _integer_ns(
                    watermark.get("local_time_ns"),
                    "watermark.local_time_ns",
                )
                query_watermark_raw = watermark.get("query_time_ns")
                query_watermark = (
                    None
                    if query_watermark_raw is None
                    else _integer_ns(
                        query_watermark_raw,
                        "watermark.query_time_ns",
                    )
                )
                absolute_min_raw = watermark.get("absolute_min_ns")
                absolute_max_raw = watermark.get("absolute_max_ns")
                if (absolute_min_raw is None) != (absolute_max_raw is None):
                    raise MultiNodeTopologyRequestError(
                        "watermark.absolute_min_ns and "
                        "watermark.absolute_max_ns must be supplied together"
                    )
                absolute_min = (
                    None
                    if absolute_min_raw is None
                    else _integer_ns_add(
                        _integer_ns(
                            absolute_min_raw,
                            "watermark.absolute_min_ns",
                        ),
                        offset,
                        "resolved relative absolute minimum",
                    )
                )
                absolute_max = (
                    None
                    if absolute_max_raw is None
                    else _integer_ns_add(
                        _integer_ns(
                            absolute_max_raw,
                            "watermark.absolute_max_ns",
                        ),
                        offset,
                        "resolved relative absolute maximum",
                    )
                )
                if (
                    absolute_min is not None
                    and absolute_max is not None
                    and absolute_min > absolute_max
                ):
                    raise MultiNodeTopologyRequestError(
                        "watermark absolute bounds are reversed"
                    )
                local_time = _integer_ns_add(
                    local_watermark,
                    offset,
                    "resolved relative local time",
                )
                query_time = (
                    None
                    if query_watermark is None
                    else _integer_ns_add(
                        query_watermark,
                        offset,
                        "resolved relative query time",
                    )
                )
                if absolute_min is None and clock:
                    if query_time is None:
                        query_time = _integer_ns_subtract(
                            local_time,
                            _integer_ns(
                                clock["local_minus_absolute_ns"],
                                "clock.local_minus_absolute_ns",
                            ),
                            "resolved relative query time",
                        )
                    clock_uncertainty = _integer_ns(
                        clock["uncertainty_ns"],
                        "clock.uncertainty_ns",
                    )
                    if clock_uncertainty < 0:
                        raise MultiNodeTopologyRequestError(
                            "clock.uncertainty_ns must be zero or positive"
                        )
                    absolute_min = _integer_ns_subtract(
                        query_time,
                        clock_uncertainty,
                        "resolved absolute minimum",
                    )
                    absolute_max = _integer_ns_add(
                        query_time,
                        clock_uncertainty,
                        "resolved absolute maximum",
                    )
                elif (
                    query_time is None
                    and absolute_min is not None
                    and absolute_max is not None
                ):
                    query_time = _integer_ns_add(
                        absolute_min,
                        (absolute_max - absolute_min) // 2,
                        "resolved query time",
                    )
                uncertainty = (
                    None
                    if absolute_min is None or absolute_max is None
                    else _integer_ns(
                        max(0, (absolute_max - absolute_min) // 2),
                        "resolved uncertainty",
                    )
                )
                quality = str(
                    watermark.get("quality")
                    or watermark.get("mapping_quality")
                    or (
                        clock.get("mapping_quality")
                        if isinstance(clock, dict)
                        else "unknown"
                    )
                )
                return {
                    **common,
                    "basis_kind": "relative_capture_vector",
                    "kind": "relative_capture_vector",
                    "query_time_ns": (
                        None if query_time is None else str(query_time)
                    ),
                    "local_time_ns": str(local_time),
                    "local_clock_domain": str(
                        watermark.get("clock_domain")
                        or (
                            clock.get("clock_domain")
                            if isinstance(clock, dict)
                            else "local"
                        )
                    ),
                    "absolute_min_ns": (
                        None if absolute_min is None else str(absolute_min)
                    ),
                    "absolute_max_ns": (
                        None if absolute_max is None else str(absolute_max)
                    ),
                    "uncertainty_ns": (
                        None if uncertainty is None else str(uncertainty)
                    ),
                    "resolution": (
                        "local_exact"
                        if absolute_min is None
                        else "exact"
                        if uncertainty == 0
                        else "bounded"
                    ),
                    "mapping_method": watermark.get("mapping_method")
                    or (
                        clock.get("mapping_method")
                        if isinstance(clock, dict)
                        else None
                    ),
                    "mapping_quality": quality,
                    "simultaneity": "not_implied",
                    "watermark_query_time_ns": (
                        None
                        if query_watermark is None
                        else str(query_watermark)
                    ),
                    "watermark_local_time_ns": str(local_watermark),
                    "watermark_scope": scope,
                    "watermark_source": "projection_declaration",
                    "relative_offset_ns": str(offset),
                }
            # Compatibility for pre-watermark topology providers. This remains
            # intentionally explicit in the result and still requires the
            # legacy node clock mapping.
            lag = _integer_ns(
                projection.get("watermark_lag_ns", 0),
                "projection.watermark_lag_ns",
            )
            watermark = _integer_ns_subtract(
                self.capture_ns,
                lag,
                "legacy projection watermark",
            )
            query_time = _integer_ns_add(
                watermark,
                offset,
                "resolved relative query time",
            )
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
                **common,
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
        uncertainty = _integer_ns(
            clock["uncertainty_ns"],
            "clock.uncertainty_ns",
        )
        if uncertainty < 0:
            raise MultiNodeTopologyRequestError(
                "clock.uncertainty_ns must be zero or positive"
            )
        local_offset = _integer_ns(
            clock["local_minus_absolute_ns"],
            "clock.local_minus_absolute_ns",
        )
        local_time = _integer_ns_add(
            query_time,
            local_offset,
            "resolved local time",
        )
        absolute_min = _integer_ns_subtract(
            query_time,
            uncertainty,
            "resolved absolute minimum",
        )
        absolute_max = _integer_ns_add(
            query_time,
            uncertainty,
            "resolved absolute maximum",
        )
        result = {
            **common,
            "basis_kind": basis_kind,
            "kind": basis_kind,
            "query_time_ns": str(query_time),
            "local_time_ns": str(local_time),
            "local_clock_domain": clock["clock_domain"],
            "absolute_min_ns": str(absolute_min),
            "absolute_max_ns": str(absolute_max),
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
                        _integer_ns_add(
                            watermark,
                            local_offset,
                            "watermark local time",
                        )
                    ),
                    "watermark_scope": scope,
                    "watermark_source": "legacy_capture_lag",
                    "relative_offset_ns": str(offset),
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
        timestamp_value = (
            resolved_time.get("query_time_ns")
            if resolved_time.get("query_time_ns") is not None
            else resolved_time["local_time_ns"]
        )
        timestamp_ns = _integer_ns(
            timestamp_value,
            "resolved_time.query_time_ns",
        )
        minimum_value = resolved_time.get("absolute_min_ns")
        maximum_value = resolved_time.get("absolute_max_ns")
        minimum_ns = (
            timestamp_ns
            if minimum_value is None
            else _integer_ns(
                minimum_value,
                "resolved_time.absolute_min_ns",
            )
        )
        maximum_ns = (
            timestamp_ns
            if maximum_value is None
            else _integer_ns(
                maximum_value,
                "resolved_time.absolute_max_ns",
            )
        )
        all_resources = list(projection.get("resources", []))
        resources: list[dict[str, Any]] = []
        state_by_id: dict[str, dict[str, Any]] = {}
        # The resource limit bounds only the response preview. Connector and
        # connectivity-domain claims are evaluated against the complete,
        # coordinator-bounded projection so lowering a table/page budget cannot
        # silently remove topology edges.
        for resource_index, item in enumerate(all_resources):
            temporal_state = _status_window_at(
                item,
                center_ns=timestamp_ns,
                minimum_ns=minimum_ns,
                maximum_ns=maximum_ns,
            )
            exists = temporal_state["exists"]
            status = temporal_state["status"]
            state = temporal_state["state"]
            usable_statuses = set(projection.get("usable_statuses", []))
            unusable_statuses = set(projection.get("unusable_statuses", []))
            status_class = (
                "usable"
                if exists is True and status in usable_statuses
                else "unusable"
                if exists is True and status in unusable_statuses
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
                "quality": temporal_state["quality"],
                "temporal_resolution": temporal_state[
                    "temporal_resolution"
                ],
                "possible_states": temporal_state["possible_states"],
                "unknown_fields": temporal_state["unknown_fields"],
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
        for item in projection.get("local_links", []):
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
        for item in projection.get("connector_claims", []):
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
        for item in projection.get("network_segment_claims", []):
            source = state_by_id.get(item["resource_id"])
            if not source:
                continue
            valid_from_ns = item.get("valid_from_ns")
            valid_to_ns = item.get("valid_to_ns")
            claim_valid = contains_time(
                timestamp_ns,
                (
                    None
                    if valid_from_ns is None
                    else _integer_ns(
                        valid_from_ns,
                        "network_segment_claim.valid_from_ns",
                    )
                ),
                (
                    None
                    if valid_to_ns is None
                    else _integer_ns(
                        valid_to_ns,
                        "network_segment_claim.valid_to_ns",
                    )
                ),
            )
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
        typed_invocations: tuple[TopologyProjectionInvocation, ...] = ()
        typed_resources: dict[
            _TypedResourceScopeKey, tuple[dict[str, Any], ...]
        ] = {}
        typed_endpoints: list[dict[str, Any]] = []
        typed_resource_rows: list[dict[str, Any]] = []
        typed_inactive_record_count = 0
        typed_unknown_basis_record_count = 0
        typed_failure_reason: str | None = None
        typed_records_complete = True
        typed_claims_complete = True
        if self._topology_federation is not None:
            try:
                selection = TopologyProjectionSelection(
                    key=self._typed_revision_key(node),
                    plugin_instance_id=_exact_nonempty_string(
                        plugin.get("plugin_instance_id"),
                        "typed topology plugin_instance_id",
                    ),
                    expected_node_id=_exact_nonempty_string(
                        node.get("node_id"),
                        "typed topology node_id",
                    ),
                    expected_basis_revision_id=_exact_nonempty_string(
                        node.get("revision_id"),
                        "typed topology revision_id",
                    ),
                    request=TopologyProjectionRequest(
                        projection_id=_exact_nonempty_string(
                            projection.get("projection_id"),
                            "typed topology projection_id",
                        ),
                        status_perspective_id=_exact_nonempty_string(
                            perspective_id,
                            "typed topology status_perspective_id",
                        ),
                        max_records=max(1, min(resource_limit, 100_000)),
                        max_world_reads=50_000,
                        max_claims=10_000,
                    ),
                    basis_time_ns=timestamp_ns,
                )
                if self._topology_federation.projection_available(selection):
                    invocation = (
                        self._topology_federation.project_with_world_factory(
                            selection,
                            lambda provider: self._typed_projection_world(
                                provider,
                                perspective_id,
                                resolved_time,
                                (
                                    self._topology_projection_state_provider(
                                        provider,
                                        perspective_id,
                                        resolved_time,
                                    )
                                    if self._topology_projection_state_provider
                                    is not None
                                    else None
                                ),
                            ),
                        )
                    )
                    typed_invocations = (invocation,)
                    typed_records_complete = (
                        invocation.invocation.result.records_complete
                    )
                    typed_claims_complete = (
                        invocation.invocation.result.claims_complete
                    )
                    (
                        typed_resource_rows,
                        typed_local_links,
                        typed_endpoints,
                        typed_resources,
                        typed_inactive_record_count,
                        typed_unknown_basis_record_count,
                    ) = self._render_typed_projection(
                        node,
                        plugin_set_id,
                        plugin,
                        projection,
                        perspective_id,
                        requested_basis,
                        resolved_time,
                        context_id,
                        invocation,
                    )
                    local_links.extend(typed_local_links)
            except (TopologyFederationError, MultiNodeTopologyRequestError):
                typed_failure_reason = "typed_projection_failed"

        all_legacy_resource_ids = {
            str(item["resource_id"]) for item in all_resources
        }
        unique_typed_rows = [
            item
            for item in typed_resource_rows
            if str(item["resource_id"]) not in all_legacy_resource_ids
        ]
        total_resource_count = len(all_resources) + len(unique_typed_rows)
        remaining_resource_slots = max(0, resource_limit - len(resources))
        resources.extend(unique_typed_rows[:remaining_resource_slots])
        resource_truncated = (
            len(resources) < total_resource_count or not typed_records_complete
        )
        projection_truncated = resource_truncated or not typed_claims_complete
        complete = (
            not projection_truncated
            and typed_failure_reason is None
            and typed_unknown_basis_record_count == 0
        )
        return {
            "plugin_provenance": self._plugin_provenance(plugin, plugin_set_id),
            "projection_id": projection["projection_id"],
            "status_perspective_id": perspective_id,
            "resolved_time": resolved_time,
            "resources": resources,
            "topology_endpoints": typed_endpoints,
            "local_links": local_links,
            "connector_claims": claims,
            "network_segment_claims": segment_claims,
            "counts": {
                "resources": {
                    "total_count": (
                        total_resource_count
                        if typed_records_complete
                        else None
                    ),
                    "returned_count": len(resources),
                    "truncated": resource_truncated,
                },
                "local_links": len(local_links),
                "connector_claims": len(claims),
                "network_segment_claims": len(segment_claims),
                "typed_projection_records": (
                    len(typed_invocations[0].invocation.result.records)
                    if typed_invocations
                    else 0
                ),
                "typed_connector_claims": (
                    len(typed_invocations[0].invocation.result.claims)
                    if typed_invocations
                    else 0
                ),
                "typed_inactive_records": typed_inactive_record_count,
                "typed_unknown_basis_records": typed_unknown_basis_record_count,
            },
            "complete": complete,
            "incomplete_reason_code": (
                typed_failure_reason
                or (
                    "typed_record_basis_unknown"
                    if typed_unknown_basis_record_count
                    else "projection_truncated"
                )
            ),
            "_typed_invocations": typed_invocations,
            "_typed_invocations_complete": typed_failure_reason is None,
            "_typed_resources": typed_resources,
        }

    @staticmethod
    def _typed_revision_key(node: Mapping[str, Any]) -> RevisionSetCapabilityKey:
        return RevisionSetCapabilityKey(
            catalog_revision_id=_exact_nonempty_string(
                node.get("catalog_revision_id"),
                "typed topology catalog_revision_id",
            ),
            member_id=_exact_nonempty_string(
                node.get("member_id"),
                "typed topology member_id",
            ),
        )

    @staticmethod
    def _typed_projection_world(
        provider: CapabilityProviderRef,
        perspective_id: str,
        resolved_time: Mapping[str, Any],
        states: Mapping[ResourceKey, ResourceStateView] | None = None,
    ) -> _TopologyProjectionWorld:
        timestamp_ns = _integer_ns(
            resolved_time.get("query_time_ns")
            if resolved_time.get("query_time_ns") is not None
            else resolved_time["local_time_ns"],
            "resolved topology projection time",
        )
        minimum_ns = _integer_ns(
            resolved_time.get("absolute_min_ns", timestamp_ns),
            "resolved topology projection minimum",
        )
        maximum_ns = _integer_ns(
            resolved_time.get("absolute_max_ns", timestamp_ns),
            "resolved topology projection maximum",
        )
        kind = (
            WorldBasisKind.ABSOLUTE_TIME
            if resolved_time.get("basis_kind") == "absolute_time"
            else WorldBasisKind.RELATIVE_CAPTURE_VECTOR
        )
        quality = (
            Quality.EXACT
            if minimum_ns == maximum_ns
            else Quality.BEST_EFFORT
        )
        return _TopologyProjectionWorld(
            WorldBasis(
                kind=kind,
                requested_time_ns=timestamp_ns,
                resolved_at_min_ns=minimum_ns,
                resolved_at_max_ns=maximum_ns,
                capture_ranges=(),
                provenance=Provenance.RECONSTRUCTED,
                quality=quality,
                clock_domain=(
                    str(resolved_time["local_clock_domain"])
                    if resolved_time.get("local_clock_domain") is not None
                    else None
                ),
            ),
            StatusPerspectiveRef(
                perspective_id=perspective_id,
                plugin_instance_id=provider.pin.instance_id,
                schema_digest=provider.pin.schema_digest,
            ),
            states,
        )

    @staticmethod
    def _typed_resource_identity(
        resource: ResourceKey,
    ) -> tuple[str, dict[str, Any]]:
        parts = [
            {"name": name, "value": _normalize_opaque_key(value)}
            for name, value in resource.parts
        ]
        identity = {
            "namespace": resource.namespace,
            "node": resource.node,
            "layer": resource.layer,
            "kind": resource.kind,
            "parts": parts,
        }
        token = json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]
        return (
            (
                f"{resource.namespace}/{resource.node}/{resource.layer}/"
                f"{resource.kind}/{digest}"
            ),
            identity,
        )

    @staticmethod
    def _typed_resource_label(resource: ResourceKey) -> str:
        labels: list[str] = []
        for _name, raw_value in resource.parts:
            value = raw_value.value if isinstance(raw_value, KeyAtom) else raw_value
            labels.append(value.hex() if isinstance(value, bytes) else str(value))
        return "/".join(labels) or resource.kind

    @staticmethod
    def _typed_record_active_during(
        record: Any,
        basis: TopologyProjectionBasisSnapshot,
    ) -> bool | None:
        """Apply half-open validity across the resolved clock interval.

        A record is authoritative only when its validity covers every possible
        instant in the member world's resolved uncertainty window.  A record
        that overlaps only part of that window is retained as unknown rather
        than being selected merely because it contains the requested instant.
        """

        minimum_ns = basis.resolved_at_min_ns
        maximum_ns = basis.resolved_at_max_ns
        if minimum_ns is None or maximum_ns is None:
            if record.valid_from_ns is not None or record.valid_to_ns is not None:
                return None
            return True
        if (
            record.valid_to_ns is not None
            and record.valid_to_ns <= minimum_ns
        ) or (
            record.valid_from_ns is not None
            and record.valid_from_ns > maximum_ns
        ):
            return False
        if (
            record.valid_from_ns is None
            or record.valid_from_ns <= minimum_ns
        ) and (
            record.valid_to_ns is None
            or maximum_ns < record.valid_to_ns
        ):
            return True
        return None

    @staticmethod
    def _typed_reference_resources(reference: Any) -> tuple[ResourceKey, ...]:
        if reference.resource is not None:
            return (reference.resource,)
        if reference.match is not None:
            return reference.match.resolved_candidates
        return ()

    def _typed_reference_payload(
        self,
        reference: Any,
        rows_by_resource: Mapping[ResourceKey, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        resources = self._typed_reference_resources(reference)
        candidates = []
        resolved_resource_ids: list[str] = []
        for resource in resources:
            resource_id, typed_key = self._typed_resource_identity(resource)
            rows = rows_by_resource.get(resource, [])
            resolved_resource_ids.extend(
                str(row["resource_id"]) for row in rows
            )
            candidates.append(
                {
                    "resource_id": resource_id,
                    "typed_resource_key": typed_key,
                    "rendered_resource_ids": [
                        str(row["resource_id"]) for row in rows
                    ],
                }
            )
        if reference.resource is not None:
            return {
                "kind": "resource",
                "resource": candidates[0],
                "resolved_resource_ids": resolved_resource_ids,
            }
        assert reference.match is not None
        return {
            "kind": "match",
            "matcher_id": reference.match.matcher_id,
            "arguments": _typed_json_value(reference.match.arguments),
            "resolved_candidates": candidates,
            "resolved_resource_ids": resolved_resource_ids,
        }

    def _render_typed_projection(
        self,
        node: dict[str, Any],
        plugin_set_id: str,
        plugin: dict[str, Any],
        projection: dict[str, Any],
        perspective_id: str,
        requested_basis: dict[str, Any],
        resolved_time: dict[str, Any],
        context_id: str,
        invocation: TopologyProjectionInvocation,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        dict[_TypedResourceScopeKey, tuple[dict[str, Any], ...]],
        int,
        int,
    ]:
        rows: list[dict[str, Any]] = []
        local_links: list[dict[str, Any]] = []
        endpoints: list[dict[str, Any]] = []
        rows_by_resource: dict[ResourceKey, list[dict[str, Any]]] = {}
        mutable_global_rows: dict[
            _TypedResourceScopeKey, list[dict[str, Any]]
        ] = {}
        provider = invocation.invocation.provider
        typed_records = invocation.invocation.result.records
        active_records: list[Any] = []
        inactive_record_count = 0
        unknown_basis_record_count = 0

        for record in typed_records:
            active = self._typed_record_active_during(
                record,
                invocation.world_basis,
            )
            if active is None:
                unknown_basis_record_count += 1
            elif active:
                active_records.append(record)
            else:
                inactive_record_count += 1

        plugin_provenance = self._plugin_provenance(plugin, plugin_set_id) | {
            "projection_id": projection["projection_id"],
            "status_perspective_id": perspective_id,
            "plan_digest": provider.plan_digest,
            "catalog_revision_id": provider.catalog_revision_id,
        }

        for record in active_records:
            if type(record.payload) is not TopologyResourceRecord:
                continue
            resource = record.payload.resource
            resource_id, resource_key = self._typed_resource_identity(resource)
            raw_label = record.properties.get("label")
            label = (
                raw_label
                if type(raw_label) is str and raw_label
                else self._typed_resource_label(resource)
            )
            properties = _typed_json_value(record.properties)
            usability = TopologyUsability(record.usability)
            status_class = (
                "usable"
                if record.exists is True and usability is TopologyUsability.USABLE
                else "unusable"
                if record.exists is True
                and usability is TopologyUsability.UNUSABLE
                else "unknown"
            )
            row = {
                "resource_id": resource_id,
                "node_id": node["node_id"],
                "member_id": node["member_id"],
                "revision_id": node["revision_id"],
                "resource_ref": {
                    "member_id": node["member_id"],
                    "node_id": node["node_id"],
                    "revision_id": node["revision_id"],
                    "local_resource_id": resource_id,
                    "typed_resource_key": resource_key,
                    "plugin_instance_id": provider.pin.instance_id,
                    "projection_id": projection["projection_id"],
                    "status_perspective_id": perspective_id,
                },
                "kind": resource.kind,
                "role": record.payload.role,
                "presentation": {
                    "two_participant_shape": (
                        record.payload.presentation.two_participant_shape.value
                    )
                },
                "label": label,
                "exists": record.exists,
                "status": usability.value,
                "status_class": status_class,
                "state": properties,
                "properties": properties,
                "status_perspective_id": perspective_id,
                "basis_time_ns": (
                    None
                    if invocation.selection.basis_time_ns is None
                    else str(invocation.selection.basis_time_ns)
                ),
                "quality": record.quality.value,
                "temporal_resolution": "typed_projection",
                "possible_states": [],
                "unknown_fields": [
                    {
                        "name": item.name,
                        "reason_code": item.reason_code,
                        "message": item.message,
                    }
                    for item in record.unknown_fields
                ],
                "provenance": record.provenance.value,
                "evidence": [_typed_evidence(item) for item in record.evidence],
                "valid_from_ns": (
                    None
                    if record.valid_from_ns is None
                    else str(record.valid_from_ns)
                ),
                "valid_to_ns": (
                    None
                    if record.valid_to_ns is None
                    else str(record.valid_to_ns)
                ),
                "source_resources": [
                    self._typed_resource_identity(item)[1]
                    for item in record.source_resources
                ],
                "plugin_provenance": plugin_provenance,
                "typed_projection": True,
            }
            row["deep_link"] = self._resource_deep_link(
                node,
                plugin_set_id,
                plugin,
                projection,
                perspective_id,
                resource_id,
                requested_basis,
                resolved_time,
                context_id,
            )
            row["navigation_target"] = row["deep_link"]
            rows.append(row)
            rows_by_resource.setdefault(resource, []).append(row)
            scoped_key = (
                GlobalResourceRef(
                    member_id=provider.member_id,
                    revision_id=provider.basis_revision_id,
                    plugin_instance_id=provider.pin.instance_id,
                    resource=resource,
                ),
                projection["projection_id"],
                perspective_id,
            )
            mutable_global_rows.setdefault(scoped_key, []).append(row)

        for record in active_records:
            if type(record.payload) is not TopologyEndpointRecord:
                continue
            target = self._typed_reference_payload(
                record.payload.target,
                rows_by_resource,
            )
            endpoints.append(
                {
                    "endpoint_id": record.payload.endpoint_id,
                    "node_id": node["node_id"],
                    "member_id": node["member_id"],
                    "revision_id": node["revision_id"],
                    "role": record.payload.role,
                    "target": target,
                    "resolved_resource_ids": target["resolved_resource_ids"],
                    "exists": record.exists,
                    "usability": record.usability.value,
                    "properties": _typed_json_value(record.properties),
                    "quality": record.quality.value,
                    "provenance": record.provenance.value,
                    "evidence": [
                        _typed_evidence(item) for item in record.evidence
                    ],
                    "unknown_fields": [
                        {
                            "name": item.name,
                            "reason_code": item.reason_code,
                            "message": item.message,
                        }
                        for item in record.unknown_fields
                    ],
                    "valid_from_ns": (
                        None
                        if record.valid_from_ns is None
                        else str(record.valid_from_ns)
                    ),
                    "valid_to_ns": (
                        None
                        if record.valid_to_ns is None
                        else str(record.valid_to_ns)
                    ),
                    "plugin_provenance": plugin_provenance,
                    "typed_projection": True,
                }
            )

        for record in active_records:
            if type(record.payload) is not TopologyLinkRecord:
                continue
            source_resources = self._typed_reference_resources(
                record.payload.source
            )
            target_resources = self._typed_reference_resources(
                record.payload.target
            )
            for source in source_resources:
                for target in target_resources:
                    for source_row in rows_by_resource.get(source, []):
                        for target_row in rows_by_resource.get(target, []):
                            local_links.append(
                                {
                                    "link_id": record.payload.link_id,
                                    "source_resource_id": source_row["resource_id"],
                                    "target_resource_id": target_row["resource_id"],
                                    "source": self._typed_reference_payload(
                                        record.payload.source,
                                        rows_by_resource,
                                    ),
                                    "target": self._typed_reference_payload(
                                        record.payload.target,
                                        rows_by_resource,
                                    ),
                                    "directed": record.payload.directed,
                                    "node_id": node["node_id"],
                                    "exists": record.exists,
                                    "usability": record.usability.value,
                                    "properties": _typed_json_value(
                                        record.properties
                                    ),
                                    "quality": record.quality.value,
                                    "provenance": record.provenance.value,
                                    "evidence": [
                                        _typed_evidence(item)
                                        for item in record.evidence
                                    ],
                                    "valid_from_ns": (
                                        None
                                        if record.valid_from_ns is None
                                        else str(record.valid_from_ns)
                                    ),
                                    "valid_to_ns": (
                                        None
                                        if record.valid_to_ns is None
                                        else str(record.valid_to_ns)
                                    ),
                                    "typed_projection": True,
                                    "plugin_provenance": plugin_provenance,
                                }
                            )
        return (
            rows,
            local_links,
            endpoints,
            {
                key: tuple(values)
                for key, values in mutable_global_rows.items()
            },
            inactive_record_count,
            unknown_basis_record_count,
        )

    @staticmethod
    def _typed_federation_endpoint(
        endpoint: GlobalResourceRef,
        claim_id: str,
        context: TopologyFederatedClaimContext | None,
        resources: Mapping[
            _TypedResourceScopeKey, tuple[dict[str, Any], ...]
        ],
    ) -> dict[str, Any]:
        rows = (
            ()
            if context is None
            else resources.get(
                (
                    endpoint,
                    context.projection_id,
                    context.status_perspective_id,
                ),
                (),
            )
        )
        resource_id, typed_key = MultiNodeTopologyService._typed_resource_identity(
            endpoint.resource
        )
        payload = {
            "member_id": endpoint.member_id,
            "node_id": endpoint.resource.node,
            "revision_id": endpoint.revision_id,
            "resource_id": resource_id,
            "claim_id": claim_id,
            "plugin_instance_id": endpoint.plugin_instance_id,
            "projection_id": (
                None if context is None else context.projection_id
            ),
            "status_perspective_id": (
                None if context is None else context.status_perspective_id
            ),
            "resource_ref": {
                "member_id": endpoint.member_id,
                "node_id": endpoint.resource.node,
                "revision_id": endpoint.revision_id,
                "local_resource_id": resource_id,
                "typed_resource_key": typed_key,
                "plugin_instance_id": endpoint.plugin_instance_id,
                "projection_id": (
                    None if context is None else context.projection_id
                ),
                "status_perspective_id": (
                    None
                    if context is None
                    else context.status_perspective_id
                ),
            },
            "status": "unknown",
            "usable": None,
            "projected_resource_candidates": [
                {
                    "resource_id": row["resource_id"],
                    "status": row["status"],
                    "status_class": row["status_class"],
                    "quality": row["quality"],
                    "deep_link": row.get("deep_link"),
                }
                for row in rows
            ],
        }
        if len(rows) == 1:
            row = rows[0]
            payload["status"] = row["status"]
            payload["usable"] = (
                True
                if row["status_class"] == "usable"
                else False
                if row["status_class"] == "unusable"
                else None
            )
            payload["deep_link"] = row["deep_link"]
        return payload

    @staticmethod
    def _federated_claim_identity(
        endpoint: GlobalResourceRef,
        claim_id: str,
    ) -> tuple[str, str, str, str]:
        return (
            endpoint.member_id,
            endpoint.revision_id,
            endpoint.plugin_instance_id,
            claim_id,
        )

    @staticmethod
    def _federated_claim_payload(
        claim: Any,
        endpoint: dict[str, Any],
    ) -> dict[str, Any]:
        local = claim.claim
        perspective = local.status_perspective
        return {
            "endpoint": endpoint,
            "claim_id": local.claim_id,
            "claim_contract_id": local.claim_contract_id,
            "match_policy_id": local.match_policy_id,
            "arguments": [
                {"name": name, "value": _normalize_opaque_key(value)}
                for name, value in local.arguments
            ],
            "provenance": local.provenance.value,
            "quality": local.quality.value,
            "link_type": local.link_type,
            "presentation": {
                "route_trace": local.presentation.route_trace.value,
            },
            "status_perspective": (
                None
                if perspective is None
                else {
                    "perspective_id": perspective.perspective_id,
                    "plugin_instance_id": perspective.plugin_instance_id,
                    "schema_digest": perspective.schema_digest,
                }
            ),
            "role": local.role,
            "valid_from_ns": (
                None
                if local.valid_from_ns is None
                else str(local.valid_from_ns)
            ),
            "valid_to_ns": (
                None if local.valid_to_ns is None else str(local.valid_to_ns)
            ),
            "evidence": [_typed_evidence(item) for item in local.evidence],
        }

    @staticmethod
    def _federated_result_severity(state: FederationMatchState) -> int:
        return {
            FederationMatchState.MATCHED: 0,
            FederationMatchState.UNRESOLVED: 1,
            FederationMatchState.AMBIGUOUS: 2,
            FederationMatchState.CONFLICT: 3,
        }[state]

    def _federated_claim_links(
        self,
        assembly: TopologyFederationAssembly,
        resources: Mapping[
            _TypedResourceScopeKey, tuple[dict[str, Any], ...]
        ],
        limit: int,
        context_id: str,
        basis: dict[str, Any],
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        list[dict[str, Any]],
        bool,
    ]:
        links_by_identity: dict[tuple[Any, ...], dict[str, Any]] = {}
        resolutions: list[dict[str, Any]] = []
        unmatched: list[dict[str, Any]] = []
        selected_node_ids = [str(item["node_id"]) for item in self.contract["nodes"]]
        contexts_by_identity = {
            self._federated_claim_identity(
                item.claim.endpoint,
                item.claim.claim.claim_id,
            ): item
            for item in assembly.claim_contexts
        }
        claims_by_identity = {
            self._federated_claim_identity(
                item.endpoint,
                item.claim.claim_id,
            ): item
            for item in assembly.claims
        }
        global_claim_coverage_complete = bool(
            assembly.invocations_complete
            and assembly.claims_complete
            and assembly.temporal_basis_unknown_claim_count == 0
        )
        global_claim_coverage_truncated = bool(
            not assembly.invocations_complete or not assembly.claims_complete
        )

        for policy_execution in assembly.policy_executions:
            execution = policy_execution.execution
            state_counts: dict[str, int] = {}
            resolution_claims: list[dict[str, Any]] = []
            result_audits: list[dict[str, Any]] = []
            for result in execution.results:
                state = FederationMatchState(result.state)
                state_counts[state.value] = state_counts.get(state.value, 0) + 1
                source_identity = self._federated_claim_identity(
                    result.source.endpoint,
                    result.source.claim.claim_id,
                )
                source_context = contexts_by_identity.get(source_identity)
                source = self._typed_federation_endpoint(
                    result.source.endpoint,
                    result.source.claim.claim_id,
                    source_context,
                    resources,
                )
                source_claim = self._federated_claim_payload(
                    result.source,
                    source,
                )
                resolution_claims.append(source_claim)
                candidate_audits: list[dict[str, Any]] = []
                for candidate in result.candidates:
                    target_identity = self._federated_claim_identity(
                        candidate.endpoint,
                        candidate.claim_id,
                    )
                    target_context = contexts_by_identity.get(target_identity)
                    target = self._typed_federation_endpoint(
                        candidate.endpoint,
                        candidate.claim_id,
                        target_context,
                        resources,
                    )
                    target_claim = claims_by_identity.get(target_identity)
                    candidate_audits.append(
                        {
                            "claim_id": candidate.claim_id,
                            "endpoint": target,
                            "claim": (
                                None
                                if target_claim is None
                                else self._federated_claim_payload(
                                    target_claim,
                                    target,
                                )
                            ),
                            "quality": candidate.quality.value,
                            "confidence": candidate.confidence,
                            "evidence": [
                                _typed_evidence(item)
                                for item in candidate.evidence
                            ],
                        }
                    )
                result_audit = {
                    "result_id": result.result_id,
                    "match_policy_id": result.match_policy_id,
                    "source": source_claim,
                    "state": state.value,
                    "candidates": candidate_audits,
                    "provenance": result.provenance.value,
                    "quality": result.quality.value,
                    "link_type": result.link_type,
                    "directed": result.directed,
                    "properties": _typed_json_value(result.properties),
                    "evidence": [
                        _typed_evidence(item) for item in result.evidence
                    ],
                }
                result_audits.append(result_audit)
                if state is FederationMatchState.UNRESOLVED:
                    unmatched.append(
                        source
                        | {
                            "matcher_id": policy_execution.policy.policy_id,
                            "claim_contract_id": (
                                policy_execution.claim_contract_id
                            ),
                            "resolution": state.value,
                            "reason_code": "no_compatible_remote_claim",
                            "result": result_audit,
                        }
                    )
                    continue
                for candidate, candidate_audit in zip(
                    result.candidates,
                    candidate_audits,
                    strict=True,
                ):
                    target = candidate_audit["endpoint"]
                    target_identity = self._federated_claim_identity(
                        candidate.endpoint,
                        candidate.claim_id,
                    )
                    pair_identity = (
                        (source_identity, target_identity)
                        if result.directed
                        else tuple(sorted((source_identity, target_identity)))
                    )
                    identity = (
                        policy_execution.claim_contract_id,
                        policy_execution.policy.policy_id,
                        result.directed,
                        pair_identity,
                    )
                    pair = (
                        ((source_identity, source), (target_identity, target))
                        if result.directed
                        else tuple(
                            sorted(
                                (
                                    (source_identity, source),
                                    (target_identity, target),
                                ),
                                key=lambda item: item[0],
                            )
                        )
                    )
                    entry = links_by_identity.setdefault(
                        identity,
                        {
                            "_pair": pair,
                            "_states": [],
                            "_qualities": [],
                            "_audits": [],
                            "_candidate_endpoints": {},
                            "_claimed_link_types": set(),
                            "_route_trace_roles": set(),
                            "_execution_complete": global_claim_coverage_complete,
                            "_execution_truncated": global_claim_coverage_truncated,
                            "_execution_provenance": execution.provenance,
                            "_linker_identity": execution.linker_identity,
                        },
                    )
                    entry["_states"].append(state)
                    entry["_qualities"].append(result.quality.value)
                    entry["_audits"].append(result_audit)
                    entry["_candidate_endpoints"][target_identity] = target
                    entry["_execution_complete"] = bool(
                        entry["_execution_complete"]
                        and execution.complete
                        and not execution.truncated
                    )
                    entry["_execution_truncated"] = bool(
                        entry["_execution_truncated"] or execution.truncated
                    )
                    claimed_link_types = entry["_claimed_link_types"]
                    claimed_link_types.add(result.source.claim.link_type)
                    remote_claim = claims_by_identity.get(target_identity)
                    if remote_claim is not None:
                        claimed_link_types.add(remote_claim.claim.link_type)
                        entry["_route_trace_roles"].add(
                            remote_claim.claim.presentation.route_trace.value
                        )
                    if result.link_type not in {None, "unknown"}:
                        claimed_link_types.add(result.link_type)
                    entry["_route_trace_roles"].add(
                        result.source.claim.presentation.route_trace.value
                    )
            resolutions.append(
                {
                    "matcher_id": policy_execution.policy.policy_id,
                    "claim_contract_id": policy_execution.claim_contract_id,
                    "resolution": (
                        next(iter(state_counts))
                        if len(state_counts) == 1
                        else "mixed"
                    ),
                    "result_counts": state_counts,
                    "claims": resolution_claims,
                    "results": result_audits,
                    "execution_provenance": execution.provenance.value,
                    "linker_plugin_provenance": (
                        None
                        if execution.linker_identity is None
                        else {
                            "plugin_id": execution.linker_identity.plugin_id,
                            "plugin_version": execution.linker_identity.plugin_version,
                        }
                    ),
                    "complete": bool(
                        global_claim_coverage_complete
                        and execution.complete
                        and not execution.truncated
                    ),
                    "truncated": bool(
                        global_claim_coverage_truncated or execution.truncated
                    ),
                    "returned_count": len(execution.results),
                    "total_count": (
                        len(execution.results)
                        if execution.complete and not execution.truncated
                        else None
                    ),
                }
            )

        for failure in assembly.failures:
            resolutions.append(
                {
                    "matcher_id": failure.policy_id,
                    "claim_contract_id": failure.claim_contract_id,
                    "resolution": "incomplete",
                    "result_counts": {},
                    "claims": [],
                    "results": [],
                    "execution_provenance": None,
                    "linker_plugin_provenance": (
                        None
                        if failure.linker_plugin_id is None
                        else {
                            "plugin_id": failure.linker_plugin_id,
                            "plugin_version": failure.linker_plugin_version,
                        }
                    ),
                    "complete": False,
                    "truncated": False,
                    "returned_count": 0,
                    "total_count": None,
                    "reason_code": failure.reason_code,
                }
            )

        ordered_links: list[dict[str, Any]] = []
        quality_rank = {
            "exact": 0,
            "best_effort": 1,
            "unknown": 2,
            "ambiguous": 3,
        }
        for identity, aggregate in sorted(links_by_identity.items()):
            endpoint_a = aggregate["_pair"][0][1]
            endpoint_b = aggregate["_pair"][1][1]
            state = max(
                aggregate["_states"],
                key=self._federated_result_severity,
            )
            claimed_link_types = tuple(sorted(aggregate["_claimed_link_types"]))
            route_trace_roles = tuple(sorted(aggregate["_route_trace_roles"]))
            if len(claimed_link_types) != 1 or len(route_trace_roles) != 1:
                state = FederationMatchState.CONFLICT
            federation_complete = bool(aggregate["_execution_complete"])
            federation_truncated = bool(aggregate["_execution_truncated"])
            source_usable = endpoint_a.get("usable")
            target_usable = endpoint_b.get("usable")
            usable = (
                False
                if state is FederationMatchState.MATCHED
                and federation_complete
                and False in {source_usable, target_usable}
                else True
                if state is FederationMatchState.MATCHED
                and federation_complete
                and {source_usable, target_usable} == {True}
                else None
            )
            operational_status = (
                "usable"
                if usable is True
                else "unusable"
                if usable is False
                else "unknown"
            )
            selected_quality = max(
                aggregate["_qualities"],
                key=lambda value: quality_rank[value],
            )
            if state in {
                FederationMatchState.AMBIGUOUS,
                FederationMatchState.CONFLICT,
            }:
                selected_quality = "ambiguous"
            link_digest = hashlib.sha256(
                json.dumps(
                    identity,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()[:24]
            link_id = f"typed-federation:{link_digest}"
            linker_identity = aggregate["_linker_identity"]
            execution_provenance = aggregate["_execution_provenance"]
            inference_owner = (
                "core_exact_matcher"
                if execution_provenance
                is FederationExecutionProvenance.CORE_EXACT_TOKEN
                else "federation_linker_plugin"
            )
            audits = sorted(
                aggregate["_audits"],
                key=lambda item: item["result_id"],
            )
            candidate_endpoints = [
                value
                for _candidate_identity, value in sorted(
                    aggregate["_candidate_endpoints"].items()
                )
            ]
            plugin_provenance = sorted(
                (
                    {
                        "plugin_instance_id": endpoint["plugin_instance_id"],
                        "claim_id": endpoint["claim_id"],
                        "projection_id": endpoint.get("projection_id"),
                        "status_perspective_id": endpoint.get(
                            "status_perspective_id"
                        ),
                    }
                    for endpoint in (endpoint_a, endpoint_b)
                ),
                key=lambda item: (
                    item["plugin_instance_id"],
                    item["claim_id"],
                    item["projection_id"] or "",
                    item["status_perspective_id"] or "",
                ),
            )
            ordered_links.append(
                {
                    "link_id": link_id,
                    "typed_federation": True,
                    "federation_complete": federation_complete,
                    "federation_truncated": federation_truncated,
                    "projection_role": (
                        "presentation_conflict"
                        if len(route_trace_roles) != 1
                        else "presentation_overlay"
                        if route_trace_roles[0] == "overlay"
                        else "federated_connector"
                    ),
                    "presentation": {
                        "physical_topology": (
                            "suppress_when_network_segments_available"
                        ),
                        "route_trace": (
                            route_trace_roles[0]
                            if len(route_trace_roles) == 1
                            else "conflict"
                        ),
                    },
                    "resolution": state.value,
                    "link_type": (
                        claimed_link_types[0]
                        if len(claimed_link_types) == 1
                        else "unknown"
                    ),
                    "claimed_link_types": list(claimed_link_types),
                    "directed": identity[2],
                    "endpoint_a": endpoint_a,
                    "endpoint_b": endpoint_b,
                    "source": endpoint_a,
                    "target": endpoint_b,
                    "exists": None,
                    "operational": {
                        "usable": usable,
                        "status": operational_status,
                        "reason": (
                            "plugin_projected_endpoint_status"
                            if state is FederationMatchState.MATCHED
                            and federation_complete
                            else "federation_evidence_not_authoritative"
                        ),
                    },
                    "status": operational_status,
                    "operational_status": operational_status,
                    "quality": selected_quality,
                    "claim_contract_id": identity[0],
                    "match_policy_id": identity[1],
                    "inference": {
                        "owner": inference_owner,
                        "linker_plugin_id": (
                            None
                            if linker_identity is None
                            else linker_identity.plugin_id
                        ),
                        "linker_plugin_version": (
                            None
                            if linker_identity is None
                            else linker_identity.plugin_version
                        ),
                        "coordinator_action": (
                            "compared complete ordered typed arguments"
                            if linker_identity is None
                            else "validated one allowlisted linker decision"
                        ),
                    },
                    "plugin_provenance": plugin_provenance,
                    "candidates": (
                        candidate_endpoints
                        if state
                        in {
                            FederationMatchState.AMBIGUOUS,
                            FederationMatchState.CONFLICT,
                        }
                        else []
                    ),
                    "resolution_audit": audits,
                    "deep_links": {
                        "topology": {
                            "href": self._topology_href(
                                basis,
                                selected_node_ids,
                                link_id,
                                context_id,
                            ),
                            "link_id": link_id,
                        },
                        "endpoint_a": endpoint_a.get("deep_link"),
                        "endpoint_b": endpoint_b.get("deep_link"),
                    },
                }
            )
        authoritative_links = [
            link
            for link in ordered_links
            if link.get("resolution") == FederationMatchState.MATCHED.value
            and link.get("federation_complete") is True
            and link.get("federation_truncated") is False
        ]
        return (
            authoritative_links[:limit],
            resolutions,
            unmatched,
            assembly.truncated or len(authoritative_links) > limit,
        )

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
        claims_by_identity: dict[tuple[str, str], dict[str, Any]] = {}
        unresolved_matchers: list[dict[str, Any]] = []

        exact_claims: list[ExactMatchClaim] = []
        for claim_index, claim in enumerate(claims):
            (
                plugin_semantics,
                plugin_semantics_key,
                plugin_semantics_descriptor,
            ) = _validated_plugin_semantics(
                claim.get("plugin_semantics")
            )
            matcher_id = str(claim["matcher_id"])
            (
                normalized_segment_key,
                canonical_segment_key,
            ) = _canonical_opaque_key(claim["segment_key"])
            matcher_contract = matcher_contracts.get(matcher_id)
            if (
                matcher_contract is None
                or matcher_contract.get("match_semantics") != "exact_token"
                or matcher_contract.get("result_shape")
                != "connectivity_domain"
            ):
                unresolved_matchers.append(
                    {
                        "matcher_id": matcher_id,
                        "segment_key": normalized_segment_key,
                        "typed_key": canonical_segment_key,
                        "resolution": "unsupported_matcher_contract",
                        "reason_code": (
                            "matcher_not_declared_as_exact_connectivity_domain"
                        ),
                        "member_id": claim.get("member_id"),
                        "node_id": claim.get("node_id"),
                        "resource_id": claim.get("resource_id"),
                    }
                )
                continue
            normalized_claim = dict(claim)
            normalized_claim["_normalized_segment_key"] = (
                normalized_segment_key
            )
            normalized_claim["plugin_semantics"] = plugin_semantics
            normalized_claim["_plugin_semantics_key"] = (
                plugin_semantics_key
            )
            normalized_claim["_plugin_semantics_descriptor"] = (
                plugin_semantics_descriptor
            )
            partition_id = str(claim["node_id"])
            claim_id = f"segment-claim-{claim_index}"
            claims_by_identity[(partition_id, claim_id)] = normalized_claim
            exact_claims.append(
                ExactMatchClaim(
                    claim_id=claim_id,
                    partition_id=partition_id,
                    matcher_id=MatcherId(matcher_id),
                    match_key=claim["segment_key"],
                )
            )

        try:
            match_result = exact_match_claims(
                exact_claims,
                max_candidates=0,
            )
        except CorroborationError as error:
            raise MultiNodeTopologyRequestError(
                f"invalid network-segment exact-match claims: {error}"
            ) from error

        selected_groups = match_result.groups[:segment_limit]
        segments_truncated = len(match_result.groups) > len(selected_groups)
        attachments: list[dict[str, Any]] = []
        segments: list[dict[str, Any]] = []
        resolutions: list[dict[str, Any]] = unresolved_matchers

        for group in selected_groups:
            matcher_id = group.matcher_id.value
            canonical_segment_key = group.typed_key
            values = [
                claims_by_identity[(claim.partition_id, claim.claim_id)]
                for claim in group.claims
            ]
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
                        self.assembly_id,
                        matcher_id,
                        matcher_contract_version,
                        canonical_segment_key,
                    ],
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()[:24]
            segment_id = f"network-segment:{segment_digest}"

            semantic_variants_by_key: dict[
                tuple[Any, ...],
                dict[str, Any],
            ] = {}
            for item in values:
                semantics = item["plugin_semantics"]
                semantic_variants_by_key.setdefault(
                    item["_plugin_semantics_key"],
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
                field_variants: dict[tuple[Any, ...], Any] = {}
                for semantics in semantic_variants:
                    value = semantics.get(field_name)
                    field_variants.setdefault(
                        _semantic_comparison_key(
                            value,
                            label=(
                                "merge-critical plugin_semantics."
                                f"{field_name}"
                            ),
                        ),
                        value,
                    )
                if len(field_variants) > 1:
                    semantic_conflicts[field_name] = list(field_variants.values())
            semantic_conflict = bool(semantic_conflicts)
            plugin_semantics = semantic_variants[0] if semantic_variants else {}
            topology_presentation = _validated_topology_presentation(
                plugin_semantics.get("topology_presentation")
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
                            self.assembly_id,
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
                    (
                        classification := item[
                            "_plugin_semantics_descriptor"
                        ].external_classification
                    )
                    is not None
                    and classification.role
                    is TopologyDomainRole.EXTERNAL
                    and classification.coverage_complete
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

        claims_by_identity: dict[tuple[str, str], dict[str, Any]] = {}
        # Duplicate snapshots of the same qualified endpoint never represented
        # a second candidate in the legacy topology join. Preserve that public
        # behavior while delegating grouping and cross-partition cardinality to
        # the reusable core exact matcher.
        seen_claims: set[tuple[str, str, tuple[Any, ...]]] = set()

        def exact_claim_stream() -> Iterator[ExactMatchClaim]:
            for claim in claims:
                presentation, route_trace_role = (
                    _validated_inter_node_presentation(
                        claim.get("presentation")
                    )
                )
                normalized_claim = dict(claim)
                normalized_claim["presentation"] = presentation
                normalized_claim["_route_trace_role"] = route_trace_role
                matcher_id = str(claim["matcher_id"])
                typed_key = _canonical_opaque_key(claim["match_key"])[1]
                identity = claim_identity(claim)
                deduplication_key = (matcher_id, typed_key, identity)
                if deduplication_key in seen_claims:
                    continue
                seen_claims.add(deduplication_key)
                partition_id = str(claim["node_id"])
                claim_digest = hashlib.sha256(
                    json.dumps(
                        [matcher_id, typed_key, identity],
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()
                claim_id = f"claim-{claim_digest}"
                claim_key = (partition_id, claim_id)
                if claim_key in claims_by_identity:
                    raise MultiNodeTopologyRequestError(
                        "inter-node exact-match claim identity collision"
                    )
                claims_by_identity[claim_key] = normalized_claim
                yield ExactMatchClaim(
                    claim_id=claim_id,
                    partition_id=partition_id,
                    matcher_id=MatcherId(matcher_id),
                    match_key=claim["match_key"],
                )

        try:
            match_result = exact_match_claims(
                exact_claim_stream(),
                max_candidates=limit,
            )
        except CorroborationError as error:
            raise MultiNodeTopologyRequestError(
                f"invalid inter-node exact-match claims: {error}"
            ) from error

        candidates_by_group: dict[
            tuple[MatcherId, str],
            list[tuple[dict[str, Any], dict[str, Any]]],
        ] = {}
        for candidate in match_result.candidates:
            left = claims_by_identity[
                (candidate.left.partition_id, candidate.left.claim_id)
            ]
            right = claims_by_identity[
                (candidate.right.partition_id, candidate.right.claim_id)
            ]
            ordered_pair = tuple(sorted((left, right), key=claim_identity))
            candidates_by_group.setdefault(
                (candidate.matcher_id, candidate.typed_key), []
            ).append((ordered_pair[0], ordered_pair[1]))

        candidates: list[dict[str, Any]] = []
        resolutions: list[dict[str, Any]] = []
        unmatched: list[dict[str, Any]] = []
        linker = self.contract["federation_plugin"]
        for group in match_result.groups:
            matcher_id = group.matcher_id.value
            values = [
                claims_by_identity[(claim.partition_id, claim.claim_id)]
                for claim in group.claims
            ]
            match_key = str(values[0]["match_key"])
            link_match_key = match_key
            if not isinstance(values[0]["match_key"], str):
                typed_key_digest = hashlib.sha256(
                    group.typed_key.encode("utf-8")
                ).hexdigest()[:16]
                link_match_key = f"{match_key}:typed-{typed_key_digest}"
            cross_node_pairs = candidates_by_group.get(
                (group.matcher_id, group.typed_key),
                [],
            )
            resolution_state = _FEDERATION_STATE_BY_EXACT_MATCH_STATE[group.state]
            resolution = resolution_state.value
            if resolution_state is FederationMatchState.UNRESOLVED:
                unresolved = [
                    {
                        "member_id": item["member_id"],
                        "node_id": item["node_id"],
                        "revision_id": item["revision_id"],
                        "resource_id": item["resource_id"],
                        "matcher_id": matcher_id,
                        "match_key": match_key,
                        "resolution": resolution,
                        "reason_code": "no_compatible_remote_claim",
                    }
                    for item in values
                ]
                unmatched.extend(unresolved)
                resolutions.append(
                    {
                        "matcher_id": matcher_id,
                        "match_key": match_key,
                        "resolution": resolution,
                        "candidate_count": 0,
                        "claims": unresolved,
                        "linker_plugin_provenance": linker,
                    }
                )
                continue
            resolutions.append(
                {
                    "matcher_id": matcher_id,
                    "match_key": match_key,
                    "resolution": resolution,
                    "candidate_count": group.candidate_count,
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
                operational: dict[str, Any]
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
                    f"{matcher_id}:{link_match_key}:"
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
                route_trace_roles: set[InterNodeRouteTraceRole] = {
                    item["_route_trace_role"] for item in (left, right)
                }
                route_trace_role = (
                    next(iter(route_trace_roles))
                    if len(route_trace_roles) == 1
                    else InterNodeRouteTraceRole.CONFLICT
                )
                if route_trace_role is InterNodeRouteTraceRole.CONFLICT:
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
                            if route_trace_role
                            is InterNodeRouteTraceRole.OVERLAY
                            else "route_trace_compatibility"
                            if route_trace_role
                            is InterNodeRouteTraceRole.INCLUDE
                            else "presentation_conflict"
                        ),
                        "presentation": {
                            "physical_topology": (
                                "suppress_when_network_segments_available"
                            ),
                            "route_trace": route_trace_role.value,
                        },
                        "resolution": resolution,
                        "link_type": (
                            next(iter(link_types))
                            if len(link_types) == 1
                            else "unknown"
                        ),
                        "claimed_link_types": sorted(link_types),
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
                            if resolution_state is FederationMatchState.AMBIGUOUS
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
            match_result.candidates_truncated,
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
            "topology_id": self.topology_id,
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
            "topology_id": self.topology_id,
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
            params["basis_offset_ns"] = str(requested_basis.get("offset_ns", "0"))

    def _topology_href(
        self,
        basis: dict[str, Any],
        node_ids: list[str],
        selected_link_id: Any = None,
        context_id: str | None = None,
    ) -> str:
        params: dict[str, Any] = {
            "topology_id": self.topology_id,
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
                        if key
                        not in {
                            "resources",
                            "local_links",
                            "connector_claims",
                            "network_segment_claims",
                            "usable_statuses",
                            "unusable_statuses",
                        }
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
