"""Immutable point-in-revision world reconstructed from typed observations.

The ingestion coordinator owns temporal selection.  This module only projects
the selected observation sequences into the :class:`ReadOnlyWorld` contract;
it never turns a capture vector into a synthetic common timestamp and it does
not apply a hidden read limit.  Capability executors remain responsible for
charging and bounding plug-in reads.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from types import MappingProxyType

from .observation_reconstruction import (
    RelationshipIdentity,
    apply_property_patch,
    relationship_observation_groups,
    relationship_order_key,
    snapshot_observation_groups,
)
from .observation_reconstruction import (
    bind_primary_perspective as _bind_primary_perspective,
)
from .observation_reconstruction import (
    canonical_relationship_endpoints as _canonical_relationship_endpoints,
)
from .observation_reconstruction import (
    canonical_resource_identity as _canonical_resource_identity,  # noqa: F401 - compatibility export
)
from .plugin_api import (
    PropertyPatch,
    Provenance,
    Quality,
    ReadOnlyWorld,
    RelationDirection,
    RelationshipObservation,
    RelationshipView,
    ResourceKey,
    ResourceStateView,
    SnapshotObservation,
    StatusPerspectiveRef,
    UnknownField,
    Value,
    WorldBasis,
)

type _RelationshipIdentityKey = RelationshipIdentity


def _relationship_identity_key(
    relationship: RelationshipView,
) -> tuple[ResourceKey, ResourceKey, str, StatusPerspectiveRef | None]:
    return (
        relationship.source,
        relationship.target,
        relationship.relation_type,
        relationship.perspective_ref,
    )


def _freeze_value(value: Value) -> Value:
    """Detach and deeply freeze one already-validated plug-in property value."""

    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(name): _freeze_value(item) for name, item in value.items()}
        )
    if type(value) is tuple:
        return tuple(_freeze_value(item) for item in value)
    if type(value) is bytes:
        return bytes(value)
    return value


def _freeze_properties(values: Mapping[str, Value]) -> Mapping[str, Value]:
    return MappingProxyType(
        {str(name): _freeze_value(value) for name, value in values.items()}
    )


def _apply_patch(
    properties: dict[str, Value],
    unknown_fields: dict[str, UnknownField],
    field_quality: dict[str, Quality],
    patch: PropertyPatch,
    *,
    default_quality: Quality,
) -> None:
    apply_property_patch(
        properties, unknown_fields, field_quality, None, patch,
        default_quality=default_quality,
        default_provenance=Provenance.OBSERVED,
        project_value=_freeze_value,
        project_unknown=lambda item: item,
        project_quality=lambda item: item,
        project_provenance=lambda item: item,
    )


def _unknown_perspective_state(
    resource: ResourceKey,
    perspective: StatusPerspectiveRef | None,
) -> ResourceStateView:
    """No selected/unique view is an unknown answer, never confirmed absence."""
    return ResourceStateView(
        resource=resource,
        exists=None,
        properties=MappingProxyType({}),
        provenance=Provenance.CORRELATED,
        quality=Quality.AMBIGUOUS if perspective is None else Quality.UNKNOWN,
        valid_from_ns=None,
        valid_to_ns=None,
        field_quality=MappingProxyType({}),
        perspective_ref=perspective,
    )


def _checked_limit(limit: int | None) -> int | None:
    if limit is None:
        return None
    if type(limit) is not int or limit < 0:
        raise ValueError("world read limit must be a non-negative integer")
    return limit


def _take[Item](items: tuple[Item, ...], limit: int | None) -> tuple[Item, ...]:
    checked = _checked_limit(limit)
    return items if checked is None else items[:checked]


def _filter_take[Item](
    items: Iterable[Item],
    predicate: Callable[[Item], bool],
    limit: int | None,
) -> tuple[Item, ...]:
    """Filter an immutable index and stop as soon as the caller limit is met."""

    checked = _checked_limit(limit)
    if checked == 0:
        return ()
    result: list[Item] = []
    for item in items:
        if not predicate(item):
            continue
        result.append(item)
        if checked is not None and len(result) >= checked:
            break
    return tuple(result)


def _merge_relationship_indexes(
    first: tuple[RelationshipView, ...],
    second: tuple[RelationshipView, ...],
    ranks: Mapping[
        tuple[ResourceKey, ResourceKey, str, StatusPerspectiveRef | None], int
    ],
) -> Iterable[RelationshipView]:
    """Merge two global-order subsequences and retain self-loops once."""

    first_index = 0
    second_index = 0
    while first_index < len(first) or second_index < len(second):
        if first_index >= len(first):
            candidate = second[second_index]
            second_index += 1
        elif second_index >= len(second):
            candidate = first[first_index]
            first_index += 1
        else:
            first_item = first[first_index]
            second_item = second[second_index]
            first_key = _relationship_identity_key(first_item)
            second_key = _relationship_identity_key(second_item)
            first_rank = ranks[first_key]
            second_rank = ranks[second_key]
            if first_rank <= second_rank:
                candidate = first_item
                first_index += 1
                if first_rank == second_rank:
                    second_index += 1
            else:
                candidate = second_item
                second_index += 1
        yield candidate


class IngestionRevisionWorld(ReadOnlyWorld):
    """Immutable indexed world for one normalized ingestion revision.

    ``basis`` is supplied by the ingestion coordinator and is retained without
    modification.  In particular, non-overlapping capture ranges remain a
    capture vector; this class never derives a common ``requested_time_ns`` or
    resolved interval from observation timestamps.

    A snapshot observation asserts that its resource exists.  Resources seen
    only as relationship endpoints are indexable through those relationships
    but do not receive a fabricated state.  A relationship is active only when
    its latest ordered observation says ``present is True``.

    Histories from distinct perspectives never patch one another. An explicit
    perspective selects only that view. Without one, scans retain independent
    states and ambiguous point lookups return ``exists=None``; a missing
    selected perspective likewise returns unknown rather than borrowing state.
    """

    __slots__ = (
        "_basis",
        "_incoming",
        "_outgoing",
        "_perspective_ref",
        "_relationship_ranks",
        "_relationships",
        "_relationships_by_type",
        "_states",
        "_states_by_kind",
        "_states_by_layer",
        "_states_by_resource",
    )

    def __init__(
        self,
        *,
        basis: WorldBasis,
        snapshots: Sequence[SnapshotObservation],
        relationship_observations: Sequence[RelationshipObservation],
        projected_relationships: Sequence[RelationshipView] = (),
        undirected_relationship_types: frozenset[str] = frozenset(),
        perspective_ref: StatusPerspectiveRef | None = None,
        primary_plugin_instance_id: str | None = None,
        primary_schema_digest: str | None = None,
    ) -> None:
        if type(basis) is not WorldBasis:
            raise TypeError("basis must be an exact WorldBasis")
        if (
            perspective_ref is not None
            and type(perspective_ref) is not StatusPerspectiveRef
        ):
            raise TypeError(
                "perspective_ref must be an exact StatusPerspectiveRef or None"
            )
        if type(undirected_relationship_types) is not frozenset or any(
            type(item) is not str or not item or len(item) > 256
            for item in undirected_relationship_types
        ):
            raise TypeError(
                "undirected_relationship_types must be an exact frozenset of "
                "bounded strings"
            )
        if (primary_plugin_instance_id is None) != (primary_schema_digest is None):
            raise TypeError(
                "primary perspective authority requires both instance and schema"
            )
        if primary_plugin_instance_id is not None and (
            type(primary_plugin_instance_id) is not str
            or not primary_plugin_instance_id
            or type(primary_schema_digest) is not str
            or not primary_schema_digest
        ):
            raise TypeError("primary perspective authority is invalid")

        detached_snapshots = tuple(snapshots)
        detached_relationships = tuple(relationship_observations)
        detached_projected_relationships = tuple(projected_relationships)
        if any(type(item) is not SnapshotObservation for item in detached_snapshots):
            raise TypeError("snapshots must contain exact SnapshotObservation values")
        if any(
            type(item) is not RelationshipObservation for item in detached_relationships
        ):
            raise TypeError(
                "relationship_observations must contain exact "
                "RelationshipObservation values"
            )
        if any(
            type(item) is not RelationshipView
            for item in detached_projected_relationships
        ):
            raise TypeError(
                "projected_relationships must contain exact RelationshipView values"
            )

        states = self._build_states(
            detached_snapshots,
            primary_plugin_instance_id=primary_plugin_instance_id,
            primary_schema_digest=primary_schema_digest,
        )
        observed_relationships, observed_relationship_keys = self._build_relationships(
            detached_relationships,
            undirected_relationship_types,
            primary_plugin_instance_id=primary_plugin_instance_id,
            primary_schema_digest=primary_schema_digest,
        )
        relationships = self._merge_projected_relationships(
            observed_relationships,
            detached_projected_relationships,
            undirected_relationship_types,
            observed_authority_keys=observed_relationship_keys,
            primary_plugin_instance_id=primary_plugin_instance_id,
            primary_schema_digest=primary_schema_digest,
        )

        selected_perspective = _bind_primary_perspective(
            perspective_ref,
            plugin_instance_id=primary_plugin_instance_id,
            schema_digest=primary_schema_digest,
        )
        states_per_resource: dict[ResourceKey, list[ResourceStateView]] = defaultdict(list)
        for state in states:
            states_per_resource[state.resource].append(state)
        states_by_resource: dict[ResourceKey, ResourceStateView] = {}
        for resource, candidates in states_per_resource.items():
            selected_states = (
                candidates
                if selected_perspective is None
                else [
                    item for item in candidates
                    if item.perspective_ref == selected_perspective
                ]
            )
            states_by_resource[resource] = (
                selected_states[0]
                if len(selected_states) == 1
                else _unknown_perspective_state(resource, selected_perspective)
            )
        if selected_perspective is not None:
            states = tuple(states_by_resource.values())
            relationships = tuple(
                item for item in relationships
                if item.perspective_ref == selected_perspective
            )
        states_by_layer: dict[str, list[ResourceStateView]] = defaultdict(list)
        states_by_kind: dict[str, list[ResourceStateView]] = defaultdict(list)
        for state in states:
            states_by_layer[state.resource.layer].append(state)
            states_by_kind[state.resource.kind].append(state)

        outgoing: dict[ResourceKey, list[RelationshipView]] = defaultdict(list)
        incoming: dict[ResourceKey, list[RelationshipView]] = defaultdict(list)
        relationships_by_type: dict[str, list[RelationshipView]] = defaultdict(list)
        for relationship in relationships:
            outgoing[relationship.source].append(relationship)
            incoming[relationship.target].append(relationship)
            relationships_by_type[relationship.relation_type].append(relationship)

        self._basis = basis
        self._perspective_ref = selected_perspective
        self._states = states
        self._relationships = relationships
        self._states_by_resource = MappingProxyType(states_by_resource)
        self._states_by_layer = MappingProxyType(
            {name: tuple(items) for name, items in states_by_layer.items()}
        )
        self._states_by_kind = MappingProxyType(
            {name: tuple(items) for name, items in states_by_kind.items()}
        )
        self._outgoing = MappingProxyType(
            {resource: tuple(items) for resource, items in outgoing.items()}
        )
        self._incoming = MappingProxyType(
            {resource: tuple(items) for resource, items in incoming.items()}
        )
        self._relationships_by_type = MappingProxyType(
            {name: tuple(items) for name, items in relationships_by_type.items()}
        )
        self._relationship_ranks = MappingProxyType(
            {
                _relationship_identity_key(item): ordinal
                for ordinal, item in enumerate(relationships)
            }
        )

    @staticmethod
    def _merge_projected_relationships(
        observed: tuple[RelationshipView, ...],
        projected: tuple[RelationshipView, ...],
        undirected_relationship_types: frozenset[str],
        *,
        observed_authority_keys: frozenset[_RelationshipIdentityKey],
        primary_plugin_instance_id: str | None,
        primary_schema_digest: str | None,
    ) -> tuple[RelationshipView, ...]:
        """Overlay revision-scoped declarations without inventing time.

        A materializer supplies at most one conservative projected view for
        each endpoint/type key. Explicit parser observations remain the
        authoritative world view when the same edge was also observed. Raw
        projector claims and their ambiguity metadata remain in the dedicated
        materialization records rather than being flattened here.
        """

        by_key = {_relationship_identity_key(item): item for item in observed}
        projected_keys: set[_RelationshipIdentityKey] = set()
        for item in projected:
            if item.valid_from_ns is not None or item.valid_to_ns is not None:
                raise ValueError(
                    "revision-scoped projected relationships must not carry "
                    "temporal validity bounds"
                )
            source, target = _canonical_relationship_endpoints(
                item.source,
                item.target,
                item.relation_type,
                undirected_relationship_types,
            )
            perspective = _bind_primary_perspective(
                item.perspective_ref,
                plugin_instance_id=primary_plugin_instance_id,
                schema_digest=primary_schema_digest,
            )
            key = (source, target, item.relation_type, perspective)
            if key in projected_keys:
                raise ValueError(
                    "projected relationships contain a duplicate endpoint/type key"
                )
            projected_keys.add(key)
            # The latest parser observation remains authoritative even when it
            # is an explicit tombstone or an unknown-presence record. Those
            # records are intentionally absent from ``observed`` but must still
            # suppress a projector from resurrecting the same edge.
            if key in observed_authority_keys:
                continue
            by_key[key] = RelationshipView(
                source=source,
                target=target,
                relation_type=item.relation_type,
                attributes=_freeze_properties(item.attributes),
                provenance=item.provenance,
                quality=item.quality,
                valid_from_ns=None,
                valid_to_ns=None,
                evidence=tuple(item.evidence),
                perspective_ref=perspective,
            )
        return tuple(
            by_key[key]
            for key in sorted(by_key, key=relationship_order_key)
        )

    @staticmethod
    def _build_states(
        snapshots: tuple[SnapshotObservation, ...],
        *,
        primary_plugin_instance_id: str | None,
        primary_schema_digest: str | None,
    ) -> tuple[ResourceStateView, ...]:
        grouped = snapshot_observation_groups(
            snapshots,
            plugin_instance_id=primary_plugin_instance_id,
            schema_digest=primary_schema_digest,
        )

        result: list[ResourceStateView] = []
        for (resource, perspective), ordered in grouped.items():
            properties: dict[str, Value] = {}
            unknown_fields: dict[str, UnknownField] = {}
            field_quality: dict[str, Quality] = {}
            for observation in ordered:
                _apply_patch(
                    properties,
                    unknown_fields,
                    field_quality,
                    observation.state,
                    default_quality=observation.quality,
                )
            latest = ordered[-1]
            result.append(
                ResourceStateView(
                    resource=resource,
                    exists=True,
                    properties=_freeze_properties(properties),
                    provenance=latest.provenance,
                    quality=latest.quality,
                    valid_from_ns=latest.observed_at_min_ns,
                    valid_to_ns=None,
                    observed_at_min_ns=latest.observed_at_min_ns,
                    observed_at_max_ns=latest.observed_at_max_ns,
                    field_quality=MappingProxyType(dict(field_quality)),
                    unknown_fields=tuple(unknown_fields.values()),
                    evidence=(latest.evidence,),
                    perspective_ref=perspective,
                )
            )
        return tuple(result)

    @staticmethod
    def _build_relationships(
        observations: tuple[RelationshipObservation, ...],
        undirected_relationship_types: frozenset[str],
        *,
        primary_plugin_instance_id: str | None,
        primary_schema_digest: str | None,
    ) -> tuple[tuple[RelationshipView, ...], frozenset[_RelationshipIdentityKey]]:
        grouped = relationship_observation_groups(
            observations,
            undirected_relationship_types,
            plugin_instance_id=primary_plugin_instance_id,
            schema_digest=primary_schema_digest,
        )
        result: list[RelationshipView] = []
        for group_key, ordered in grouped.items():
            attributes: dict[str, Value] = {}
            unknown_fields: dict[str, UnknownField] = {}
            field_quality: dict[str, Quality] = {}
            for observation in ordered:
                _apply_patch(
                    attributes,
                    unknown_fields,
                    field_quality,
                    observation.attributes,
                    default_quality=observation.quality,
                )
            latest = ordered[-1]
            if latest.present is not True:
                continue
            source, target, relation_type, perspective = group_key
            result.append(
                RelationshipView(
                    source=source,
                    target=target,
                    relation_type=relation_type,
                    attributes=_freeze_properties(attributes),
                    provenance=latest.provenance,
                    quality=latest.quality,
                    valid_from_ns=latest.observed_at_min_ns,
                    valid_to_ns=None,
                    evidence=(latest.evidence,),
                    perspective_ref=perspective,
                )
            )
        return tuple(result), frozenset(grouped)

    @property
    def basis(self) -> WorldBasis:
        return self._basis

    @property
    def perspective_ref(self) -> StatusPerspectiveRef | None:
        return self._perspective_ref

    def state_of(self, resource: ResourceKey) -> ResourceStateView | None:
        return self._states_by_resource.get(resource)

    def iter_states(
        self,
        layers: frozenset[str] | None = None,
        kinds: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[ResourceStateView]:
        if layers is None and kinds is None:
            return _take(self._states, limit)
        if layers is not None and kinds is None and len(layers) == 1:
            candidates = self._states_by_layer.get(next(iter(layers)), ())
        elif kinds is not None and layers is None and len(kinds) == 1:
            candidates = self._states_by_kind.get(next(iter(kinds)), ())
        else:
            candidates = self._states
        return _filter_take(
            candidates,
            lambda state: (
                (layers is None or state.resource.layer in layers)
                and (kinds is None or state.resource.kind in kinds)
            ),
            limit,
        )

    def related(
        self,
        resource: ResourceKey,
        direction: RelationDirection = RelationDirection.OUTGOING,
        relation_types: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        candidates: Iterable[RelationshipView]
        try:
            resolved_direction = RelationDirection(direction)
        except (TypeError, ValueError) as error:
            raise ValueError("unsupported relationship direction") from error
        if resolved_direction is RelationDirection.OUTGOING:
            candidates = self._outgoing.get(resource, ())
        elif resolved_direction is RelationDirection.INCOMING:
            candidates = self._incoming.get(resource, ())
        else:
            candidates = _merge_relationship_indexes(
                self._outgoing.get(resource, ()),
                self._incoming.get(resource, ()),
                self._relationship_ranks,
            )
        return _filter_take(
            candidates,
            lambda item: relation_types is None or item.relation_type in relation_types,
            limit,
        )

    def iter_relationships(
        self,
        relation_types: frozenset[str] | None = None,
        layers: frozenset[str] | None = None,
        limit: int | None = None,
    ) -> Iterable[RelationshipView]:
        if relation_types is not None and len(relation_types) == 1:
            candidates = self._relationships_by_type.get(
                next(iter(relation_types)),
                (),
            )
        else:
            candidates = self._relationships
        return _filter_take(
            candidates,
            lambda item: (
                (relation_types is None or item.relation_type in relation_types)
                and (
                    layers is None
                    or item.source.layer in layers
                    or item.target.layer in layers
                )
            ),
            limit,
        )


__all__ = ["IngestionRevisionWorld"]
