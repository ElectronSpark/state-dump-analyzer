"""Domain-neutral cross-partition matching and event corroboration.

The helpers in this module intentionally know nothing about devices, addresses,
UUID semantics, protocols, or resource types.  Plug-ins declare matcher
identities and opaque keys; the core only canonicalizes exact values, groups
claims, and reports bounded candidate pairs.

Corroboration is similarly conservative.  It emits independent facts from
explicit source-record linkage, canonical resource identity, uncertain time
intervals, and plug-in-declared causal links.  It never invents causality from
names or payload content.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from itertools import combinations, product
from math import isfinite
from typing import Any
from uuid import UUID

from .canonical import (
    MAX_OPAQUE_ATOM_PAYLOAD_UNITS,
    MAX_OPAQUE_CONTAINER_ITEMS,
    MAX_OPAQUE_INTEGER_BITS,
    MAX_OPAQUE_VALUE_DEPTH,
    MAX_OPAQUE_VALUE_UNITS,
    CanonicalValueError,
    canonical_opaque_value,
)
from .contract_validation import validate_bounded_json_value
from .plugin_api import MAX_TIMESTAMP_NS, MIN_TIMESTAMP_NS, KeyAtom

_MAX_IDENTIFIER_LENGTH = 1_024
_DEFAULT_MAX_CANDIDATES = 1_000
_DEFAULT_MAX_CLAIMS = 100_000
_MAX_CANDIDATE_OUTPUT = 100_000
_MAX_CLAIM_INPUT = 100_000
_MAX_EVENT_SOURCE_RECORDS = 4_096
_MAX_EVENT_RESOURCE_IDS = 4_096
_MAX_EVENT_CAUSAL_LINKS = 4_096
_MAX_GENERIC_CONTAINER_ITEMS = 256
_MAX_GENERIC_VALUE_UNITS = 4_096
_MAX_GENERIC_ATOM_UNITS = 16_384
_MAX_GENERIC_DEPTH = 8
_MAX_FACT_GENERIC_CONTAINER_ITEMS = 4_096
_MAX_FACT_GENERIC_VALUE_UNITS = 16_384


class CorroborationError(ValueError):
    """An exact-match or corroboration request is invalid."""


def _validated_identifier(value: str, *, label: str) -> str:
    if type(value) is not str or not value or len(value) > _MAX_IDENTIFIER_LENGTH:
        raise CorroborationError(
            f"{label} must be a non-empty string of at most "
            f"{_MAX_IDENTIFIER_LENGTH} characters"
        )
    return value


def _validate_generic_value(
    value: Any,
    *,
    label: str,
    maximum_container_items: int = _MAX_GENERIC_CONTAINER_ITEMS,
    maximum_units: int = _MAX_GENERIC_VALUE_UNITS,
) -> Any:
    """Return retained generic data as one bounded exact snapshot."""

    try:
        return validate_bounded_json_value(
            value,
            label,
            maximum_depth=_MAX_GENERIC_DEPTH,
            maximum_container_items=maximum_container_items,
            maximum_units=maximum_units,
            maximum_atom_units=_MAX_GENERIC_ATOM_UNITS,
            exact_types=True,
            allow_exact_tuples=True,
            snapshot=True,
        )
    except ValueError as error:
        raise CorroborationError(str(error)) from error


def _validate_generic_tuple(
    value: Any,
    *,
    label: str,
    maximum_container_items: int = _MAX_GENERIC_CONTAINER_ITEMS,
    maximum_units: int = _MAX_GENERIC_VALUE_UNITS,
) -> tuple[Any, ...]:
    if type(value) is not tuple:
        raise CorroborationError(f"{label} must be a tuple")
    snapshot = _validate_generic_value(
        value,
        label=label,
        maximum_container_items=maximum_container_items,
        maximum_units=maximum_units,
    )
    assert type(snapshot) is tuple
    return snapshot


def _clone_opaque_key(
    value: Any,
    *,
    _container_depth: int = 0,
    _active_container_ids: set[int] | None = None,
    _units: list[int] | None = None,
) -> Any:
    """Detach one opaque key with the canonical key bounds and exact types."""

    active_container_ids = (
        set() if _active_container_ids is None else _active_container_ids
    )
    units = [0] if _units is None else _units
    units[0] += 1
    if units[0] > MAX_OPAQUE_VALUE_UNITS:
        raise CorroborationError(
            f"opaque matcher keys support at most {MAX_OPAQUE_VALUE_UNITS} value units"
        )

    value_type = type(value)
    if value is None or value_type is bool:
        return value
    if value_type is KeyAtom:
        if type(value.type_tag) is not str:
            raise CorroborationError("opaque matcher key contains an invalid key atom")
        atom_id = id(value)
        if atom_id in active_container_ids:
            raise CorroborationError("opaque matcher keys must not contain reference cycles")
        active_container_ids.add(atom_id)
        try:
            return KeyAtom(
                value.type_tag,
                _clone_opaque_key(
                    value.value,
                    _container_depth=_container_depth,
                    _active_container_ids=active_container_ids,
                    _units=units,
                ),
            )
        finally:
            active_container_ids.remove(atom_id)
    if value_type is int:
        if value.bit_length() > MAX_OPAQUE_INTEGER_BITS:
            raise CorroborationError(
                f"opaque matcher key integers exceed {MAX_OPAQUE_INTEGER_BITS} bits"
            )
        return value
    if value_type is float:
        if not isfinite(value):
            raise CorroborationError(
                "opaque matcher keys require finite floating-point values"
            )
        return value
    if value_type is UUID:
        return value
    if value_type is str:
        if len(value) > MAX_OPAQUE_ATOM_PAYLOAD_UNITS:
            raise CorroborationError(
                "opaque matcher key strings exceed their character limit"
            )
        return value
    if value_type is bytes:
        if len(value) > MAX_OPAQUE_ATOM_PAYLOAD_UNITS:
            raise CorroborationError("opaque matcher key bytes exceed their limit")
        return value
    if value_type is bytearray:
        if len(value) > MAX_OPAQUE_ATOM_PAYLOAD_UNITS:
            raise CorroborationError("opaque matcher key bytes exceed their limit")
        return bytes(value)
    if value_type is memoryview:
        if value.nbytes > MAX_OPAQUE_ATOM_PAYLOAD_UNITS:
            raise CorroborationError("opaque matcher key bytes exceed their limit")
        return bytes(value)
    if value_type not in {dict, list, tuple}:
        raise CorroborationError("opaque matcher key contains an unsupported type")

    child_depth = _container_depth + 1
    if child_depth > MAX_OPAQUE_VALUE_DEPTH:
        raise CorroborationError(
            f"opaque matcher keys support at most {MAX_OPAQUE_VALUE_DEPTH} container levels"
        )
    if len(value) > MAX_OPAQUE_CONTAINER_ITEMS:
        raise CorroborationError(
            "opaque matcher key containers exceed their item limit"
        )
    container_id = id(value)
    if container_id in active_container_ids:
        raise CorroborationError("opaque matcher keys must not contain reference cycles")
    active_container_ids.add(container_id)
    try:
        if value_type is list:
            detached_list: list[Any] = []
            for index, item in enumerate(value):
                if index >= MAX_OPAQUE_CONTAINER_ITEMS:
                    raise CorroborationError(
                        "opaque matcher key containers exceed their item limit"
                    )
                detached_list.append(_clone_opaque_key(
                    item,
                    _container_depth=child_depth,
                    _active_container_ids=active_container_ids,
                    _units=units,
                ))
            return detached_list
        if value_type is tuple:
            detached_tuple: list[Any] = []
            for index, item in enumerate(value):
                if index >= MAX_OPAQUE_CONTAINER_ITEMS:
                    raise CorroborationError(
                        "opaque matcher key containers exceed their item limit"
                    )
                detached_tuple.append(_clone_opaque_key(
                    item,
                    _container_depth=child_depth,
                    _active_container_ids=active_container_ids,
                    _units=units,
                ))
            return tuple(detached_tuple)
        detached_mapping: dict[Any, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_OPAQUE_CONTAINER_ITEMS:
                raise CorroborationError(
                    "opaque matcher key containers exceed their item limit"
                )
            detached_key = _clone_opaque_key(
                key,
                _container_depth=child_depth,
                _active_container_ids=active_container_ids,
                _units=units,
            )
            detached_mapping[detached_key] = _clone_opaque_key(
                item,
                _container_depth=child_depth,
                _active_container_ids=active_container_ids,
                _units=units,
            )
        return detached_mapping
    finally:
        active_container_ids.remove(container_id)


def _validated_exact_tuple(
    value: Any,
    *,
    label: str,
    maximum: int,
    item_type: type[Any] | None = None,
) -> tuple[Any, ...]:
    if type(value) is not tuple:
        raise CorroborationError(f"{label} must be a tuple")
    if len(value) > maximum:
        raise CorroborationError(f"{label} supports at most {maximum} values")
    if item_type is not None and any(type(item) is not item_type for item in value):
        raise CorroborationError(f"{label} must contain {item_type.__name__} values")
    return value


def _bounded_fact_values(
    groups: Iterable[Iterable[Any]],
    *,
    label: str,
) -> tuple[Any, ...]:
    """Combine generic fact values without first building an unbounded tuple."""

    result: list[Any] = []
    for group in groups:
        for item in group:
            if len(result) >= _MAX_FACT_GENERIC_CONTAINER_ITEMS:
                raise CorroborationError(
                    f"{label} supports at most "
                    f"{_MAX_FACT_GENERIC_CONTAINER_ITEMS} values"
                )
            result.append(item)
    combined = tuple(result)
    cloned = _validate_generic_tuple(
        combined,
        label=label,
        maximum_container_items=_MAX_FACT_GENERIC_CONTAINER_ITEMS,
        maximum_units=_MAX_FACT_GENERIC_VALUE_UNITS,
    )
    return cloned


@dataclass(frozen=True, slots=True, order=True)
class MatcherId:
    """One opaque, typed matcher identity owned by a producer."""

    value: str

    def __post_init__(self) -> None:
        _validated_identifier(self.value, label="matcher id")


class ExactMatchState(StrEnum):
    """Cardinality of cross-partition candidates for one exact-match group."""

    MATCHED = "matched"
    AMBIGUOUS = "ambiguous"
    UNMATCHED = "unmatched"


@dataclass(frozen=True, slots=True)
class ExactMatchClaim:
    """One partition-owned claim offered to an opaque exact matcher.

    ``evidence``, ``provenance``, and ``payload`` are preserved as supplied
    after the core verifies that they are bounded JSON values.  Their domain
    meaning is not inspected while matching.
    """

    claim_id: str
    partition_id: str
    matcher_id: MatcherId
    match_key: Any
    evidence: tuple[Any, ...] = ()
    provenance: tuple[Any, ...] = ()
    payload: Any = None

    def __post_init__(self) -> None:
        _validated_identifier(self.claim_id, label="claim id")
        _validated_identifier(self.partition_id, label="partition id")
        if type(self.matcher_id) is not MatcherId:
            raise CorroborationError("matcher_id must be a MatcherId")
        evidence = _validate_generic_tuple(self.evidence, label="claim evidence")
        provenance = _validate_generic_tuple(
            self.provenance,
            label="claim provenance",
        )
        payload = _validate_generic_value(self.payload, label="claim payload")
        try:
            match_key = _clone_opaque_key(self.match_key)
            canonical_opaque_value(match_key, key_atom_type=KeyAtom)
        except (
            CanonicalValueError,
            CorroborationError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as error:
            raise CorroborationError("claim has an invalid exact-match key") from error
        object.__setattr__(self, "match_key", match_key)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(self, "payload", payload)


@dataclass(frozen=True, slots=True)
class ExactMatchCandidate:
    """One deterministic cross-partition candidate pair."""

    matcher_id: MatcherId
    normalized_key: dict[str, Any]
    typed_key: str
    left: ExactMatchClaim
    right: ExactMatchClaim


@dataclass(frozen=True, slots=True)
class ExactMatchGroup:
    """All claims and candidate cardinality for one canonical exact key."""

    matcher_id: MatcherId
    normalized_key: dict[str, Any]
    typed_key: str
    state: ExactMatchState
    candidate_count: int
    claims: tuple[ExactMatchClaim, ...]


@dataclass(frozen=True, slots=True)
class ExactMatchResult:
    """Bounded exact-match output.

    ``candidate_count`` is exact even when ``candidates`` is truncated.  This
    lets callers distinguish a unique match from ambiguity without ever
    materializing an unbounded Cartesian product.
    """

    groups: tuple[ExactMatchGroup, ...]
    candidates: tuple[ExactMatchCandidate, ...]
    candidate_count: int
    candidates_truncated: bool


@dataclass(slots=True)
class _ClaimGroupBuilder:
    matcher_id: MatcherId
    normalized_key: dict[str, Any]
    typed_key: str
    claims: list[ExactMatchClaim]


def _candidate_count_by_partition(
    partition_counts: tuple[tuple[str, int], ...],
) -> int:
    """Count cross-partition pairs in O(number of partitions)."""

    seen = 0
    total = 0
    for _partition_id, claim_count in partition_counts:
        total += seen * claim_count
        seen += claim_count
    return total


def _iter_group_candidates(
    group: ExactMatchGroup,
) -> Iterator[ExactMatchCandidate]:
    partitions_by_id: dict[str, list[ExactMatchClaim]] = defaultdict(list)
    for claim in group.claims:
        partitions_by_id[claim.partition_id].append(claim)
    partitions = tuple(
        (partition_id, tuple(claims))
        for partition_id, claims in sorted(partitions_by_id.items())
    )
    for (_left_id, left_claims), (_right_id, right_claims) in combinations(
        partitions,
        2,
    ):
        for left, right in product(left_claims, right_claims):
            yield ExactMatchCandidate(
                matcher_id=group.matcher_id,
                normalized_key=group.normalized_key,
                typed_key=group.typed_key,
                left=left,
                right=right,
            )


def exact_match_claims(
    claims: Iterable[ExactMatchClaim],
    *,
    max_candidates: int = _DEFAULT_MAX_CANDIDATES,
    max_claims: int = _DEFAULT_MAX_CLAIMS,
) -> ExactMatchResult:
    """Group opaque claims and return bounded cross-partition candidate pairs.

    Runtime and storage before output are linear in the claim count (plus
    sorting).  Candidate pairs are generated lazily and stop once the global
    output limit is reached; group cardinalities are computed algebraically.
    """

    if (
        type(max_candidates) is not int
        or not 0 <= max_candidates <= _MAX_CANDIDATE_OUTPUT
    ):
        raise CorroborationError(
            "max_candidates must be a non-negative integer no greater than "
            f"{_MAX_CANDIDATE_OUTPUT}"
        )
    if type(max_claims) is not int or not 0 <= max_claims <= _MAX_CLAIM_INPUT:
        raise CorroborationError(
            "max_claims must be a non-negative integer no greater than "
            f"{_MAX_CLAIM_INPUT}"
        )

    builders: dict[tuple[MatcherId, str], _ClaimGroupBuilder] = {}
    claim_identities: set[tuple[str, str]] = set()
    for claim_count, claim in enumerate(claims):
        if claim_count >= max_claims:
            raise CorroborationError(f"claims support at most {max_claims} values")
        if type(claim) is not ExactMatchClaim:
            raise CorroborationError("claims must contain ExactMatchClaim values")
        # A frozen dataclass does not recursively freeze its nested values.
        # Snapshot again at the operation boundary so mutations performed
        # through a previously-created claim cannot alter returned results.
        claim = ExactMatchClaim(
            claim_id=claim.claim_id,
            partition_id=claim.partition_id,
            matcher_id=claim.matcher_id,
            match_key=claim.match_key,
            evidence=claim.evidence,
            provenance=claim.provenance,
            payload=claim.payload,
        )
        identity = (claim.partition_id, claim.claim_id)
        if identity in claim_identities:
            raise CorroborationError("duplicate claim identity")
        claim_identities.add(identity)
        try:
            normalized_key, typed_key = canonical_opaque_value(
                claim.match_key,
                key_atom_type=KeyAtom,
            )
        except CanonicalValueError as error:
            raise CorroborationError(
                "claim has an invalid exact-match key"
            ) from error
        group_identity = (claim.matcher_id, typed_key)
        builder = builders.get(group_identity)
        if builder is None:
            builder = _ClaimGroupBuilder(
                matcher_id=claim.matcher_id,
                normalized_key=normalized_key,
                typed_key=typed_key,
                claims=[],
            )
            builders[group_identity] = builder
        builder.claims.append(claim)

    groups: list[ExactMatchGroup] = []
    for builder in sorted(
        builders.values(),
        key=lambda value: (value.matcher_id.value, value.typed_key),
    ):
        ordered_claims = tuple(
            sorted(
                builder.claims,
                key=lambda claim: (claim.partition_id, claim.claim_id),
            )
        )
        partition_counts: dict[str, int] = defaultdict(int)
        for claim in ordered_claims:
            partition_counts[claim.partition_id] += 1
        counts = tuple(
            (partition_id, count)
            for partition_id, count in sorted(partition_counts.items())
        )
        candidate_count = _candidate_count_by_partition(counts)
        if candidate_count == 0:
            state = ExactMatchState.UNMATCHED
        elif candidate_count == 1:
            state = ExactMatchState.MATCHED
        else:
            state = ExactMatchState.AMBIGUOUS
        groups.append(
            ExactMatchGroup(
                matcher_id=builder.matcher_id,
                normalized_key=builder.normalized_key,
                typed_key=builder.typed_key,
                state=state,
                candidate_count=candidate_count,
                claims=ordered_claims,
            )
        )

    total_candidate_count = sum(group.candidate_count for group in groups)
    candidates: list[ExactMatchCandidate] = []
    if max_candidates:
        for group in groups:
            for candidate in _iter_group_candidates(group):
                candidates.append(candidate)
                if len(candidates) == max_candidates:
                    break
            if len(candidates) == max_candidates:
                break

    return ExactMatchResult(
        groups=tuple(groups),
        candidates=tuple(candidates),
        candidate_count=total_candidate_count,
        candidates_truncated=total_candidate_count > len(candidates),
    )


@dataclass(frozen=True, slots=True, order=True)
class EventIdentity:
    """A revision/partition-qualified event identity."""

    partition_id: str
    event_id: str

    def __post_init__(self) -> None:
        _validated_identifier(self.partition_id, label="event partition id")
        _validated_identifier(self.event_id, label="event id")


@dataclass(frozen=True, slots=True, order=True)
class SourceRecordIdentity:
    """A source-scope-qualified record identity."""

    source_id: str
    record_id: str

    def __post_init__(self) -> None:
        _validated_identifier(self.source_id, label="source id")
        _validated_identifier(self.record_id, label="source record id")


@dataclass(frozen=True, slots=True)
class ExplicitCausalLink:
    """A causal link asserted by a plug-in, without core interpretation."""

    link_id: str
    target: EventIdentity
    evidence: tuple[Any, ...] = ()
    provenance: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        _validated_identifier(self.link_id, label="causal link id")
        if type(self.target) is not EventIdentity:
            raise CorroborationError("causal-link target must be an EventIdentity")
        evidence = _validate_generic_tuple(
            self.evidence,
            label="causal-link evidence",
        )
        provenance = _validate_generic_tuple(
            self.provenance,
            label="causal-link provenance",
        )
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "provenance", provenance)


@dataclass(frozen=True, slots=True)
class ResolvedEventRef:
    """The minimal resolved event surface used for generic corroboration."""

    identity: EventIdentity
    source_records: tuple[SourceRecordIdentity, ...] = ()
    canonical_resource_ids: tuple[str, ...] = ()
    earliest_ns: int | None = None
    latest_ns: int | None = None
    causal_links: tuple[ExplicitCausalLink, ...] = ()
    evidence: tuple[Any, ...] = ()
    provenance: tuple[Any, ...] = ()
    clock_domain: str | None = None

    def __post_init__(self) -> None:
        if type(self.identity) is not EventIdentity:
            raise CorroborationError("event identity must be an EventIdentity")
        source_records = _validated_exact_tuple(
            self.source_records,
            label="source_records",
            maximum=_MAX_EVENT_SOURCE_RECORDS,
            item_type=SourceRecordIdentity,
        )
        if len(source_records) != len(set(source_records)):
            raise CorroborationError("source_records must not contain duplicates")
        resource_ids = _validated_exact_tuple(
            self.canonical_resource_ids,
            label="canonical_resource_ids",
            maximum=_MAX_EVENT_RESOURCE_IDS,
        )
        for resource_id in self.canonical_resource_ids:
            _validated_identifier(resource_id, label="canonical resource id")
        if len(resource_ids) != len(set(resource_ids)):
            raise CorroborationError(
                "canonical_resource_ids must not contain duplicates"
            )
        if (self.earliest_ns is None) != (self.latest_ns is None):
            raise CorroborationError(
                "event time uncertainty requires both earliest_ns and latest_ns"
            )
        if self.earliest_ns is not None:
            if type(self.earliest_ns) is not int or type(self.latest_ns) is not int:
                raise CorroborationError("event time bounds must be integers")
            if (
                not MIN_TIMESTAMP_NS <= self.earliest_ns <= MAX_TIMESTAMP_NS
                or not MIN_TIMESTAMP_NS <= self.latest_ns <= MAX_TIMESTAMP_NS
            ):
                raise CorroborationError(
                    "event time bounds must be signed 64-bit integers"
                )
            if self.earliest_ns > self.latest_ns:
                raise CorroborationError(
                    "event earliest_ns must not be later than latest_ns"
                )
        if self.clock_domain is not None:
            _validated_identifier(
                self.clock_domain,
                label="event clock domain",
            )
        causal_links = _validated_exact_tuple(
            self.causal_links,
            label="causal_links",
            maximum=_MAX_EVENT_CAUSAL_LINKS,
            item_type=ExplicitCausalLink,
        )
        causal_link_ids = tuple(link.link_id for link in causal_links)
        if len(causal_link_ids) != len(set(causal_link_ids)):
            raise CorroborationError("causal_links must not contain duplicate link ids")
        evidence = _validate_generic_tuple(self.evidence, label="event evidence")
        provenance = _validate_generic_tuple(
            self.provenance,
            label="event provenance",
        )
        object.__setattr__(
            self,
            "causal_links",
            tuple(
                ExplicitCausalLink(
                    link_id=link.link_id,
                    target=link.target,
                    evidence=link.evidence,
                    provenance=link.provenance,
                )
                for link in causal_links
            ),
        )
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "provenance", provenance)


class CorroborationOutcome(StrEnum):
    """Whether one generic fact supports the requested left-to-right relation."""

    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    UNKNOWN = "unknown"


class CorroborationReasonCode(StrEnum):
    """Closed core reason vocabulary for generic event corroboration."""

    EXPLICIT_CAUSAL_LINK = "explicit_causal_link"
    EXPLICIT_REVERSE_CAUSAL_LINK = "explicit_reverse_causal_link"
    SAME_SOURCE_RECORD = "same_source_record"
    SHARED_RESOURCE_ORDERED = "shared_resource_ordered"
    SHARED_RESOURCE_REVERSE_ORDER = "shared_resource_reverse_order"
    SHARED_RESOURCE_TIME_OVERLAP = "shared_resource_time_overlap"
    SHARED_RESOURCE_TIME_UNKNOWN = "shared_resource_time_unknown"
    SHARED_RESOURCE_CLOCK_UNALIGNED = "shared_resource_clock_unaligned"
    NO_CORROBORATING_LINK = "no_corroborating_link"


class TemporalRelation(StrEnum):
    """Ordering established from two uncertain closed time intervals."""

    BEFORE = "before"
    AFTER = "after"
    OVERLAPS = "overlaps"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CorroborationFact:
    """One independently auditable generic corroboration fact."""

    left: EventIdentity
    right: EventIdentity
    outcome: CorroborationOutcome
    reason_code: CorroborationReasonCode
    temporal_relation: TemporalRelation
    shared_source_records: tuple[SourceRecordIdentity, ...] = ()
    shared_resource_ids: tuple[str, ...] = ()
    causal_link_ids: tuple[str, ...] = ()
    evidence: tuple[Any, ...] = ()
    provenance: tuple[Any, ...] = ()
    left_clock_domain: str | None = None
    right_clock_domain: str | None = None

    def __post_init__(self) -> None:
        if type(self.left) is not EventIdentity or type(self.right) is not EventIdentity:
            raise CorroborationError(
                "corroboration fact endpoints must be EventIdentity values"
            )
        if type(self.outcome) is not CorroborationOutcome:
            raise CorroborationError(
                "corroboration fact outcome must be a CorroborationOutcome"
            )
        if type(self.reason_code) is not CorroborationReasonCode:
            raise CorroborationError(
                "corroboration fact reason_code must be a CorroborationReasonCode"
            )
        if type(self.temporal_relation) is not TemporalRelation:
            raise CorroborationError(
                "corroboration fact temporal_relation must be a TemporalRelation"
            )
        source_records = _validated_exact_tuple(
            self.shared_source_records,
            label="corroboration fact shared_source_records",
            maximum=_MAX_EVENT_SOURCE_RECORDS,
            item_type=SourceRecordIdentity,
        )
        if len(source_records) != len(set(source_records)):
            raise CorroborationError(
                "corroboration fact shared_source_records must not contain duplicates"
            )
        resource_ids = _validated_exact_tuple(
            self.shared_resource_ids,
            label="corroboration fact shared_resource_ids",
            maximum=_MAX_EVENT_RESOURCE_IDS,
        )
        for resource_id in resource_ids:
            _validated_identifier(
                resource_id,
                label="corroboration fact shared resource id",
            )
        if len(resource_ids) != len(set(resource_ids)):
            raise CorroborationError(
                "corroboration fact shared_resource_ids must not contain duplicates"
            )
        causal_link_ids = _validated_exact_tuple(
            self.causal_link_ids,
            label="corroboration fact causal_link_ids",
            maximum=_MAX_EVENT_CAUSAL_LINKS,
        )
        for link_id in causal_link_ids:
            _validated_identifier(
                link_id,
                label="corroboration fact causal link id",
            )
        if len(causal_link_ids) != len(set(causal_link_ids)):
            raise CorroborationError(
                "corroboration fact causal_link_ids must not contain duplicates"
            )
        if self.left_clock_domain is not None:
            _validated_identifier(
                self.left_clock_domain,
                label="corroboration fact left clock domain",
            )
        if self.right_clock_domain is not None:
            _validated_identifier(
                self.right_clock_domain,
                label="corroboration fact right clock domain",
            )
        evidence = _validate_generic_tuple(
            self.evidence,
            label="corroboration fact evidence",
            maximum_container_items=_MAX_FACT_GENERIC_CONTAINER_ITEMS,
            maximum_units=_MAX_FACT_GENERIC_VALUE_UNITS,
        )
        provenance = _validate_generic_tuple(
            self.provenance,
            label="corroboration fact provenance",
            maximum_container_items=_MAX_FACT_GENERIC_CONTAINER_ITEMS,
            maximum_units=_MAX_FACT_GENERIC_VALUE_UNITS,
        )
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "provenance", provenance)


def _snapshot_resolved_event(value: ResolvedEventRef) -> ResolvedEventRef:
    """Revalidate and detach one event at the corroboration call boundary."""

    return ResolvedEventRef(
        identity=value.identity,
        source_records=value.source_records,
        canonical_resource_ids=value.canonical_resource_ids,
        earliest_ns=value.earliest_ns,
        latest_ns=value.latest_ns,
        causal_links=value.causal_links,
        evidence=value.evidence,
        provenance=value.provenance,
        clock_domain=value.clock_domain,
    )


def _temporal_relation(
    left: ResolvedEventRef,
    right: ResolvedEventRef,
) -> TemporalRelation:
    if left.earliest_ns is None or right.earliest_ns is None:
        return TemporalRelation.UNKNOWN
    if (
        left.clock_domain is None
        or right.clock_domain is None
        or left.clock_domain != right.clock_domain
    ):
        return TemporalRelation.UNKNOWN
    assert left.latest_ns is not None
    assert right.latest_ns is not None
    if left.latest_ns < right.earliest_ns:
        return TemporalRelation.BEFORE
    if right.latest_ns < left.earliest_ns:
        return TemporalRelation.AFTER
    return TemporalRelation.OVERLAPS


def corroborate_events(
    left: ResolvedEventRef,
    right: ResolvedEventRef,
) -> tuple[CorroborationFact, ...]:
    """Generate pure facts for an asserted ``left`` then ``right`` relation.

    Multiple facts may coexist, including a supporting explicit link and a
    contradictory temporal fact.  The caller, not this utility, decides how to
    aggregate independent evidence into a policy verdict.
    """

    if type(left) is not ResolvedEventRef or type(right) is not ResolvedEventRef:
        raise CorroborationError(
            "corroborate_events requires two ResolvedEventRef values"
        )

    # Frozen dataclasses do not recursively freeze caller-owned dictionaries
    # and lists. Revalidate and snapshot both operands so later mutations of a
    # previously-created reference cannot change a returned, hashed fact.
    left = _snapshot_resolved_event(left)
    right = _snapshot_resolved_event(right)

    facts: list[CorroborationFact] = []
    base_evidence = _bounded_fact_values(
        (left.evidence, right.evidence),
        label="corroboration fact evidence",
    )
    base_provenance = _bounded_fact_values(
        (left.provenance, right.provenance),
        label="corroboration fact provenance",
    )

    links = tuple(
        sorted(
            (link for link in left.causal_links if link.target == right.identity),
            key=lambda link: link.link_id,
        )
    )
    reverse_links = tuple(
        sorted(
            (link for link in right.causal_links if link.target == left.identity),
            key=lambda link: link.link_id,
        )
    )
    if links:
        facts.append(
            CorroborationFact(
                left=left.identity,
                right=right.identity,
                outcome=CorroborationOutcome.SUPPORTS,
                reason_code=CorroborationReasonCode.EXPLICIT_CAUSAL_LINK,
                temporal_relation=_temporal_relation(left, right),
                causal_link_ids=tuple(link.link_id for link in links),
                left_clock_domain=left.clock_domain,
                right_clock_domain=right.clock_domain,
                evidence=_bounded_fact_values(
                    (base_evidence, *(link.evidence for link in links)),
                    label="corroboration fact evidence",
                ),
                provenance=_bounded_fact_values(
                    (base_provenance, *(link.provenance for link in links)),
                    label="corroboration fact provenance",
                ),
            )
        )
    if reverse_links:
        facts.append(
            CorroborationFact(
                left=left.identity,
                right=right.identity,
                outcome=CorroborationOutcome.CONTRADICTS,
                reason_code=CorroborationReasonCode.EXPLICIT_REVERSE_CAUSAL_LINK,
                temporal_relation=_temporal_relation(left, right),
                causal_link_ids=tuple(link.link_id for link in reverse_links),
                left_clock_domain=left.clock_domain,
                right_clock_domain=right.clock_domain,
                evidence=_bounded_fact_values(
                    (
                        base_evidence,
                        *(link.evidence for link in reverse_links),
                    ),
                    label="corroboration fact evidence",
                ),
                provenance=_bounded_fact_values(
                    (
                        base_provenance,
                        *(link.provenance for link in reverse_links),
                    ),
                    label="corroboration fact provenance",
                ),
            )
        )

    shared_source_records = tuple(
        sorted(set(left.source_records).intersection(right.source_records))
    )
    if shared_source_records:
        relation = _temporal_relation(left, right)
        if relation is TemporalRelation.BEFORE:
            outcome = CorroborationOutcome.SUPPORTS
        elif relation is TemporalRelation.AFTER:
            outcome = CorroborationOutcome.CONTRADICTS
        else:
            outcome = CorroborationOutcome.UNKNOWN
        facts.append(
            CorroborationFact(
                left=left.identity,
                right=right.identity,
                outcome=outcome,
                reason_code=CorroborationReasonCode.SAME_SOURCE_RECORD,
                temporal_relation=relation,
                shared_source_records=shared_source_records,
                left_clock_domain=left.clock_domain,
                right_clock_domain=right.clock_domain,
                evidence=base_evidence,
                provenance=base_provenance,
            )
        )

    shared_resource_ids = tuple(
        sorted(
            set(left.canonical_resource_ids).intersection(right.canonical_resource_ids)
        )
    )
    if shared_resource_ids:
        relation = _temporal_relation(left, right)
        has_both_times = left.earliest_ns is not None and right.earliest_ns is not None
        clocks_aligned = (
            left.clock_domain is not None and left.clock_domain == right.clock_domain
        )
        if has_both_times and not clocks_aligned:
            outcome = CorroborationOutcome.UNKNOWN
            reason_code = CorroborationReasonCode.SHARED_RESOURCE_CLOCK_UNALIGNED
        elif relation is TemporalRelation.BEFORE:
            outcome = CorroborationOutcome.SUPPORTS
            reason_code = CorroborationReasonCode.SHARED_RESOURCE_ORDERED
        elif relation is TemporalRelation.AFTER:
            outcome = CorroborationOutcome.CONTRADICTS
            reason_code = CorroborationReasonCode.SHARED_RESOURCE_REVERSE_ORDER
        elif relation is TemporalRelation.OVERLAPS:
            outcome = CorroborationOutcome.UNKNOWN
            reason_code = CorroborationReasonCode.SHARED_RESOURCE_TIME_OVERLAP
        else:
            outcome = CorroborationOutcome.UNKNOWN
            reason_code = CorroborationReasonCode.SHARED_RESOURCE_TIME_UNKNOWN
        facts.append(
            CorroborationFact(
                left=left.identity,
                right=right.identity,
                outcome=outcome,
                reason_code=reason_code,
                temporal_relation=relation,
                shared_resource_ids=shared_resource_ids,
                left_clock_domain=left.clock_domain,
                right_clock_domain=right.clock_domain,
                evidence=base_evidence,
                provenance=base_provenance,
            )
        )

    if not facts:
        facts.append(
            CorroborationFact(
                left=left.identity,
                right=right.identity,
                outcome=CorroborationOutcome.UNKNOWN,
                reason_code=CorroborationReasonCode.NO_CORROBORATING_LINK,
                temporal_relation=_temporal_relation(left, right),
                left_clock_domain=left.clock_domain,
                right_clock_domain=right.clock_domain,
                evidence=base_evidence,
                provenance=base_provenance,
            )
        )
    return tuple(facts)
