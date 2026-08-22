from .canonical import CanonicalValueError as CanonicalValueError, MAX_OPAQUE_ATOM_PAYLOAD_UNITS as MAX_OPAQUE_ATOM_PAYLOAD_UNITS, MAX_OPAQUE_CONTAINER_ITEMS as MAX_OPAQUE_CONTAINER_ITEMS, MAX_OPAQUE_INTEGER_BITS as MAX_OPAQUE_INTEGER_BITS, MAX_OPAQUE_VALUE_DEPTH as MAX_OPAQUE_VALUE_DEPTH, MAX_OPAQUE_VALUE_UNITS as MAX_OPAQUE_VALUE_UNITS, canonical_opaque_value as canonical_opaque_value
from .contract_validation import validate_bounded_json_value as validate_bounded_json_value
from .plugin_api import KeyAtom as KeyAtom, MAX_TIMESTAMP_NS as MAX_TIMESTAMP_NS, MIN_TIMESTAMP_NS as MIN_TIMESTAMP_NS
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

class CorroborationError(ValueError): ...

@dataclass(frozen=True, slots=True, order=True)
class MatcherId:
    value: str
    def __post_init__(self) -> None: ...

class ExactMatchState(StrEnum):
    MATCHED = 'matched'
    AMBIGUOUS = 'ambiguous'
    UNMATCHED = 'unmatched'

@dataclass(frozen=True, slots=True)
class ExactMatchClaim:
    claim_id: str
    partition_id: str
    matcher_id: MatcherId
    match_key: Any
    evidence: tuple[Any, ...] = ...
    provenance: tuple[Any, ...] = ...
    payload: Any = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ExactMatchCandidate:
    matcher_id: MatcherId
    normalized_key: dict[str, Any]
    typed_key: str
    left: ExactMatchClaim
    right: ExactMatchClaim

@dataclass(frozen=True, slots=True)
class ExactMatchGroup:
    matcher_id: MatcherId
    normalized_key: dict[str, Any]
    typed_key: str
    state: ExactMatchState
    candidate_count: int
    claims: tuple[ExactMatchClaim, ...]

@dataclass(frozen=True, slots=True)
class ExactMatchResult:
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

def exact_match_claims(claims: Iterable[ExactMatchClaim], *, max_candidates: int = ..., max_claims: int = ...) -> ExactMatchResult: ...

@dataclass(frozen=True, slots=True, order=True)
class EventIdentity:
    partition_id: str
    event_id: str
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True, order=True)
class SourceRecordIdentity:
    source_id: str
    record_id: str
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ExplicitCausalLink:
    link_id: str
    target: EventIdentity
    evidence: tuple[Any, ...] = ...
    provenance: tuple[Any, ...] = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class ResolvedEventRef:
    identity: EventIdentity
    source_records: tuple[SourceRecordIdentity, ...] = ...
    canonical_resource_ids: tuple[str, ...] = ...
    earliest_ns: int | None = ...
    latest_ns: int | None = ...
    causal_links: tuple[ExplicitCausalLink, ...] = ...
    evidence: tuple[Any, ...] = ...
    provenance: tuple[Any, ...] = ...
    clock_domain: str | None = ...
    def __post_init__(self) -> None: ...

class CorroborationOutcome(StrEnum):
    SUPPORTS = 'supports'
    CONTRADICTS = 'contradicts'
    UNKNOWN = 'unknown'

class CorroborationReasonCode(StrEnum):
    EXPLICIT_CAUSAL_LINK = 'explicit_causal_link'
    EXPLICIT_REVERSE_CAUSAL_LINK = 'explicit_reverse_causal_link'
    SAME_SOURCE_RECORD = 'same_source_record'
    SHARED_RESOURCE_ORDERED = 'shared_resource_ordered'
    SHARED_RESOURCE_REVERSE_ORDER = 'shared_resource_reverse_order'
    SHARED_RESOURCE_TIME_OVERLAP = 'shared_resource_time_overlap'
    SHARED_RESOURCE_TIME_UNKNOWN = 'shared_resource_time_unknown'
    SHARED_RESOURCE_CLOCK_UNALIGNED = 'shared_resource_clock_unaligned'
    NO_CORROBORATING_LINK = 'no_corroborating_link'

class TemporalRelation(StrEnum):
    BEFORE = 'before'
    AFTER = 'after'
    OVERLAPS = 'overlaps'
    UNKNOWN = 'unknown'

@dataclass(frozen=True, slots=True)
class CorroborationFact:
    left: EventIdentity
    right: EventIdentity
    outcome: CorroborationOutcome
    reason_code: CorroborationReasonCode
    temporal_relation: TemporalRelation
    shared_source_records: tuple[SourceRecordIdentity, ...] = ...
    shared_resource_ids: tuple[str, ...] = ...
    causal_link_ids: tuple[str, ...] = ...
    evidence: tuple[Any, ...] = ...
    provenance: tuple[Any, ...] = ...
    left_clock_domain: str | None = ...
    right_clock_domain: str | None = ...
    def __post_init__(self) -> None: ...

def corroborate_events(left: ResolvedEventRef, right: ResolvedEventRef) -> tuple[CorroborationFact, ...]: ...
