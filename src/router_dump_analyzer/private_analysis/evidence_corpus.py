"""Immutable, indexed evidence snapshots for private-analysis tool services.

The corpus is a pure in-memory value boundary.  It performs no authorization,
policy evaluation, catalog access, I/O, plug-in invocation, or model work.
Callers build it only from already validated immutable revision evidence, then
pass its narrow callbacks to :class:`PrivateAnalysisToolService`.

Payloads are retained as bounded canonical JSON strings so neither input
dictionaries nor returned materializations can mutate the snapshot.  Every
lookup revalidates the caller-visible reference against the stored value.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from json import loads
from threading import Condition, Lock
from types import MappingProxyType
from typing import Final

from ..cancellation import cooperatively_sorted
from ..canonical import strict_canonical_json
from ..process_control import PROCESS_CONTROL_EXCEPTIONS
from .contracts import PrivateAnalysisRequest
from .disclosure import PrivateAnalysisEvidenceClass
from .evidence import (
    MAX_EVIDENCE_PAYLOAD_BYTES,
    EvidenceKind,
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
    EvidenceTimeBasis,
    evidence_payload_digest,
    snapshot_evidence_reference,
)
from .query_cancellation import (
    PrivateAnalysisEvidenceQueryCancellationProbeError,
    PrivateAnalysisEvidenceQueryCancellationProbeResultError,
    PrivateAnalysisEvidenceQueryCancelledError,
    check_private_analysis_evidence_query_cancellation,
)
from .tool_catalog import (
    PrivateAnalysisEvidenceCursorInvalidError,
    PrivateAnalysisEvidenceQueryPage,
    PrivateAnalysisQueryArguments,
)

DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES: Final = 1_000_000
MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES: Final = 2_000_000
DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES: Final[int] = 512 * 1024 * 1024
MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES: Final[int] = 2 * 1024 * 1024 * 1024


def _detached_reference(value: object) -> EvidenceReference:
    if type(value) is not EvidenceReference:
        raise TypeError("reference must be EvidenceReference")
    return snapshot_evidence_reference(value)


@dataclass(frozen=True, slots=True, init=False)
class PrivateAnalysisEvidenceEntry:
    """One frozen reference and its digest-bound canonical payload snapshot."""

    reference: EvidenceReference
    _payload_json: str = field(repr=False)
    _payload_bytes: int = field(repr=False)

    def __init__(
        self,
        reference: EvidenceReference,
        payload: dict[str, object],
    ) -> None:
        detached_reference = _detached_reference(reference)
        if type(payload) is not dict:
            raise TypeError("payload must be an exact JSON object")
        actual_digest = evidence_payload_digest(
            detached_reference.payload_schema,
            payload,
        )
        if actual_digest != detached_reference.content_digest:
            raise ValueError("evidence payload digest does not match its reference")
        # evidence_payload_digest has already validated exact JSON types and all
        # evidence bounds.  Canonical JSON is the immutable storage form.
        payload_json = strict_canonical_json(payload)
        payload_bytes = len(payload_json.encode("utf-8"))
        object.__setattr__(self, "reference", detached_reference)
        object.__setattr__(self, "_payload_json", payload_json)
        object.__setattr__(self, "_payload_bytes", payload_bytes)

    @property
    def payload_bytes(self) -> int:
        """Return the immutable canonical payload's encoded byte size."""

        return self._payload_bytes

    @property
    def payload(self) -> dict[str, object]:
        """Return a detached exact JSON object for one materialization."""

        value = loads(self._payload_json)
        if type(value) is not dict:  # pragma: no cover - constructor invariant
            raise RuntimeError("stored evidence payload is not an object")
        return value


@dataclass(frozen=True, slots=True)
class _StoredEvidenceEntry:
    """Private canonical storage detached from caller-owned entry objects."""

    reference: EvidenceReference
    payload_json: str = field(repr=False)
    payload_bytes: int = field(repr=False)

    def payload(self) -> dict[str, object]:
        value = loads(self.payload_json)
        if type(value) is not dict:  # pragma: no cover - validated on admission
            raise RuntimeError("stored evidence payload is not an object")
        return value


def _revalidated_entry(value: object) -> _StoredEvidenceEntry:
    if type(value) is not PrivateAnalysisEvidenceEntry:
        raise TypeError("entries must contain PrivateAnalysisEvidenceEntry values")
    if type(value._payload_json) is not str:
        raise TypeError("stored evidence payload JSON must be a string")
    if len(value._payload_json) > MAX_EVIDENCE_PAYLOAD_BYTES:
        raise ValueError("stored evidence payload exceeds its encoded byte limit")
    try:
        encoded_bytes = len(value._payload_json.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ValueError(
            "stored evidence payload must contain Unicode scalars"
        ) from error
    if encoded_bytes > MAX_EVIDENCE_PAYLOAD_BYTES:
        raise ValueError("stored evidence payload exceeds its encoded byte limit")
    reference = _detached_reference(value.reference)
    payload = loads(value._payload_json)
    if type(payload) is not dict:
        raise TypeError("stored evidence payload must be an exact JSON object")
    if strict_canonical_json(payload) != value._payload_json:
        raise ValueError("stored evidence payload must be exact canonical JSON")
    if (
        evidence_payload_digest(reference.payload_schema, payload)
        != reference.content_digest
    ):
        raise ValueError("evidence payload digest does not match its reference")
    # Store only detached immutable components. The private storage value is
    # never returned, so caller-side reflective mutation of the supplied entry
    # cannot alter the corpus and no reflective constructor is needed here.
    return _StoredEvidenceEntry(reference, value._payload_json, encoded_bytes)


class PrivateAnalysisEvidenceQueryTooBroadError(ValueError):
    """Deprecated compatibility error; paged corpus queries are no longer capped."""


@dataclass(frozen=True, slots=True)
class _CachedQuerySnapshot:
    digests: tuple[str, ...]
    snapshot_digest: str


_QUERY_CACHE_ENTRIES: Final = 16
_QUERY_CHECKPOINT_INTERVAL: Final = 64
_QUERY_SINGLEFLIGHT_WAIT_SECONDS: Final = 0.05


def _snapshot_digest(
    digests: tuple[str, ...],
    cancellation_checkpoint: Callable[[], None] | None = None,
) -> str:
    """Incrementally bind exact ordered membership without a giant JSON value."""

    digest = sha256()
    digest.update(b"router_dump_analyzer.private_analysis.evidence_snapshot.v2\0")
    for ordinal, value in enumerate(digests):
        if (
            ordinal % _QUERY_CHECKPOINT_INTERVAL == 0
            and cancellation_checkpoint is not None
        ):
            cancellation_checkpoint()
        digest.update(value.encode("ascii"))
        digest.update(b"\0")
    if cancellation_checkpoint is not None:
        cancellation_checkpoint()
    return "sha256:" + digest.hexdigest()


def _time_matches(
    reference: EvidenceReference,
    arguments: PrivateAnalysisQueryArguments,
) -> bool:
    if arguments.time_basis is None:
        return True
    assert arguments.time_start_ns is not None
    assert arguments.time_end_ns is not None
    time_range = reference.time_range
    if (
        time_range.basis is arguments.time_basis
        and time_range.clock_domain == arguments.time_clock_domain
        and time_range.start_ns is not None
        and time_range.end_ns is not None
    ):
        start, end = _effective_time_bounds(reference)
        return start <= arguments.time_end_ns and end >= arguments.time_start_ns
    return False


def _effective_time_bounds(reference: EvidenceReference) -> tuple[int, int]:
    time_range = reference.time_range
    assert time_range.start_ns is not None and time_range.end_ns is not None
    uncertainty = time_range.uncertainty_ns or 0
    minimum = (
        0 if time_range.basis is EvidenceTimeBasis.ABSOLUTE_UNIX_NS else -(1 << 63)
    )
    maximum = (1 << 63) - 1
    return (
        max(minimum, time_range.start_ns - uncertainty),
        min(maximum, time_range.end_ns + uncertainty),
    )


_checkpointed_sorted = cooperatively_sorted


def _frozen_index[IndexKey](
    mutable: dict[IndexKey, list[str]],
    construction_checkpoint: Callable[[], None] | None,
) -> MappingProxyType[IndexKey, tuple[str, ...]]:
    frozen: dict[IndexKey, tuple[str, ...]] = {}
    for ordinal, (key, digests) in enumerate(mutable.items()):
        if ordinal % 256 == 0 and construction_checkpoint is not None:
            construction_checkpoint()
        frozen[key] = _checkpointed_sorted(digests, construction_checkpoint)
    return MappingProxyType(frozen)


def _add_index_value[IndexKey](
    index: dict[IndexKey, list[str]],
    key: IndexKey,
    digest: str,
) -> None:
    index.setdefault(key, []).append(digest)


@dataclass(frozen=True, slots=True)
class _TrustedCorpusInitialization:
    """Internal constructor carrier for already validated projected entries."""

    entries: tuple[PrivateAnalysisEvidenceEntry, ...]
    construction_checkpoint: Callable[[], None] | None


@dataclass(frozen=True, slots=True, init=False)
class PrivateAnalysisEvidenceCorpus:
    """One bounded, immutable and deterministically indexed evidence corpus.

    The methods have the exact callback shapes expected by
    :class:`~router_dump_analyzer.private_analysis_tool_service.PrivateAnalysisToolService`.
    Query results are bounded pages from cached candidate snapshots in
    reference-digest order; disclosure classes are supplied by the service.
    """

    _entries: tuple[_StoredEvidenceEntry, ...] = field(repr=False)
    maximum_entries: int
    maximum_payload_bytes: int
    payload_bytes: int
    _by_digest: MappingProxyType[str, _StoredEvidenceEntry] = field(repr=False)
    _by_scope: MappingProxyType[EvidenceScope, tuple[str, ...]] = field(repr=False)
    _by_revision: MappingProxyType[EvidenceRevisionBinding, tuple[str, ...]] = field(
        repr=False
    )
    _by_kind: MappingProxyType[EvidenceKind, tuple[str, ...]] = field(repr=False)
    _by_node: MappingProxyType[str, tuple[str, ...]] = field(repr=False)
    _by_producer: MappingProxyType[str, tuple[str, ...]] = field(repr=False)
    _by_subject: MappingProxyType[str, tuple[str, ...]] = field(repr=False)
    _by_class: MappingProxyType[PrivateAnalysisEvidenceClass, tuple[str, ...]] = field(
        repr=False
    )
    _by_time_points: MappingProxyType[
        tuple[EvidenceTimeBasis, str | None], tuple[tuple[int, str], ...]
    ] = field(repr=False)
    _by_time_intervals: MappingProxyType[
        tuple[EvidenceTimeBasis, str | None], tuple[tuple[int, int, str], ...]
    ] = field(repr=False)
    _query_cache: OrderedDict[
        tuple[str, str, tuple[str, ...]], _CachedQuerySnapshot
    ] = field(repr=False, compare=False)
    _query_cache_condition: Condition = field(repr=False, compare=False)
    _query_building: set[tuple[str, str, tuple[str, ...]]] = field(
        repr=False,
        compare=False,
    )

    def __init__(
        self,
        entries: (
            tuple[PrivateAnalysisEvidenceEntry, ...]
            | _TrustedCorpusInitialization
        ),
        *,
        maximum_entries: int = DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES,
        maximum_payload_bytes: int = (
            DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES
        ),
    ) -> None:
        trusted_entries = type(entries) is _TrustedCorpusInitialization
        if trusted_entries:
            assert isinstance(entries, _TrustedCorpusInitialization)
            supplied_entries = entries.entries
            construction_checkpoint = entries.construction_checkpoint
        else:
            supplied_entries = entries
            construction_checkpoint = None
        self._initialize(
            supplied_entries,
            maximum_entries=maximum_entries,
            maximum_payload_bytes=maximum_payload_bytes,
            trusted_entries=trusted_entries,
            construction_checkpoint=construction_checkpoint,
        )

    @classmethod
    def _from_trusted_entries(
        cls,
        entries: tuple[PrivateAnalysisEvidenceEntry, ...],
        *,
        maximum_entries: int,
        maximum_payload_bytes: int = (
            DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES
        ),
        construction_checkpoint: Callable[[], None] | None = None,
    ) -> PrivateAnalysisEvidenceCorpus:
        """Index entries just created by the core projection without rehashing.

        This is deliberately private.  The public constructor revalidates and
        detaches every caller-owned entry.  The revision-evidence adapter has
        already constructed and digest-validated these values locally, retains
        no caller reference to them, and can therefore avoid repeating the
        dominant canonicalization/hash work while still copying them into the
        corpus' private stored representation.
        """

        if construction_checkpoint is not None and not callable(
            construction_checkpoint
        ):
            raise TypeError("construction_checkpoint must be callable or None")
        return cls(
            _TrustedCorpusInitialization(entries, construction_checkpoint),
            maximum_entries=maximum_entries,
            maximum_payload_bytes=maximum_payload_bytes,
        )

    def _initialize(
        self,
        entries: tuple[PrivateAnalysisEvidenceEntry, ...],
        *,
        maximum_entries: int,
        maximum_payload_bytes: int,
        trusted_entries: bool,
        construction_checkpoint: Callable[[], None] | None,
    ) -> None:
        if type(entries) is not tuple:
            raise TypeError("entries must be a tuple")
        if (
            type(maximum_entries) is not int
            or not 1 <= maximum_entries <= MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES
        ):
            raise ValueError(
                "maximum_entries must be between 1 and "
                f"{MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES}"
            )
        if len(entries) > maximum_entries:
            raise ValueError(
                f"evidence corpus supports at most {maximum_entries} entries"
            )
        if (
            type(maximum_payload_bytes) is not int
            or not 1
            <= maximum_payload_bytes
            <= MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES
        ):
            raise ValueError(
                "maximum_payload_bytes must be between 1 and "
                f"{MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES}"
            )

        by_digest: dict[str, _StoredEvidenceEntry] = {}
        by_scope: dict[EvidenceScope, list[str]] = {}
        by_revision: dict[EvidenceRevisionBinding, list[str]] = {}
        by_kind: dict[EvidenceKind, list[str]] = {}
        by_node: dict[str, list[str]] = {}
        by_producer: dict[str, list[str]] = {}
        by_subject: dict[str, list[str]] = {}
        by_class: dict[PrivateAnalysisEvidenceClass, list[str]] = {}
        by_time_points: dict[
            tuple[EvidenceTimeBasis, str | None], list[tuple[int, str]]
        ] = {}
        by_time_intervals: dict[
            tuple[EvidenceTimeBasis, str | None], list[tuple[int, int, str]]
        ] = {}

        payload_bytes = 0
        for ordinal, supplied in enumerate(entries):
            if ordinal % 256 == 0 and construction_checkpoint is not None:
                construction_checkpoint()
            if trusted_entries:
                if type(supplied) is not PrivateAnalysisEvidenceEntry:
                    raise TypeError(
                        "trusted entries must contain PrivateAnalysisEvidenceEntry values"
                    )
                entry = _StoredEvidenceEntry(
                    supplied.reference,
                    supplied._payload_json,
                    supplied._payload_bytes,
                )
            else:
                entry = _revalidated_entry(supplied)
            payload_bytes += entry.payload_bytes
            if payload_bytes > maximum_payload_bytes:
                raise ValueError(
                    "evidence corpus exceeds its canonical payload byte limit"
                )
            reference = entry.reference
            digest = reference.reference_digest
            if digest in by_digest:
                raise ValueError("evidence corpus reference digests must be unique")
            by_digest[digest] = entry
            _add_index_value(by_scope, reference.scope, digest)
            _add_index_value(by_revision, reference.revision, digest)
            _add_index_value(by_kind, reference.kind, digest)
            _add_index_value(by_node, reference.revision.node_id, digest)
            _add_index_value(by_producer, reference.producer.producer_id, digest)
            _add_index_value(by_subject, reference.subject_kind, digest)
            _add_index_value(by_class, reference.evidence_class, digest)
            time_range = reference.time_range
            if time_range.start_ns is not None and time_range.end_ns is not None:
                key = (time_range.basis, time_range.clock_domain)
                effective_start, effective_end = _effective_time_bounds(reference)
                if effective_start == effective_end:
                    by_time_points.setdefault(key, []).append((effective_start, digest))
                else:
                    by_time_intervals.setdefault(key, []).append(
                        (effective_start, effective_end, digest)
                    )

        ordered_digests = _checkpointed_sorted(
            list(by_digest),
            construction_checkpoint,
        )
        ordered_entries_values: list[_StoredEvidenceEntry] = []
        ordered_by_digest: dict[str, _StoredEvidenceEntry] = {}
        for ordinal, digest in enumerate(ordered_digests):
            if ordinal % 256 == 0 and construction_checkpoint is not None:
                construction_checkpoint()
            entry = by_digest[digest]
            ordered_entries_values.append(entry)
            ordered_by_digest[digest] = entry
        ordered_entries = tuple(ordered_entries_values)
        frozen_by_scope = _frozen_index(by_scope, construction_checkpoint)
        frozen_by_revision = _frozen_index(by_revision, construction_checkpoint)
        frozen_by_kind = _frozen_index(by_kind, construction_checkpoint)
        frozen_by_node = _frozen_index(by_node, construction_checkpoint)
        frozen_by_producer = _frozen_index(by_producer, construction_checkpoint)
        frozen_by_subject = _frozen_index(by_subject, construction_checkpoint)
        frozen_by_class = _frozen_index(by_class, construction_checkpoint)
        frozen_time_points: dict[
            tuple[EvidenceTimeBasis, str | None],
            tuple[tuple[int, str], ...],
        ] = {}
        for ordinal, (key, values) in enumerate(by_time_points.items()):
            if ordinal % 256 == 0 and construction_checkpoint is not None:
                construction_checkpoint()
            frozen_time_points[key] = _checkpointed_sorted(
                values,
                construction_checkpoint,
            )
        frozen_time_intervals: dict[
            tuple[EvidenceTimeBasis, str | None],
            tuple[tuple[int, int, str], ...],
        ] = {}
        for ordinal, (key, values) in enumerate(by_time_intervals.items()):
            if ordinal % 256 == 0 and construction_checkpoint is not None:
                construction_checkpoint()
            frozen_time_intervals[key] = _checkpointed_sorted(
                values,
                construction_checkpoint,
            )
        object.__setattr__(self, "_entries", ordered_entries)
        object.__setattr__(self, "maximum_entries", maximum_entries)
        object.__setattr__(self, "maximum_payload_bytes", maximum_payload_bytes)
        object.__setattr__(self, "payload_bytes", payload_bytes)
        object.__setattr__(self, "_by_digest", MappingProxyType(ordered_by_digest))
        object.__setattr__(self, "_by_scope", frozen_by_scope)
        object.__setattr__(self, "_by_revision", frozen_by_revision)
        object.__setattr__(self, "_by_kind", frozen_by_kind)
        object.__setattr__(self, "_by_node", frozen_by_node)
        object.__setattr__(self, "_by_producer", frozen_by_producer)
        object.__setattr__(self, "_by_subject", frozen_by_subject)
        object.__setattr__(self, "_by_class", frozen_by_class)
        object.__setattr__(
            self,
            "_by_time_points",
            MappingProxyType(frozen_time_points),
        )
        object.__setattr__(
            self,
            "_by_time_intervals",
            MappingProxyType(frozen_time_intervals),
        )
        object.__setattr__(self, "_query_cache", OrderedDict())
        object.__setattr__(self, "_query_cache_condition", Condition(Lock()))
        object.__setattr__(self, "_query_building", set())
        if construction_checkpoint is not None:
            construction_checkpoint()

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> tuple[PrivateAnalysisEvidenceEntry, ...]:
        """Return detached public entries without exposing corpus storage."""

        return tuple(
            PrivateAnalysisEvidenceEntry(entry.reference, entry.payload())
            for entry in self._entries
        )

    @property
    def reference_digests(self) -> tuple[str, ...]:
        """Return the corpus membership in canonical digest order."""

        return tuple(entry.reference.reference_digest for entry in self._entries)

    def query_references(
        self,
        request: PrivateAnalysisRequest,
        arguments: PrivateAnalysisQueryArguments,
        evidence_classes: tuple[PrivateAnalysisEvidenceClass, ...] = tuple(
            PrivateAnalysisEvidenceClass
        ),
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> PrivateAnalysisEvidenceQueryPage:
        """Return one keyset page of the exact eligible/filter intersection."""

        if type(request) is not PrivateAnalysisRequest:
            raise TypeError("request must be PrivateAnalysisRequest")
        if type(arguments) is not PrivateAnalysisQueryArguments:
            raise TypeError("arguments must be PrivateAnalysisQueryArguments")
        if type(evidence_classes) is not tuple or any(
            type(value) is not PrivateAnalysisEvidenceClass
            for value in evidence_classes
        ):
            raise TypeError("evidence_classes must contain evidence classes")
        if cancellation_probe is not None and not callable(cancellation_probe):
            raise TypeError("cancellation_probe must be callable or None")
        def checkpoint() -> None:
            check_private_analysis_evidence_query_cancellation(cancellation_probe)

        checkpoint()
        accepted_classes = tuple(
            sorted(set(evidence_classes), key=lambda item: item.value)
        )
        cache_key = (
            request.request_digest,
            arguments.query_digest,
            tuple(item.value for item in accepted_classes),
        )
        build_snapshot = False
        snapshot: _CachedQuerySnapshot | None = None
        while True:
            checkpoint()
            with self._query_cache_condition:
                snapshot = self._query_cache.get(cache_key)
                if snapshot is not None:
                    self._query_cache.move_to_end(cache_key)
                    break
                # A continuation is admitted only against the exact snapshot
                # that is cached at this lookup. It must never join a later
                # cursorless rebuild for the same query fingerprint: even an
                # identical rebuilt digest would silently extend cursor
                # lifetime beyond the bounded-cache contract.
                if arguments.cursor is not None:
                    raise PrivateAnalysisEvidenceCursorInvalidError(
                        "cursor evidence snapshot is no longer available"
                    )
                if cache_key not in self._query_building:
                    self._query_building.add(cache_key)
                    build_snapshot = True
                    break
                self._query_cache_condition.wait(
                    timeout=_QUERY_SINGLEFLIGHT_WAIT_SECONDS
                )
        if build_snapshot:
            try:
                built = self._build_query_snapshot(
                    request,
                    arguments,
                    accepted_classes,
                    cancellation_probe,
                )
                checkpoint()
            except BaseException:
                with self._query_cache_condition:
                    self._query_building.discard(cache_key)
                    self._query_cache_condition.notify_all()
                raise
            with self._query_cache_condition:
                existing = self._query_cache.get(cache_key)
                if existing is None:
                    snapshot = built
                    self._query_cache[cache_key] = snapshot
                    if len(self._query_cache) > _QUERY_CACHE_ENTRIES:
                        self._query_cache.popitem(last=False)
                else:  # pragma: no cover - single-flight owns this key.
                    snapshot = existing
                    self._query_cache.move_to_end(cache_key)
                self._query_building.discard(cache_key)
                self._query_cache_condition.notify_all()
        assert snapshot is not None
        checkpoint()

        start = 0
        cursor = arguments.cursor
        if cursor is not None:
            if cursor.snapshot_digest != snapshot.snapshot_digest:
                raise PrivateAnalysisEvidenceCursorInvalidError(
                    "cursor belongs to another evidence snapshot"
                )
            start = bisect_left(snapshot.digests, cursor.after_reference_digest)
            if (
                start >= len(snapshot.digests)
                or snapshot.digests[start] != cursor.after_reference_digest
            ):
                raise PrivateAnalysisEvidenceCursorInvalidError(
                    "cursor boundary is not in the evidence snapshot"
                )
            start += 1
        stop = min(start + arguments.page_size, len(snapshot.digests))
        references_list: list[EvidenceReference] = []
        for ordinal, digest in enumerate(snapshot.digests[start:stop]):
            if ordinal % _QUERY_CHECKPOINT_INTERVAL == 0:
                checkpoint()
            references_list.append(
                _detached_reference(self._by_digest[digest].reference)
            )
        checkpoint()
        return PrivateAnalysisEvidenceQueryPage(
            snapshot_digest=snapshot.snapshot_digest,
            references=tuple(references_list),
            has_more=stop < len(snapshot.digests),
        )

    def _build_query_snapshot(
        self,
        request: PrivateAnalysisRequest,
        arguments: PrivateAnalysisQueryArguments,
        evidence_classes: tuple[PrivateAnalysisEvidenceClass, ...],
        cancellation_probe: Callable[[], bool] | None,
    ) -> _CachedQuerySnapshot:
        """Build and cache canonical membership once, never once per page."""

        def checkpoint() -> None:
            check_private_analysis_evidence_query_cancellation(cancellation_probe)

        checkpoint()
        revisions = frozenset(request.revisions)
        kinds = frozenset(arguments.evidence_kinds)
        nodes = frozenset(arguments.node_ids)
        producers = frozenset(arguments.producer_ids)
        subjects = frozenset(arguments.subject_kinds)

        # Seed from the smallest applicable index.  A query for one uncommon
        # subject in a two-million-entry revision must not first allocate a
        # two-million-element candidate set.  Values within one dimension are
        # disjoint because each reference has exactly one value for that field.
        seeds: list[tuple[tuple[str, ...], ...]] = [
            (self._by_scope.get(request.scope, ()),),
            tuple(self._by_revision.get(value, ()) for value in revisions),
        ]
        for accepted, index in (
            (arguments.evidence_kinds, self._by_kind),
            (arguments.node_ids, self._by_node),
            (arguments.producer_ids, self._by_producer),
            (arguments.subject_kinds, self._by_subject),
        ):
            if accepted:
                seeds.append(tuple(index.get(value, ()) for value in accepted))
        # An empty class set deliberately yields an empty snapshot.
        seeds.append(tuple(self._by_class.get(value, ()) for value in evidence_classes))
        if arguments.time_basis is not None:
            time_key = (arguments.time_basis, arguments.time_clock_domain)
            points = self._by_time_points.get(time_key, ())
            intervals = self._by_time_intervals.get(time_key, ())
            assert arguments.time_end_ns is not None
            assert arguments.time_start_ns is not None
            point_start = bisect_left(points, (arguments.time_start_ns, ""))
            point_stop = bisect_right(
                points,
                (arguments.time_end_ns, "\U0010ffff"),
            )
            interval_stop = bisect_right(
                intervals,
                (arguments.time_end_ns, (1 << 63) - 1, "\U0010ffff"),
            )
            time_digests: list[str] = []
            for ordinal, point_index in enumerate(range(point_start, point_stop)):
                if ordinal % _QUERY_CHECKPOINT_INTERVAL == 0:
                    checkpoint()
                time_digests.append(points[point_index][1])
            for ordinal, interval_index in enumerate(range(interval_stop)):
                if ordinal % _QUERY_CHECKPOINT_INTERVAL == 0:
                    checkpoint()
                _start, end, digest = intervals[interval_index]
                if end >= arguments.time_start_ns:
                    time_digests.append(digest)
            seeds.append((tuple(time_digests),))
        checkpoint()
        seed = min(seeds, key=lambda groups: sum(map(len, groups)))

        candidates: list[str] = []
        for group in seed:
            for ordinal, digest in enumerate(group):
                if ordinal % _QUERY_CHECKPOINT_INTERVAL == 0:
                    checkpoint()
                reference = self._by_digest[digest].reference
                if (
                    reference.scope != request.scope
                    or reference.revision not in revisions
                    or (kinds and reference.kind not in kinds)
                    or (nodes and reference.revision.node_id not in nodes)
                    or (producers and reference.producer.producer_id not in producers)
                    or (subjects and reference.subject_kind not in subjects)
                    or reference.evidence_class not in evidence_classes
                    or not _time_matches(reference, arguments)
                ):
                    continue
                candidates.append(digest)
        digests = _checkpointed_sorted(candidates, checkpoint)
        return _CachedQuerySnapshot(
            digests=digests,
            snapshot_digest=_snapshot_digest(digests, checkpoint),
        )

    def resolve_reference(
        self,
        request: PrivateAnalysisRequest,
        reference_digest: str,
    ) -> EvidenceReference | None:
        """Resolve an exact request-member reference in O(1) average time."""

        if type(request) is not PrivateAnalysisRequest:
            raise TypeError("request must be PrivateAnalysisRequest")
        if type(reference_digest) is not str:
            raise TypeError("reference_digest must be a string")
        entry = self._by_digest.get(reference_digest)
        if entry is None:
            return None
        reference = entry.reference
        if (
            reference.scope != request.scope
            or reference.revision not in request.revisions
        ):
            return None
        return _detached_reference(reference)

    def validate_reference(self, reference: EvidenceReference) -> bool:
        """Return true only for an exact reference stored in this snapshot."""

        try:
            detached = _detached_reference(reference)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - fail-closed callback boundary
            return False
        entry = self._by_digest.get(detached.reference_digest)
        return entry is not None and entry.reference == detached

    def validate_references(
        self,
        references: tuple[EvidenceReference, ...],
    ) -> bool:
        """Validate a detached query/read batch against one immutable corpus."""

        if type(references) is not tuple:
            return False
        return all(self.validate_reference(reference) for reference in references)

    def materialize_payload(
        self,
        reference: EvidenceReference,
    ) -> dict[str, object]:
        """Return a detached payload only for an exact stored reference."""

        detached = _detached_reference(reference)
        entry = self._by_digest.get(detached.reference_digest)
        if entry is None or entry.reference != detached:
            raise KeyError("evidence reference is not a corpus member")
        return entry.payload()


__all__ = [
    "DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES",
    "DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES",
    "MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES",
    "MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES",
    "PrivateAnalysisEvidenceCorpus",
    "PrivateAnalysisEvidenceEntry",
    "PrivateAnalysisEvidenceQueryCancellationProbeError",
    "PrivateAnalysisEvidenceQueryCancellationProbeResultError",
    "PrivateAnalysisEvidenceQueryCancelledError",
    "PrivateAnalysisEvidenceQueryTooBroadError",
]
