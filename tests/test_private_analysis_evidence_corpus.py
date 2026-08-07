from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event, Lock
from time import monotonic
from unittest.mock import patch

import router_dump_analyzer.private_analysis.evidence_corpus as evidence_corpus_module
from router_dump_analyzer.private_analysis import (
    CoreEvidenceProducer,
    EvidenceAuthority,
    EvidenceFactProvenance,
    EvidenceKind,
    EvidenceProducer,
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
    EvidenceTimeBasis,
    EvidenceTimeRange,
    PrivateAnalysisClockMode,
    PrivateAnalysisCursor,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisEvidenceCorpus,
    PrivateAnalysisEvidenceCursorInvalidError,
    PrivateAnalysisEvidenceEntry,
    PrivateAnalysisEvidenceQueryCancellationProbeError,
    PrivateAnalysisEvidenceQueryCancellationProbeResultError,
    PrivateAnalysisEvidenceQueryCancelledError,
    PrivateAnalysisLimits,
    PrivateAnalysisQueryArguments,
    PrivateAnalysisRequest,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTaskKind,
    PrivateAnalysisTransport,
    default_private_analysis_tool_catalog,
    evidence_locator_digest,
    evidence_payload_digest,
)
from router_dump_analyzer.private_analysis_tool_service import (
    PrivateAnalysisPayloadMaterializer,
    PrivateAnalysisReferencePageQuery,
    PrivateAnalysisReferenceResolver,
    PrivateAnalysisReferenceValidator,
)


def _scope(suffix: str = "a") -> EvidenceScope:
    return EvidenceScope(
        tenant_id=f"tenant-{suffix}",
        project_id=f"project-{suffix}",
        workspace_id=f"workspace-{suffix}",
    )


def _revision(ordinal: int, *, node_id: str | None = None) -> EvidenceRevisionBinding:
    return EvidenceRevisionBinding(
        fixture_id=f"fixture-{ordinal:03d}",
        fixture_content_sha256=f"{ordinal + 1:064x}",
        node_id=node_id or f"node-{ordinal:03d}",
        revision_id=f"revision-{ordinal:03d}",
        revision_identity_sha256=f"{ordinal + 2:064x}",
        plan_basis_revision_id=f"basis-{ordinal:03d}",
        execution_plan_digest="sha256:" + f"{ordinal + 3:064x}",
    )


def _payload(ordinal: int) -> dict[str, object]:
    return {"ordinal": ordinal, "status": "observed"}


def _entry(
    ordinal: int,
    *,
    scope: EvidenceScope | None = None,
    revision: EvidenceRevisionBinding | None = None,
    kind: EvidenceKind = EvidenceKind.EVENT,
    subject_kind: str = "ctf_event",
    producer_id: str = CoreEvidenceProducer.CORROBORATION_V1.value,
    time_ns: int | None = None,
) -> PrivateAnalysisEvidenceEntry:
    payload = _payload(ordinal)
    producer = EvidenceProducer(
        authority=EvidenceAuthority.CORE_CORROBORATION,
        producer_id=producer_id,
    )
    reference = EvidenceReference(
        scope=scope or _scope(),
        revision=revision or _revision(1),
        producer=producer,
        kind=kind,
        subject_kind=subject_kind,
        locator_digest=evidence_locator_digest(
            subject_kind,
            {"ordinal": ordinal},
        ),
        evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        payload_schema="test.corpus-evidence.v1",
        fact_provenance=EvidenceFactProvenance.CORE_CORROBORATED,
        time_range=(
            EvidenceTimeRange.not_applicable()
            if time_ns is None
            else EvidenceTimeRange(
                EvidenceTimeBasis.ABSOLUTE_UNIX_NS,
                start_ns=time_ns,
                end_ns=time_ns,
            )
        ),
        content_digest=evidence_payload_digest(
            "test.corpus-evidence.v1",
            payload,
        ),
    )
    return PrivateAnalysisEvidenceEntry(reference, payload)


def _request(
    revisions: tuple[EvidenceRevisionBinding, ...],
    *,
    scope: EvidenceScope | None = None,
) -> PrivateAnalysisRequest:
    return PrivateAnalysisRequest(
        scope=scope or _scope(),
        revisions=revisions,
        runner=PrivateAnalysisRunnerSelection(
            runner_id="deployment.private-runner",
            runner_version="1.0.0",
            transport=PrivateAnalysisTransport.IN_PROCESS,
            configuration_digest="sha256:" + "a" * 64,
        ),
        workspace_policy_digest="b" * 64,
        instruction_profile_digest="sha256:" + "c" * 64,
        tool_catalog_digest=default_private_analysis_tool_catalog().catalog_digest,
        task_kind=PrivateAnalysisTaskKind.LTTNG_ANALYSIS,
        query="Correlate events.",
        clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
        selected_time_ns=None,
        limits=PrivateAnalysisLimits(),
    )


class PrivateAnalysisEvidenceEntryTests(unittest.TestCase):
    def test_entry_snapshots_input_and_materializations(self) -> None:
        payload = _payload(1)
        reference = _entry(1).reference
        entry = PrivateAnalysisEvidenceEntry(reference, payload)

        payload["status"] = "mutated"
        first = entry.payload
        first["status"] = "also-mutated"

        self.assertEqual(entry.payload, {"ordinal": 1, "status": "observed"})
        self.assertIsNot(entry.reference, reference)

    def test_entry_rejects_payload_reference_digest_conflict(self) -> None:
        with self.assertRaisesRegex(ValueError, "payload digest"):
            PrivateAnalysisEvidenceEntry(_entry(1).reference, _payload(2))


class PrivateAnalysisEvidenceCorpusTests(unittest.TestCase):
    def test_corpus_has_deterministic_digest_order_and_rejects_duplicates(self) -> None:
        entries = tuple(_entry(ordinal) for ordinal in range(1, 5))
        corpus = PrivateAnalysisEvidenceCorpus(tuple(reversed(entries)))

        self.assertEqual(
            corpus.reference_digests, tuple(sorted(corpus.reference_digests))
        )
        self.assertEqual(
            corpus.reference_digests,
            PrivateAnalysisEvidenceCorpus(entries).reference_digests,
        )
        with self.assertRaisesRegex(ValueError, "must be unique"):
            PrivateAnalysisEvidenceCorpus((entries[0], entries[0]))

    def test_corpus_enforces_exact_container_and_entry_bound(self) -> None:
        entry = _entry(1)
        self.assertGreater(entry.payload_bytes, 0)
        with self.assertRaisesRegex(TypeError, "entries must be a tuple"):
            PrivateAnalysisEvidenceCorpus([entry])  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "at most 1"):
            PrivateAnalysisEvidenceCorpus(
                (entry, _entry(2)),
                maximum_entries=1,
            )
        with self.assertRaisesRegex(ValueError, "payload byte limit"):
            PrivateAnalysisEvidenceCorpus(
                (entry,),
                maximum_payload_bytes=entry.payload_bytes - 1,
            )
        corpus = PrivateAnalysisEvidenceCorpus(
            (entry,),
            maximum_payload_bytes=entry.payload_bytes,
        )
        self.assertEqual(corpus.payload_bytes, entry.payload_bytes)

    def test_trusted_construction_cancels_during_global_and_index_ordering(
        self,
    ) -> None:
        class ConstructionCancelled(Exception):
            pass

        entries = tuple(_entry(ordinal) for ordinal in range(1, 258))
        original_sort = evidence_corpus_module._checkpointed_sorted
        for phase, expected_sort_calls in (("global", 1), ("index", 2)):
            with self.subTest(phase=phase):
                state = {"sort_calls": 0}

                def checkpoint(
                    *,
                    state: dict[str, int] = state,
                    cancel_after: int = expected_sort_calls,
                ) -> None:
                    if state["sort_calls"] >= cancel_after:
                        raise ConstructionCancelled

                def observed_sort(  # type: ignore[no-untyped-def]
                    values,
                    construction_checkpoint,
                    *,
                    state: dict[str, int] = state,
                ):
                    state["sort_calls"] += 1
                    return original_sort(values, construction_checkpoint)

                with (
                    patch.object(
                        evidence_corpus_module,
                        "_checkpointed_sorted",
                        side_effect=observed_sort,
                    ),
                    self.assertRaises(ConstructionCancelled),
                ):
                    PrivateAnalysisEvidenceCorpus._from_trusted_entries(
                        entries,
                        maximum_entries=len(entries),
                        construction_checkpoint=checkpoint,
                    )
                self.assertEqual(state["sort_calls"], expected_sort_calls)

    def test_query_intersects_request_membership_and_all_filter_indexes(self) -> None:
        revision_a = _revision(1, node_id="node-a")
        revision_b = _revision(2, node_id="node-b")
        foreign_scope = _scope("foreign")
        event_a = _entry(1, revision=revision_a)
        source_a = _entry(
            2,
            revision=revision_a,
            kind=EvidenceKind.SOURCE_RECORD,
            subject_kind="ctf_record",
            producer_id=CoreEvidenceProducer.REVISION_METADATA_V1.value,
        )
        event_b = _entry(3, revision=revision_b)
        foreign = _entry(4, scope=foreign_scope, revision=revision_a)
        corpus = PrivateAnalysisEvidenceCorpus((foreign, event_b, source_a, event_a))
        request = _request((revision_a, revision_b))

        unfiltered = corpus.query_references(request, PrivateAnalysisQueryArguments())
        self.assertEqual(
            tuple(item.reference_digest for item in unfiltered.references),
            tuple(
                sorted(
                    (
                        event_a.reference.reference_digest,
                        source_a.reference.reference_digest,
                        event_b.reference.reference_digest,
                    )
                )
            ),
        )
        filtered = corpus.query_references(
            request,
            PrivateAnalysisQueryArguments(
                evidence_kinds=(EvidenceKind.SOURCE_RECORD,),
                node_ids=("node-a",),
                producer_ids=(CoreEvidenceProducer.REVISION_METADATA_V1.value,),
                subject_kinds=("ctf_record",),
            ),
        )
        self.assertEqual(
            tuple(item.reference_digest for item in filtered.references),
            (source_a.reference.reference_digest,),
        )

    def test_resolve_validate_and_materialize_are_exact_and_detached(self) -> None:
        revision = _revision(1)
        entry = _entry(1, revision=revision)
        corpus = PrivateAnalysisEvidenceCorpus((entry,))
        request = _request((revision,))

        resolved = corpus.resolve_reference(
            request,
            entry.reference.reference_digest,
        )
        self.assertEqual(resolved, entry.reference)
        self.assertIsNot(resolved, entry.reference)
        self.assertTrue(corpus.validate_reference(entry.reference))
        payload = corpus.materialize_payload(entry.reference)
        payload["status"] = "mutated"
        self.assertEqual(corpus.materialize_payload(entry.reference), _payload(1))

        foreign_request = _request((revision,), scope=_scope("foreign"))
        self.assertIsNone(
            corpus.resolve_reference(
                foreign_request,
                entry.reference.reference_digest,
            )
        )
        self.assertIsNone(corpus.resolve_reference(request, "sha256:" + "0" * 64))
        conflicting = replace(
            entry.reference,
            content_digest="sha256:" + "0" * 64,
            reference_digest="",
        )
        self.assertFalse(corpus.validate_reference(conflicting))
        self.assertFalse(corpus.validate_reference(object.__new__(EvidenceReference)))
        with self.assertRaisesRegex(KeyError, "not a corpus member"):
            corpus.materialize_payload(conflicting)

    def test_methods_match_all_tool_service_evidence_callback_contracts(self) -> None:
        corpus = PrivateAnalysisEvidenceCorpus((_entry(1),))
        query: PrivateAnalysisReferencePageQuery = corpus.query_references
        resolver: PrivateAnalysisReferenceResolver = corpus.resolve_reference
        validator: PrivateAnalysisReferenceValidator = corpus.validate_reference
        materializer: PrivateAnalysisPayloadMaterializer = corpus.materialize_payload

        self.assertTrue(all(map(callable, (query, resolver, validator, materializer))))

    def test_indexed_snapshot_filter_uses_canonical_results(self) -> None:
        revision = _revision(1, node_id="node-a")
        entries = tuple(
            _entry(
                ordinal,
                revision=revision,
                kind=(
                    EvidenceKind.EVENT if ordinal % 10 else EvidenceKind.SOURCE_RECORD
                ),
                subject_kind="ctf_event" if ordinal % 10 else "ctf_record",
            )
            for ordinal in range(1, 1_001)
        )
        corpus = PrivateAnalysisEvidenceCorpus(tuple(reversed(entries)))
        request = _request((revision,))

        result = corpus.query_references(
            request,
            PrivateAnalysisQueryArguments(
                evidence_kinds=(EvidenceKind.SOURCE_RECORD,),
                node_ids=("node-a",),
                subject_kinds=("ctf_record",),
            ),
        )

        self.assertEqual(len(corpus), 1_000)
        self.assertEqual(len(result.references), 100)
        self.assertEqual(
            tuple(item.reference_digest for item in result.references),
            tuple(sorted(item.reference_digest for item in result.references)),
        )

    def test_time_window_indexes_points_expands_uncertainty_and_excludes_unknown(
        self,
    ) -> None:
        revision = _revision(1)
        timed = _entry(1, revision=revision, time_ns=100)
        uncertain_reference = replace(
            timed.reference,
            time_range=EvidenceTimeRange(
                EvidenceTimeBasis.ABSOLUTE_UNIX_NS,
                start_ns=100,
                end_ns=100,
                uncertainty_ns=10,
            ),
            reference_digest="",
        )
        uncertain = PrivateAnalysisEvidenceEntry(uncertain_reference, timed.payload)
        unknown_seed = _entry(2, revision=revision)
        unknown_reference = replace(
            unknown_seed.reference,
            time_range=EvidenceTimeRange.unknown(),
            reference_digest="",
        )
        unknown = PrivateAnalysisEvidenceEntry(unknown_reference, unknown_seed.payload)
        corpus = PrivateAnalysisEvidenceCorpus((uncertain, unknown))
        request = _request((revision,))

        self.assertEqual(
            len(
                corpus.query_references(
                    request, PrivateAnalysisQueryArguments()
                ).references
            ),
            2,
        )
        bounded = corpus.query_references(
            request,
            PrivateAnalysisQueryArguments(
                time_basis=EvidenceTimeBasis.ABSOLUTE_UNIX_NS,
                time_start_ns=90,
                time_end_ns=90,
            ),
        )
        self.assertEqual(bounded.references, (uncertain.reference,))

    def test_evicted_continuation_fails_without_rebuilding_membership(self) -> None:
        revision = _revision(1)
        corpus = PrivateAnalysisEvidenceCorpus(
            tuple(_entry(ordinal, revision=revision) for ordinal in range(1, 5))
        )
        request = _request((revision,))
        first_arguments = PrivateAnalysisQueryArguments(page_size=1)
        first = corpus.query_references(request, first_arguments)
        self.assertTrue(first.has_more)
        continuation = replace(
            first_arguments,
            cursor=PrivateAnalysisCursor(
                request_digest=request.request_digest,
                tool_catalog_digest=request.tool_catalog_digest,
                query_digest=first_arguments.query_digest,
                snapshot_digest=first.snapshot_digest,
                after_reference_digest=first.references[-1].reference_digest,
            ),
        )

        # The cache holds 16 snapshots. Sixteen newer fingerprints evict the
        # first query's snapshot without ever changing the immutable corpus.
        for page_size in range(2, 18):
            corpus.query_references(
                request,
                PrivateAnalysisQueryArguments(page_size=page_size),
            )

        def unexpected_build(*_args: object) -> object:
            raise AssertionError("continuation attempted to rebuild membership")

        with (
            patch.object(
                PrivateAnalysisEvidenceCorpus,
                "_build_query_snapshot",
                new=unexpected_build,
            ),
            self.assertRaisesRegex(
                PrivateAnalysisEvidenceCursorInvalidError,
                "no longer available",
            ),
        ):
            corpus.query_references(request, continuation)

    def test_evicted_continuation_never_joins_cursorless_rebuild(self) -> None:
        revision = _revision(1)
        corpus = PrivateAnalysisEvidenceCorpus(
            tuple(_entry(ordinal, revision=revision) for ordinal in range(1, 5))
        )
        request = _request((revision,))
        first_arguments = PrivateAnalysisQueryArguments(page_size=1)
        first = corpus.query_references(request, first_arguments)
        continuation = replace(
            first_arguments,
            cursor=PrivateAnalysisCursor(
                request_digest=request.request_digest,
                tool_catalog_digest=request.tool_catalog_digest,
                query_digest=first_arguments.query_digest,
                snapshot_digest=first.snapshot_digest,
                after_reference_digest=first.references[-1].reference_digest,
            ),
        )
        for page_size in range(2, 18):
            corpus.query_references(
                request,
                PrivateAnalysisQueryArguments(page_size=page_size),
            )

        original = PrivateAnalysisEvidenceCorpus._build_query_snapshot
        started = Event()
        release = Event()

        def blocked_build(selected, *args):  # type: ignore[no-untyped-def]
            started.set()
            if not release.wait(5):
                raise AssertionError("snapshot build release timed out")
            return original(selected, *args)

        with (
            patch.object(
                PrivateAnalysisEvidenceCorpus,
                "_build_query_snapshot",
                new=blocked_build,
            ),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            producer = executor.submit(
                corpus.query_references,
                request,
                first_arguments,
            )
            self.assertTrue(started.wait(2))
            stale = executor.submit(
                corpus.query_references,
                request,
                continuation,
            )
            try:
                with self.assertRaises(
                    PrivateAnalysisEvidenceCursorInvalidError
                ):
                    stale.result(timeout=1)
                self.assertFalse(producer.done())
            finally:
                release.set()
            rebuilt = producer.result(timeout=5)

        self.assertEqual(rebuilt.references, first.references)

    def test_identical_concurrent_queries_build_one_snapshot(self) -> None:
        revision = _revision(1)
        corpus = PrivateAnalysisEvidenceCorpus(
            tuple(_entry(ordinal, revision=revision) for ordinal in range(1, 65))
        )
        request = _request((revision,))
        arguments = PrivateAnalysisQueryArguments(page_size=8)
        original = PrivateAnalysisEvidenceCorpus._build_query_snapshot
        started = Event()
        release = Event()
        counter_lock = Lock()
        builds = 0

        def blocked_build(selected, *args):  # type: ignore[no-untyped-def]
            nonlocal builds
            with counter_lock:
                builds += 1
            started.set()
            if not release.wait(5):
                raise AssertionError("snapshot build release timed out")
            return original(selected, *args)

        with (
            patch.object(
                PrivateAnalysisEvidenceCorpus,
                "_build_query_snapshot",
                new=blocked_build,
            ),
            ThreadPoolExecutor(max_workers=8) as executor,
        ):
            futures = tuple(
                executor.submit(corpus.query_references, request, arguments)
                for _ in range(8)
            )
            self.assertTrue(started.wait(2))
            release.set()
            pages = tuple(future.result(timeout=5) for future in futures)

        self.assertEqual(builds, 1)
        self.assertTrue(all(page == pages[0] for page in pages))

    def test_broad_query_cancels_during_predicate_scan_and_cleans_producer(
        self,
    ) -> None:
        revision = _revision(1)
        corpus = PrivateAnalysisEvidenceCorpus(
            tuple(_entry(ordinal, revision=revision) for ordinal in range(1_024))
        )
        request = _request((revision,))
        arguments = PrivateAnalysisQueryArguments(page_size=8)
        predicate_calls = 0
        original_time_matches = evidence_corpus_module._time_matches

        def observed_time_matches(reference, selected):  # type: ignore[no-untyped-def]
            nonlocal predicate_calls
            predicate_calls += 1
            return original_time_matches(reference, selected)

        with (
            patch.object(
                evidence_corpus_module,
                "_time_matches",
                new=observed_time_matches,
            ),
            self.assertRaises(PrivateAnalysisEvidenceQueryCancelledError),
        ):
            corpus.query_references(
                request,
                arguments,
                cancellation_probe=lambda: predicate_calls >= 8,
            )

        self.assertGreaterEqual(predicate_calls, 8)
        self.assertLess(predicate_calls, 128)
        self.assertFalse(corpus._query_building)
        retry = corpus.query_references(request, arguments)
        self.assertEqual(len(retry.references), 8)

    def test_cancelled_singleflight_waiter_leaves_producer_and_cache_intact(
        self,
    ) -> None:
        revision = _revision(1)
        corpus = PrivateAnalysisEvidenceCorpus(
            tuple(_entry(ordinal, revision=revision) for ordinal in range(64))
        )
        request = _request((revision,))
        arguments = PrivateAnalysisQueryArguments(page_size=8)
        original = PrivateAnalysisEvidenceCorpus._build_query_snapshot
        started = Event()
        release = Event()
        cancelled = Event()
        waiter_polled = Event()
        probe_calls = 0
        builds = 0

        def blocked_build(selected, *args):  # type: ignore[no-untyped-def]
            nonlocal builds
            builds += 1
            started.set()
            if not release.wait(5):
                raise AssertionError("snapshot build release timed out")
            return original(selected, *args)

        def waiter_probe() -> bool:
            nonlocal probe_calls
            probe_calls += 1
            if probe_calls >= 3:
                waiter_polled.set()
            return cancelled.is_set()

        with (
            patch.object(
                PrivateAnalysisEvidenceCorpus,
                "_build_query_snapshot",
                new=blocked_build,
            ),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            producer = executor.submit(corpus.query_references, request, arguments)
            self.assertTrue(started.wait(2))
            waiter = executor.submit(
                corpus.query_references,
                request,
                arguments,
                tuple(PrivateAnalysisEvidenceClass),
                waiter_probe,
            )
            self.assertTrue(waiter_polled.wait(2))
            cancelled.set()
            with self.assertRaises(PrivateAnalysisEvidenceQueryCancelledError):
                waiter.result(timeout=1)
            self.assertFalse(producer.done())
            self.assertIn(
                (
                    request.request_digest,
                    arguments.query_digest,
                    tuple(sorted(item.value for item in PrivateAnalysisEvidenceClass)),
                ),
                corpus._query_building,
            )
            release.set()
            produced = producer.result(timeout=5)

        cached = corpus.query_references(request, arguments)
        self.assertEqual(builds, 1)
        self.assertEqual(cached, produced)
        self.assertFalse(corpus._query_building)

    def test_deadline_probe_interrupts_singleflight_wait(self) -> None:
        revision = _revision(1)
        corpus = PrivateAnalysisEvidenceCorpus(
            tuple(_entry(ordinal, revision=revision) for ordinal in range(64))
        )
        request = _request((revision,))
        arguments = PrivateAnalysisQueryArguments(page_size=8)
        original = PrivateAnalysisEvidenceCorpus._build_query_snapshot
        started = Event()
        release = Event()

        def blocked_build(selected, *args):  # type: ignore[no-untyped-def]
            started.set()
            if not release.wait(5):
                raise AssertionError("snapshot build release timed out")
            return original(selected, *args)

        with (
            patch.object(
                PrivateAnalysisEvidenceCorpus,
                "_build_query_snapshot",
                new=blocked_build,
            ),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            producer = executor.submit(corpus.query_references, request, arguments)
            self.assertTrue(started.wait(2))
            deadline = monotonic() + 0.1
            waiter = executor.submit(
                corpus.query_references,
                request,
                arguments,
                tuple(PrivateAnalysisEvidenceClass),
                lambda: monotonic() >= deadline,
            )
            with self.assertRaises(PrivateAnalysisEvidenceQueryCancelledError):
                waiter.result(timeout=1)
            self.assertFalse(producer.done())
            release.set()
            producer.result(timeout=5)

        self.assertFalse(corpus._query_building)

    def test_query_cancellation_probe_failures_are_typed_static_and_strict(
        self,
    ) -> None:
        revision = _revision(1)
        corpus = PrivateAnalysisEvidenceCorpus((_entry(1, revision=revision),))
        request = _request((revision,))
        arguments = PrivateAnalysisQueryArguments()

        def unavailable() -> bool:
            raise RuntimeError("secret cancellation diagnostic")

        with self.assertRaises(
            PrivateAnalysisEvidenceQueryCancellationProbeError
        ) as caught:
            corpus.query_references(
                request,
                arguments,
                cancellation_probe=unavailable,
            )
        self.assertNotIn("secret", str(caught.exception))
        with self.assertRaises(
            PrivateAnalysisEvidenceQueryCancellationProbeResultError
        ):
            corpus.query_references(
                request,
                arguments,
                cancellation_probe=lambda: 1,  # type: ignore[return-value]
            )

        def interrupted() -> bool:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            corpus.query_references(
                request,
                arguments,
                cancellation_probe=interrupted,
            )

    def test_more_than_100k_homogeneous_events_page_without_rebuilding_snapshot(
        self,
    ) -> None:
        revision = _revision(1, node_id="node-a")
        selected = _entry(
            1,
            revision=revision,
            subject_kind="normalized_event",
            time_ns=100_001,
        )
        bulk = tuple(
            _entry(
                ordinal + 2,
                revision=revision,
                subject_kind="normalized_event",
                time_ns=ordinal,
            )
            for ordinal in range(100_000)
        )
        # This is the same trusted path used after the core has constructed and
        # digest-validated every production projection entry.  Nothing is
        # forged and no validation/hash helper is patched out.
        corpus = PrivateAnalysisEvidenceCorpus._from_trusted_entries(
            bulk + (selected,),
            maximum_entries=100_001,
        )
        request = _request((revision,))
        snapshot_builds = 0
        original_build = PrivateAnalysisEvidenceCorpus._build_query_snapshot

        def counted_build(selected, *args):  # type: ignore[no-untyped-def]
            nonlocal snapshot_builds
            snapshot_builds += 1
            return original_build(selected, *args)

        self.assertGreater(len(corpus), 100_000)
        with patch.object(
                PrivateAnalysisEvidenceCorpus,
                "_build_query_snapshot",
                new=counted_build,
            ):
            first_arguments = PrivateAnalysisQueryArguments(page_size=256)
            first = corpus.query_references(request, first_arguments)
            self.assertEqual(len(first.references), 256)
            self.assertTrue(first.has_more)
            second = corpus.query_references(
                request,
                replace(
                    first_arguments,
                    cursor=PrivateAnalysisCursor(
                        request_digest=request.request_digest,
                        tool_catalog_digest=request.tool_catalog_digest,
                        query_digest=first_arguments.query_digest,
                        snapshot_digest=first.snapshot_digest,
                        after_reference_digest=first.references[-1].reference_digest,
                    ),
                ),
            )
            self.assertEqual(len(second.references), 256)
            self.assertGreater(
                second.references[0].reference_digest,
                first.references[-1].reference_digest,
            )
            self.assertEqual(snapshot_builds, 1)
            narrowed = corpus.query_references(
                request,
                PrivateAnalysisQueryArguments(
                    evidence_kinds=(EvidenceKind.EVENT,),
                    time_basis=EvidenceTimeBasis.ABSOLUTE_UNIX_NS,
                    time_start_ns=99_999,
                    time_end_ns=100_001,
                ),
            )
            self.assertEqual(snapshot_builds, 2)
        self.assertEqual(len(narrowed.references), 2)
        self.assertIn(selected.reference, narrowed.references)


if __name__ == "__main__":
    unittest.main()
