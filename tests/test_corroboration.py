from __future__ import annotations

import unittest
from uuid import UUID

from router_dump_analyzer.corroboration import (
    CorroborationError,
    CorroborationFact,
    CorroborationOutcome,
    CorroborationReasonCode,
    EventIdentity,
    ExactMatchClaim,
    ExactMatchState,
    ExplicitCausalLink,
    MatcherId,
    ResolvedEventRef,
    SourceRecordIdentity,
    TemporalRelation,
    corroborate_events,
    exact_match_claims,
)
from router_dump_analyzer.plugin_api import KeyAtom


def _claim(
    claim_id: str,
    partition_id: str,
    match_key: object,
    *,
    matcher: str = "example.matcher",
    evidence: tuple[object, ...] = (),
    provenance: tuple[object, ...] = (),
    payload: object = None,
) -> ExactMatchClaim:
    return ExactMatchClaim(
        claim_id=claim_id,
        partition_id=partition_id,
        matcher_id=MatcherId(matcher),
        match_key=match_key,
        evidence=evidence,
        provenance=provenance,
        payload=payload,
    )


class ExactCrossPartitionMatchingTests(unittest.TestCase):
    def test_canonical_keys_preserve_scalar_and_tagged_atom_types(self) -> None:
        identifier = UUID("7ff7d7dc-88c7-44df-8578-72b049c22500")
        keys = (
            1,
            "1",
            b"1",
            identifier,
            str(identifier),
            identifier.bytes,
            KeyAtom("uuid", identifier.bytes),
            (1,),
            [1],
        )
        claims = [
            _claim(f"left-{index}", "left", key) for index, key in enumerate(keys)
        ] + [_claim(f"right-{index}", "right", key) for index, key in enumerate(keys)]

        result = exact_match_claims(reversed(claims), max_candidates=100)

        self.assertEqual(len(result.groups), len(keys))
        self.assertEqual(result.candidate_count, len(keys))
        self.assertFalse(result.candidates_truncated)
        self.assertTrue(
            all(group.state is ExactMatchState.MATCHED for group in result.groups)
        )
        self.assertEqual(
            {
                (candidate.left.claim_id, candidate.right.claim_id)
                for candidate in result.candidates
            },
            {(f"left-{index}", f"right-{index}") for index in range(len(keys))},
        )
        self.assertEqual(
            len({group.typed_key for group in result.groups}),
            len(keys),
        )

    def test_matcher_identity_is_part_of_the_group_key(self) -> None:
        result = exact_match_claims(
            (
                _claim("a", "p1", "key", matcher="matcher.one"),
                _claim("b", "p2", "key", matcher="matcher.two"),
            )
        )

        self.assertEqual(len(result.groups), 2)
        self.assertEqual(result.candidate_count, 0)
        self.assertTrue(
            all(group.state is ExactMatchState.UNMATCHED for group in result.groups)
        )

    def test_duplicate_claim_identity_fails_closed(self) -> None:
        duplicate = (
            _claim("same", "partition", "first"),
            _claim("same", "partition", "second", matcher="different.matcher"),
        )

        with self.assertRaisesRegex(CorroborationError, "duplicate claim identity"):
            exact_match_claims(duplicate)

    def test_ambiguous_and_unmatched_groups_use_cross_partition_pairs_only(
        self,
    ) -> None:
        claims = (
            _claim("a-2", "a", "ambiguous"),
            _claim("a-1", "a", "ambiguous"),
            _claim("b-1", "b", "ambiguous"),
            _claim("c-1", "c", "ambiguous"),
            _claim("local-1", "a", "local"),
            _claim("local-2", "a", "local"),
            _claim("unique-left", "a", "unique"),
            _claim("unique-right", "b", "unique"),
        )

        result = exact_match_claims(claims, max_candidates=20)
        groups = {group.normalized_key["value"]: group for group in result.groups}

        self.assertEqual(groups["ambiguous"].candidate_count, 5)
        self.assertIs(groups["ambiguous"].state, ExactMatchState.AMBIGUOUS)
        self.assertEqual(groups["local"].candidate_count, 0)
        self.assertIs(groups["local"].state, ExactMatchState.UNMATCHED)
        self.assertEqual(groups["unique"].candidate_count, 1)
        self.assertIs(groups["unique"].state, ExactMatchState.MATCHED)
        self.assertNotIn(
            ("a-1", "a-2"),
            {
                (candidate.left.claim_id, candidate.right.claim_id)
                for candidate in result.candidates
            },
        )

    def test_candidate_output_is_bounded_without_losing_exact_cardinality(
        self,
    ) -> None:
        evidence = {"record": "kept-by-reference"}
        claims = tuple(
            _claim(
                f"left-{index:03d}",
                "left",
                "shared",
                evidence=(evidence,),
                provenance=("left-parser",),
            )
            for index in range(200)
        ) + tuple(
            _claim(
                f"right-{index:03d}",
                "right",
                "shared",
                provenance=("right-parser",),
            )
            for index in range(200)
        )

        result = exact_match_claims(claims, max_candidates=3)

        self.assertEqual(result.candidate_count, 40_000)
        self.assertEqual(len(result.candidates), 3)
        self.assertTrue(result.candidates_truncated)
        self.assertIs(result.groups[0].state, ExactMatchState.AMBIGUOUS)
        self.assertEqual(result.candidates[0].left.evidence[0], evidence)
        self.assertIsNot(result.candidates[0].left.evidence[0], evidence)
        self.assertEqual(
            result.candidates[0].left.provenance,
            ("left-parser",),
        )
        self.assertEqual(
            [
                (candidate.left.claim_id, candidate.right.claim_id)
                for candidate in result.candidates
            ],
            [
                ("left-000", "right-000"),
                ("left-000", "right-001"),
                ("left-000", "right-002"),
            ],
        )

        no_output = exact_match_claims(claims, max_candidates=0)
        self.assertEqual(no_output.candidate_count, 40_000)
        self.assertEqual(no_output.candidates, ())
        self.assertTrue(no_output.candidates_truncated)

    def test_output_order_does_not_depend_on_input_order(self) -> None:
        claims = (
            _claim("z", "partition-c", ("key", 2)),
            _claim("b", "partition-b", ("key", 1)),
            _claim("a", "partition-a", ("key", 1)),
            _claim("c", "partition-c", ("key", 1)),
            _claim("x", "partition-a", ("key", 2)),
        )

        forward = exact_match_claims(claims, max_candidates=20)
        backward = exact_match_claims(reversed(claims), max_candidates=20)

        self.assertEqual(
            [
                (
                    group.matcher_id,
                    group.typed_key,
                    group.state,
                    group.candidate_count,
                    tuple(
                        (claim.partition_id, claim.claim_id) for claim in group.claims
                    ),
                )
                for group in forward.groups
            ],
            [
                (
                    group.matcher_id,
                    group.typed_key,
                    group.state,
                    group.candidate_count,
                    tuple(
                        (claim.partition_id, claim.claim_id) for claim in group.claims
                    ),
                )
                for group in backward.groups
            ],
        )
        self.assertEqual(
            [
                (candidate.left.claim_id, candidate.right.claim_id)
                for candidate in forward.candidates
            ],
            [
                (candidate.left.claim_id, candidate.right.claim_id)
                for candidate in backward.candidates
            ],
        )

    def test_invalid_key_and_limit_fail_closed(self) -> None:
        with self.assertRaisesRegex(CorroborationError, "invalid exact-match key"):
            exact_match_claims((_claim("bad", "p1", object()),))
        with self.assertRaisesRegex(CorroborationError, "non-negative integer"):
            exact_match_claims((), max_candidates=-1)
        with self.assertRaisesRegex(CorroborationError, "non-negative integer"):
            exact_match_claims((), max_candidates=True)
        with self.assertRaisesRegex(CorroborationError, "non-negative integer"):
            exact_match_claims((), max_claims=-1)
        with self.assertRaisesRegex(CorroborationError, "non-negative integer"):
            exact_match_claims((), max_claims=True)
        with self.assertRaisesRegex(CorroborationError, "no greater than 100000"):
            exact_match_claims((), max_candidates=100_001)
        with self.assertRaisesRegex(CorroborationError, "no greater than 100000"):
            exact_match_claims((), max_claims=100_001)

    def test_claim_input_count_is_bounded_before_unbounded_grouping(self) -> None:
        claims = (
            _claim("first", "left", "shared"),
            _claim("second", "right", "shared"),
        )

        with self.assertRaisesRegex(
            CorroborationError,
            "claims support at most 1 values",
        ):
            exact_match_claims(claims, max_claims=1)

        empty = exact_match_claims((), max_claims=0)
        self.assertEqual(empty.groups, ())
        self.assertEqual(empty.candidates, ())

    def test_generic_claim_values_are_json_safe_and_bounded(self) -> None:
        payload = {"status": ["up", {"source": "plugin"}]}
        valid = _claim(
            "valid",
            "partition",
            "key",
            evidence=({"record": 7},),
            provenance=("plugin.matcher",),
            payload=payload,
        )
        self.assertEqual(valid.payload, payload)
        self.assertIsNot(valid.payload, payload)
        payload["status"].append("mutated")
        self.assertEqual(
            valid.payload,
            {"status": ["up", {"source": "plugin"}]},
        )

    def test_exact_match_result_snapshots_mutable_claim_values(self) -> None:
        original_key = ["circuit", {"side": "left"}]
        original_payload = {"state": ["up"]}
        left = _claim(
            "left",
            "a",
            original_key,
            evidence=({"source": [1]},),
            payload=original_payload,
        )
        right = _claim("right", "b", ["circuit", {"side": "left"}])
        original_key.append("caller mutation")
        original_payload["state"].append("caller mutation")

        result = exact_match_claims((left, right))
        selected = result.candidates[0].left
        assert isinstance(left.payload, dict)
        assert isinstance(left.payload["state"], list)
        left.payload["state"].append("post-match mutation")
        assert isinstance(left.evidence[0], dict)
        left.evidence[0]["source"].append(2)

        self.assertEqual(selected.match_key, ["circuit", {"side": "left"}])
        self.assertEqual(selected.payload, {"state": ["up"]})
        self.assertEqual(selected.evidence, ({"source": [1]},))

        with self.assertRaisesRegex(CorroborationError, "non-JSON type object"):
            _claim(
                "bad-payload",
                "partition",
                "key",
                payload=object(),
            )
        with self.assertRaisesRegex(
            CorroborationError,
            "arrays support at most 256 items",
        ):
            _claim(
                "too-much-evidence",
                "partition",
                "key",
                evidence=tuple(range(257)),
            )
        recursive: list[object] = []
        recursive.append(recursive)
        with self.assertRaisesRegex(CorroborationError, "reference cycles"):
            _claim(
                "cyclic-provenance",
                "partition",
                "key",
                provenance=(recursive,),
            )


class GenericEventCorroborationTests(unittest.TestCase):
    def test_event_and_causal_generic_values_use_the_same_bounds(self) -> None:
        identity = EventIdentity("revision-a", "event-1")
        with self.assertRaisesRegex(CorroborationError, "non-JSON type object"):
            ExplicitCausalLink(
                "link-1",
                identity,
                evidence=(object(),),
            )
        with self.assertRaisesRegex(CorroborationError, "non-JSON type object"):
            ResolvedEventRef(
                identity,
                provenance=(object(),),
            )

    def test_event_collections_and_time_bounds_fail_closed(self) -> None:
        identity = EventIdentity("revision-a", "event-1")
        source = SourceRecordIdentity("source-a", "record-a")
        with self.assertRaisesRegex(CorroborationError, "must be a tuple"):
            ResolvedEventRef(
                identity,
                source_records=[source],  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(CorroborationError, "duplicates"):
            ResolvedEventRef(
                identity,
                source_records=(source, source),
            )
        with self.assertRaisesRegex(CorroborationError, "duplicates"):
            ResolvedEventRef(
                identity,
                canonical_resource_ids=("resource-a", "resource-a"),
            )
        link = ExplicitCausalLink("link-a", identity)
        with self.assertRaisesRegex(CorroborationError, "duplicate link ids"):
            ResolvedEventRef(
                identity,
                causal_links=(link, link),
            )
        with self.assertRaisesRegex(CorroborationError, "signed 64-bit"):
            ResolvedEventRef(
                identity,
                earliest_ns=-(1 << 63) - 1,
                latest_ns=1,
            )
        with self.assertRaisesRegex(CorroborationError, "signed 64-bit"):
            ResolvedEventRef(
                identity,
                earliest_ns=0,
                latest_ns=1 << 63,
            )
        signed = ResolvedEventRef(
            identity,
            earliest_ns=-(1 << 63),
            latest_ns=-1,
            clock_domain="utc",
        )
        self.assertEqual(signed.earliest_ns, -(1 << 63))

    def test_fact_shape_and_combined_evidence_are_bounded(self) -> None:
        left_identity = EventIdentity("revision-a", "event-1")
        right_identity = EventIdentity("revision-b", "event-2")
        with self.assertRaisesRegex(CorroborationError, "outcome"):
            CorroborationFact(
                left=left_identity,
                right=right_identity,
                outcome="supports",  # type: ignore[arg-type]
                reason_code=CorroborationReasonCode.NO_CORROBORATING_LINK,
                temporal_relation=TemporalRelation.UNKNOWN,
            )

        links = tuple(
            ExplicitCausalLink(
                f"link-{index}",
                right_identity,
                evidence=tuple(range(256)),
            )
            for index in range(17)
        )
        with self.assertRaisesRegex(
            CorroborationError,
            "supports at most 4096 values",
        ):
            corroborate_events(
                ResolvedEventRef(
                    left_identity,
                    causal_links=links,
                ),
                ResolvedEventRef(right_identity),
            )

    def test_independent_generic_facts_preserve_evidence_and_provenance(
        self,
    ) -> None:
        left_identity = EventIdentity("revision-a", "event-1")
        right_identity = EventIdentity("revision-b", "event-2")
        source_record = SourceRecordIdentity("capture-7", "record-42")
        link_evidence = {"assertion": "plug-in-owned"}
        left = ResolvedEventRef(
            identity=left_identity,
            source_records=(source_record,),
            canonical_resource_ids=("resource:opaque:1",),
            earliest_ns=100,
            latest_ns=110,
            clock_domain="utc",
            causal_links=(
                ExplicitCausalLink(
                    "causal-1",
                    right_identity,
                    evidence=(link_evidence,),
                    provenance=("plugin.linker",),
                ),
            ),
            evidence=("left-evidence",),
            provenance=("left-parser",),
        )
        right = ResolvedEventRef(
            identity=right_identity,
            source_records=(source_record,),
            canonical_resource_ids=("resource:opaque:1",),
            earliest_ns=120,
            latest_ns=140,
            clock_domain="utc",
            evidence=("right-evidence",),
            provenance=("right-parser",),
        )

        facts = corroborate_events(left, right)

        self.assertEqual(
            [fact.reason_code for fact in facts],
            [
                CorroborationReasonCode.EXPLICIT_CAUSAL_LINK,
                CorroborationReasonCode.SAME_SOURCE_RECORD,
                CorroborationReasonCode.SHARED_RESOURCE_ORDERED,
            ],
        )
        self.assertTrue(
            all(fact.outcome is CorroborationOutcome.SUPPORTS for fact in facts)
        )
        self.assertTrue(
            all(fact.temporal_relation is TemporalRelation.BEFORE for fact in facts)
        )
        self.assertEqual(facts[0].causal_link_ids, ("causal-1",))
        self.assertEqual(facts[1].shared_source_records, (source_record,))
        self.assertEqual(
            facts[2].shared_resource_ids,
            ("resource:opaque:1",),
        )
        self.assertEqual(facts[0].evidence[-1], link_evidence)
        self.assertIsNot(facts[0].evidence[-1], link_evidence)
        self.assertEqual(
            facts[0].provenance,
            ("left-parser", "right-parser", "plugin.linker"),
        )

    def test_live_corroboration_values_are_deeply_detached(self) -> None:
        left_identity = EventIdentity("revision-a", "event-1")
        right_identity = EventIdentity("revision-b", "event-2")
        caller_link_evidence = {"path": ["original"]}
        caller_event_evidence = {"event": ["original"]}
        caller_fact_evidence = {"fact": ["original"]}
        link = ExplicitCausalLink(
            "causal-1",
            right_identity,
            evidence=(caller_link_evidence,),
        )
        left = ResolvedEventRef(
            left_identity,
            causal_links=(link,),
            evidence=(caller_event_evidence,),
        )
        fact = CorroborationFact(
            left=left_identity,
            right=right_identity,
            outcome=CorroborationOutcome.UNKNOWN,
            reason_code=CorroborationReasonCode.NO_CORROBORATING_LINK,
            temporal_relation=TemporalRelation.UNKNOWN,
            evidence=(caller_fact_evidence,),
        )

        caller_link_evidence["path"].append("caller mutation")
        caller_event_evidence["event"].append("caller mutation")
        caller_fact_evidence["fact"].append("caller mutation")
        self.assertEqual(link.evidence, ({"path": ["original"]},))
        self.assertEqual(left.evidence, ({"event": ["original"]},))
        self.assertEqual(fact.evidence, ({"fact": ["original"]},))

        facts = corroborate_events(left, ResolvedEventRef(right_identity))
        assert isinstance(left.evidence[0], dict)
        assert isinstance(left.evidence[0]["event"], list)
        left.evidence[0]["event"].append("post-call mutation")
        assert isinstance(left.causal_links[0].evidence[0], dict)
        assert isinstance(left.causal_links[0].evidence[0]["path"], list)
        left.causal_links[0].evidence[0]["path"].append("post-call mutation")

        self.assertEqual(
            facts[0].evidence,
            ({"event": ["original"]}, {"path": ["original"]}),
        )

    def test_reverse_temporal_order_is_a_contradiction(self) -> None:
        left = ResolvedEventRef(
            EventIdentity("node-a", "later"),
            canonical_resource_ids=("opaque/resource",),
            earliest_ns=200,
            latest_ns=210,
            clock_domain="utc",
        )
        right = ResolvedEventRef(
            EventIdentity("node-b", "earlier"),
            canonical_resource_ids=("opaque/resource",),
            earliest_ns=100,
            latest_ns=110,
            clock_domain="utc",
        )

        (fact,) = corroborate_events(left, right)

        self.assertIs(fact.outcome, CorroborationOutcome.CONTRADICTS)
        self.assertIs(
            fact.reason_code,
            CorroborationReasonCode.SHARED_RESOURCE_REVERSE_ORDER,
        )
        self.assertIs(fact.temporal_relation, TemporalRelation.AFTER)

    def test_shared_source_record_respects_asserted_temporal_direction(
        self,
    ) -> None:
        source = SourceRecordIdentity("capture", "record-1")
        cases = (
            (
                "before",
                (100, 110, "utc"),
                (120, 130, "utc"),
                CorroborationOutcome.SUPPORTS,
                TemporalRelation.BEFORE,
            ),
            (
                "after",
                (200, 210, "utc"),
                (100, 110, "utc"),
                CorroborationOutcome.CONTRADICTS,
                TemporalRelation.AFTER,
            ),
            (
                "overlap",
                (100, 150, "utc"),
                (140, 170, "utc"),
                CorroborationOutcome.UNKNOWN,
                TemporalRelation.OVERLAPS,
            ),
            (
                "missing",
                (None, None, None),
                (100, 110, "utc"),
                CorroborationOutcome.UNKNOWN,
                TemporalRelation.UNKNOWN,
            ),
            (
                "unaligned",
                (100, 110, "node-a"),
                (120, 130, "node-b"),
                CorroborationOutcome.UNKNOWN,
                TemporalRelation.UNKNOWN,
            ),
        )
        for name, left_time, right_time, outcome, relation in cases:
            with self.subTest(name=name):
                left = ResolvedEventRef(
                    EventIdentity("left", name),
                    source_records=(source,),
                    earliest_ns=left_time[0],
                    latest_ns=left_time[1],
                    clock_domain=left_time[2],
                )
                right = ResolvedEventRef(
                    EventIdentity("right", name),
                    source_records=(source,),
                    earliest_ns=right_time[0],
                    latest_ns=right_time[1],
                    clock_domain=right_time[2],
                )
                (fact,) = corroborate_events(left, right)
                self.assertIs(
                    fact.reason_code,
                    CorroborationReasonCode.SAME_SOURCE_RECORD,
                )
                self.assertIs(fact.outcome, outcome)
                self.assertIs(fact.temporal_relation, relation)

    def test_uncertain_overlap_and_missing_time_remain_unknown(self) -> None:
        identity = EventIdentity("node-a", "event-a")
        overlap = corroborate_events(
            ResolvedEventRef(
                identity,
                canonical_resource_ids=("resource",),
                earliest_ns=100,
                latest_ns=150,
                clock_domain="utc",
            ),
            ResolvedEventRef(
                EventIdentity("node-b", "event-b"),
                canonical_resource_ids=("resource",),
                earliest_ns=140,
                latest_ns=170,
                clock_domain="utc",
            ),
        )
        unknown_time = corroborate_events(
            ResolvedEventRef(identity, canonical_resource_ids=("resource",)),
            ResolvedEventRef(
                EventIdentity("node-b", "event-b"),
                canonical_resource_ids=("resource",),
            ),
        )

        self.assertIs(overlap[0].outcome, CorroborationOutcome.UNKNOWN)
        self.assertIs(
            overlap[0].reason_code,
            CorroborationReasonCode.SHARED_RESOURCE_TIME_OVERLAP,
        )
        self.assertIs(overlap[0].temporal_relation, TemporalRelation.OVERLAPS)
        self.assertIs(unknown_time[0].outcome, CorroborationOutcome.UNKNOWN)
        self.assertIs(
            unknown_time[0].reason_code,
            CorroborationReasonCode.SHARED_RESOURCE_TIME_UNKNOWN,
        )
        self.assertIs(unknown_time[0].temporal_relation, TemporalRelation.UNKNOWN)

    def test_no_linkage_does_not_infer_semantics_from_lookalike_values(self) -> None:
        left = ResolvedEventRef(
            EventIdentity("node-a", "event-a"),
            source_records=(SourceRecordIdentity("capture-a", "same"),),
            canonical_resource_ids=("10.0.0.1",),
            earliest_ns=100,
            latest_ns=100,
        )
        right = ResolvedEventRef(
            EventIdentity("node-b", "event-b"),
            source_records=(SourceRecordIdentity("capture-b", "same"),),
            canonical_resource_ids=("0a000001",),
            earliest_ns=200,
            latest_ns=200,
        )

        (fact,) = corroborate_events(left, right)

        self.assertIs(fact.outcome, CorroborationOutcome.UNKNOWN)
        self.assertIs(
            fact.reason_code,
            CorroborationReasonCode.NO_CORROBORATING_LINK,
        )
        self.assertEqual(fact.shared_source_records, ())
        self.assertEqual(fact.shared_resource_ids, ())

    def test_explicit_support_and_temporal_contradiction_can_coexist(self) -> None:
        left_identity = EventIdentity("node-a", "later")
        right_identity = EventIdentity("node-b", "earlier")
        left = ResolvedEventRef(
            left_identity,
            canonical_resource_ids=("resource",),
            earliest_ns=200,
            latest_ns=210,
            clock_domain="utc",
            causal_links=(ExplicitCausalLink("declared", right_identity),),
        )
        right = ResolvedEventRef(
            right_identity,
            canonical_resource_ids=("resource",),
            earliest_ns=100,
            latest_ns=110,
            clock_domain="utc",
        )

        facts = corroborate_events(left, right)

        self.assertEqual(
            [(fact.reason_code, fact.outcome) for fact in facts],
            [
                (
                    CorroborationReasonCode.EXPLICIT_CAUSAL_LINK,
                    CorroborationOutcome.SUPPORTS,
                ),
                (
                    CorroborationReasonCode.SHARED_RESOURCE_REVERSE_ORDER,
                    CorroborationOutcome.CONTRADICTS,
                ),
            ],
        )

    def test_reverse_explicit_causal_link_contradicts_requested_order(self) -> None:
        left_identity = EventIdentity("node-a", "event-a")
        right_identity = EventIdentity("node-b", "event-b")
        facts = corroborate_events(
            ResolvedEventRef(left_identity),
            ResolvedEventRef(
                right_identity,
                causal_links=(ExplicitCausalLink("reverse", left_identity),),
            ),
        )

        self.assertEqual(len(facts), 1)
        self.assertIs(facts[0].outcome, CorroborationOutcome.CONTRADICTS)
        self.assertIs(
            facts[0].reason_code,
            CorroborationReasonCode.EXPLICIT_REVERSE_CAUSAL_LINK,
        )
        self.assertEqual(facts[0].causal_link_ids, ("reverse",))

    def test_cross_clock_shared_resource_is_auditable_unknown(self) -> None:
        left = ResolvedEventRef(
            EventIdentity("node-a", "event-a"),
            canonical_resource_ids=("resource",),
            earliest_ns=100,
            latest_ns=110,
            clock_domain="node-a:realtime",
        )
        right = ResolvedEventRef(
            EventIdentity("node-b", "event-b"),
            canonical_resource_ids=("resource",),
            earliest_ns=200,
            latest_ns=210,
            clock_domain="node-b:realtime",
        )

        (fact,) = corroborate_events(left, right)

        self.assertIs(fact.outcome, CorroborationOutcome.UNKNOWN)
        self.assertIs(
            fact.reason_code,
            CorroborationReasonCode.SHARED_RESOURCE_CLOCK_UNALIGNED,
        )
        self.assertIs(fact.temporal_relation, TemporalRelation.UNKNOWN)
        self.assertEqual(fact.left_clock_domain, "node-a:realtime")
        self.assertEqual(fact.right_clock_domain, "node-b:realtime")

    def test_invalid_time_interval_fails_closed(self) -> None:
        with self.assertRaisesRegex(CorroborationError, "requires both"):
            ResolvedEventRef(
                EventIdentity("node", "event"),
                earliest_ns=10,
            )
        with self.assertRaisesRegex(CorroborationError, "must not be later"):
            ResolvedEventRef(
                EventIdentity("node", "event"),
                earliest_ns=20,
                latest_ns=10,
            )


if __name__ == "__main__":
    unittest.main()
