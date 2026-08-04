from __future__ import annotations

import json
import math
import unittest
from dataclasses import FrozenInstanceError, replace
from typing import Any

from router_dump_analyzer.private_analysis import (
    EVIDENCE_ENVELOPE_VERSION,
    EVIDENCE_REFERENCE_VERSION,
    MAX_EVIDENCE_PAYLOAD_BYTES,
    CoreEvidenceProducer,
    DisclosureDecision,
    DisclosureDecisionReason,
    EvidenceAuthority,
    EvidenceFactProvenance,
    EvidenceKind,
    EvidenceProducer,
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
    EvidenceTimeBasis,
    EvidenceTimeRange,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisTransport,
    disclosure_scope_digest,
    evidence_envelope_dict,
    evidence_envelope_from_dict,
    evidence_envelope_from_json,
    evidence_envelope_json,
    evidence_locator_digest,
    evidence_payload_digest,
    evidence_reference_dict,
    evidence_reference_from_dict,
    make_evidence_envelope,
)


def _revision(suffix: str = "a") -> EvidenceRevisionBinding:
    return EvidenceRevisionBinding(
        fixture_id=f"fixture-{suffix}",
        fixture_content_sha256=suffix * 64,
        node_id=f"node-{suffix}",
        revision_id=f"revision-{suffix}",
        revision_identity_sha256=("b" if suffix == "a" else "c") * 64,
        plan_basis_revision_id=f"basis-{suffix}",
        execution_plan_digest="sha256:" + ("d" if suffix == "a" else "e") * 64,
    )


def _scope(suffix: str = "a") -> EvidenceScope:
    return EvidenceScope(
        tenant_id=f"tenant-{suffix}",
        project_id=f"project-{suffix}",
        workspace_id=f"workspace-{suffix}",
    )


def _decision(
    evidence_class: PrivateAnalysisEvidenceClass = (
        PrivateAnalysisEvidenceClass.PROPRIETARY
    ),
    *,
    allowed: bool = True,
) -> DisclosureDecision:
    return DisclosureDecision(
        policy_digest="9" * 64,
        scope_digest=disclosure_scope_digest(
            tenant_id="tenant-a",
            project_id="project-a",
            workspace_id="workspace-a",
        ),
        transport=PrivateAnalysisTransport.IN_PROCESS,
        evidence_class=evidence_class,
        allowed=allowed,
        reason=(
            DisclosureDecisionReason.ALLOWED
            if allowed
            else DisclosureDecisionReason.EVIDENCE_CLASS_NOT_APPROVED
        ),
    )


def _reference(
    payload: dict[str, Any] | None = None,
    *,
    evidence_class: PrivateAnalysisEvidenceClass = (
        PrivateAnalysisEvidenceClass.PROPRIETARY
    ),
    authority: EvidenceAuthority = EvidenceAuthority.PLUGIN_INFERRED,
) -> EvidenceReference:
    value = payload or {"message": "full-fidelity event", "timestamp_ns": "17"}
    revision = _revision()
    producer = (
        EvidenceProducer(
            authority=authority,
            producer_id="vendor.event-parser",
            plugin_instance_id="parser-1",
            plugin_capability="source_record_parser",
        )
        if authority is EvidenceAuthority.PLUGIN_INFERRED
        else EvidenceProducer(
            authority=authority,
            producer_id=CoreEvidenceProducer.CORROBORATION_V1.value,
        )
    )
    return EvidenceReference(
        scope=_scope(),
        revision=revision,
        producer=producer,
        kind=EvidenceKind.SOURCE_RECORD,
        subject_kind="lttng_event",
        locator_digest=evidence_locator_digest(
            "lttng_event",
            {"source_record_uid": "secret-source-id", "ordinal": 17},
        ),
        evidence_class=evidence_class,
        payload_schema="vendor.lttng.event.v3",
        fact_provenance=EvidenceFactProvenance.OBSERVED,
        time_range=EvidenceTimeRange(
            EvidenceTimeBasis.REVISION_START_RELATIVE_NS,
            start_ns=-3,
            end_ns=5,
            uncertainty_ns=2,
        ),
        content_digest=evidence_payload_digest("vendor.lttng.event.v3", value),
    )


class PrivateAnalysisEvidenceTests(unittest.TestCase):
    def test_reference_and_envelope_round_trip_exact_canonical_wire(self) -> None:
        payload = {
            "message": "EVPN 恢復 \u0000 \U0001f6a7",
            "timestamp_ns": "9223372036854775807",
            "labels": [16000, 16001],
        }
        reference = _reference(payload)
        envelope = make_evidence_envelope(reference, _decision(), payload)

        self.assertEqual(reference.contract_version, EVIDENCE_REFERENCE_VERSION)
        self.assertEqual(envelope.contract_version, EVIDENCE_ENVELOPE_VERSION)
        self.assertEqual(
            evidence_reference_from_dict(evidence_reference_dict(reference)),
            reference,
        )
        self.assertEqual(
            evidence_envelope_from_dict(evidence_envelope_dict(envelope)),
            envelope,
        )
        encoded = evidence_envelope_json(envelope)
        self.assertEqual(evidence_envelope_from_json(encoded), envelope)
        self.assertEqual(encoded, json.dumps(json.loads(encoded), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        self.assertIn("恢復", encoded)
        self.assertIn("\\u0000", encoded)

    def test_payload_is_deeply_detached_in_both_directions(self) -> None:
        payload: dict[str, object] = {"nested": {"items": [1, 2]}}
        envelope = make_evidence_envelope(_reference(payload), _decision(), payload)
        nested = payload["nested"]
        assert isinstance(nested, dict)
        items = nested["items"]
        assert isinstance(items, list)
        items.append(3)
        self.assertEqual(envelope.payload, {"nested": {"items": [1, 2]}})

        detached = envelope.payload
        detached_nested = detached["nested"]
        assert isinstance(detached_nested, dict)
        detached_nested["items"] = []
        self.assertEqual(envelope.payload, {"nested": {"items": [1, 2]}})
        with self.assertRaises(FrozenInstanceError):
            envelope.payload_json = "{}"  # type: ignore[misc]

    def test_locator_is_typed_opaque_and_does_not_echo_raw_identity(self) -> None:
        integer = evidence_locator_digest("event", {"id": 1})
        string = evidence_locator_digest("event", {"id": "1"})
        other_kind = evidence_locator_digest("record", {"id": 1})
        self.assertNotEqual(integer, string)
        self.assertNotEqual(integer, other_kind)
        reference_wire = json.dumps(evidence_reference_dict(_reference()))
        self.assertNotIn("secret-source-id", reference_wire)
        self.assertNotIn("locator", set(evidence_reference_dict(_reference())))

    def test_reference_digest_binds_every_identity_and_semantic_tier(self) -> None:
        base = _reference()
        changes = (
            replace(base, scope=replace(base.scope, tenant_id="tenant-b"), reference_digest=""),
            replace(base, scope=replace(base.scope, project_id="project-b"), reference_digest=""),
            replace(base, scope=replace(base.scope, workspace_id="workspace-b"), reference_digest=""),
            replace(base, revision=_revision("f"), reference_digest=""),
            replace(base, kind=EvidenceKind.EVENT, reference_digest=""),
            replace(base, subject_kind="source_record", reference_digest=""),
            replace(base, locator_digest="sha256:" + "3" * 64, reference_digest=""),
            replace(base, evidence_class=PrivateAnalysisEvidenceClass.CLIENT_SAFE, reference_digest=""),
            replace(base, payload_schema="vendor.lttng.event.v4", reference_digest=""),
            replace(
                base,
                fact_provenance=EvidenceFactProvenance.LOG_DERIVED,
                reference_digest="",
            ),
            replace(base, time_range=EvidenceTimeRange.not_applicable(), reference_digest=""),
            replace(base, content_digest="sha256:" + "4" * 64, reference_digest=""),
        )
        for changed in changes:
            with self.subTest(changed=changed):
                self.assertNotEqual(changed.reference_digest, base.reference_digest)

        plugin = base.producer
        producer_changes = (
            replace(plugin, producer_id="vendor.other"),
            replace(plugin, plugin_instance_id="parser-2"),
            replace(plugin, plugin_capability="event_mapper"),
        )
        for producer in producer_changes:
            changed = replace(base, producer=producer, reference_digest="")
            self.assertNotEqual(changed.reference_digest, base.reference_digest)

    def test_payload_digest_is_projection_schema_bound(self) -> None:
        payload = {"value": "same record"}
        first = evidence_payload_digest("vendor.full.v1", payload)
        second = evidence_payload_digest("vendor.client-safe.v1", payload)
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("sha256:"))
        self.assertEqual(len(first), 71)

    def test_revision_binding_covers_raw_fixture_dataset_and_plan(self) -> None:
        base = _revision()
        fields = {
            "fixture_id": "fixture-z",
            "fixture_content_sha256": "3" * 64,
            "node_id": "node-z",
            "revision_id": "revision-z",
            "revision_identity_sha256": "4" * 64,
            "plan_basis_revision_id": "basis-z",
            "execution_plan_digest": "sha256:" + "5" * 64,
        }
        original = _reference()
        for field, value in fields.items():
            binding = replace(base, **{field: value})
            changed = replace(
                original,
                revision=binding,
                reference_digest="",
            )
            self.assertNotEqual(changed.reference_digest, original.reference_digest)

    def test_reference_and_envelope_tampering_fails_closed(self) -> None:
        payload = {"value": "private"}
        reference = _reference(payload)
        wire = evidence_reference_dict(reference)
        wire["subject_kind"] = "different"
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            evidence_reference_from_dict(wire)

        envelope = make_evidence_envelope(reference, _decision(), payload)
        envelope_wire = evidence_envelope_dict(envelope)
        envelope_payload = envelope_wire["payload"]
        assert isinstance(envelope_payload, dict)
        envelope_payload["value"] = "substituted"
        with self.assertRaisesRegex(ValueError, "payload digest"):
            evidence_envelope_from_dict(envelope_wire)

        envelope_wire = evidence_envelope_dict(envelope)
        envelope_wire["envelope_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "envelope digest"):
            evidence_envelope_from_dict(envelope_wire)

    def test_disclosure_decision_is_part_of_and_required_by_envelope(self) -> None:
        payload = {"value": "private"}
        reference = _reference(payload)
        first = make_evidence_envelope(reference, _decision(), payload)
        second_decision = replace(_decision(), policy_digest="8" * 64)
        second = make_evidence_envelope(reference, second_decision, payload)
        self.assertNotEqual(first.envelope_digest, second.envelope_digest)

        with self.assertRaisesRegex(ValueError, "allowed decision"):
            make_evidence_envelope(reference, _decision(allowed=False), payload)
        with self.assertRaisesRegex(ValueError, "evidence class disagree"):
            make_evidence_envelope(
                reference,
                _decision(PrivateAnalysisEvidenceClass.CLIENT_SAFE),
                payload,
            )

        other_scope = replace(
            reference,
            scope=_scope("b"),
            reference_digest="",
        )
        with self.assertRaisesRegex(ValueError, "evidence scope disagree"):
            make_evidence_envelope(other_scope, _decision(), payload)

        never_reference = _reference(
            payload,
            evidence_class=PrivateAnalysisEvidenceClass.NEVER_ASSISTANT,
        )
        with self.assertRaisesRegex(ValueError, "never-assistant"):
            make_evidence_envelope(
                never_reference,
                _decision(PrivateAnalysisEvidenceClass.NEVER_ASSISTANT),
                payload,
            )

    def test_disclosure_is_rejected_before_payload_validation(self) -> None:
        reference = _reference()
        invalid_payload = {"unsafe_integer": 1 << 53}

        with self.assertRaisesRegex(ValueError, "allowed decision"):
            make_evidence_envelope(
                reference,
                _decision(allowed=False),
                invalid_payload,
            )

        wire = evidence_envelope_dict(
            make_evidence_envelope(
                reference,
                _decision(),
                {"message": "full-fidelity event", "timestamp_ns": "17"},
            )
        )
        decision = wire["disclosure_decision"]
        assert isinstance(decision, dict)
        decision["allowed"] = False
        decision["reason"] = (
            DisclosureDecisionReason.EVIDENCE_CLASS_NOT_APPROVED.value
        )
        wire["payload"] = invalid_payload
        with self.assertRaisesRegex(ValueError, "allowed decision"):
            evidence_envelope_from_dict(wire)

    def test_plugin_producer_is_exact_and_plan_bound(self) -> None:
        with self.assertRaisesRegex(ValueError, "capability and instance"):
            EvidenceProducer(
                authority=EvidenceAuthority.PLUGIN_INFERRED,
                producer_id="vendor.plugin",
            )
        with self.assertRaisesRegex(ValueError, "only plugin-inferred"):
            EvidenceProducer(
                authority=EvidenceAuthority.CORE_CORROBORATION,
                producer_id="core",
                plugin_instance_id="instance",
                plugin_capability="route_resolver",
            )
        with self.assertRaisesRegex(ValueError, "core evidence producer"):
            EvidenceProducer(
                authority=EvidenceAuthority.CORE_CORROBORATION,
                producer_id="assistant.output.v1",
            )
        with self.assertRaisesRegex(ValueError, "execution_plan_digest"):
            replace(_revision(), execution_plan_digest="d" * 64)
        for provenance in (
            "assistant_suggested",
            "assistant_generated",
            "user_asserted",
            "mutable_user_annotation",
        ):
            with (
                self.subTest(provenance=provenance),
                self.assertRaisesRegex(TypeError, "EvidenceFactProvenance"),
            ):
                replace(
                    _reference(),
                    fact_provenance=provenance,  # type: ignore[arg-type]
                    reference_digest="",
                )

    def test_multi_node_claims_compose_distinct_atomic_references(self) -> None:
        left = _reference()
        right = replace(
            left,
            scope=_scope("b"),
            revision=_revision("f"),
            reference_digest="",
        )
        self.assertNotEqual(left.reference_digest, right.reference_digest)
        self.assertEqual(len({left.reference_digest, right.reference_digest}), 2)

    def test_time_coordinate_semantics_are_explicit_and_signed(self) -> None:
        relative = EvidenceTimeRange(
            EvidenceTimeBasis.REVISION_END_RELATIVE_NS,
            start_ns=-(1 << 63),
            end_ns=-1,
        )
        self.assertEqual(relative.start_ns, -(1 << 63))
        source = EvidenceTimeRange(
            EvidenceTimeBasis.SOURCE_CLOCK_NS,
            start_ns=1,
            end_ns=2,
            clock_domain="router-monotonic",
        )
        self.assertEqual(source.clock_domain, "router-monotonic")
        with self.assertRaisesRegex(ValueError, "requires clock_domain"):
            EvidenceTimeRange(
                EvidenceTimeBasis.SOURCE_CLOCK_NS,
                start_ns=1,
                end_ns=2,
            )
        with self.assertRaisesRegex(ValueError, "only for source-clock"):
            EvidenceTimeRange(
                EvidenceTimeBasis.ABSOLUTE_UNIX_NS,
                start_ns=1,
                end_ns=2,
                clock_domain="wrong",
            )
        with self.assertRaisesRegex(ValueError, "between 0"):
            EvidenceTimeRange(
                EvidenceTimeBasis.ABSOLUTE_UNIX_NS,
                start_ns=-1,
                end_ns=2,
            )
        with self.assertRaisesRegex(ValueError, "must not exceed"):
            EvidenceTimeRange(
                EvidenceTimeBasis.REVISION_START_RELATIVE_NS,
                start_ns=2,
                end_ns=1,
            )
        with self.assertRaisesRegex(ValueError, "must not carry"):
            EvidenceTimeRange(EvidenceTimeBasis.NOT_APPLICABLE, start_ns=0)

    def test_wire_coordinates_are_canonical_decimal_strings(self) -> None:
        wire = evidence_reference_dict(_reference())
        time_range = wire["time_range"]
        assert isinstance(time_range, dict)
        self.assertEqual(time_range["start_ns"], "-3")
        time_range["start_ns"] = "-03"
        with self.assertRaises(ValueError):
            evidence_reference_from_dict(wire)

    def test_payload_contract_rejects_nonportable_or_unbounded_values(self) -> None:
        invalid_payloads: tuple[object, ...] = (
            {"tuple": (1, 2)},
            {"set": {1, 2}},
            {"nan": math.nan},
            {"infinite": math.inf},
            {"unsafe_integer": 1 << 53},
            {"surrogate": "\ud800"},
        )
        for index, payload in enumerate(invalid_payloads):
            with (
                self.subTest(index=index),
                self.assertRaises((TypeError, ValueError)),
            ):
                    evidence_payload_digest("schema.v1", payload)  # type: ignore[arg-type]

        cyclic: dict[str, object] = {}
        cyclic["self"] = cyclic
        with self.assertRaisesRegex(ValueError, "reference cycles"):
            evidence_payload_digest("schema.v1", cyclic)
        with self.assertRaisesRegex(ValueError, "strings exceed|encoded UTF-8 bytes"):
            evidence_payload_digest(
                "schema.v1",
                {"large": "x" * (MAX_EVIDENCE_PAYLOAD_BYTES + 1)},
            )

    def test_exact_fields_versions_and_canonical_json_fail_closed(self) -> None:
        envelope = make_evidence_envelope(_reference(), _decision(), {"message": "full-fidelity event", "timestamp_ns": "17"})
        wire = evidence_envelope_dict(envelope)
        wire["unknown"] = True
        with self.assertRaisesRegex(ValueError, "exactly"):
            evidence_envelope_from_dict(wire)

        reference_wire = evidence_reference_dict(envelope.reference)
        reference_wire["contract_version"] = "future"
        with self.assertRaisesRegex(ValueError, "unsupported"):
            evidence_reference_from_dict(reference_wire)

        reference_wire = evidence_reference_dict(envelope.reference)
        producer = reference_wire["producer"]
        assert isinstance(producer, dict)
        producer["authority"] = "assistant_suggested"
        with self.assertRaisesRegex(ValueError, "authority is unsupported"):
            evidence_reference_from_dict(reference_wire)

        reference_wire = evidence_reference_dict(envelope.reference)
        reference_wire["reference_digest"] = ""
        with self.assertRaisesRegex(ValueError, "reference_digest"):
            evidence_reference_from_dict(reference_wire)

        envelope_wire = evidence_envelope_dict(envelope)
        envelope_wire["envelope_digest"] = ""
        with self.assertRaisesRegex(ValueError, "envelope_digest"):
            evidence_envelope_from_dict(envelope_wire)

        envelope_wire = evidence_envelope_dict(envelope)
        nested_reference = envelope_wire["reference"]
        assert isinstance(nested_reference, dict)
        nested_reference["reference_digest"] = ""
        with self.assertRaisesRegex(ValueError, "reference_digest"):
            evidence_envelope_from_dict(envelope_wire)

        envelope_wire = evidence_envelope_dict(envelope)
        envelope_wire["contract_version"] = "future"
        with self.assertRaisesRegex(ValueError, "unsupported"):
            evidence_envelope_from_dict(envelope_wire)

        canonical = evidence_envelope_json(envelope)
        pretty = json.dumps(json.loads(canonical), indent=2, ensure_ascii=False)
        with self.assertRaisesRegex(ValueError, "exact canonical"):
            evidence_envelope_from_json(pretty)
        duplicate = '{"contract_version":"a","contract_version":"b"}'
        with self.assertRaisesRegex(ValueError, "strict JSON"):
            evidence_envelope_from_json(duplicate)
        pathological = "[" * 2_000 + "0" + "]" * 2_000
        with self.assertRaisesRegex(ValueError, "strict JSON|JSON object"):
            evidence_envelope_from_json(pathological)

    def test_reference_wire_contains_no_raw_locator_or_runtime_handle_field(self) -> None:
        wire = evidence_reference_dict(_reference())

        def keys(value: object) -> set[str]:
            result: set[str] = set()
            if isinstance(value, dict):
                for key, child in value.items():
                    result.add(key)
                    result.update(keys(child))
            elif isinstance(value, list):
                for child in value:
                    result.update(keys(child))
            return result

        forbidden = {
            "path",
            "filesystem_path",
            "database_handle",
            "callback",
            "plugin_object",
            "route_context_id",
            "topology_context_id",
            "plugin_run_id",
            "raw_locator",
        }
        self.assertTrue(forbidden.isdisjoint(keys(wire)))

    def test_reference_identifiers_reject_host_path_shapes(self) -> None:
        path_shapes = (
            r"C:\Users\alice\secret",
            r"\\server\share\dump",
            "/var/lib/router/dump",
            "../../tenant-secret",
            "file:///tmp/dump",
            "/v1/etc/passwd",
            "/api/private/workspace",
            "tenant /v1/etc/passwd",
            "./private/dump",
            r".\private\dump",
            r"C:private\dump",
            r"\private",
            "relative/private/dump",
        )
        for value in path_shapes:
            with self.subTest(value=value), self.assertRaises(ValueError):
                replace(_scope(), workspace_id=value)


if __name__ == "__main__":
    unittest.main()
