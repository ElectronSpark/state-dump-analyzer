from __future__ import annotations

import copy
import dataclasses
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from typing import Any, cast
from unittest.mock import patch

from router_dump_analyzer.private_analysis import (
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
    EvidenceTimeRange,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisTransport,
    disclosure_scope_digest,
    evidence_locator_digest,
    evidence_payload_digest,
    make_evidence_envelope,
)
from router_dump_analyzer.private_analysis.tool_catalog import (
    MAX_PRIVATE_ANALYSIS_QUERY_FILTER_ITEMS,
    MAX_PRIVATE_ANALYSIS_QUERY_PAGE_SIZE,
    PrivateAnalysisQueryArguments,
    PrivateAnalysisReadArguments,
    PrivateAnalysisToolBinding,
    PrivateAnalysisToolCall,
    PrivateAnalysisToolCatalog,
    PrivateAnalysisToolError,
    PrivateAnalysisToolErrorCode,
    PrivateAnalysisToolName,
    PrivateAnalysisToolResult,
    PrivateAnalysisToolResultKind,
    default_private_analysis_tool_catalog,
    evidence_snapshot_digest,
    make_private_analysis_cursor,
    make_private_analysis_query_page,
    private_analysis_cursor_dict,
    private_analysis_cursor_from_dict,
    private_analysis_cursor_from_json,
    private_analysis_cursor_json,
    private_analysis_query_arguments_dict,
    private_analysis_query_arguments_from_dict,
    private_analysis_query_arguments_from_json,
    private_analysis_query_arguments_json,
    private_analysis_read_arguments_dict,
    private_analysis_read_arguments_from_dict,
    private_analysis_read_arguments_from_json,
    private_analysis_read_arguments_json,
    private_analysis_tool_binding_dict,
    private_analysis_tool_binding_from_dict,
    private_analysis_tool_binding_from_json,
    private_analysis_tool_binding_json,
    private_analysis_tool_call_dict,
    private_analysis_tool_call_from_dict,
    private_analysis_tool_call_from_json,
    private_analysis_tool_call_json,
    private_analysis_tool_catalog_dict,
    private_analysis_tool_catalog_from_dict,
    private_analysis_tool_catalog_from_json,
    private_analysis_tool_catalog_json,
    private_analysis_tool_definition_dict,
    private_analysis_tool_definition_from_dict,
    private_analysis_tool_definition_from_json,
    private_analysis_tool_definition_json,
    private_analysis_tool_error_dict,
    private_analysis_tool_error_from_dict,
    private_analysis_tool_error_from_json,
    private_analysis_tool_error_json,
    private_analysis_tool_result_dict,
    private_analysis_tool_result_from_dict,
    private_analysis_tool_result_from_json,
    private_analysis_tool_result_json,
)

_REQUEST_A = "sha256:" + "1" * 64
_REQUEST_B = "sha256:" + "2" * 64


def _scope() -> EvidenceScope:
    return EvidenceScope(
        tenant_id="tenant-a",
        project_id="project-a",
        workspace_id="workspace-a",
    )


def _revision(ordinal: int = 1) -> EvidenceRevisionBinding:
    return EvidenceRevisionBinding(
        fixture_id=f"fixture-{ordinal}",
        fixture_content_sha256=f"{ordinal:064x}",
        node_id=f"node-{ordinal}",
        revision_id=f"revision-{ordinal}",
        revision_identity_sha256=f"{ordinal + 100:064x}",
        plan_basis_revision_id=f"basis-{ordinal}",
        execution_plan_digest="sha256:" + f"{ordinal + 200:064x}",
    )


def _reference(ordinal: int = 1) -> EvidenceReference:
    payload = {"ordinal": ordinal, "message": f"event-{ordinal}"}
    return EvidenceReference(
        scope=_scope(),
        revision=_revision(ordinal),
        producer=EvidenceProducer(
            authority=EvidenceAuthority.CORE_CORROBORATION,
            producer_id=CoreEvidenceProducer.CORROBORATION_V1.value,
        ),
        kind=EvidenceKind.EVENT,
        subject_kind="route_event",
        locator_digest=evidence_locator_digest(
            "route_event",
            {"event_id": f"event-{ordinal}"},
        ),
        evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        payload_schema="test.route-event.v1",
        fact_provenance=EvidenceFactProvenance.CORE_CORROBORATED,
        time_range=EvidenceTimeRange.not_applicable(),
        content_digest=evidence_payload_digest("test.route-event.v1", payload),
    )


def _envelope(ordinal: int = 1):
    reference = _reference(ordinal)
    payload = {"ordinal": ordinal, "message": f"event-{ordinal}"}
    decision = DisclosureDecision(
        policy_digest="9" * 64,
        scope_digest=disclosure_scope_digest(
            tenant_id="tenant-a",
            project_id="project-a",
            workspace_id="workspace-a",
        ),
        transport=PrivateAnalysisTransport.IN_PROCESS,
        evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        allowed=True,
        reason=DisclosureDecisionReason.ALLOWED,
    )
    return make_evidence_envelope(reference, decision, payload)


def _binding(
    name: PrivateAnalysisToolName,
    *,
    request_digest: str = _REQUEST_A,
) -> PrivateAnalysisToolBinding:
    return PrivateAnalysisToolBinding(
        request_digest=request_digest,
        tool_catalog_digest=default_private_analysis_tool_catalog().catalog_digest,
        name=name,
    )


def _query_arguments(**changes: Any) -> PrivateAnalysisQueryArguments:
    values: dict[str, Any] = {
        "evidence_kinds": (EvidenceKind.EVENT,),
        "node_ids": (),
        "producer_ids": (CoreEvidenceProducer.CORROBORATION_V1.value,),
        "subject_kinds": ("route_event",),
        "page_size": 2,
    }
    values.update(changes)
    return PrivateAnalysisQueryArguments(**values)


def _query_call(
    *,
    arguments: PrivateAnalysisQueryArguments | None = None,
    request_digest: str = _REQUEST_A,
) -> PrivateAnalysisToolCall:
    return PrivateAnalysisToolCall(
        call_id="call-query-1",
        binding=_binding(
            PrivateAnalysisToolName.QUERY_EVIDENCE,
            request_digest=request_digest,
        ),
        arguments=arguments or _query_arguments(),
    )


def _read_call(ordinal: int = 1) -> PrivateAnalysisToolCall:
    return PrivateAnalysisToolCall(
        call_id=f"call-read-{ordinal}",
        binding=_binding(PrivateAnalysisToolName.READ_EVIDENCE),
        arguments=PrivateAnalysisReadArguments(
            evidence_reference_digest=_reference(ordinal).reference_digest,
        ),
    )


class PrivateAnalysisToolCatalogTests(unittest.TestCase):
    def test_catalog_is_closed_canonical_frozen_and_value_only(self) -> None:
        catalog = default_private_analysis_tool_catalog()
        self.assertEqual(
            tuple(tool.name for tool in catalog.tools),
            (
                PrivateAnalysisToolName.QUERY_EVIDENCE,
                PrivateAnalysisToolName.READ_EVIDENCE,
            ),
        )
        self.assertTrue(catalog.catalog_digest.startswith("sha256:"))
        for value in (catalog, *catalog.tools):
            for field in dataclasses.fields(cast(Any, value)):
                self.assertNotIn(
                    field.name,
                    {
                        "handler",
                        "callback",
                        "executor",
                        "plugin",
                        "path",
                        "socket",
                        "database",
                    },
                )
        with self.assertRaises(FrozenInstanceError):
            catalog.catalog_digest = _REQUEST_A  # type: ignore[misc]

        with self.assertRaises(TypeError):

            class Derived(PrivateAnalysisToolCatalog):
                pass

    def test_catalog_rejects_missing_reordered_duplicate_and_third_tools(self) -> None:
        catalog = default_private_analysis_tool_catalog()
        invalid = (
            catalog.tools[:1],
            tuple(reversed(catalog.tools)),
            (catalog.tools[0], catalog.tools[0]),
            (*catalog.tools, catalog.tools[0]),
        )
        for tools in invalid:
            with self.subTest(tools=tools), self.assertRaises((TypeError, ValueError)):
                PrivateAnalysisToolCatalog(tools=tools)
        with self.assertRaises(TypeError):
            PrivateAnalysisToolCatalog(tools=list(catalog.tools))  # type: ignore[arg-type]

    def test_catalog_and_message_values_round_trip_exact_canonical_json(self) -> None:
        catalog = default_private_analysis_tool_catalog()
        query_arguments = _query_arguments()
        query_call = _query_call(arguments=query_arguments)
        snapshot = evidence_snapshot_digest((_reference(1), _reference(2)))
        cursor = make_private_analysis_cursor(
            query_call,
            snapshot_digest=snapshot,
            after_reference_digest=_reference(2).reference_digest,
        )
        read_arguments = PrivateAnalysisReadArguments(
            evidence_reference_digest=_reference(1).reference_digest
        )
        read_call = _read_call()
        result = PrivateAnalysisToolResult(
            call=read_call,
            kind=PrivateAnalysisToolResultKind.EVIDENCE_ENVELOPE,
            envelope=_envelope(),
        )
        error = PrivateAnalysisToolError(
            call=query_call,
            code=PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
            retryable=False,
        )
        round_trips: tuple[tuple[Any, Any, Any, Any, Any], ...] = (
            (
                catalog.tools[0],
                private_analysis_tool_definition_dict,
                private_analysis_tool_definition_from_dict,
                private_analysis_tool_definition_json,
                private_analysis_tool_definition_from_json,
            ),
            (
                catalog,
                private_analysis_tool_catalog_dict,
                private_analysis_tool_catalog_from_dict,
                private_analysis_tool_catalog_json,
                private_analysis_tool_catalog_from_json,
            ),
            (
                query_call.binding,
                private_analysis_tool_binding_dict,
                private_analysis_tool_binding_from_dict,
                private_analysis_tool_binding_json,
                private_analysis_tool_binding_from_json,
            ),
            (
                cursor,
                private_analysis_cursor_dict,
                private_analysis_cursor_from_dict,
                private_analysis_cursor_json,
                private_analysis_cursor_from_json,
            ),
            (
                query_arguments,
                private_analysis_query_arguments_dict,
                private_analysis_query_arguments_from_dict,
                private_analysis_query_arguments_json,
                private_analysis_query_arguments_from_json,
            ),
            (
                read_arguments,
                private_analysis_read_arguments_dict,
                private_analysis_read_arguments_from_dict,
                private_analysis_read_arguments_json,
                private_analysis_read_arguments_from_json,
            ),
            (
                query_call,
                private_analysis_tool_call_dict,
                private_analysis_tool_call_from_dict,
                private_analysis_tool_call_json,
                private_analysis_tool_call_from_json,
            ),
            (
                result,
                private_analysis_tool_result_dict,
                private_analysis_tool_result_from_dict,
                private_analysis_tool_result_json,
                private_analysis_tool_result_from_json,
            ),
            (
                error,
                private_analysis_tool_error_dict,
                private_analysis_tool_error_from_dict,
                private_analysis_tool_error_json,
                private_analysis_tool_error_from_json,
            ),
        )
        for value, to_dict, from_dict, to_json, from_json in round_trips:
            with self.subTest(value=type(value).__name__):
                self.assertEqual(from_dict(to_dict(value)), value)
                encoded = to_json(value)
                self.assertEqual(from_json(encoded), value)
                self.assertEqual(
                    encoded,
                    json.dumps(
                        json.loads(encoded),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )

    def test_json_parsers_reject_duplicate_unknown_and_noncanonical_members(
        self,
    ) -> None:
        catalog_json = private_analysis_tool_catalog_json(
            default_private_analysis_tool_catalog()
        )
        with self.assertRaisesRegex(ValueError, "canonical"):
            private_analysis_tool_catalog_from_json(" " + catalog_json)
        duplicate = catalog_json.replace(
            '"contract_version":',
            '"contract_version":"duplicate","contract_version":',
            1,
        )
        with self.assertRaisesRegex(ValueError, "strict JSON"):
            private_analysis_tool_catalog_from_json(duplicate)
        wire = private_analysis_tool_catalog_dict(
            default_private_analysis_tool_catalog()
        )
        wire["unknown"] = True
        with self.assertRaisesRegex(ValueError, "exactly"):
            private_analysis_tool_catalog_from_dict(wire)

    def test_query_filters_are_exact_bounded_unique_and_canonical(self) -> None:
        kinds = tuple(
            sorted(
                (EvidenceKind.EVENT, EvidenceKind.RESOURCE_IDENTITY),
                key=lambda item: item.value,
            )
        )
        value = _query_arguments(
            evidence_kinds=kinds,
            node_ids=("node-a", "node-b"),
            producer_ids=("producer-a", "producer-b"),
            subject_kinds=("event", "resource"),
        )
        self.assertEqual(value.evidence_kinds, kinds)
        invalid = (
            {"node_ids": ("node-b", "node-a")},
            {"node_ids": ("node-a", "node-a")},
            {"evidence_kinds": tuple(reversed(kinds))},
            {"page_size": True},
            {"page_size": 0},
            {"page_size": MAX_PRIVATE_ANALYSIS_QUERY_PAGE_SIZE + 1},
            {
                "subject_kinds": tuple(
                    f"subject-{index:03d}"
                    for index in range(MAX_PRIVATE_ANALYSIS_QUERY_FILTER_ITEMS + 1)
                )
            },
        )
        for changes in invalid:
            with (
                self.subTest(changes=changes),
                self.assertRaises((TypeError, ValueError)),
            ):
                _query_arguments(**changes)

    def test_query_filter_domains_match_the_evidence_fields_they_select(self) -> None:
        spaced_node = "node west 1"
        reference = replace(
            _reference(1),
            revision=replace(_revision(1), node_id=spaced_node),
            reference_digest="",
        )
        arguments = _query_arguments(node_ids=(spaced_node,))
        result = make_private_analysis_query_page(
            _query_call(arguments=arguments),
            (reference,),
        )
        self.assertEqual(result.references, (reference,))

        longest_subject = "s" * 128
        self.assertEqual(
            _query_arguments(subject_kinds=(longest_subject,)).subject_kinds,
            (longest_subject,),
        )
        with self.assertRaises(ValueError):
            _query_arguments(subject_kinds=(longest_subject + "s",))

    def test_query_digest_excludes_cursor_but_covers_every_query_semantic(self) -> None:
        base = _query_arguments()
        changes = (
            replace(base, evidence_kinds=(), query_digest=""),
            replace(base, node_ids=("node-1",), query_digest=""),
            replace(base, producer_ids=(), query_digest=""),
            replace(base, subject_kinds=(), query_digest=""),
            replace(base, page_size=1, query_digest=""),
        )
        for changed in changes:
            with self.subTest(changed=changed):
                self.assertNotEqual(changed.query_digest, base.query_digest)
        call = _query_call(arguments=base)
        cursor = make_private_analysis_cursor(
            call,
            snapshot_digest=evidence_snapshot_digest((_reference(1),)),
            after_reference_digest=_reference(1).reference_digest,
        )
        continued = replace(base, cursor=cursor)
        self.assertEqual(continued.query_digest, base.query_digest)

    def test_tool_call_rejects_cross_tool_arguments_and_cursor_replay(self) -> None:
        with self.assertRaises(TypeError):
            PrivateAnalysisToolCall(
                call_id="wrong-query",
                binding=_binding(PrivateAnalysisToolName.QUERY_EVIDENCE),
                arguments=PrivateAnalysisReadArguments(
                    evidence_reference_digest=_reference().reference_digest
                ),
            )
        with self.assertRaises(TypeError):
            PrivateAnalysisToolCall(
                call_id="wrong-read",
                binding=_binding(PrivateAnalysisToolName.READ_EVIDENCE),
                arguments=_query_arguments(),
            )
        first = _query_call()
        cursor = make_private_analysis_cursor(
            first,
            snapshot_digest=evidence_snapshot_digest((_reference(1),)),
            after_reference_digest=_reference(1).reference_digest,
        )
        with self.assertRaisesRegex(ValueError, "another request"):
            _query_call(
                arguments=_query_arguments(cursor=cursor),
                request_digest=_REQUEST_B,
            )

    def test_snapshot_digest_is_order_independent_and_membership_sensitive(
        self,
    ) -> None:
        references = (_reference(1), _reference(2), _reference(3))
        self.assertEqual(
            evidence_snapshot_digest(references),
            evidence_snapshot_digest(tuple(reversed(references))),
        )
        self.assertNotEqual(
            evidence_snapshot_digest(references),
            evidence_snapshot_digest(references[:2]),
        )
        with self.assertRaisesRegex(ValueError, "unique"):
            evidence_snapshot_digest((references[0], references[0]))

    def test_query_page_is_ordered_bounded_and_cursor_bound(self) -> None:
        references = tuple(
            sorted((_reference(1), _reference(2)), key=lambda x: x.reference_digest)
        )
        call = _query_call()
        snapshot = evidence_snapshot_digest(references)
        cursor = make_private_analysis_cursor(
            call,
            snapshot_digest=snapshot,
            after_reference_digest=references[-1].reference_digest,
        )
        result = PrivateAnalysisToolResult(
            call=call,
            kind=PrivateAnalysisToolResultKind.QUERY_PAGE,
            snapshot_digest=snapshot,
            references=references,
            next_cursor=cursor,
        )
        self.assertEqual(result.references, references)
        with self.assertRaisesRegex(ValueError, "canonical"):
            replace(result, references=tuple(reversed(references)), result_digest="")
        with self.assertRaisesRegex(ValueError, "unique"):
            replace(result, references=(references[0], references[0]), result_digest="")
        with self.assertRaisesRegex(ValueError, "empty"):
            replace(result, references=(), next_cursor=cursor, result_digest="")
        wrong_cursor = replace(
            cursor,
            snapshot_digest="sha256:" + "f" * 64,
            cursor_digest="",
        )
        with self.assertRaisesRegex(ValueError, "another snapshot"):
            replace(result, next_cursor=wrong_cursor, result_digest="")
        with self.assertRaisesRegex(ValueError, "outside its filters"):
            PrivateAnalysisToolResult(
                call=_query_call(arguments=_query_arguments(node_ids=("node-999",))),
                kind=PrivateAnalysisToolResultKind.QUERY_PAGE,
                snapshot_digest=snapshot,
                references=(references[0],),
            )

    def test_paging_helper_has_no_gaps_and_rejects_changed_snapshot_or_boundary(
        self,
    ) -> None:
        eligible = tuple(_reference(index) for index in range(1, 6))
        first = make_private_analysis_query_page(_query_call(), eligible)
        self.assertEqual(len(first.references), 2)
        self.assertIsNotNone(first.next_cursor)
        assert first.next_cursor is not None
        second_call = _query_call(arguments=_query_arguments(cursor=first.next_cursor))
        second = make_private_analysis_query_page(
            second_call, tuple(reversed(eligible))
        )
        self.assertEqual(len(second.references), 2)
        assert second.next_cursor is not None
        third_call = _query_call(arguments=_query_arguments(cursor=second.next_cursor))
        third = make_private_analysis_query_page(third_call, eligible)
        self.assertEqual(len(third.references), 1)
        self.assertIsNone(third.next_cursor)
        combined = first.references + second.references + third.references
        self.assertEqual(
            tuple(item.reference_digest for item in combined),
            tuple(sorted(item.reference_digest for item in eligible)),
        )
        with self.assertRaisesRegex(ValueError, "another evidence snapshot"):
            make_private_analysis_query_page(second_call, eligible[:-1])
        forged = replace(
            first.next_cursor,
            after_reference_digest="sha256:" + "f" * 64,
            cursor_digest="",
        )
        forged_call = _query_call(arguments=_query_arguments(cursor=forged))
        with self.assertRaisesRegex(ValueError, "boundary"):
            make_private_analysis_query_page(forged_call, eligible)

    def test_continuation_result_itself_enforces_snapshot_and_forward_order(
        self,
    ) -> None:
        eligible = tuple(_reference(index) for index in range(1, 6))
        first = make_private_analysis_query_page(_query_call(), eligible)
        assert first.next_cursor is not None
        continued_call = _query_call(
            arguments=_query_arguments(cursor=first.next_cursor)
        )
        snapshot = evidence_snapshot_digest(eligible)
        with self.assertRaisesRegex(ValueError, "another evidence snapshot"):
            PrivateAnalysisToolResult(
                call=continued_call,
                kind=PrivateAnalysisToolResultKind.QUERY_PAGE,
                snapshot_digest=evidence_snapshot_digest(eligible[:-1]),
                references=(),
            )
        with self.assertRaisesRegex(ValueError, "follow its input cursor"):
            PrivateAnalysisToolResult(
                call=continued_call,
                kind=PrivateAnalysisToolResultKind.QUERY_PAGE,
                snapshot_digest=snapshot,
                references=(first.references[-1],),
            )

    def test_read_result_requires_one_matching_disclosure_gated_envelope(self) -> None:
        result = PrivateAnalysisToolResult(
            call=_read_call(1),
            kind=PrivateAnalysisToolResultKind.EVIDENCE_ENVELOPE,
            envelope=_envelope(1),
        )
        self.assertEqual(
            result.envelope.reference.reference_digest,  # type: ignore[union-attr]
            _reference(1).reference_digest,
        )
        with self.assertRaisesRegex(ValueError, "requested reference"):
            replace(result, envelope=_envelope(2), result_digest="")
        with self.assertRaisesRegex(ValueError, "query-page"):
            replace(
                result,
                references=(_reference(1),),
                result_digest="",
            )

    def test_tool_errors_are_closed_static_and_payload_free(self) -> None:
        call = _query_call()
        for code in PrivateAnalysisToolErrorCode:
            retryable = code is PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE
            error = PrivateAnalysisToolError(
                call=call,
                code=code,
                retryable=retryable,
            )
            wire = private_analysis_tool_error_dict(error)
            self.assertNotIn("message", wire)
            self.assertNotIn("detail", wire)
            self.assertNotIn("path", wire)
            self.assertTrue(error.safe_message.endswith("."))
            with self.assertRaisesRegex(ValueError, "retryable"):
                replace(error, retryable=not retryable, error_digest="")

    def test_public_serializers_revalidate_tampered_nested_values(self) -> None:
        catalog = default_private_analysis_tool_catalog()
        object.__setattr__(catalog.tools[0], "result_contract_version", "changed")
        with self.assertRaises(ValueError):
            private_analysis_tool_catalog_dict(catalog)

        call = _query_call()
        object.__setattr__(call.binding, "request_digest", _REQUEST_B)
        with self.assertRaises(ValueError):
            private_analysis_tool_call_dict(call)

        result = PrivateAnalysisToolResult(
            call=_read_call(),
            kind=PrivateAnalysisToolResultKind.EVIDENCE_ENVELOPE,
            envelope=_envelope(),
        )
        object.__setattr__(result.envelope.reference, "reference_digest", _REQUEST_B)  # type: ignore[union-attr]
        with self.assertRaises(ValueError):
            private_analysis_tool_result_dict(result)

    def test_wire_parsers_bound_obvious_oversize_before_json_decode(self) -> None:
        with (
            patch(
                "router_dump_analyzer.private_analysis.tool_catalog.loads"
            ) as loads,
            self.assertRaisesRegex(ValueError, "byte limit"),
        ):
            private_analysis_tool_catalog_from_json("{" + "x" * (8 * 1024 * 1024))
        loads.assert_not_called()

    def test_result_dict_bounds_aggregate_before_nested_reference_parsing(self) -> None:
        result = make_private_analysis_query_page(
            _query_call(),
            (_reference(1),),
        )
        wire = private_analysis_tool_result_dict(result)
        references = wire["references"]
        assert isinstance(references, list)
        reference = references[0]
        assert isinstance(reference, dict)
        reference["subject_kind"] = "x" * (8 * 1024 * 1024)
        with (
            patch(
                "router_dump_analyzer.private_analysis.tool_catalog."
                "evidence_reference_from_dict"
            ) as parser,
            self.assertRaisesRegex(
                ValueError,
                "characters|encoded byte",
            ),
        ):
            private_analysis_tool_result_from_dict(wire)
        parser.assert_not_called()

    def test_dict_parsers_reject_missing_digest_and_type_coercion(self) -> None:
        wire = private_analysis_query_arguments_dict(_query_arguments())
        del wire["query_digest"]
        with self.assertRaisesRegex(ValueError, "exactly"):
            private_analysis_query_arguments_from_dict(wire)
        wire = private_analysis_query_arguments_dict(_query_arguments())
        wire["page_size"] = "2"
        with self.assertRaises(ValueError):
            private_analysis_query_arguments_from_dict(wire)

    def test_dict_parsers_never_mint_missing_or_empty_wire_digests(self) -> None:
        query_call = _query_call()
        cursor = make_private_analysis_cursor(
            query_call,
            snapshot_digest=evidence_snapshot_digest((_reference(1),)),
            after_reference_digest=_reference(1).reference_digest,
        )
        read_arguments = PrivateAnalysisReadArguments(
            evidence_reference_digest=_reference(1).reference_digest,
        )
        result = make_private_analysis_query_page(query_call, (_reference(1),))
        error = PrivateAnalysisToolError(
            call=query_call,
            code=PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED,
            retryable=False,
        )
        query_arguments = query_call.arguments
        assert isinstance(query_arguments, PrivateAnalysisQueryArguments)
        cases = (
            (
                private_analysis_tool_binding_dict(query_call.binding),
                "binding_digest",
                private_analysis_tool_binding_from_dict,
            ),
            (
                private_analysis_cursor_dict(cursor),
                "cursor_digest",
                private_analysis_cursor_from_dict,
            ),
            (
                private_analysis_query_arguments_dict(query_arguments),
                "query_digest",
                private_analysis_query_arguments_from_dict,
            ),
            (
                private_analysis_read_arguments_dict(read_arguments),
                "arguments_digest",
                private_analysis_read_arguments_from_dict,
            ),
            (
                private_analysis_tool_call_dict(query_call),
                "call_digest",
                private_analysis_tool_call_from_dict,
            ),
            (
                private_analysis_tool_result_dict(result),
                "result_digest",
                private_analysis_tool_result_from_dict,
            ),
            (
                private_analysis_tool_error_dict(error),
                "error_digest",
                private_analysis_tool_error_from_dict,
            ),
        )
        for wire_value, digest_field, parser in cases:
            with self.subTest(digest_field=digest_field):
                wire_value[digest_field] = ""
                with self.assertRaisesRegex(ValueError, "digest"):
                    parser(wire_value)

        nested = private_analysis_tool_result_dict(result)
        nested_call = nested["call"]
        assert isinstance(nested_call, dict)
        nested_binding = nested_call["binding"]
        assert isinstance(nested_binding, dict)
        nested_binding["binding_digest"] = ""
        with self.assertRaisesRegex(ValueError, "binding_digest"):
            private_analysis_tool_result_from_dict(nested)
        wire = private_analysis_query_arguments_dict(_query_arguments())
        wire["node_ids"] = ["node-1", "node-1"]
        wire["query_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            private_analysis_query_arguments_from_dict(wire)

    def test_wire_objects_are_detached_from_caller_owned_nested_values(self) -> None:
        call = _query_call()
        result = PrivateAnalysisToolResult(
            call=call,
            kind=PrivateAnalysisToolResultKind.QUERY_PAGE,
            snapshot_digest=evidence_snapshot_digest((_reference(1),)),
            references=(_reference(1),),
        )
        self.assertIsNot(result.call, call)
        self.assertIsNot(result.call.binding, call.binding)
        wire = private_analysis_tool_result_dict(result)
        mutated = copy.deepcopy(wire)
        references = mutated["references"]
        assert isinstance(references, list)
        references.clear()
        self.assertEqual(len(result.references), 1)


if __name__ == "__main__":
    unittest.main()
