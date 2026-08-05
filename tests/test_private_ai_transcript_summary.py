from __future__ import annotations

import json
import unittest
from dataclasses import FrozenInstanceError

from router_dump_analyzer.private_analysis import PrivateAnalysisTransport
from router_dump_analyzer.private_analysis_runner_support import (
    MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES,
    MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES,
    PrivateAnalysisInProcessTranscriptSummaryMetadata,
    PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata,
    PrivateAnalysisRunAccountingSnapshot,
    PrivateAnalysisTranscriptSummary,
    detached_private_analysis_transcript_summary,
    private_analysis_transcript_summary_dict,
    private_analysis_transcript_summary_from_dict,
    private_analysis_transcript_summary_from_json,
    private_analysis_transcript_summary_json,
)
from router_dump_analyzer.private_analysis_tool_service import (
    PrivateAnalysisToolBudgetState,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _budget(*, consumed: int = 1) -> PrivateAnalysisToolBudgetState:
    return PrivateAnalysisToolBudgetState(
        max_tool_calls=4,
        tool_calls_consumed=consumed,
        max_evidence_items=8,
        evidence_items_disclosed=1,
        max_evidence_bytes=4096,
        evidence_bytes_disclosed=128,
    )


def _in_process_summary() -> PrivateAnalysisTranscriptSummary:
    return PrivateAnalysisTranscriptSummary(
        transport=PrivateAnalysisTransport.IN_PROCESS,
        request_digest=_digest("a"),
        catalog_digest=_digest("b"),
        instruction_profile_digest=_digest("c"),
        runner_configuration_digest=_digest("d"),
        outcome_digest=_digest("e"),
        evidence_ledger_digest=_digest("f"),
        budget_state=_budget(),
        metadata=PrivateAnalysisInProcessTranscriptSummaryMetadata(
            transcript_digest=_digest("1"),
            exchange_count=1,
            unattributed_tool_call_count=0,
            exchange_metadata_bytes=512,
            exchange_chain_digest=_digest("2"),
        ),
    )


def _local_subprocess_summary() -> PrivateAnalysisTranscriptSummary:
    return PrivateAnalysisTranscriptSummary(
        transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS,
        request_digest=_digest("a"),
        catalog_digest=_digest("b"),
        instruction_profile_digest=_digest("c"),
        runner_configuration_digest=_digest("d"),
        outcome_digest=_digest("e"),
        evidence_ledger_digest=_digest("f"),
        budget_state=_budget(),
        metadata=PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata(
            transcript_digest=_digest("1"),
            launch_configuration_digest=_digest("2"),
            run_digest=_digest("3"),
            message_count=6,
            tool_call_count=1,
            message_metadata_bytes=2048,
            message_chain_digest=_digest("4"),
            stderr_bytes=32,
        ),
    )


class PrivateAnalysisTranscriptSummaryTests(unittest.TestCase):
    def test_accounting_observer_commits_before_local_publication(self) -> None:
        initial = PrivateAnalysisToolBudgetState(
            max_tool_calls=4,
            tool_calls_consumed=0,
            max_evidence_items=8,
            evidence_items_disclosed=0,
            max_evidence_bytes=4096,
            evidence_bytes_disclosed=0,
        )
        updated = PrivateAnalysisToolBudgetState(
            max_tool_calls=4,
            tool_calls_consumed=1,
            max_evidence_items=8,
            evidence_items_disclosed=0,
            max_evidence_bytes=4096,
            evidence_bytes_disclosed=0,
        )
        observed: list[PrivateAnalysisToolBudgetState] = []

        class Lease:
            disclosed_references = ()
            budget_state = updated

        snapshot = PrivateAnalysisRunAccountingSnapshot(
            (),
            initial,
            observer=lambda _references, budget: observed.append(budget),
        )
        snapshot.refresh(Lease())  # type: ignore[arg-type]
        self.assertEqual(observed, [updated])
        self.assertEqual(snapshot.budget_state, updated)

        def fail_before_publish(
            _references: object,
            _budget_state: object,
        ) -> None:
            raise RuntimeError("durable accounting unavailable")

        failed = PrivateAnalysisRunAccountingSnapshot(
            (),
            initial,
            observer=fail_before_publish,  # type: ignore[arg-type]
        )
        with self.assertRaisesRegex(RuntimeError, "durable accounting unavailable"):
            failed.refresh(Lease())  # type: ignore[arg-type]
        self.assertEqual(failed.budget_state, initial)

    def test_in_process_summary_is_frozen_canonical_and_detached(self) -> None:
        summary = _in_process_summary()
        wire = private_analysis_transcript_summary_dict(summary)

        self.assertEqual(wire["transport"], "in_process")
        self.assertIn("in_process", wire)
        self.assertNotIn("local_subprocess", wire)
        self.assertEqual(
            wire["summary_digest"],
            summary.summary_digest,
        )
        encoded = private_analysis_transcript_summary_json(summary)
        self.assertEqual(
            private_analysis_transcript_summary_from_json(encoded), summary
        )
        self.assertEqual(private_analysis_transcript_summary_from_dict(wire), summary)

        detached = detached_private_analysis_transcript_summary(summary)
        self.assertEqual(detached, summary)
        self.assertIsNot(detached, summary)
        self.assertIsNot(detached.metadata, summary.metadata)
        with self.assertRaises(FrozenInstanceError):
            summary.request_digest = _digest("0")  # type: ignore[misc]

    def test_local_subprocess_summary_has_only_bounded_safe_metadata(self) -> None:
        summary = _local_subprocess_summary()
        wire = private_analysis_transcript_summary_dict(summary)

        self.assertEqual(wire["transport"], "local_subprocess")
        self.assertIn("local_subprocess", wire)
        self.assertNotIn("in_process", wire)
        metadata = wire["local_subprocess"]
        self.assertIs(type(metadata), dict)
        assert isinstance(metadata, dict)
        self.assertEqual(metadata["stderr_bytes"], 32)
        for forbidden in (
            "payload",
            "stderr",
            "path",
            "argv",
            "environment",
            "model_text",
        ):
            self.assertNotIn(forbidden, metadata)
            self.assertNotIn(forbidden, wire)
        self.assertEqual(
            private_analysis_transcript_summary_from_json(
                private_analysis_transcript_summary_json(summary)
            ),
            summary,
        )

    def test_parser_rejects_wrong_branch_extra_fields_and_noncanonical_json(
        self,
    ) -> None:
        summary = _in_process_summary()
        wire = private_analysis_transcript_summary_dict(summary)
        wrong_branch = dict(wire)
        wrong_branch["local_subprocess"] = {}
        with self.assertRaises(ValueError):
            private_analysis_transcript_summary_from_dict(wrong_branch)

        unknown = dict(wire)
        unknown["payload"] = "secret"
        with self.assertRaises(ValueError):
            private_analysis_transcript_summary_from_dict(unknown)

        tampered = dict(wire)
        tampered["outcome_digest"] = _digest("0")
        with self.assertRaises(ValueError):
            private_analysis_transcript_summary_from_dict(tampered)

        noncanonical = json.dumps(wire, sort_keys=True)
        with self.assertRaises(ValueError):
            private_analysis_transcript_summary_from_json(noncanonical)

        encoded = private_analysis_transcript_summary_json(summary)
        duplicate = encoded[:-1] + ',"transport":"in_process"}'
        with self.assertRaises(ValueError):
            private_analysis_transcript_summary_from_json(duplicate)

    def test_transport_metadata_and_accounting_are_exactly_bounded(self) -> None:
        with self.assertRaises(ValueError):
            PrivateAnalysisInProcessTranscriptSummaryMetadata(
                transcript_digest=_digest("1"),
                exchange_count=1,
                unattributed_tool_call_count=0,
                exchange_metadata_bytes=(
                    MAX_PRIVATE_ANALYSIS_IN_PROCESS_TRANSCRIPT_BYTES + 1
                ),
                exchange_chain_digest=_digest("2"),
            )
        with self.assertRaises(ValueError):
            PrivateAnalysisLocalSubprocessTranscriptSummaryMetadata(
                transcript_digest=_digest("1"),
                launch_configuration_digest=_digest("2"),
                run_digest=_digest("3"),
                message_count=4,
                tool_call_count=1,
                message_metadata_bytes=512,
                message_chain_digest=_digest("4"),
                stderr_bytes=MAX_PRIVATE_ANALYSIS_SUBPROCESS_STDERR_BYTES + 1,
            )

        oversized_budget = PrivateAnalysisToolBudgetState(
            max_tool_calls=2**53,
            tool_calls_consumed=0,
            max_evidence_items=0,
            evidence_items_disclosed=0,
            max_evidence_bytes=0,
            evidence_bytes_disclosed=0,
        )
        with self.assertRaises(ValueError):
            PrivateAnalysisTranscriptSummary(
                transport=PrivateAnalysisTransport.IN_PROCESS,
                request_digest=_digest("a"),
                catalog_digest=_digest("b"),
                instruction_profile_digest=_digest("c"),
                runner_configuration_digest=_digest("d"),
                outcome_digest=_digest("e"),
                evidence_ledger_digest=_digest("f"),
                budget_state=oversized_budget,
                metadata=PrivateAnalysisInProcessTranscriptSummaryMetadata(
                    transcript_digest=_digest("1"),
                    exchange_count=0,
                    unattributed_tool_call_count=0,
                    exchange_metadata_bytes=0,
                    exchange_chain_digest=_digest("2"),
                ),
            )

        in_process = _in_process_summary()
        with self.assertRaises(ValueError):
            PrivateAnalysisTranscriptSummary(
                transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS,
                request_digest=in_process.request_digest,
                catalog_digest=in_process.catalog_digest,
                instruction_profile_digest=in_process.instruction_profile_digest,
                runner_configuration_digest=(in_process.runner_configuration_digest),
                outcome_digest=in_process.outcome_digest,
                evidence_ledger_digest=in_process.evidence_ledger_digest,
                budget_state=in_process.budget_state,
                metadata=in_process.metadata,
            )
        with self.assertRaises(ValueError):
            PrivateAnalysisTranscriptSummary(
                transport=PrivateAnalysisTransport.IN_PROCESS,
                request_digest=in_process.request_digest,
                catalog_digest=in_process.catalog_digest,
                instruction_profile_digest=in_process.instruction_profile_digest,
                runner_configuration_digest=(in_process.runner_configuration_digest),
                outcome_digest=in_process.outcome_digest,
                evidence_ledger_digest=in_process.evidence_ledger_digest,
                budget_state=_budget(consumed=3),
                metadata=in_process.metadata,
            )


if __name__ == "__main__":
    unittest.main()
