from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from router_dump_analyzer.private_analysis import (
    DisclosureDecisionReason,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisPolicy,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
    disclosure_decision_dict,
    evaluate_workspace_disclosure,
    workspace_disclosure_policy_dict,
    workspace_disclosure_policy_from_dict,
)


class WorkspaceDisclosurePolicyTests(unittest.TestCase):
    def test_default_policy_is_explicitly_disabled_and_frozen(self) -> None:
        policy = WorkspaceDisclosurePolicy.disabled()
        self.assertEqual(policy.mode, PrivateAnalysisDisclosureMode.DISABLED)
        self.assertEqual(policy.transports, ())
        with self.assertRaises(FrozenInstanceError):
            policy.mode = PrivateAnalysisDisclosureMode.FULL_FIDELITY  # type: ignore[misc]

    def test_enabled_policy_requires_canonical_local_transports(self) -> None:
        with self.assertRaises(TypeError):
            WorkspaceDisclosurePolicy(  # type: ignore[arg-type]
                PrivateAnalysisDisclosureMode.CLIENT_SAFE,
                [PrivateAnalysisTransport.IN_PROCESS],
            )
        with self.assertRaises(ValueError):
            WorkspaceDisclosurePolicy(
                PrivateAnalysisDisclosureMode.CLIENT_SAFE,
                (),
            )
        with self.assertRaises(ValueError):
            WorkspaceDisclosurePolicy(
                PrivateAnalysisDisclosureMode.DISABLED,
                (PrivateAnalysisTransport.IN_PROCESS,),
            )
        with self.assertRaises(ValueError):
            WorkspaceDisclosurePolicy(
                PrivateAnalysisDisclosureMode.FULL_FIDELITY,
                (
                    PrivateAnalysisTransport.LOCAL_SUBPROCESS,
                    PrivateAnalysisTransport.IN_PROCESS,
                ),
            )
        with self.assertRaises(ValueError):
            WorkspaceDisclosurePolicy(
                PrivateAnalysisDisclosureMode.FULL_FIDELITY,
                (
                    PrivateAnalysisTransport.IN_PROCESS,
                    PrivateAnalysisTransport.IN_PROCESS,
                ),
            )

    def test_wire_contract_is_exact_canonical_and_digest_stable(self) -> None:
        policy = WorkspaceDisclosurePolicy(
            PrivateAnalysisDisclosureMode.FULL_FIDELITY,
            (
                PrivateAnalysisTransport.IN_PROCESS,
                PrivateAnalysisTransport.LOCAL_SUBPROCESS,
            ),
        )
        wire = workspace_disclosure_policy_dict(policy)
        self.assertEqual(workspace_disclosure_policy_from_dict(wire), policy)
        self.assertEqual(workspace_disclosure_policy_from_dict(wire).digest, policy.digest)
        hostile = dict(wire)
        hostile["future"] = True
        with self.assertRaisesRegex(ValueError, "fields"):
            workspace_disclosure_policy_from_dict(hostile)
        missing = dict(wire)
        missing.pop("mode")
        with self.assertRaisesRegex(ValueError, "fields"):
            workspace_disclosure_policy_from_dict(missing)

    def test_never_assistant_dominates_every_mode_and_transport(self) -> None:
        for policy in (
            WorkspaceDisclosurePolicy.disabled(),
            WorkspaceDisclosurePolicy(
                PrivateAnalysisDisclosureMode.CLIENT_SAFE,
                (PrivateAnalysisTransport.IN_PROCESS,),
            ),
            WorkspaceDisclosurePolicy(
                PrivateAnalysisDisclosureMode.FULL_FIDELITY,
                (PrivateAnalysisTransport.IN_PROCESS,),
            ),
        ):
            with self.subTest(mode=policy.mode):
                decision = evaluate_workspace_disclosure(
                    policy,
                    runner_policy=PrivateAnalysisPolicy(
                        PrivateAnalysisTransport.IN_PROCESS
                    ),
                    evidence_class=PrivateAnalysisEvidenceClass.NEVER_ASSISTANT,
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    DisclosureDecisionReason.NEVER_ASSISTANT,
                )

    def test_modes_and_transport_are_evaluated_fail_closed(self) -> None:
        client_safe = WorkspaceDisclosurePolicy(
            PrivateAnalysisDisclosureMode.CLIENT_SAFE,
            (PrivateAnalysisTransport.IN_PROCESS,),
        )
        self.assertTrue(
            evaluate_workspace_disclosure(
                client_safe,
                runner_policy=PrivateAnalysisPolicy(
                    PrivateAnalysisTransport.IN_PROCESS
                ),
                evidence_class=PrivateAnalysisEvidenceClass.CLIENT_SAFE,
            ).allowed
        )
        proprietary = evaluate_workspace_disclosure(
            client_safe,
            runner_policy=PrivateAnalysisPolicy(
                PrivateAnalysisTransport.IN_PROCESS
            ),
            evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        )
        self.assertEqual(
            proprietary.reason,
            DisclosureDecisionReason.EVIDENCE_CLASS_NOT_APPROVED,
        )
        limited_client_safe = evaluate_workspace_disclosure(
            client_safe,
            runner_policy=PrivateAnalysisPolicy(
                PrivateAnalysisTransport.IN_PROCESS,
                full_fidelity_workspace_data=False,
            ),
            evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        )
        self.assertEqual(
            limited_client_safe.reason,
            DisclosureDecisionReason.EVIDENCE_CLASS_NOT_APPROVED,
        )
        wrong_transport = evaluate_workspace_disclosure(
            client_safe,
            runner_policy=PrivateAnalysisPolicy(
                PrivateAnalysisTransport.LOCAL_SUBPROCESS
            ),
            evidence_class=PrivateAnalysisEvidenceClass.CLIENT_SAFE,
        )
        self.assertEqual(
            wrong_transport.reason,
            DisclosureDecisionReason.TRANSPORT_NOT_APPROVED,
        )
        full_workspace = WorkspaceDisclosurePolicy(
            PrivateAnalysisDisclosureMode.FULL_FIDELITY,
            (PrivateAnalysisTransport.IN_PROCESS,),
        )
        limited_runner = evaluate_workspace_disclosure(
            full_workspace,
            runner_policy=PrivateAnalysisPolicy(
                PrivateAnalysisTransport.IN_PROCESS,
                full_fidelity_workspace_data=False,
            ),
            evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        )
        self.assertEqual(
            limited_runner.reason,
            DisclosureDecisionReason.RUNNER_FULL_FIDELITY_NOT_APPROVED,
        )

    def test_decision_projection_is_closed_and_payload_free(self) -> None:
        marker = "SECRET-PAYLOAD-MUST-NOT-APPEAR"
        decision = evaluate_workspace_disclosure(
            WorkspaceDisclosurePolicy(
                PrivateAnalysisDisclosureMode.FULL_FIDELITY,
                (PrivateAnalysisTransport.IN_PROCESS,),
            ),
            runner_policy=PrivateAnalysisPolicy(
                PrivateAnalysisTransport.IN_PROCESS
            ),
            evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        )
        projected = disclosure_decision_dict(decision)
        self.assertEqual(
            set(projected),
            {"policy_digest", "transport", "evidence_class", "allowed", "reason"},
        )
        self.assertNotIn(marker, repr(projected))
        self.assertEqual(len(decision.digest), 64)


if __name__ == "__main__":
    unittest.main()
