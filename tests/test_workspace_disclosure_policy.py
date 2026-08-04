from __future__ import annotations

import builtins
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from router_dump_analyzer.private_analysis import (
    DisclosureDecisionReason,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisPolicy,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
    disclosure_decision_dict,
    disclosure_decision_from_dict,
    disclosure_scope_digest,
    evaluate_workspace_disclosure,
    workspace_disclosure_policy_dict,
    workspace_disclosure_policy_from_dict,
)


def _evaluate(
    policy: WorkspaceDisclosurePolicy,
    *,
    runner_policy: PrivateAnalysisPolicy,
    evidence_class: PrivateAnalysisEvidenceClass,
):
    return evaluate_workspace_disclosure(
        policy,
        tenant_id="tenant-a",
        project_id="project-a",
        workspace_id="workspace-a",
        runner_policy=runner_policy,
        evidence_class=evidence_class,
    )


class WorkspaceDisclosurePolicyTests(unittest.TestCase):
    def test_scope_digest_rejects_every_filesystem_path_shape(self) -> None:
        for workspace_id in (
            "./private/dump",
            r".\private\dump",
            r"C:private\dump",
            r"\private",
            "/v1/private/dump",
            "relative/private/dump",
        ):
            with self.subTest(workspace_id=workspace_id), self.assertRaises(
                ValueError
            ):
                disclosure_scope_digest(
                    tenant_id="tenant-a",
                    project_id="project-a",
                    workspace_id=workspace_id,
                )

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

    def test_direct_dict_parsers_reject_wrong_cardinality_before_key_scans(
        self,
    ) -> None:
        oversized = {f"field-{index}": None for index in range(10_000)}
        with (
            patch.object(
                builtins,
                "set",
                side_effect=AssertionError("key set must not be materialized"),
            ),
            self.assertRaises(ValueError),
        ):
            workspace_disclosure_policy_from_dict(oversized)
        with (
            patch.object(
                builtins,
                "set",
                side_effect=AssertionError("key set must not be materialized"),
            ),
            self.assertRaises(ValueError),
        ):
            disclosure_decision_from_dict(oversized)

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
                decision = _evaluate(
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
            _evaluate(
                client_safe,
                runner_policy=PrivateAnalysisPolicy(
                    PrivateAnalysisTransport.IN_PROCESS
                ),
                evidence_class=PrivateAnalysisEvidenceClass.CLIENT_SAFE,
            ).allowed
        )
        proprietary = _evaluate(
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
        limited_client_safe = _evaluate(
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
        wrong_transport = _evaluate(
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
        limited_runner = _evaluate(
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

    def test_authority_gate_revalidates_detached_policy_values(self) -> None:
        workspace_policy = WorkspaceDisclosurePolicy(
            PrivateAnalysisDisclosureMode.FULL_FIDELITY,
            (PrivateAnalysisTransport.IN_PROCESS,),
        )
        runner_policy = PrivateAnalysisPolicy(
            PrivateAnalysisTransport.IN_PROCESS,
            full_fidelity_workspace_data=False,
        )
        object.__setattr__(runner_policy, "full_fidelity_workspace_data", 1)
        with self.assertRaisesRegex(TypeError, "must be a boolean"):
            _evaluate(
                workspace_policy,
                runner_policy=runner_policy,
                evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
            )

        object.__setattr__(workspace_policy, "transports", [])
        with self.assertRaisesRegex(TypeError, "must be a tuple"):
            _evaluate(
                workspace_policy,
                runner_policy=PrivateAnalysisPolicy(
                    PrivateAnalysisTransport.IN_PROCESS
                ),
                evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
            )
        with self.assertRaisesRegex(TypeError, "must be a tuple"):
            workspace_disclosure_policy_dict(workspace_policy)

        decision = _evaluate(
            WorkspaceDisclosurePolicy(
                PrivateAnalysisDisclosureMode.CLIENT_SAFE,
                (PrivateAnalysisTransport.IN_PROCESS,),
            ),
            runner_policy=PrivateAnalysisPolicy(
                PrivateAnalysisTransport.IN_PROCESS
            ),
            evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        )
        object.__setattr__(decision, "allowed", True)
        with self.assertRaisesRegex(ValueError, "allowed flag and reason disagree"):
            disclosure_decision_dict(decision)

    def test_decision_projection_is_closed_and_payload_free(self) -> None:
        marker = "SECRET-PAYLOAD-MUST-NOT-APPEAR"
        decision = _evaluate(
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
            {
                "policy_digest",
                "scope_digest",
                "transport",
                "evidence_class",
                "allowed",
                "reason",
            },
        )
        self.assertNotIn(marker, repr(projected))
        self.assertEqual(len(decision.digest), 64)


if __name__ == "__main__":
    unittest.main()
