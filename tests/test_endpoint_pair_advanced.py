from __future__ import annotations

import unittest

from router_dump_analyzer.route_trace_core import (
    RouteTraceContractError,
    evaluate_endpoint_reachability_pair,
)


class EndpointPairAdvancedTests(unittest.TestCase):
    @staticmethod
    def evaluate(**overrides: object):
        arguments: dict[str, object] = {
            "forward_reaches_destination": True,
            "reverse_reaches_source": True,
            "forward_complete": True,
            "reverse_complete": True,
            "forward_node_sequence": ("node-a", "transit-p-1", "node-b"),
            "reverse_node_sequence": ("node-b", "transit-p-1", "node-a"),
            "forward_start_node_id": "node-a",
            "traffic_source_node_id": "node-a",
            "reverse_starts_at_destination_endpoint": True,
        }
        arguments.update(overrides)
        return evaluate_endpoint_reachability_pair(**arguments)  # type: ignore[arg-type]

    def test_existing_boolean_only_call_shape_remains_compatible(self) -> None:
        evaluation = self.evaluate(
            reverse_starts_at_destination_endpoint=None,
        )

        self.assertEqual(evaluation.endpoint_state, "bidirectionally_reachable")
        self.assertEqual(
            evaluation.comparison_state,
            "bidirectionally_reachable",
        )
        self.assertTrue(evaluation.consistent)
        self.assertEqual(evaluation.path_relation, "not_comparable")
        self.assertEqual(evaluation.forward_reachability_state, "reached")
        self.assertEqual(evaluation.reverse_reachability_state, "reached")
        self.assertTrue(evaluation.forward_endpoint_span_complete)
        self.assertFalse(evaluation.reverse_endpoint_span_complete)
        self.assertEqual(evaluation.path_relation_basis, "single_path")
        self.assertEqual(
            evaluation.path_relation_reason,
            "reverse_endpoint_start_unknown",
        )

    def test_partial_active_direction_is_preserved_not_flattened_to_unknown(
        self,
    ) -> None:
        evaluation = self.evaluate(
            forward_reaches_destination=None,
            forward_reachability_state="partial_active_reachability",
        )

        self.assertEqual(
            evaluation.forward_reachability_state,
            "partial_active_reachability",
        )
        self.assertEqual(
            evaluation.endpoint_state,
            "partial_active_reachability",
        )
        self.assertEqual(
            evaluation.comparison_state,
            "partial_active_reachability",
        )
        self.assertFalse(evaluation.consistent)
        self.assertFalse(evaluation.forward_endpoint_span_complete)
        self.assertEqual(evaluation.path_relation, "not_comparable")
        self.assertEqual(
            evaluation.path_relation_reason,
            "insufficient_complete_endpoint_span",
        )

    def test_mirrored_sequences_are_not_comparable_when_span_is_incomplete(
        self,
    ) -> None:
        evaluation = self.evaluate(forward_complete=False)

        # Endpoint reachability remains independent from path-shape metadata.
        self.assertEqual(evaluation.endpoint_state, "bidirectionally_reachable")
        self.assertTrue(evaluation.consistent)
        self.assertFalse(evaluation.forward_endpoint_span_complete)
        self.assertEqual(evaluation.path_relation, "not_comparable")
        self.assertEqual(
            evaluation.path_relation_reason,
            "insufficient_complete_endpoint_span",
        )
        self.assertEqual(
            evaluation.comparison_state,
            "bidirectionally_reachable",
        )

    def test_same_node_different_attachment_is_not_a_complete_endpoint_span(
        self,
    ) -> None:
        evaluation = self.evaluate(
            forward_start_node_id="node-a",
            traffic_source_node_id="node-a",
            forward_starts_at_source_endpoint=False,
        )

        self.assertFalse(evaluation.forward_endpoint_span_complete)
        self.assertEqual(evaluation.path_relation, "not_comparable")
        self.assertEqual(
            evaluation.path_relation_reason,
            "forward_starts_inside_flow_path",
        )

    def test_typed_attachment_match_overrides_node_only_fallback(self) -> None:
        evaluation = self.evaluate(
            forward_start_node_id="transit-alias",
            traffic_source_node_id="node-a",
            forward_starts_at_source_endpoint=True,
            reverse_starts_at_destination_endpoint=True,
        )

        self.assertTrue(evaluation.forward_endpoint_span_complete)
        self.assertEqual(evaluation.path_relation, "symmetric")

    def test_reverse_trace_must_start_at_destination_attachment_for_comparison(
        self,
    ) -> None:
        evaluation = self.evaluate(
            reverse_starts_at_destination_endpoint=False,
        )

        self.assertFalse(evaluation.reverse_endpoint_span_complete)
        self.assertEqual(evaluation.path_relation, "not_comparable")
        self.assertEqual(
            evaluation.path_relation_reason,
            "reverse_starts_inside_flow_path",
        )

    def test_failed_direction_does_not_supply_a_complete_endpoint_span(
        self,
    ) -> None:
        evaluation = self.evaluate(
            reverse_reaches_source=False,
            reverse_reachability_state="not_reached",
        )

        self.assertEqual(evaluation.endpoint_state, "one_way_reachable")
        self.assertFalse(evaluation.reverse_endpoint_span_complete)
        self.assertEqual(evaluation.path_relation, "not_comparable")

    def test_two_conclusive_terminal_failures_are_both_unreachable(self) -> None:
        evaluation = self.evaluate(
            forward_reaches_destination=False,
            reverse_reaches_source=False,
            forward_reachability_state="not_reached",
            reverse_reachability_state="not_reached",
            forward_complete=False,
            reverse_complete=False,
        )

        self.assertEqual(evaluation.endpoint_state, "both_unreachable")
        self.assertEqual(evaluation.comparison_state, "both_unreachable")
        self.assertFalse(evaluation.consistent)
        self.assertEqual(evaluation.path_relation, "not_comparable")

    def test_complete_multipath_branch_sets_can_be_compared(self) -> None:
        evaluation = self.evaluate(
            # Representative paths deliberately disagree.  The branch sets
            # are the declared comparison basis.
            forward_node_sequence=("node-a", "transit-p-1", "node-b"),
            reverse_node_sequence=("node-b", "transit-p-3", "node-a"),
            multipath=True,
            forward_branch_node_sequences=(
                ("node-a", "transit-p-1", "node-b"),
                ("node-a", "transit-p-2", "node-b"),
            ),
            reverse_branch_node_sequences=(
                ("node-b", "transit-p-2", "node-a"),
                ("node-b", "transit-p-1", "node-a"),
            ),
        )

        self.assertEqual(evaluation.path_relation, "symmetric")
        self.assertIsNone(evaluation.path_relation_reason)
        self.assertEqual(evaluation.path_relation_basis, "branch_set")
        self.assertEqual(evaluation.comparison_state, "symmetric_reachable")

    def test_complete_multipath_branch_sets_retain_asymmetry(self) -> None:
        evaluation = self.evaluate(
            forward_branch_node_sequences=(
                ("node-a", "transit-p-1", "node-b"),
                ("node-a", "transit-p-2", "node-b"),
            ),
            reverse_branch_node_sequences=(
                ("node-b", "transit-p-1", "node-a"),
                ("node-b", "transit-p-3", "node-a"),
            ),
        )

        self.assertEqual(evaluation.path_relation, "asymmetric")
        self.assertEqual(evaluation.path_relation_basis, "branch_set")
        self.assertEqual(evaluation.comparison_state, "asymmetric_reachable")

    def test_known_multipath_without_branch_sets_is_explicitly_not_comparable(
        self,
    ) -> None:
        evaluation = self.evaluate(multipath=True)

        self.assertEqual(evaluation.path_relation, "not_comparable")
        self.assertEqual(evaluation.path_relation_basis, "branch_set")
        self.assertEqual(
            evaluation.path_relation_reason,
            "multipath_branch_sets_unavailable",
        )
        self.assertEqual(
            evaluation.comparison_state,
            "bidirectionally_reachable",
        )
        self.assertIsNone(evaluation.reverse_visits_forward_start)

    def test_one_sided_branch_set_is_not_silently_compared_to_a_single_path(
        self,
    ) -> None:
        evaluation = self.evaluate(
            forward_branch_node_sequences=(
                ("node-a", "transit-p-1", "node-b"),
            ),
        )

        self.assertEqual(evaluation.path_relation, "not_comparable")
        self.assertEqual(
            evaluation.path_relation_reason,
            "multipath_branch_sets_unavailable",
        )

    def test_reverse_visit_uses_all_declared_reverse_branches(self) -> None:
        evaluation = self.evaluate(
            forward_start_node_id="transit-observer",
            traffic_source_node_id="node-a",
            multipath=True,
            forward_branch_node_sequences=(
                ("transit-observer", "node-b"),
            ),
            reverse_branch_node_sequences=(
                ("node-b", "transit-p-1", "node-a"),
                ("node-b", "transit-observer", "node-a"),
            ),
        )

        self.assertEqual(evaluation.path_relation, "not_comparable")
        self.assertEqual(
            evaluation.path_relation_reason,
            "forward_starts_inside_flow_path",
        )
        self.assertTrue(evaluation.reverse_visits_forward_start)
        self.assertFalse(evaluation.reverse_must_visit_forward_start)

    def test_explicit_state_must_agree_with_legacy_boolean(self) -> None:
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "conflicts with its directional reachability value",
        ):
            self.evaluate(forward_reachability_state="not_reached")

    def test_branch_sets_require_non_empty_typed_node_sequences(self) -> None:
        with self.assertRaisesRegex(
            RouteTraceContractError,
            "forward_branch_node_sequences",
        ):
            self.evaluate(
                forward_branch_node_sequences=((),),
                reverse_branch_node_sequences=(
                    ("node-b", "transit-p-1", "node-a"),
                ),
            )


if __name__ == "__main__":
    unittest.main()
