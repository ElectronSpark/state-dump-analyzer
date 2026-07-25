"""Protocol-neutral route traversal and policy outcome helpers.

Plug-ins own the meaning of forwarding objects, ingress scopes, encapsulation,
and policies.  The core treats those values as opaque structured identity,
detects exact repeated states, applies explicit budgets, and produces validated
generic policy verdicts from plug-in-declared constraints.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .plugin_api import (
    ForwardingCandidateConstraint,
    ForwardingCycleReport,
    ForwardingMtuConstraint,
    ForwardingPacketDisposition,
    ForwardingPacketLayer,
    ForwardingPacketState,
    ForwardingPacketTransition,
    ForwardingPolicyDecision,
    ForwardingPolicyScope,
    ForwardingPolicyVerdict,
    ForwardingStepRequest,
    ForwardingStepResult,
    ForwardingSteeringRule,
    ForwardingTransitionOrigin,
    ForwardingTraversalStateKey,
    ResourceKey,
)


class RouteTraceContractError(ValueError):
    """A plug-in supplied an invalid normalized route-trace record."""


@dataclass(frozen=True, slots=True)
class ForwardingTraversalEvaluation:
    """Bounded core verdict over plug-in-normalized traversal keys."""

    outcome: str
    stop_step: int
    terminal_reason: str | None
    cycle: ForwardingCycleReport | None = None
    budget_kind: str | None = None
    budget_limit: int | None = None
    budget_observed: int | None = None


@dataclass(frozen=True, slots=True)
class ForwardingPolicyEvaluation:
    """Aggregate core verdict over all declared constraints for a candidate."""

    verdict: ForwardingPolicyVerdict
    decisions: tuple[ForwardingPolicyDecision, ...]


@dataclass(frozen=True, slots=True)
class EndpointReachabilityPairEvaluation:
    """Core-owned bidirectional verdict for one immutable traffic flow.

    ``forward_reaches_destination`` and ``reverse_reaches_source`` are supplied
    only after exact, typed endpoint/attachment matching.  The observation
    point where the forward trace starts is deliberately independent from the
    traffic source.  Consequently path shape is descriptive and can be
    ``not_comparable`` when the forward trace begins at a transit node.
    """

    endpoint_state: str
    comparison_state: str
    consistent: bool
    forward_reaches_destination: bool | None
    reverse_reaches_source: bool | None
    path_relation: str
    path_relation_reason: str | None
    reverse_visits_forward_start: bool | None
    reverse_must_visit_forward_start: bool = False
    forward_reachability_state: str = "unknown"
    reverse_reachability_state: str = "unknown"
    forward_endpoint_span_complete: bool = False
    reverse_endpoint_span_complete: bool = False
    path_relation_basis: str = "single_path"


@dataclass(frozen=True, slots=True)
class ForwardingPacketStateDiff:
    """Protocol-neutral structural difference between two packet snapshots."""

    added_layer_ids: tuple[str, ...]
    removed_layer_ids: tuple[str, ...]
    changed_layer_ids: tuple[str, ...]
    moved_layer_ids: tuple[str, ...]
    complete: bool

    @property
    def changed(self) -> bool:
        return any(
            (
                self.added_layer_ids,
                self.removed_layer_ids,
                self.changed_layer_ids,
                self.moved_layer_ids,
            )
        )


@dataclass(frozen=True, slots=True)
class ForwardingMtuEvaluation:
    """Core arithmetic over a packet size and an exactly comparable MTU."""

    outcome: str
    size_bytes: int | None
    limit_bytes: int | None
    excess_bytes: int | None
    basis_contract_id: str | None


@dataclass(frozen=True, slots=True)
class ForwardingPacketTransitionEvaluation:
    """Validated result for one plug-in-declared packet transition."""

    transition: ForwardingPacketTransition
    diff: ForwardingPacketStateDiff
    mtu: ForwardingMtuEvaluation
    counterfactual: bool


@dataclass(frozen=True, slots=True)
class ForwardingPacketTraceEvaluation:
    """Bounded continuity and terminal result for one packet evolution branch."""

    outcome: str
    stop_step: int
    continuity: str
    transitions: tuple[ForwardingPacketTransitionEvaluation, ...]
    terminal_disposition: ForwardingPacketDisposition | None = None
    budget_kind: str | None = None
    budget_limit: int | None = None
    budget_observed: int | None = None


def evaluate_endpoint_reachability_pair(
    *,
    forward_reaches_destination: bool | None,
    reverse_reaches_source: bool | None,
    forward_complete: bool,
    reverse_complete: bool,
    forward_node_sequence: tuple[str, ...] = (),
    reverse_node_sequence: tuple[str, ...] = (),
    forward_start_node_id: str | None = None,
    traffic_source_node_id: str | None = None,
    forward_starts_at_source_endpoint: bool | None = None,
    reverse_starts_at_destination_endpoint: bool | None = None,
    forward_reachability_state: str | None = None,
    reverse_reachability_state: str | None = None,
    forward_branch_node_sequences: tuple[tuple[str, ...], ...] | None = None,
    reverse_branch_node_sequences: tuple[tuple[str, ...], ...] | None = None,
    multipath: bool = False,
) -> EndpointReachabilityPairEvaluation:
    """Classify a forward/return pair by endpoint reachability.

    A return trace targets the traffic source endpoint.  It is never required
    to revisit the forward observation point.  Sequence symmetry is evaluated
    only across the same endpoint-to-endpoint span.  A coordinator that has
    matched typed endpoint attachments should pass the two ``*_endpoint``
    booleans.  The older node-ID comparison remains a compatibility fallback
    and cannot distinguish two attachments on the same node.

    Existing callers may continue to supply only the directional booleans.
    Explicit directional states preserve richer aggregate results such as
    ``partial_active_reachability`` instead of collapsing them into unknown.
    A caller that knows the active result is multipath may provide both branch
    sets for comparison, or set ``multipath=True`` without branch sets to
    explicitly make path shape non-comparable.
    """

    for label, value in (
        ("forward_reaches_destination", forward_reaches_destination),
        ("reverse_reaches_source", reverse_reaches_source),
    ):
        if value is not None and not isinstance(value, bool):
            raise RouteTraceContractError(
                f"{label} must be a boolean or None"
            )
    if not isinstance(multipath, bool):
        raise RouteTraceContractError("multipath must be a boolean")
    for label, value in (
        ("forward_complete", forward_complete),
        ("reverse_complete", reverse_complete),
    ):
        if not isinstance(value, bool):
            raise RouteTraceContractError(f"{label} must be a boolean")
    for label, value in (
        (
            "forward_starts_at_source_endpoint",
            forward_starts_at_source_endpoint,
        ),
        (
            "reverse_starts_at_destination_endpoint",
            reverse_starts_at_destination_endpoint,
        ),
    ):
        if value is not None and not isinstance(value, bool):
            raise RouteTraceContractError(
                f"{label} must be a boolean or None"
            )
    for label, sequence in (
        ("forward_node_sequence", forward_node_sequence),
        ("reverse_node_sequence", reverse_node_sequence),
    ):
        if not isinstance(sequence, tuple) or any(
            not isinstance(node_id, str) or not node_id for node_id in sequence
        ):
            raise RouteTraceContractError(
                f"{label} must be a tuple of non-empty node identifiers"
            )
    for label, branch_sequences in (
        ("forward_branch_node_sequences", forward_branch_node_sequences),
        ("reverse_branch_node_sequences", reverse_branch_node_sequences),
    ):
        if branch_sequences is None:
            continue
        if not isinstance(branch_sequences, tuple) or any(
            not isinstance(sequence, tuple)
            or not sequence
            or any(
                not isinstance(node_id, str) or not node_id
                for node_id in sequence
            )
            for sequence in branch_sequences
        ):
            raise RouteTraceContractError(
                f"{label} must be a tuple of non-empty node-sequence tuples "
                "or None"
            )
    for label, node_id in (
        ("forward_start_node_id", forward_start_node_id),
        ("traffic_source_node_id", traffic_source_node_id),
    ):
        if node_id is not None and (
            not isinstance(node_id, str) or not node_id
        ):
            raise RouteTraceContractError(
                f"{label} must be a non-empty string or None"
            )

    allowed_reachability_states = {
        "reached": True,
        "not_reached": False,
        "unknown": None,
        "partial_active_reachability": None,
    }

    def normalized_directional_state(
        *,
        label: str,
        explicit_state: str | None,
        reaches_target: bool | None,
    ) -> str:
        if explicit_state is None:
            if reaches_target is True:
                return "reached"
            if reaches_target is False:
                return "not_reached"
            return "unknown"
        if (
            not isinstance(explicit_state, str)
            or explicit_state not in allowed_reachability_states
        ):
            raise RouteTraceContractError(
                f"{label} must be one of "
                "reached, not_reached, unknown, or "
                "partial_active_reachability"
            )
        expected_reachability = allowed_reachability_states[explicit_state]
        if reaches_target is not expected_reachability:
            raise RouteTraceContractError(
                f"{label} conflicts with its directional reachability value"
            )
        return explicit_state

    forward_state = normalized_directional_state(
        label="forward_reachability_state",
        explicit_state=forward_reachability_state,
        reaches_target=forward_reaches_destination,
    )
    reverse_state = normalized_directional_state(
        label="reverse_reachability_state",
        explicit_state=reverse_reachability_state,
        reaches_target=reverse_reaches_source,
    )

    directional_states = {forward_state, reverse_state}
    if "partial_active_reachability" in directional_states:
        endpoint_state = "partial_active_reachability"
        consistent = False
    elif "unknown" in directional_states:
        # An unresolved direction must never be collapsed into a confirmed
        # one-way failure merely because the other direction reached its goal.
        endpoint_state = "unknown_incomplete"
        consistent = False
    elif forward_state == "reached" and reverse_state == "reached":
        endpoint_state = "bidirectionally_reachable"
        consistent = True
    elif "reached" in directional_states:
        endpoint_state = "one_way_reachable"
        consistent = False
    elif (
        forward_state == "not_reached"
        and reverse_state == "not_reached"
    ):
        # A directional ``False`` is already an exact, plug-in-classified
        # endpoint outcome.  ``complete`` describes path resolution coverage,
        # not whether a terminal drop verdict is conclusive.
        endpoint_state = "both_unreachable"
        consistent = False
    else:
        endpoint_state = "unknown_incomplete"
        consistent = False

    forward_span_starts_at_source = (
        forward_starts_at_source_endpoint
        if forward_starts_at_source_endpoint is not None
        else (
            forward_start_node_id is not None
            and traffic_source_node_id is not None
            and forward_start_node_id == traffic_source_node_id
        )
    )
    reverse_span_starts_at_destination = (
        reverse_starts_at_destination_endpoint
        if reverse_starts_at_destination_endpoint is not None
        else True
    )
    forward_endpoint_span_complete = (
        forward_complete
        and forward_state == "reached"
        and forward_span_starts_at_source
    )
    reverse_endpoint_span_complete = (
        reverse_complete
        and reverse_state == "reached"
        and reverse_span_starts_at_destination
    )
    branch_set_comparison = (
        multipath
        or forward_branch_node_sequences is not None
        or reverse_branch_node_sequences is not None
    )
    path_relation_basis = (
        "branch_set" if branch_set_comparison else "single_path"
    )
    if branch_set_comparison:
        has_comparison_sequences = bool(
            forward_branch_node_sequences
        ) and bool(reverse_branch_node_sequences)
    else:
        has_comparison_sequences = bool(forward_node_sequence) and bool(
            reverse_node_sequence
        )
    comparable = (
        forward_endpoint_span_complete
        and reverse_endpoint_span_complete
        and has_comparison_sequences
    )
    if not comparable:
        path_relation = "not_comparable"
        if not forward_span_starts_at_source:
            path_relation_reason = "forward_starts_inside_flow_path"
        elif not reverse_span_starts_at_destination:
            path_relation_reason = "reverse_starts_inside_flow_path"
        elif (
            branch_set_comparison
            and (
                not forward_branch_node_sequences
                or not reverse_branch_node_sequences
            )
            and forward_endpoint_span_complete
            and reverse_endpoint_span_complete
        ):
            path_relation_reason = "multipath_branch_sets_unavailable"
        else:
            path_relation_reason = "insufficient_complete_endpoint_span"
    elif branch_set_comparison:
        assert forward_branch_node_sequences is not None
        assert reverse_branch_node_sequences is not None
        normalized_forward_branches = tuple(
            sorted(forward_branch_node_sequences)
        )
        normalized_reverse_branches = tuple(
            sorted(
                tuple(reversed(sequence))
                for sequence in reverse_branch_node_sequences
            )
        )
        if normalized_forward_branches == normalized_reverse_branches:
            path_relation = "symmetric"
        else:
            path_relation = "asymmetric"
        path_relation_reason = None
    elif forward_node_sequence == tuple(reversed(reverse_node_sequence)):
        path_relation = "symmetric"
        path_relation_reason = None
    else:
        path_relation = "asymmetric"
        path_relation_reason = None

    if endpoint_state == "bidirectionally_reachable":
        comparison_state = (
            "symmetric_reachable"
            if path_relation == "symmetric"
            else "asymmetric_reachable"
            if path_relation == "asymmetric"
            else "bidirectionally_reachable"
        )
    else:
        comparison_state = endpoint_state

    reverse_visit_sequences = (
        reverse_branch_node_sequences or ()
        if branch_set_comparison
        else (reverse_node_sequence,) if reverse_node_sequence else ()
    )
    reverse_visits_forward_start = (
        any(
            forward_start_node_id in sequence
            for sequence in reverse_visit_sequences
        )
        if forward_start_node_id and reverse_visit_sequences
        else None
    )
    return EndpointReachabilityPairEvaluation(
        endpoint_state=endpoint_state,
        comparison_state=comparison_state,
        consistent=consistent,
        forward_reaches_destination=forward_reaches_destination,
        reverse_reaches_source=reverse_reaches_source,
        path_relation=path_relation,
        path_relation_reason=path_relation_reason,
        reverse_visits_forward_start=reverse_visits_forward_start,
        forward_reachability_state=forward_state,
        reverse_reachability_state=reverse_state,
        forward_endpoint_span_complete=forward_endpoint_span_complete,
        reverse_endpoint_span_complete=reverse_endpoint_span_complete,
        path_relation_basis=path_relation_basis,
    )


def diff_forwarding_packet_states(
    before: ForwardingPacketState,
    after: ForwardingPacketState,
) -> ForwardingPacketStateDiff:
    """Return an identity-based layer diff without interpreting protocols."""

    if not isinstance(before, ForwardingPacketState) or not isinstance(
        after,
        ForwardingPacketState,
    ):
        raise RouteTraceContractError(
            "packet state diff requires ForwardingPacketState values"
        )
    before_by_id: dict[str, tuple[int, ForwardingPacketLayer]] = {
        layer.layer_id: (index, layer)
        for index, layer in enumerate(before.layers)
    }
    after_by_id: dict[str, tuple[int, ForwardingPacketLayer]] = {
        layer.layer_id: (index, layer)
        for index, layer in enumerate(after.layers)
    }
    before_ids = set(before_by_id)
    after_ids = set(after_by_id)
    retained = before_ids & after_ids
    retained_before_positions = {
        layer.layer_id: index
        for index, layer in enumerate(
            layer for layer in before.layers if layer.layer_id in retained
        )
    }
    retained_after_positions = {
        layer.layer_id: index
        for index, layer in enumerate(
            layer for layer in after.layers if layer.layer_id in retained
        )
    }
    moved_retained_ids = {
        layer_id
        for layer_id in retained
        if any(
            (
                retained_before_positions[layer_id]
                < retained_before_positions[other_id]
            )
            != (
                retained_after_positions[layer_id]
                < retained_after_positions[other_id]
            )
            for other_id in retained
            if other_id != layer_id
        )
    }
    return ForwardingPacketStateDiff(
        added_layer_ids=tuple(
            layer.layer_id
            for layer in after.layers
            if layer.layer_id not in before_ids
        ),
        removed_layer_ids=tuple(
            layer.layer_id
            for layer in before.layers
            if layer.layer_id not in after_ids
        ),
        changed_layer_ids=tuple(
            layer.layer_id
            for layer in after.layers
            if layer.layer_id in retained
            and before_by_id[layer.layer_id][1] != layer
        ),
        moved_layer_ids=tuple(
            layer.layer_id
            for layer in after.layers
            if layer.layer_id in moved_retained_ids
        ),
        complete=before.identity_complete and after.identity_complete,
    )


def evaluate_forwarding_mtu(
    packet_state: ForwardingPacketState,
    constraint: ForwardingMtuConstraint | None,
) -> ForwardingMtuEvaluation:
    """Compare only complete size values that share one exact basis contract."""

    if not isinstance(packet_state, ForwardingPacketState):
        raise RouteTraceContractError(
            "forwarding MTU evaluation requires a ForwardingPacketState"
        )
    if constraint is not None and not isinstance(
        constraint,
        ForwardingMtuConstraint,
    ):
        raise RouteTraceContractError(
            "forwarding MTU constraint must be ForwardingMtuConstraint or None"
        )
    if constraint is None:
        return ForwardingMtuEvaluation(
            outcome="not_declared",
            size_bytes=packet_state.size.size_bytes if packet_state.size else None,
            limit_bytes=None,
            excess_bytes=None,
            basis_contract_id=(
                packet_state.size.basis_contract_id if packet_state.size else None
            ),
        )
    size = packet_state.size
    if size is None or not size.complete or not constraint.complete:
        return ForwardingMtuEvaluation(
            outcome="unknown",
            size_bytes=size.size_bytes if size else None,
            limit_bytes=constraint.limit_bytes,
            excess_bytes=None,
            basis_contract_id=constraint.basis_contract_id,
        )
    if size.basis_contract_id != constraint.basis_contract_id:
        return ForwardingMtuEvaluation(
            outcome="unknown_basis_mismatch",
            size_bytes=size.size_bytes,
            limit_bytes=constraint.limit_bytes,
            excess_bytes=None,
            basis_contract_id=None,
        )
    excess = max(size.size_bytes - constraint.limit_bytes, 0)
    return ForwardingMtuEvaluation(
        outcome="exceeds" if excess else "fits",
        size_bytes=size.size_bytes,
        limit_bytes=constraint.limit_bytes,
        excess_bytes=excess,
        basis_contract_id=size.basis_contract_id,
    )


def evaluate_forwarding_packet_transition(
    transition: ForwardingPacketTransition,
) -> ForwardingPacketTransitionEvaluation:
    """Validate and classify one declarative node packet transition."""

    if not isinstance(transition, ForwardingPacketTransition):
        raise RouteTraceContractError(
            "packet transition evaluation requires ForwardingPacketTransition"
        )
    return ForwardingPacketTransitionEvaluation(
        transition=transition,
        diff=diff_forwarding_packet_states(
            transition.before,
            transition.after,
        ),
        mtu=evaluate_forwarding_mtu(transition.after, transition.mtu),
        counterfactual=(
            transition.origin is ForwardingTransitionOrigin.USER_FORCED
        ),
    )


def select_forwarding_steering_rule(
    *,
    step_id: str,
    packet_state: ForwardingPacketState,
    rules: tuple[ForwardingSteeringRule, ...],
) -> ForwardingSteeringRule | None:
    """Select one exact, highest-priority user rule for a trace step."""

    if not isinstance(step_id, str) or not step_id:
        raise RouteTraceContractError(
            "forwarding steering step_id must be a non-empty string"
        )
    if not isinstance(packet_state, ForwardingPacketState):
        raise RouteTraceContractError(
            "forwarding steering packet_state must be ForwardingPacketState"
        )
    if not isinstance(rules, tuple) or any(
        not isinstance(rule, ForwardingSteeringRule)
        for rule in rules
    ):
        raise RouteTraceContractError(
            "forwarding steering rules must be a tuple of "
            "ForwardingSteeringRule values"
        )
    if len(rules) > 64:
        raise RouteTraceContractError(
            "forwarding steering supports at most 64 rules"
        )
    matches = [
        rule
        for rule in rules
        if rule.target_step_id == step_id
        and (
            rule.expected_before is None
            or rule.expected_before == packet_state
        )
    ]
    if not matches:
        return None
    highest_priority = max(rule.priority for rule in matches)
    winners = [
        rule for rule in matches if rule.priority == highest_priority
    ]
    if len(winners) > 1:
        raise RouteTraceContractError(
            "forwarding steering has ambiguous rules at the highest priority"
        )
    return winners[0]


def apply_forwarding_steering_rule(
    transition: ForwardingPacketTransition,
    rule: ForwardingSteeringRule,
    *,
    actor_id: str = "user",
) -> ForwardingPacketTransition:
    """Apply one exact forced packet override and retain counterfactual provenance."""

    if not isinstance(transition, ForwardingPacketTransition):
        raise RouteTraceContractError(
            "forwarding steering requires ForwardingPacketTransition"
        )
    if not isinstance(rule, ForwardingSteeringRule):
        raise RouteTraceContractError(
            "forwarding steering requires ForwardingSteeringRule"
        )
    if rule.target_step_id != transition.step_id:
        raise RouteTraceContractError(
            "forwarding steering rule targets a different step"
        )
    if (
        rule.expected_before is not None
        and rule.expected_before != transition.before
    ):
        raise RouteTraceContractError(
            "forwarding steering expected packet state does not match"
        )
    if not isinstance(actor_id, str) or not actor_id:
        raise RouteTraceContractError(
            "forwarding steering actor_id must be a non-empty string"
        )
    action_prefix = "Forced: "
    action_reason = rule.reason
    available_reason_units = 160 - len(action_prefix)
    if len(action_reason) > available_reason_units:
        action_reason = (
            action_reason[: available_reason_units - 1] + "…"
        )
    return replace(
        transition,
        after=rule.packet_after or transition.after,
        action_contract_id=rule.action_contract_id,
        action_label=f"{action_prefix}{action_reason}",
        disposition=rule.disposition or transition.disposition,
        origin=ForwardingTransitionOrigin.USER_FORCED,
        actor_id=actor_id,
        forced_rule_id=rule.rule_id,
    )


def validate_forwarding_step_result(
    request: ForwardingStepRequest,
    result: ForwardingStepResult,
) -> ForwardingStepResult:
    """Validate one node result against its exact request and steering input.

    The plug-in owns forwarding semantics.  Core verifies only request/result
    continuity and that an explicit user rule is neither lost nor fabricated.
    Returning the validated result keeps the helper convenient in coordinator
    pipelines without constructing a second representation.
    """

    if not isinstance(request, ForwardingStepRequest):
        raise RouteTraceContractError(
            "forwarding step request must be ForwardingStepRequest"
        )
    if not isinstance(result, ForwardingStepResult):
        raise RouteTraceContractError(
            "forwarding step result must be ForwardingStepResult"
        )
    if result.step_id != request.step_id:
        raise RouteTraceContractError(
            "forwarding step result does not match the request step_id"
        )
    if result.transition.before != request.packet_state:
        raise RouteTraceContractError(
            "forwarding step result transition before state does not match "
            "the requested packet state"
        )

    selected_rule = select_forwarding_steering_rule(
        step_id=request.step_id,
        packet_state=request.packet_state,
        rules=request.steering_rules,
    )
    transition = result.transition
    if selected_rule is None:
        if transition.origin is ForwardingTransitionOrigin.USER_FORCED:
            raise RouteTraceContractError(
                "forwarding step result claims a user-forced transition "
                "without a matching steering rule"
            )
        return result

    if transition.origin is not ForwardingTransitionOrigin.USER_FORCED:
        raise RouteTraceContractError(
            "forwarding step result did not retain the selected steering rule"
        )
    if transition.forced_rule_id != selected_rule.rule_id:
        raise RouteTraceContractError(
            "forwarding step result forced_rule_id does not match the selected "
            "steering rule"
        )
    if transition.action_contract_id != selected_rule.action_contract_id:
        raise RouteTraceContractError(
            "forwarding step result action contract does not match the selected "
            "steering rule"
        )
    if (
        selected_rule.selected_candidate is not None
        and result.selected_candidate != selected_rule.selected_candidate
    ):
        raise RouteTraceContractError(
            "forwarding step result selected candidate does not match the "
            "selected steering rule"
        )
    if (
        selected_rule.packet_after is not None
        and transition.after != selected_rule.packet_after
    ):
        raise RouteTraceContractError(
            "forwarding step result packet after state does not match the "
            "selected steering rule"
        )
    if (
        selected_rule.disposition is not None
        and transition.disposition is not selected_rule.disposition
    ):
        raise RouteTraceContractError(
            "forwarding step result disposition does not match the selected "
            "steering rule"
        )
    return result


def evaluate_forwarding_packet_trace(
    initial_state: ForwardingPacketState,
    transitions: tuple[ForwardingPacketTransition, ...],
    *,
    max_steps: int = 256,
) -> ForwardingPacketTraceEvaluation:
    """Validate packet continuity and classify one bounded evolution branch.

    A complete before/after mismatch is a plug-in contract error.  When either
    side is explicitly incomplete, core retains the branch with unknown
    continuity instead of guessing across the gap.
    """

    if not isinstance(initial_state, ForwardingPacketState):
        raise RouteTraceContractError(
            "packet trace initial_state must be ForwardingPacketState"
        )
    if not isinstance(transitions, tuple) or any(
        not isinstance(transition, ForwardingPacketTransition)
        for transition in transitions
    ):
        raise RouteTraceContractError(
            "packet trace transitions must be a tuple of "
            "ForwardingPacketTransition values"
        )
    if (
        not isinstance(max_steps, int)
        or isinstance(max_steps, bool)
        or max_steps < 0
    ):
        raise RouteTraceContractError(
            "packet trace max_steps must be a non-negative integer"
        )

    expected = initial_state
    continuity = "complete"
    evaluations: list[ForwardingPacketTransitionEvaluation] = []
    for step, transition in enumerate(transitions):
        if step >= max_steps:
            return ForwardingPacketTraceEvaluation(
                outcome="step_limit_exceeded",
                stop_step=step,
                continuity=continuity,
                transitions=tuple(evaluations),
                budget_kind="max_steps",
                budget_limit=max_steps,
                budget_observed=step + 1,
            )
        if transition.before != expected:
            if (
                transition.before.identity_complete
                and expected.identity_complete
            ):
                raise RouteTraceContractError(
                    "complete packet transition continuity mismatch at "
                    f"step {step}"
                )
            continuity = "unknown_incomplete"
        evaluation = evaluate_forwarding_packet_transition(transition)
        evaluations.append(evaluation)
        expected = transition.after
        disposition = transition.disposition
        if disposition in {
            ForwardingPacketDisposition.DELIVER,
            ForwardingPacketDisposition.DROP,
            ForwardingPacketDisposition.PUNT,
            ForwardingPacketDisposition.REPLICATE,
            ForwardingPacketDisposition.UNKNOWN,
        }:
            if step != len(transitions) - 1:
                raise RouteTraceContractError(
                    "packet transitions must not follow a terminal disposition "
                    f"at step {step}"
                )
            return ForwardingPacketTraceEvaluation(
                outcome=disposition.value,
                stop_step=step,
                continuity=continuity,
                transitions=tuple(evaluations),
                terminal_disposition=disposition,
            )
    return ForwardingPacketTraceEvaluation(
        outcome="continuation_required",
        stop_step=len(evaluations) - 1,
        continuity=continuity,
        transitions=tuple(evaluations),
    )


def _validate_forwarding_policy_inputs(
    *,
    candidate: ResourceKey,
    ingress_scopes: frozenset[ForwardingPolicyScope],
    traffic_class: str | None,
    ingress_scopes_complete: bool,
) -> None:
    """Validate common policy inputs even when no decision is constructed."""

    if not isinstance(candidate, ResourceKey):
        raise RouteTraceContractError(
            "forwarding policy candidate must be a ResourceKey"
        )
    if not isinstance(ingress_scopes, frozenset):
        raise RouteTraceContractError(
            "forwarding policy ingress_scopes must be a frozenset"
        )
    if len(ingress_scopes) > 64:
        raise RouteTraceContractError(
            "forwarding policy supports at most 64 ingress scopes"
        )
    if any(
        not isinstance(scope, ForwardingPolicyScope)
        for scope in ingress_scopes
    ):
        raise RouteTraceContractError(
            "forwarding policy ingress_scopes must contain "
            "ForwardingPolicyScope values"
        )
    if traffic_class is not None and not isinstance(traffic_class, str):
        raise RouteTraceContractError(
            "forwarding policy traffic_class must be a string or None"
        )
    if not isinstance(ingress_scopes_complete, bool):
        raise RouteTraceContractError(
            "ingress_scopes_complete must be a boolean"
        )


def evaluate_forwarding_traversal(
    states: tuple[ForwardingTraversalStateKey, ...],
    *,
    max_hops: int,
    max_recursion: int,
    hop_indices: tuple[int, ...] | None = None,
    recursion_depths: tuple[int, ...] | None = None,
    cycle_reason: str = "forwarding_cycle",
) -> ForwardingTraversalEvaluation:
    """Evaluate exact typed state equality before bounded traversal limits."""

    if not isinstance(states, tuple):
        raise RouteTraceContractError(
            "forwarding traversal states must be a tuple"
        )
    if any(not isinstance(item, ForwardingTraversalStateKey) for item in states):
        raise RouteTraceContractError(
            "forwarding traversal requires ForwardingTraversalStateKey values"
        )
    for label, limit in (
        ("max_hops", max_hops),
        ("max_recursion", max_recursion),
    ):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise RouteTraceContractError(
                f"{label} must be a non-negative integer"
            )
    if hop_indices is None:
        hop_indices = tuple(range(len(states)))
    elif not isinstance(hop_indices, tuple):
        raise RouteTraceContractError("hop_indices must be a tuple or None")
    if recursion_depths is None:
        recursion_depths = tuple(0 for _item in states)
    elif not isinstance(recursion_depths, tuple):
        raise RouteTraceContractError(
            "recursion_depths must be a tuple or None"
        )
    if len(hop_indices) != len(states) or len(recursion_depths) != len(states):
        raise RouteTraceContractError(
            "traversal budgets must provide one value per state"
        )
    for label, values in (
        ("hop indices", hop_indices),
        ("recursion depths", recursion_depths),
    ):
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            for value in values
        ):
            raise RouteTraceContractError(
                f"{label} must be non-negative integers"
            )
    if not states:
        return ForwardingTraversalEvaluation(
            outcome="resolved",
            stop_step=-1,
            terminal_reason=None,
        )

    seen: dict[ForwardingTraversalStateKey, int] = {}
    for step, state in enumerate(states):
        conclusive_identity = (
            state.policy_scopes_complete
            and (
                state.packet_state is None
                or state.packet_state.identity_complete
            )
        )
        if conclusive_identity and state in seen:
            first_step = seen[state]
            return ForwardingTraversalEvaluation(
                outcome="cycle",
                stop_step=step,
                terminal_reason=cycle_reason,
                cycle=ForwardingCycleReport(
                    first_seen_step=first_step,
                    repeated_at_step=step,
                    cycle_states=states[first_step : step + 1],
                ),
            )
        hop_index = hop_indices[step]
        recursion_depth = recursion_depths[step]
        if hop_index > max_hops:
            return ForwardingTraversalEvaluation(
                outcome="hop_limit_exceeded",
                stop_step=step,
                terminal_reason="hop_limit_exceeded",
                budget_kind="max_hops",
                budget_limit=max_hops,
                budget_observed=hop_index,
            )
        if recursion_depth > max_recursion:
            return ForwardingTraversalEvaluation(
                outcome="recursion_limit_exceeded",
                stop_step=step,
                terminal_reason="recursion_limit_exceeded",
                budget_kind="max_recursion",
                budget_limit=max_recursion,
                budget_observed=recursion_depth,
            )
        if conclusive_identity:
            seen[state] = step
    return ForwardingTraversalEvaluation(
        outcome="resolved",
        stop_step=len(states) - 1,
        terminal_reason=None,
    )


def detect_forwarding_cycle(
    states: tuple[ForwardingTraversalStateKey, ...],
) -> ForwardingCycleReport | None:
    """Return the first exact typed cycle, retaining the closing state."""

    evaluation = evaluate_forwarding_traversal(
        states,
        max_hops=max(len(states), 1),
        max_recursion=max(len(states), 1),
    )
    return evaluation.cycle


def evaluate_forwarding_constraint(
    *,
    candidate: ResourceKey,
    constraint: ForwardingCandidateConstraint,
    ingress_scopes: frozenset[ForwardingPolicyScope],
    traffic_class: str | None,
    ingress_scopes_complete: bool = True,
) -> ForwardingPolicyDecision:
    """Evaluate one exact-scope constraint without treating omission as absence."""

    _validate_forwarding_policy_inputs(
        candidate=candidate,
        ingress_scopes=ingress_scopes,
        traffic_class=traffic_class,
        ingress_scopes_complete=ingress_scopes_complete,
    )
    if not isinstance(constraint, ForwardingCandidateConstraint):
        raise RouteTraceContractError(
            "forwarding policy constraint must be a "
            "ForwardingCandidateConstraint"
        )
    applies = constraint.applies_to(traffic_class)
    if applies is None:
        verdict = ForwardingPolicyVerdict.UNKNOWN
    elif not applies:
        verdict = ForwardingPolicyVerdict.NOT_APPLICABLE
    elif constraint.candidate_scope in ingress_scopes:
        verdict = ForwardingPolicyVerdict.BLOCKED
    elif not ingress_scopes_complete:
        verdict = ForwardingPolicyVerdict.UNKNOWN
    else:
        verdict = ForwardingPolicyVerdict.PERMITTED
    return ForwardingPolicyDecision(
        candidate=candidate,
        constraint=constraint,
        verdict=verdict,
        traffic_class=traffic_class,
        ingress_scopes=ingress_scopes,
        ingress_scopes_complete=ingress_scopes_complete,
    )


def evaluate_forwarding_policy(
    *,
    candidate: ResourceKey,
    constraints: tuple[ForwardingCandidateConstraint, ...],
    ingress_scopes: frozenset[ForwardingPolicyScope],
    traffic_class: str | None,
    ingress_scopes_complete: bool = True,
) -> ForwardingPolicyEvaluation:
    """Evaluate and aggregate a candidate's bounded plug-in constraints."""

    _validate_forwarding_policy_inputs(
        candidate=candidate,
        ingress_scopes=ingress_scopes,
        traffic_class=traffic_class,
        ingress_scopes_complete=ingress_scopes_complete,
    )
    if not isinstance(constraints, tuple):
        raise RouteTraceContractError(
            "forwarding policy constraints must be a tuple"
        )
    if len(constraints) > 64:
        raise RouteTraceContractError(
            "forwarding policy supports at most 64 constraints"
        )
    if any(
        not isinstance(constraint, ForwardingCandidateConstraint)
        for constraint in constraints
    ):
        raise RouteTraceContractError(
            "forwarding policy constraints must contain "
            "ForwardingCandidateConstraint values"
        )
    decisions = tuple(
        evaluate_forwarding_constraint(
            candidate=candidate,
            constraint=constraint,
            ingress_scopes=ingress_scopes,
            traffic_class=traffic_class,
            ingress_scopes_complete=ingress_scopes_complete,
        )
        for constraint in constraints
    )
    verdicts = {item.verdict for item in decisions}
    if ForwardingPolicyVerdict.BLOCKED in verdicts:
        aggregate = ForwardingPolicyVerdict.BLOCKED
    elif ForwardingPolicyVerdict.UNKNOWN in verdicts:
        aggregate = ForwardingPolicyVerdict.UNKNOWN
    elif ForwardingPolicyVerdict.PERMITTED in verdicts or not decisions:
        aggregate = ForwardingPolicyVerdict.PERMITTED
    else:
        aggregate = ForwardingPolicyVerdict.NOT_APPLICABLE
    return ForwardingPolicyEvaluation(
        verdict=aggregate,
        decisions=decisions,
    )
