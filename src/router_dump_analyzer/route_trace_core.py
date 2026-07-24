"""Protocol-neutral route traversal and policy outcome helpers.

Plug-ins own the meaning of forwarding objects, ingress scopes, encapsulation,
and policies.  The core treats those values as opaque structured identity,
detects exact repeated states, applies explicit budgets, and produces validated
generic policy verdicts from plug-in-declared constraints.
"""

from __future__ import annotations

from dataclasses import dataclass

from .plugin_api import (
    ForwardingCandidateConstraint,
    ForwardingCycleReport,
    ForwardingPolicyDecision,
    ForwardingPolicyScope,
    ForwardingPolicyVerdict,
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
        if state in seen:
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
