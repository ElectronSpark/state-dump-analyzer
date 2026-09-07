"""Demo-owned comparison of explicitly paired node-local boundary facts.

These are independent configuration/lookup observations, not packet snapshots.
Core packet continuity and endpoint reachability rules remain unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any


def _valid_timestamp(value: Any) -> bool:
    return (
        type(value) is int and value > 0
        or isinstance(value, str) and value.isascii() and value.isdecimal() and bool(value.strip("0"))
    )


def _valid_identity(
    item: Mapping[str, Any], rule: Mapping[str, Any], direction: str,
) -> bool:
    participant = rule.get("participants", {}).get(direction, {}).get(item.get("role"), {})
    return bool(participant) and (
        item.get("node_id") == participant.get("node_id")
        and item.get("source_resource_id") == participant.get("source_resource_id")
        and item.get("resource_type") == rule.get("resource_type")
        and item.get("resource_id") == (
            f"{participant['node_id']}/{rule.get('resource_layer')}/"
            f"{rule.get('resource_type')}/{participant['source_resource_id']}"
        )
        and _valid_timestamp(item.get("observed_at_ns"))
    )


def evaluate_boundary_findings(
    scenario_id: str,
    rule: Mapping[str, Any],
    candidate_paths: Sequence[Mapping[str, Any]],
    observations: Sequence[Mapping[str, Any]],
    revision_ids_by_node: Mapping[str, str],
) -> list[dict[str, Any]]:
    """Compare complete paired facts; absence is unknown, never disagreement."""

    findings: list[dict[str, Any]] = []
    for direction in ("forward", "reverse"):
        candidates = [item for item in candidate_paths if item.get("direction") == direction]
        if not candidates:
            continue
        facts = [dict(item) for item in observations if item.get("direction") == direction]
        senders = [item for item in facts if item.get("role") == "sender"]
        receivers = [item for item in facts if item.get("role") == "receiver"]
        paired = len(facts) == 2 and len(senders) == len(receivers) == 1
        valid = paired and all(
            item.get("identity_valid", True) is True
            and item.get("scenario_id") == scenario_id
            and item.get("contract_id") == rule.get("contract_id")
            and item.get("complete") is True
            and type(item.get("value")) is int
            and item.get("value", -1) >= 0
            and isinstance(item.get("node_id"), str)
            and item.get("revision_id") == revision_ids_by_node.get(str(item.get("node_id")))
            and bool(item.get("revision_id"))
            and _valid_identity(item, rule, direction)
            for item in facts
        )
        if valid:
            sender, receiver = senders[0], receivers[0]
            valid = (
                sender["node_id"] != receiver["node_id"]
                and sender.get("peer_node_id") == receiver["node_id"]
                and receiver.get("peer_node_id") == sender["node_id"]
                and bool(sender.get("boundary_id"))
                and sender.get("boundary_id") == receiver.get("boundary_id")
                and sender.get("field") == rule.get("sender_field")
                and receiver.get("field") == rule.get("receiver_field")
                and all(
                    sender["node_id"] in candidate.get("node_sequence", [])
                    and receiver["node_id"] in candidate.get("node_sequence", [])
                    for candidate in candidates
                )
            )
        if valid and senders[0]["value"] == receivers[0]["value"]:
            continue
        result = "mismatch" if valid else "unknown"
        label = str(rule["field_label"])
        summary = (
            f"Cross-node {label} disagreement ({direction})"
            if valid else f"Cross-node {label} check is unknown ({direction})"
        )
        fact_details = [
            f"{str(item.get('role', 'unclassified')).capitalize()} {item.get('node_id', 'unknown')}: "
            f"{item.get('field', 'field')}={item.get('value', 'unknown')}; "
            f"resource {item.get('resource_id', 'unknown')}; revision {item.get('revision_id', 'unknown')}; "
            f"source {item.get('source_resource_id', 'unknown')}; observed at {item.get('observed_at_ns', 'unknown')} ns; "
            f"complete={item.get('complete') is True}."
            for item in facts
        ]
        explanation = (
            "The paired node-local declarations disagree under the demo plug-in's exact handoff rule. "
            "This is evidence inconsistency, not a packet-continuity failure or inferred drop."
            if valid else
            "A complete, identity-valid sender/receiver pair is unavailable; no cross-node mismatch is established."
        )
        findings.append({
            "finding_id": f"{scenario_id}:boundary:{direction}",
            "category": "boundary",
            "finding_type": str(rule["finding_type"]),
            "summary": summary,
            "detail": " ".join([explanation, *fact_details]),
            "severity": "warning" if valid else "info",
            "result": result,
            "candidate_ids": [str(item["candidate_id"]) for item in candidates],
            "path_ids": [str(item["path_id"]) for item in candidates],
            "affects_consistency": bool(valid),
            "semantic_owner": "plugin",
            "observations": facts,
        })
    return findings


def revalidate_boundary_coverage(
    coverage: Mapping[str, Any],
    projections_by_node: Mapping[str, Mapping[str, Any]],
    revision_ids_by_node: Mapping[str, str],
    scenarios: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive findings from persisted rows, replacing stale generated verdicts."""

    result = deepcopy(dict(coverage))
    for case in result.get("cases", []):
        scenario_id = str(case.get("case_id", ""))
        rule = scenarios.get(scenario_id, {}).get("cross_node_rule")
        if not isinstance(rule, Mapping):
            continue
        observations: list[dict[str, Any]] = []
        for node_id, projection in projections_by_node.items():
            for row in projection.get("forwarding", []):
                if row.get("scenario_id") != scenario_id:
                    continue
                for direction, decisions in row.get("directional_decisions", {}).items():
                    for decision in decisions:
                        local_observations = decision.get("boundary_observations", [])
                        if not isinstance(local_observations, list):
                            local_observations = [None]
                        for raw in local_observations:
                            if not isinstance(raw, Mapping):
                                observations.append({"direction": direction, "identity_valid": False})
                                continue
                            observation = dict(raw)
                            observation["identity_valid"] = (
                                row.get("node_id") == node_id
                                and row.get("revision_id") == revision_ids_by_node.get(node_id)
                                and observation.get("node_id") == node_id
                                and observation.get("revision_id") == row.get("revision_id")
                                and observation.get("direction") == direction
                                and observation.get("scenario_id") == scenario_id
                                and observation.get("resource_id") in row.get("evidence_resource_ids", [])
                            )
                            observations.append(observation)
        case["consistency_findings"] = evaluate_boundary_findings(
            scenario_id, rule, case.get("candidate_paths", []), observations, revision_ids_by_node,
        )
    return result


__all__ = ["evaluate_boundary_findings", "revalidate_boundary_coverage"]
