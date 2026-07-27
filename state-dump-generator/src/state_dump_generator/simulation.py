"""Deterministic generic replay from private truth to node-local dump plans."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .boundary import private_identifier_paths
from .model import (
    ScenarioDocument,
    ScenarioValidationError,
    scenario_from_dict,
    validate_scenario,
)


_DELETE_KINDS = {"delete", "remove", "resource-delete", "resource-remove"}
_LOG_ONLY_KINDS = {"log", "log-only", "clock"}
_PHYSICAL_KINDS = {
    "link-state",
    "medium-state",
    "physical-link-state",
    "physical-state",
}


@dataclass(frozen=True, slots=True)
class _ScheduledObservation:
    timestamp_ns: int
    order: int
    stable_id: str
    node_id: str
    resource_id: str
    resource_type: str
    operation: str
    outcome: str
    status: str | None
    properties: dict[str, Any]
    message: str
    update_snapshot: bool
    source: str


def _stable_unit_interval(seed: int, *parts: str) -> float:
    digest = hashlib.sha256(str(seed).encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return int.from_bytes(digest.digest()[:8], "big") / float(2**64 - 1)


def _delay_ns(
    seed: int,
    event: Mapping[str, Any],
    node_id: str,
    ordinal: int,
) -> int:
    propagation = event.get("propagation", {})
    if not isinstance(propagation, Mapping):
        return 0
    if "delay_ns" in propagation or "jitter_ns" in propagation:
        base = int(propagation.get("delay_ns", 0))
        jitter = int(propagation.get("jitter_ns", 0))
    else:
        base = int(
            propagation.get(
                "delay_ms",
                propagation.get("base_delay_ms", 0),
            )
        ) * 1_000_000
        jitter = int(propagation.get("jitter_ms", 0)) * 1_000_000
    cadence = str(propagation.get("cadence", "parallel")).casefold()
    if cadence == "serial":
        base += ordinal * max(base, 1_000_000)
    elif cadence == "waves":
        base += (ordinal // 2) * max(base // 2, 1_000_000)
    if not jitter:
        return max(0, base)
    unit = _stable_unit_interval(
        seed,
        str(event["event_id"]),
        node_id,
        str(ordinal),
    )
    signed = round((unit * 2.0 - 1.0) * jitter)
    return max(0, base + signed)


def _event_is_physical(event: Mapping[str, Any]) -> bool:
    kind = str(event.get("kind", "")).casefold().replace("_", "-")
    target_type = str(event.get("target_type", "")).casefold()
    return kind in _PHYSICAL_KINDS or target_type in {
        "link",
        "medium",
        "physical-link",
    }


def _resource_record(
    value: Any,
    *,
    default_id: str,
    timestamp_ns: int = 0,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ScenarioValidationError("initial resource entries must be objects")
    record = deepcopy(dict(value))
    resource_id = str(
        record.get("resource_id", record.get("id", default_id))
    )
    resource_type = str(
        record.get(
            "resource_type",
            record.get("type", record.get("kind", "resource")),
        )
    )
    status = record.get("status", "unknown")
    properties = record.get("properties", record.get("state", {}))
    if not isinstance(properties, Mapping):
        properties = {"value": deepcopy(properties)}
    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "status": str(status),
        "properties": deepcopy(dict(properties)),
        "updated_at_ns": timestamp_ns,
    }


def _event_target_resource(event: Mapping[str, Any]) -> str:
    return str(
        event.get(
            "resource_id",
            event.get("subject", event.get("target_id", "event")),
        )
    )


def _event_properties(event: Mapping[str, Any]) -> dict[str, Any]:
    value = event.get(
        "properties",
        event.get("payload", event.get("state_patch", {})),
    )
    if isinstance(value, Mapping):
        return deepcopy(dict(value))
    return {"value": deepcopy(value)}


def _attachment_resource_id(attachment: Mapping[str, Any]) -> str:
    """Return one stable, node-local identity for a physical attachment."""

    observation = attachment.get("node_local_observation", {})
    if not isinstance(observation, Mapping):
        raise ScenarioValidationError(
            "attachment.node_local_observation must be an object"
        )
    declared = observation.get("resource_id")
    if declared is not None and str(declared):
        return str(declared)
    port_id = str(attachment["port_id"])
    return port_id if ":" in port_id else f"interface:{port_id}"


def _physical_event_state(event: Mapping[str, Any]) -> str:
    properties = _event_properties(event)
    return str(
        event.get(
            "status",
            event.get("state", properties.get("state", "unknown")),
        )
    )


def _observation_outcome(
    seed: int,
    event: Mapping[str, Any],
    node_id: str,
    ordinal: int,
) -> str:
    propagation = event.get("propagation", {})
    if not isinstance(propagation, Mapping):
        return "success"
    outcomes = propagation.get("outcomes", {})
    if isinstance(outcomes, Mapping) and node_id in outcomes:
        return str(outcomes[node_id])
    parent_outcome = str(event.get("outcome", "success")).casefold()
    intended = str(
        propagation.get(
            "outcome",
            propagation.get("intended_outcome", parent_outcome),
        )
    ).casefold()
    if intended == "partial":
        return (
            "success"
            if _stable_unit_interval(
                seed,
                str(event["event_id"]),
                node_id,
                str(ordinal),
                "partial",
            )
            >= 0.5
            else "stale"
        )
    if intended in {"failure", "failed"}:
        return "failed"
    if intended in {"stale", "suppressed", "dropped"}:
        return intended
    if intended in {"ok", "success", "succeeded"}:
        return "success"
    # Unknown parent outcomes are not proof that a propagated update applied.
    # Authors can explicitly override them per target through
    # ``propagation.outcomes`` or ``propagation.outcome``.
    return intended


def _target_node_ids(
    event: Mapping[str, Any],
    *,
    neighbor_ids: Sequence[str],
    dump_node_ids: Sequence[str],
) -> list[str]:
    propagation = event.get("propagation", {})
    if not isinstance(propagation, Mapping):
        return list(neighbor_ids)
    explicit = propagation.get(
        "targets",
        propagation.get("target_node_ids"),
    )
    if isinstance(explicit, Sequence) and not isinstance(explicit, (str, bytes)):
        return list(dict.fromkeys(str(item) for item in explicit))
    target_mode = str(
        propagation.get(
            "target_mode",
            propagation.get("targets_mode", "neighbors"),
        )
    ).casefold()
    if target_mode in {"all", "all-nodes", "all_nodes"}:
        return list(dump_node_ids)
    return list(neighbor_ids)


def _physical_observations(
    document: ScenarioDocument,
    event: Mapping[str, Any],
    medium: Mapping[str, Any],
    dump_node_ids: Sequence[str],
) -> list[_ScheduledObservation]:
    propagation = event.get("propagation", {})
    if not isinstance(propagation, Mapping) or not propagation:
        # Physical truth and router observations are deliberately separate.
        # The author must explicitly request automatic propagation.
        return []
    mode = (
        str(propagation.get("mode", "manual")).casefold()
    )
    if isinstance(propagation, Mapping) and (
        propagation.get("materialized") is True
        or propagation.get("generated") is True
    ):
        return []
    if mode in {"manual", "none", "suppressed"}:
        return []
    attachments = list(medium.get("attachments", []))
    attachment_by_node = {
        str(item["node_id"]): item
        for item in attachments
        if str(item["node_id"]) in dump_node_ids
    }
    targets = _target_node_ids(
        event,
        neighbor_ids=list(attachment_by_node),
        dump_node_ids=dump_node_ids,
    )
    requested_state = str(
        _physical_event_state(event)
    )
    observations: list[_ScheduledObservation] = []
    for ordinal, node_id in enumerate(targets):
        attachment = attachment_by_node.get(node_id)
        if attachment is None:
            # A manually selected remote node receives a generic signal rather
            # than an invented interface attachment.
            port_id = str(event.get("resource_id", "physical-observation"))
            properties = {"observed_physical_state": requested_state}
            resource_type = "observation"
        else:
            port_id = str(attachment["port_id"])
            resource_id = _attachment_resource_id(attachment)
            local_observation = attachment.get(
                "node_local_observation",
                {},
            )
            if not isinstance(local_observation, Mapping):
                raise ScenarioValidationError(
                    "attachment.node_local_observation must be an object"
                )
            properties = {
                "admin_status": "up",
                "oper_status": requested_state,
                **deepcopy(
                    dict(local_observation.get("properties", {}))
                ),
            }
            resource_type = str(
                local_observation.get("resource_type", "interface")
            )
        outcome = (
            "failed"
            if mode == "failed"
            else _observation_outcome(
                document.seed,
                event,
                node_id,
                ordinal,
            )
        )
        state_changed = outcome == "success"
        timestamp_ns = int(event["timestamp_ns"]) + _delay_ns(
            document.seed,
            event,
            node_id,
            ordinal,
        )
        observations.append(
            _ScheduledObservation(
                timestamp_ns=timestamp_ns,
                order=int(event["order"]) * 10_000 + ordinal,
                stable_id=f"{event['event_id']}:observe:{node_id}",
                node_id=node_id,
                resource_id=(
                    resource_id
                    if attachment is not None
                    else (
                        port_id
                        if ":" in port_id
                        else f"interface:{port_id}"
                    )
                ),
                resource_type=resource_type,
                operation="observe_physical_state",
                outcome=outcome,
                status=requested_state if state_changed else None,
                properties=properties if state_changed else {},
                message=(
                    f"Observed local carrier {requested_state} on {port_id}."
                    if state_changed
                    else f"Local carrier update for {port_id} was {outcome}; previous state remains."
                ),
                update_snapshot=state_changed,
                source="auto-propagation",
            )
        )
    return observations


def _local_observation(
    event: Mapping[str, Any],
    *,
    node_id: str,
    timestamp_ns: int | None = None,
    stable_suffix: str = "local",
    source: str = "authored",
) -> _ScheduledObservation:
    kind = str(event.get("kind", "status")).casefold().replace("_", "-")
    outcome = str(event.get("outcome", "ok"))
    properties = _event_properties(event)
    status_value = event.get("status")
    if status_value is None:
        for status_key in (
            "status",
            "oper_status",
            "state",
            "condition",
        ):
            if status_key in properties and not isinstance(
                properties[status_key],
                (dict, list),
            ):
                status_value = properties[status_key]
                break
    resource_id = _event_target_resource(event)
    resource_type = str(
        event.get(
            "resource_type",
            event.get("resource_kind", properties.get("resource_type", "resource")),
        )
    )
    operation = str(event.get("operation", event.get("action", kind)))
    update_snapshot = bool(
        event.get(
            "update_snapshot",
            event.get("update_final_state", kind not in _LOG_ONLY_KINDS),
        )
    )
    if kind in _DELETE_KINDS:
        operation = "delete"
    failed_without_effect = outcome.casefold() in {"failed", "failure"} and not bool(
        event.get("apply_on_failure", False)
    )
    if failed_without_effect:
        update_snapshot = False
    message = str(
        event.get(
            "message",
            event.get(
                "log",
                event.get(
                    "log_text",
                    f"{operation} {resource_id}: {outcome}",
                ),
            ),
        )
    )
    return _ScheduledObservation(
        timestamp_ns=(
            int(event["timestamp_ns"])
            if timestamp_ns is None
            else timestamp_ns
        ),
        order=int(event.get("order", 0)),
        stable_id=f"{event['event_id']}:{stable_suffix}:{node_id}",
        node_id=node_id,
        resource_id=resource_id,
        resource_type=resource_type,
        operation=operation,
        outcome=outcome,
        status=None if status_value is None else str(status_value),
        properties=properties,
        message=message,
        update_snapshot=update_snapshot,
        source=source,
    )


def _propagated_local_observations(
    document: ScenarioDocument,
    event: Mapping[str, Any],
    *,
    neighbor_ids: Sequence[str],
    dump_node_ids: Sequence[str],
) -> list[_ScheduledObservation]:
    propagation = event.get("propagation", {})
    if not isinstance(propagation, Mapping) or not propagation:
        return []
    if (
        propagation.get("materialized") is True
        or propagation.get("generated") is True
    ):
        # The editor can turn a preview into ordinary, individually editable
        # child events.  The parent then retains its intent for explanation
        # but must not synthesize a second copy during compilation.
        return []
    mode = str(propagation.get("mode", "best-effort")).casefold()
    if mode in {"manual", "none", "suppressed"}:
        return []
    source_node = str(event.get("node_id", ""))
    targets = [
        node_id
        for node_id in _target_node_ids(
            event,
            neighbor_ids=neighbor_ids,
            dump_node_ids=dump_node_ids,
        )
        if node_id != source_node
    ]
    observations: list[_ScheduledObservation] = []
    for ordinal, node_id in enumerate(targets):
        outcome = (
            "failed"
            if mode == "failed"
            else _observation_outcome(
                document.seed,
                event,
                node_id,
                ordinal,
            )
        )
        propagated = dict(event)
        propagated["outcome"] = outcome
        if outcome != "success":
            propagated["update_snapshot"] = False
            propagated["message"] = (
                f"Propagation of {event['event_id']} to this node was {outcome}; "
                "previous state remains."
            )
        timestamp_ns = int(event["timestamp_ns"]) + _delay_ns(
            document.seed,
            event,
            node_id,
            ordinal,
        )
        observations.append(
            _local_observation(
                propagated,
                node_id=node_id,
                timestamp_ns=timestamp_ns,
                stable_suffix=f"propagated-{ordinal}",
                source="auto-propagation",
            )
        )
    return observations


def _neighbors_by_node(document: ScenarioDocument) -> dict[str, list[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for medium in document.media:
        node_ids = [
            str(item["node_id"])
            for item in medium.get("attachments", [])
        ]
        for node_id in node_ids:
            result[node_id].update(
                candidate for candidate in node_ids if candidate != node_id
            )
    return {
        node_id: sorted(neighbors)
        for node_id, neighbors in result.items()
    }


def _initial_state(
    document: ScenarioDocument,
    node: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    node_id = str(node["node_id"])
    resources: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(node.get("initial_resources", [])):
        record = _resource_record(
            value,
            default_id=f"resource:{index + 1}",
        )
        resources[str(record["resource_id"])] = record
    # The physical graph is consulted only to create each node's local port
    # observation.  No medium ID, complete participant list, or remote graph
    # structure is copied into the record.
    for medium in document.media:
        physical_state = str(medium.get("state", "up"))
        for attachment in medium.get("attachments", []):
            if str(attachment["node_id"]) != node_id:
                continue
            port_id = str(attachment["port_id"])
            resource_id = _attachment_resource_id(attachment)
            local_observation = attachment.get(
                "node_local_observation",
                {},
            )
            if not isinstance(local_observation, Mapping):
                raise ScenarioValidationError(
                    "attachment.node_local_observation must be an object"
                )
            observed_state = str(
                local_observation.get(
                    "observed_state",
                    physical_state,
                )
            )
            resources[resource_id] = {
                "resource_id": resource_id,
                "resource_type": str(
                    local_observation.get("resource_type", "interface")
                ),
                "status": observed_state,
                "properties": {
                    "admin_status": "up",
                    "oper_status": observed_state,
                    **deepcopy(
                        dict(local_observation.get("properties", {}))
                    ),
                },
                "updated_at_ns": 0,
            }
    return resources


def _apply_observation(
    state: dict[str, dict[str, Any]],
    observation: _ScheduledObservation,
) -> None:
    if not observation.update_snapshot:
        return
    if observation.operation.casefold().replace("_", "-") in _DELETE_KINDS:
        state.pop(observation.resource_id, None)
        return
    current = deepcopy(
        state.get(
            observation.resource_id,
            {
                "resource_id": observation.resource_id,
                "resource_type": observation.resource_type,
                "status": "unknown",
                "properties": {},
                "updated_at_ns": 0,
            },
        )
    )
    current["resource_type"] = observation.resource_type
    if observation.status is not None:
        current["status"] = observation.status
    properties = current.get("properties")
    if not isinstance(properties, Mapping):
        properties = {}
    merged = deepcopy(dict(properties))
    merged.update(deepcopy(observation.properties))
    current["properties"] = merged
    current["updated_at_ns"] = observation.timestamp_ns
    state[observation.resource_id] = current


def _log_record(
    observation: _ScheduledObservation,
    *,
    clock_offset_ns: int,
) -> dict[str, Any]:
    return {
        "event_id": observation.stable_id,
        "timestamp_ns": observation.timestamp_ns + clock_offset_ns,
        "source_sequence": observation.order,
        "resource_id": observation.resource_id,
        "resource_type": observation.resource_type,
        "operation": observation.operation,
        "outcome": observation.outcome,
        "state_changed": observation.update_snapshot,
        "message": observation.message,
        "properties": deepcopy(observation.properties),
        "source": observation.source,
    }


def _scenario_document(
    value: ScenarioDocument | Mapping[str, Any],
) -> ScenarioDocument:
    document = (
        value
        if isinstance(value, ScenarioDocument)
        else scenario_from_dict(value)
    )
    report = validate_scenario(document)
    if not report["ok"]:
        messages = [
            str(item.get("message", item))
            for item in report["errors"]
        ]
        raise ScenarioValidationError("; ".join(messages))
    return document


def _reconstruction_time_ns(
    document: ScenarioDocument,
    at_time_ns: int | str | None,
) -> int:
    if at_time_ns is None:
        return document.capture_time_ns
    if isinstance(at_time_ns, bool):
        raise ScenarioValidationError("at_time_ns must be an integer")
    if isinstance(at_time_ns, float) and not at_time_ns.is_integer():
        raise ScenarioValidationError("at_time_ns must be an integer")
    try:
        result = int(at_time_ns)
    except (TypeError, ValueError) as error:
        raise ScenarioValidationError("at_time_ns must be an integer") from error
    if result < 0:
        raise ScenarioValidationError("at_time_ns cannot be negative")
    if result > document.capture_time_ns:
        raise ScenarioValidationError(
            "at_time_ns cannot be after the final snapshot capture"
        )
    return result


def _private_medium_truth_at(
    document: ScenarioDocument,
    at_time_ns: int,
) -> dict[str, Any]:
    """Replay private physical truth without projecting it into node plans."""

    media_by_id: dict[str, dict[str, Any]] = {}
    for medium in document.media:
        medium_id = str(medium["medium_id"])
        media_by_id[medium_id] = {
            "medium_id": medium_id,
            "name": str(medium.get("name", medium_id)),
            "kind": str(medium.get("kind", "point-to-point")),
            "state": str(medium.get("state", "up")),
            "properties": deepcopy(
                dict(medium.get("properties", {}))
                if isinstance(medium.get("properties", {}), Mapping)
                else {}
            ),
            "changed_at_ns": None,
            "source_event_id": None,
            "attachments": [
                {
                    "node_id": str(attachment["node_id"]),
                    "port_id": str(attachment["port_id"]),
                    "resource_id": _attachment_resource_id(attachment),
                    "properties": deepcopy(
                        dict(attachment.get("properties", {}))
                    ),
                }
                for attachment in medium.get("attachments", [])
            ],
        }
    for event in sorted(
        document.events,
        key=lambda item: (
            int(item["timestamp_ns"]),
            int(item["order"]),
            str(item["event_id"]),
        ),
    ):
        timestamp_ns = int(event["timestamp_ns"])
        if timestamp_ns > at_time_ns:
            break
        if not _event_is_physical(event):
            continue
        outcome = str(event.get("outcome", "ok")).casefold()
        if outcome in {"failed", "failure"} and not bool(
            event.get("apply_on_failure", False)
        ):
            continue
        medium_id = str(
            event.get(
                "medium_id",
                event.get("link_id", event.get("target_id")),
            )
        )
        medium = media_by_id[medium_id]
        medium["state"] = _physical_event_state(event)
        medium["changed_at_ns"] = timestamp_ns
        medium["source_event_id"] = str(event["event_id"])
    return {
        "visibility": "authoring-only",
        "exported_to_node_dumps": False,
        "at_time_ns": at_time_ns,
        "media": sorted(
            media_by_id.values(),
            key=lambda item: str(item["medium_id"]),
        ),
    }


def reconstruct_scenario(
    value: ScenarioDocument | Mapping[str, Any],
    *,
    at_time_ns: int | str | None = None,
) -> dict[str, Any]:
    """Replay node observations and private medium truth through one instant.

    ``at_time_ns`` uses the scenario's relative nanosecond timeline.  The
    returned ``node_plans`` are safe inputs to the archive writer.  The
    separate ``private_truth`` value exists only for the local authoring UI
    and validation and is never added to a node dump.
    """

    document = _scenario_document(value)
    reconstruction_time_ns = _reconstruction_time_ns(document, at_time_ns)

    dump_nodes = [
        node for node in document.nodes if node.get("dump_enabled", True)
    ]
    dump_node_ids = [str(node["node_id"]) for node in dump_nodes]
    neighbors = _neighbors_by_node(document)
    media_by_id = {
        str(medium["medium_id"]): medium for medium in document.media
    }
    scheduled_by_node: dict[str, list[_ScheduledObservation]] = defaultdict(list)

    for event in sorted(
        document.events,
        key=lambda item: (
            int(item["timestamp_ns"]),
            int(item["order"]),
            str(item["event_id"]),
        ),
    ):
        if int(event["timestamp_ns"]) > reconstruction_time_ns:
            break
        if _event_is_physical(event):
            medium_id = str(
                event.get(
                    "medium_id",
                    event.get("link_id", event.get("target_id")),
                )
            )
            for observation in _physical_observations(
                document,
                event,
                media_by_id[medium_id],
                dump_node_ids,
            ):
                scheduled_by_node[observation.node_id].append(observation)
            continue
        node_id = str(event.get("node_id", ""))
        if node_id in dump_node_ids:
            scheduled_by_node[node_id].append(
                _local_observation(event, node_id=node_id)
            )
        for observation in _propagated_local_observations(
            document,
            event,
            neighbor_ids=neighbors.get(node_id, []),
            dump_node_ids=dump_node_ids,
        ):
            scheduled_by_node[observation.node_id].append(observation)

    result: dict[str, dict[str, Any]] = {}
    for node in dump_nodes:
        node_id = str(node["node_id"])
        clock = node.get("clock", {})
        clock_offset_ns = (
            int(clock.get("offset_ns", 0))
            if isinstance(clock, Mapping)
            else 0
        )
        state = _initial_state(document, node)
        logs: list[dict[str, Any]] = []
        observations = sorted(
            scheduled_by_node.get(node_id, []),
            key=lambda item: (
                item.timestamp_ns,
                item.order,
                item.stable_id,
            ),
        )
        for observation in observations:
            if observation.timestamp_ns > reconstruction_time_ns:
                break
            _apply_observation(state, observation)
            logs.append(
                _log_record(
                    observation,
                    clock_offset_ns=clock_offset_ns,
                )
            )
        final_state = sorted(
            (
                {
                    **deepcopy(record),
                    # Every exported node timestamp uses that node's wall
                    # clock. The private simulation timeline never enters a
                    # generated dump as an absolute-time oracle.
                    "updated_at_ns": int(record.get("updated_at_ns", 0))
                    + clock_offset_ns,
                }
                for record in state.values()
            ),
            key=lambda item: str(item["resource_id"]),
        )
        result[node_id] = {
            "node_id": node_id,
            "captured_at_ns": reconstruction_time_ns + clock_offset_ns,
            "final_state": final_state,
            "logs": logs,
        }
    private_medium_ids = frozenset(
        str(medium["medium_id"]) for medium in document.media
    )
    for node_id, plan in result.items():
        leaked_path = next(
            private_identifier_paths(
                plan,
                private_medium_ids,
                location=f"node_plans.{node_id}",
            ),
            None,
        )
        if leaked_path is not None:
            raise ScenarioValidationError(
                f"{leaked_path} copies a private physical medium identifier "
                "into a node-local observation"
            )
    return {
        "at_time_ns": reconstruction_time_ns,
        "capture_time_ns": document.capture_time_ns,
        "is_final": reconstruction_time_ns == document.capture_time_ns,
        "node_plans": result,
        "private_truth": _private_medium_truth_at(
            document,
            reconstruction_time_ns,
        ),
    }


def compile_scenario(
    value: ScenarioDocument | Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Compile the final capture into independent node-local plans."""

    return reconstruct_scenario(value)["node_plans"]


__all__ = ["compile_scenario", "reconstruct_scenario"]
