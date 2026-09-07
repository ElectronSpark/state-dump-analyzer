"""Deterministic generic replay from private truth to node-local dump plans."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from ._semantics import (
    delay_ns as _delay_ns,
)
from ._semantics import (
    event_is_physical as _event_is_physical,
)
from ._semantics import EVENT_SEMANTICS, event_target_resource, event_updates_snapshot
from ._semantics import integer as _semantic_integer
from ._semantics import (
    observation_outcome as _observation_outcome,
)
from ._semantics import (
    propagation_target_ids as _propagation_target_ids,
)
from .boundary import node_dump_projection_issue
from .model import (
    ScenarioDocument,
    ScenarioValidationError,
    scenario_from_dict,
    validate_scenario,
)

_DELETE_KINDS = {"delete", "remove", "resource-delete", "resource-remove"}


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


def _resource_record(
    value: Any,
    *,
    default_id: str,
    timestamp_ns: int = 0,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ScenarioValidationError("initial resource entries must be objects")
    record = deepcopy(dict(value))
    resource_id = str(record.get("resource_id", record.get("id", default_id)))
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


def _physical_observations(
    document: ScenarioDocument,
    event: Mapping[str, Any],
    medium: Mapping[str, Any],
    dump_node_ids: Sequence[str],
) -> list[_ScheduledObservation]:
    attachments_by_node: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for attachment in medium.get("attachments", []):
        attachments_by_node[str(attachment["node_id"])].append(attachment)
    targets = _propagation_target_ids(document.media, event, dump_node_ids)
    requested_state = str(_physical_event_state(event))
    observations: list[_ScheduledObservation] = []
    for ordinal, node_id in enumerate(targets):
        outcome = _observation_outcome(document.seed, event, node_id, ordinal)
        state_changed = outcome == "success"
        timestamp_ns = int(event["timestamp_ns"]) + _delay_ns(
            document.seed,
            event,
            node_id,
            ordinal,
        )
        # Cadence/outcome describe a node's observation, shared by all its
        # explicitly attached interfaces. No LAG or parent/member inference.
        local_attachments = attachments_by_node.get(node_id, [])
        for attachment_index, local_attachment in enumerate(local_attachments or [None]):
            if local_attachment is None:
                # A manually selected remote node receives a generic signal.
                port_id = str(event.get("resource_id", "physical-observation"))
                resource_id = port_id if ":" in port_id else f"interface:{port_id}"
                properties = {"observed_physical_state": requested_state}
                resource_type = "observation"
            else:
                port_id = str(local_attachment["port_id"])
                resource_id = _attachment_resource_id(local_attachment)
                local_observation = local_attachment.get("node_local_observation", {})
                if not isinstance(local_observation, Mapping):
                    raise ScenarioValidationError(
                        "attachment.node_local_observation must be an object"
                    )
                properties = {
                    "admin_status": "up",
                    **deepcopy(dict(local_observation.get("properties", {}))),
                    # This scheduled observation supersedes the attachment's
                    # starting carrier state, not its other local properties.
                    "oper_status": requested_state,
                }
                resource_type = str(local_observation.get("resource_type", "interface"))
            stable_id = f"{event['event_id']}:observe:{node_id}"
            if len(local_attachments) > 1:
                stable_id += f":attachment:{attachment_index}"
            observations.append(
                _ScheduledObservation(
                    timestamp_ns=timestamp_ns,
                    order=int(event["order"]),
                    stable_id=stable_id,
                    node_id=node_id,
                    resource_id=resource_id,
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
    resource_id = event_target_resource(event)
    resource_type = str(
        event.get(
            "resource_type",
            event.get(
                "resource_kind",
                properties.get("resource_type", EVENT_SEMANTICS["default_resource_type"]),
            ),
        )
    )
    operation = str(event.get("operation", event.get("action", kind)))
    update_snapshot = event_updates_snapshot(event)
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
            int(event["timestamp_ns"]) if timestamp_ns is None else timestamp_ns
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
    dump_node_ids: Sequence[str],
) -> list[_ScheduledObservation]:
    targets = _propagation_target_ids(document.media, event, dump_node_ids)
    observations: list[_ScheduledObservation] = []
    for ordinal, node_id in enumerate(targets):
        outcome = _observation_outcome(document.seed, event, node_id, ordinal)
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
                    **deepcopy(dict(local_observation.get("properties", {}))),
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
        **({"status": observation.status} if observation.status is not None else {}),
        "message": observation.message,
        "properties": deepcopy(observation.properties),
        "source": observation.source,
    }


def _scenario_document(
    value: ScenarioDocument | Mapping[str, Any],
) -> ScenarioDocument:
    document = (
        value if isinstance(value, ScenarioDocument) else scenario_from_dict(value)
    )
    report = validate_scenario(document)
    if not report["ok"]:
        messages = [str(item.get("message", item)) for item in report["errors"]]
        raise ScenarioValidationError("; ".join(messages))
    return document


def _reconstruction_time_ns(
    document: ScenarioDocument,
    at_time_ns: int | str | None,
) -> int:
    if at_time_ns is None:
        return document.capture_time_ns
    try:
        result = _semantic_integer(at_time_ns, "at_time_ns", minimum=None)
    except ValueError as error:
        raise ScenarioValidationError(str(error)) from error
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
            "properties": deepcopy(
                dict(medium.get("properties", {}))
                if isinstance(medium.get("properties", {}), Mapping)
                else {}
            ),
            "attachments": [
                {
                    "node_id": str(attachment["node_id"]),
                    "port_id": str(attachment["port_id"]),
                    "resource_id": _attachment_resource_id(attachment),
                    "properties": deepcopy(dict(attachment.get("properties", {}))),
                }
                for attachment in medium.get("attachments", [])
            ],
        }
    for medium_id, state in _medium_states_at(document, at_time_ns).items():
        media_by_id[medium_id].update(state)
    return {
        "visibility": "authoring-only",
        "exported_to_node_dumps": False,
        "at_time_ns": at_time_ns,
        "media": sorted(
            media_by_id.values(),
            key=lambda item: str(item["medium_id"]),
        ),
    }


def _medium_states_at(
    document: ScenarioDocument, at_time_ns: int
) -> dict[str, dict[str, Any]]:
    """The single physical replay used by reconstruction and the canvas."""

    states = {
        str(medium["medium_id"]): {
            "state": str(medium.get("state", "up")),
            "changed_at_ns": None,
            "source_event_id": None,
        }
        for medium in document.media
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
        medium = states[medium_id]
        medium["state"] = _physical_event_state(event)
        medium["changed_at_ns"] = timestamp_ns
        medium["source_event_id"] = str(event["event_id"])
    return states


def _preview_physical_truth(
    value: ScenarioDocument | Mapping[str, Any],
    *,
    at_time_ns: int | str | None = None,
) -> dict[str, Any]:
    """Return one state per medium without constructing node histories."""

    document = _scenario_document(value)
    timestamp_ns = _reconstruction_time_ns(document, at_time_ns)
    states = _medium_states_at(document, timestamp_ns)
    return {
        "ok": True,
        "visibility": "authoring-only",
        "exported_to_node_dumps": False,
        "at_time_ns": str(timestamp_ns),
        "media": [
            {"medium_id": medium_id, "state": states[medium_id]["state"]}
            for medium_id in sorted(states)
        ],
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

    dump_nodes = [node for node in document.nodes if node.get("dump_enabled", True)]
    dump_node_ids = [str(node["node_id"]) for node in dump_nodes]
    media_by_id = {str(medium["medium_id"]): medium for medium in document.media}
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
            dump_node_ids=dump_node_ids,
        ):
            scheduled_by_node[observation.node_id].append(observation)

    result: dict[str, dict[str, Any]] = {}
    for node in dump_nodes:
        node_id = str(node["node_id"])
        clock = node.get("clock", {})
        clock_offset_ns = (
            int(clock.get("offset_ns", 0)) if isinstance(clock, Mapping) else 0
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
        issue = node_dump_projection_issue(
            plan,
            private_medium_ids,
            location=f"node_plans.{node_id}",
        )
        if issue is not None:
            path, message = issue
            raise ScenarioValidationError(f"{path}: {message}")
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


def _preview_propagation(document: ScenarioDocument, event_id: str) -> dict[str, Any]:
    """Return editable observations from the exact compilation scheduler."""
    event = next(
        (item for item in document.events if item["event_id"] == event_id), None
    )
    if event is None:
        raise ScenarioValidationError("unknown propagation source event")
    node_ids = [
        str(node["node_id"])
        for node in document.nodes
        if node.get("dump_enabled", True)
    ]
    target_ids = _propagation_target_ids(document.media, event, node_ids)
    target_count = len(target_ids)
    physical = _event_is_physical(event)
    medium = None
    if physical:
        medium_id = str(
            event.get("medium_id", event.get("link_id", event.get("target_id", "")))
        )
        medium = next(
            item for item in document.media if str(item["medium_id"]) == medium_id
        )
    observation_count = target_count
    if medium is not None:
        attachment_counts: dict[str, int] = defaultdict(int)
        for attachment in medium.get("attachments", []):
            attachment_counts[str(attachment["node_id"])] += 1
        observation_count = sum(max(1, attachment_counts[node_id]) for node_id in target_ids)
    # Reject amplification before constructing per-attachment payload copies.
    estimated_bytes = (
        len(json.dumps(event, ensure_ascii=False).encode("utf-8")) + 4096
    ) * observation_count
    if medium is not None:
        targets = frozenset(target_ids)
        estimated_bytes += sum(
            len(json.dumps(attachment, ensure_ascii=False).encode("utf-8"))
            for attachment in medium.get("attachments", [])
            if str(attachment["node_id"]) in targets
        )
    if observation_count > 512 or estimated_bytes > 4 * 1024 * 1024:
        raise ScenarioValidationError(
            "propagation preview exceeds the 512-observation or 4 MiB response budget; select fewer targets"
        )
    if medium is not None:
        observations = _physical_observations(document, event, medium, node_ids)
    else:
        observations = _propagated_local_observations(
            document, event, dump_node_ids=node_ids
        )
    result = {
        "ok": True,
        "events": [
            {
                "event_id": observation.stable_id,
                "timestamp_ns": str(observation.timestamp_ns),
                "order": observation.order,
                "node_id": observation.node_id,
                "resource_id": observation.resource_id,
                "resource_type": observation.resource_type,
                "kind": "propagated-observation",
                "operation": observation.operation,
                "outcome": observation.outcome,
                **(
                    {"status": observation.status}
                    if observation.status is not None
                    else {}
                ),
                "properties": deepcopy(observation.properties),
                "message": observation.message,
                "update_snapshot": observation.update_snapshot,
                "propagation": {
                    "mode": "manual",
                    "generated": True,
                    "materialized": True,
                    "parent_event_id": event_id,
                },
            }
            for observation in observations
        ],
    }
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > 4 * 1024 * 1024:
        raise ScenarioValidationError(
            "propagation preview exceeds the 4 MiB response budget"
        )
    return result


def compile_scenario(
    value: ScenarioDocument | Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Compile the final capture into independent node-local plans."""

    return reconstruct_scenario(value)["node_plans"]


__all__ = ["compile_scenario", "reconstruct_scenario"]
