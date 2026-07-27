"""Saved-project model for the standalone state-dump generator.

The document in this module is an authoring format, not a router dump format.
It may contain the complete supposed physical topology and the intended
propagation behavior.  :mod:`state_dump_generator.simulation` is the only
component allowed to turn that private model into node-local observations.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .boundary import node_dump_projection_issue
from .path_safety import resolve_regular_file


SCHEMA_VERSION = 1
SCHEMA_ID = "state-dump-generator-scenario/v1"
MAX_NODES = 10_000
MAX_MEDIA = 100_000
MAX_EVENTS = 1_000_000
_ID_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:@/+~-]{0,255})\Z")


class ScenarioValidationError(ValueError):
    """Raised when an authoring project cannot be compiled safely."""


def _detached(value: Any) -> Any:
    try:
        return json.loads(
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        )
    except (TypeError, ValueError) as error:
        raise ScenarioValidationError(
            f"scenario values must be finite JSON values: {error}"
        ) from error


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ScenarioValidationError(f"{label} must be an object")
    return {str(key): _detached(item) for key, item in value.items()}


def _sequence(value: Any, label: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ScenarioValidationError(f"{label} must be an array")
    return [_detached(item) for item in value]


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool):
        raise ScenarioValidationError(f"{label} must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as error:
        raise ScenarioValidationError(f"{label} must be an integer") from error
    if result < minimum:
        raise ScenarioValidationError(
            f"{label} must be greater than or equal to {minimum}"
        )
    return result


def _identifier(value: Any, label: str) -> str:
    result = str(value or "").strip()
    if not _ID_PATTERN.fullmatch(result):
        raise ScenarioValidationError(
            f"{label} must contain 1-256 safe identifier characters"
        )
    return result


def _time_ns(record: Mapping[str, Any], *, default: int = 0) -> int:
    for name in ("timestamp_ns", "time_ns", "at_ns"):
        if name in record:
            return _integer(record[name], name)
    for name in ("time_seconds", "at_seconds", "time_s"):
        if name in record:
            value = record[name]
            if isinstance(value, bool):
                raise ScenarioValidationError(f"{name} must be numeric")
            try:
                seconds = float(value)
            except (TypeError, ValueError) as error:
                raise ScenarioValidationError(f"{name} must be numeric") from error
            if seconds < 0 or not seconds < float("inf"):
                raise ScenarioValidationError(
                    f"{name} must be a finite non-negative number"
                )
            return round(seconds * 1_000_000_000)
    for name in ("time_ms", "timestamp_ms", "at_ms"):
        if name in record:
            value = record[name]
            if isinstance(value, bool):
                raise ScenarioValidationError(f"{name} must be numeric")
            try:
                milliseconds = float(value)
            except (TypeError, ValueError) as error:
                raise ScenarioValidationError(f"{name} must be numeric") from error
            if milliseconds < 0 or not milliseconds < float("inf"):
                raise ScenarioValidationError(
                    f"{name} must be a finite non-negative number"
                )
            return round(milliseconds * 1_000_000)
    return default


def _node_id(record: Mapping[str, Any], index: int) -> str:
    return _identifier(
        record.get("node_id", record.get("id")),
        f"nodes[{index}].node_id",
    )


def _medium_id(record: Mapping[str, Any], index: int) -> str:
    return _identifier(
        record.get(
            "medium_id",
            record.get("link_id", record.get("id")),
        ),
        f"media[{index}].medium_id",
    )


def _attachment(
    value: Any,
    *,
    label: str,
    default_port: str,
) -> dict[str, Any]:
    if isinstance(value, str):
        return {
            "node_id": _identifier(value, f"{label}.node_id"),
            "port_id": default_port,
            "resource_id": f"interface:{default_port}",
            "properties": {},
            "node_local_observation": {
                "resource_id": f"interface:{default_port}",
                "resource_type": "interface",
                "properties": {},
            },
        }
    item = _mapping(value, label)
    node_id = _identifier(
        item.get("node_id", item.get("object_id", item.get("node"))),
        f"{label}.node_id",
    )
    port_id = _identifier(
        item.get(
            "port_id",
            item.get("port", item.get("interface", default_port)),
        ),
        f"{label}.port_id",
    )
    raw_resource_id = item.get(
        "resource_id",
        item.get("local_resource_id"),
    )
    resource_id = (
        _identifier(raw_resource_id, f"{label}.resource_id")
        if raw_resource_id is not None
        else (
            port_id
            if ":" in port_id
            else f"interface:{port_id}"
        )
    )
    properties = item.get("properties", {})
    if not isinstance(properties, Mapping):
        raise ScenarioValidationError(f"{label}.properties must be an object")
    raw_observation = item.get("node_local_observation")
    if "node_local_observation" in item:
        observation = _mapping(
            raw_observation,
            f"{label}.node_local_observation",
        )
        observation_properties = observation.get("properties", {})
        if not isinstance(observation_properties, Mapping):
            raise ScenarioValidationError(
                f"{label}.node_local_observation.properties must be an object"
            )
    else:
        # Attachment properties belong only to the private authoring model.
        # Node-local evidence crosses the dump boundary exclusively through
        # the explicit observation envelope.
        observation = {}
        observation_properties = {}
    raw_observation_resource_id = observation.get(
        "resource_id",
        observation.get("local_resource_id", resource_id),
    )
    observation_resource_id = _identifier(
        raw_observation_resource_id,
        f"{label}.node_local_observation.resource_id",
    )
    observation_resource_type = str(
        observation.get(
            "resource_type",
            observation.get("type", "interface"),
        )
    ).strip() or "interface"
    node_local_observation = {
        "resource_id": observation_resource_id,
        "resource_type": observation_resource_type,
        "properties": _detached(dict(observation_properties)),
    }
    observation_status = observation.get(
        "observed_state",
        observation.get("status"),
    )
    if observation_status is not None:
        node_local_observation["observed_state"] = str(observation_status)
    result = {
        "node_id": node_id,
        "port_id": port_id,
        "resource_id": resource_id,
        "properties": _detached(dict(properties)),
        "node_local_observation": node_local_observation,
    }
    if "observed_state" in item:
        result["observed_state"] = str(item["observed_state"])
    return result


def _normalize_medium(value: Any, index: int) -> dict[str, Any]:
    item = _mapping(value, f"media[{index}]")
    medium_id = _medium_id(item, index)
    raw_attachments = item.get("attachments")
    if raw_attachments is None:
        endpoint_a = item.get(
            "a",
            item.get("from", item.get("source", item.get("node_a"))),
        )
        endpoint_b = item.get(
            "b",
            item.get("to", item.get("target", item.get("node_b"))),
        )
        if endpoint_a is None or endpoint_b is None:
            raw_attachments = []
        else:
            raw_attachments = [
                (
                    {"node_id": endpoint_a, "port_id": item.get("port_a", "port-1")}
                    if isinstance(endpoint_a, str)
                    else endpoint_a
                ),
                (
                    {"node_id": endpoint_b, "port_id": item.get("port_b", "port-1")}
                    if isinstance(endpoint_b, str)
                    else endpoint_b
                ),
            ]
    attachments = [
        _attachment(
            attachment,
            label=f"media[{index}].attachments[{attachment_index}]",
            default_port=f"port-{attachment_index + 1}",
        )
        for attachment_index, attachment in enumerate(
            _sequence(raw_attachments, f"media[{index}].attachments")
        )
    ]
    return {
        **item,
        "medium_id": medium_id,
        "name": str(item.get("name", item.get("label", medium_id))),
        "kind": str(item.get("kind", item.get("media_type", "point-to-point"))),
        "state": str(item.get("state", item.get("initial_state", "up"))),
        "attachments": attachments,
    }


def _normalize_node(value: Any, index: int) -> dict[str, Any]:
    item = _mapping(value, f"nodes[{index}]")
    node_id = _node_id(item, index)
    kind = str(item.get("kind", item.get("type", "router"))).strip() or "router"
    dump_enabled = item.get("dump_enabled")
    if dump_enabled is None:
        dump_enabled = kind.casefold() == "router"
    if not isinstance(dump_enabled, bool):
        raise ScenarioValidationError(f"nodes[{index}].dump_enabled must be boolean")
    raw_clock = item.get("clock", {})
    if not isinstance(raw_clock, Mapping):
        raise ScenarioValidationError(f"nodes[{index}].clock must be an object")
    clock = {
        "offset_ns": int(raw_clock.get("offset_ns", item.get("clock_offset_ns", 0))),
        "uncertainty_ns": _integer(
            raw_clock.get(
                "uncertainty_ns",
                item.get("clock_uncertainty_ns", 0),
            ),
            f"nodes[{index}].clock.uncertainty_ns",
        ),
    }
    initial_resources = _sequence(
        item.get("initial_resources", item.get("resources", [])),
        f"nodes[{index}].initial_resources",
    )
    return {
        **item,
        "node_id": node_id,
        "name": str(item.get("name", item.get("label", node_id))),
        "kind": kind,
        "dump_enabled": dump_enabled,
        "clock": clock,
        "initial_resources": initial_resources,
    }


def _normalize_event(value: Any, index: int) -> dict[str, Any]:
    item = _mapping(value, f"events[{index}]")
    event_id = _identifier(
        item.get("event_id", item.get("change_id", item.get("id"))),
        f"events[{index}].event_id",
    )
    timestamp_ns = _time_ns(item)
    kind = str(item.get("kind", item.get("event_type", "status"))).strip()
    if not kind:
        raise ScenarioValidationError(f"events[{index}].kind cannot be empty")
    propagation = item.get("propagation")
    if propagation is None and item.get("auto_propagate"):
        propagation = {"mode": "best-effort"}
    if propagation is not None and not isinstance(propagation, Mapping):
        raise ScenarioValidationError(
            f"events[{index}].propagation must be an object"
        )
    result = {
        **item,
        "event_id": event_id,
        "timestamp_ns": timestamp_ns,
        "order": _integer(item.get("order", index), f"events[{index}].order"),
        "kind": kind,
        "outcome": str(item.get("outcome", "ok")),
        "propagation": _detached(dict(propagation or {})),
    }
    if "properties" not in result:
        for alias in ("payload", "state_patch"):
            if alias in item:
                result["properties"] = _detached(item[alias])
                break
    if "subject" in item and "resource_id" not in result:
        result["resource_id"] = str(item["subject"])
    if "log_text" in item and "message" not in result:
        result["message"] = str(item["log_text"])
    if "update_snapshot" not in result and "update_final_state" in item:
        result["update_snapshot"] = bool(item["update_final_state"])
    return result


@dataclass(frozen=True, slots=True)
class ScenarioDocument:
    """Normalized standalone authoring project."""

    scenario_id: str
    name: str
    seed: int
    capture_time_ns: int
    nodes: tuple[dict[str, Any], ...]
    media: tuple[dict[str, Any], ...]
    events: tuple[dict[str, Any], ...]
    metadata: dict[str, Any]
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "schema_id": SCHEMA_ID,
            "scenario_id": self.scenario_id,
            "name": self.name,
            "seed": self.seed,
            "capture_time_ns": self.capture_time_ns,
            "nodes": _detached(self.nodes),
            "media": _detached(self.media),
            "events": _detached(self.events),
            "metadata": _detached(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ScenarioDocument":
        return scenario_from_dict(value)


def scenario_from_dict(value: Mapping[str, Any]) -> ScenarioDocument:
    """Parse and normalize a saved project.

    ``links`` and ``timeline`` are accepted as UI-friendly aliases for
    ``media`` and ``events``.  They are normalized when the project is saved.
    """

    root = _mapping(value, "scenario")
    schema_id = root.get("schema_id")
    if schema_id is not None and str(schema_id) != SCHEMA_ID:
        raise ScenarioValidationError(
            f"unsupported schema_id {schema_id!r}; expected {SCHEMA_ID!r}"
        )
    raw_version = root.get("schema_version", SCHEMA_VERSION)
    if isinstance(raw_version, str) and raw_version == SCHEMA_ID:
        raw_version = SCHEMA_VERSION
    schema_version = _integer(raw_version, "schema_version", minimum=1)
    nodes = tuple(
        _normalize_node(item, index)
        for index, item in enumerate(_sequence(root.get("nodes", []), "nodes"))
    )
    raw_media = root.get(
        "media",
        root.get("physical_links", root.get("links", [])),
    )
    media = tuple(
        _normalize_medium(item, index)
        for index, item in enumerate(_sequence(raw_media, "media"))
    )
    raw_events = root.get("events", root.get("timeline", []))
    events = tuple(
        _normalize_event(item, index)
        for index, item in enumerate(_sequence(raw_events, "events"))
    )
    dump_node_ids = frozenset(
        str(node["node_id"])
        for node in nodes
        if bool(node.get("dump_enabled", True))
    )
    latest_scheduled_ns = max(
        (
            int(event["timestamp_ns"])
            + _propagation_horizon_ns(
                event.get("propagation", {}),
                target_count=len(
                    _propagation_target_ids(
                        media,
                        event,
                        dump_node_ids,
                    )
                ),
            )
            for event in events
        ),
        default=0,
    )
    capture_value = root.get(
        "capture_time_ns",
        root.get(
            "final_snapshot_ns",
            max(60_000_000_000, latest_scheduled_ns + 1_000_000_000),
        ),
    )
    metadata = root.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise ScenarioValidationError("metadata must be an object")
    document = ScenarioDocument(
        schema_version=schema_version,
        scenario_id=_identifier(
            root.get("scenario_id", root.get("id", "untitled-scenario")),
            "scenario_id",
        ),
        name=str(root.get("name", root.get("title", "Untitled scenario"))),
        seed=_integer(root.get("seed", 1), "seed"),
        capture_time_ns=_integer(capture_value, "capture_time_ns"),
        nodes=nodes,
        media=media,
        events=events,
        metadata=_detached(dict(metadata)),
    )
    return document


def _propagation_horizon_ns(value: Any, *, target_count: int) -> int:
    """Return a safe upper bound for every generated target observation."""

    if not isinstance(value, Mapping) or target_count < 1:
        return 0
    if "delay_ns" in value or "jitter_ns" in value:
        delay = _integer(value.get("delay_ns", 0), "propagation.delay_ns")
        jitter = _integer(value.get("jitter_ns", 0), "propagation.jitter_ns")
    else:
        delay = _integer(
            value.get("delay_ms", value.get("base_delay_ms", 0)),
            "propagation.delay_ms",
        ) * 1_000_000
        jitter = _integer(
            value.get("jitter_ms", 0),
            "propagation.jitter_ms",
        ) * 1_000_000
    cadence = str(value.get("cadence", "parallel")).casefold()
    final_ordinal = target_count - 1
    if cadence == "serial":
        delay += final_ordinal * max(delay, 1_000_000)
    elif cadence == "waves":
        delay += (final_ordinal // 2) * max(delay // 2, 1_000_000)
    return max(0, delay + abs(jitter))


def _propagation_target_ids(
    media: Sequence[Mapping[str, Any]],
    event: Mapping[str, Any],
    dump_node_ids: frozenset[str],
) -> tuple[str, ...]:
    """Mirror the simulator's generated-observation target selection."""

    propagation = event.get("propagation", {})
    if not isinstance(propagation, Mapping) or not propagation:
        return ()
    if (
        propagation.get("materialized") is True
        or propagation.get("generated") is True
    ):
        return ()
    physical = _event_is_physical(event)
    default_mode = "manual" if physical else "best-effort"
    mode = str(propagation.get("mode", default_mode)).casefold()
    if mode in {"manual", "none", "suppressed"}:
        return ()

    explicit = propagation.get(
        "targets",
        propagation.get("target_node_ids"),
    )
    if isinstance(explicit, Sequence) and not isinstance(explicit, (str, bytes)):
        candidates = list(dict.fromkeys(str(item) for item in explicit))
    else:
        target_mode = str(
            propagation.get(
                "target_mode",
                propagation.get("targets_mode", "neighbors"),
            )
        ).casefold()
        if target_mode in {"all", "all-nodes", "all_nodes"}:
            candidates = sorted(dump_node_ids)
        elif physical:
            medium_id = str(
                event.get(
                    "medium_id",
                    event.get("link_id", event.get("target_id", "")),
                )
            )
            medium = next(
                (
                    item
                    for item in media
                    if str(item["medium_id"]) == medium_id
                ),
                None,
            )
            candidates = (
                [
                    str(item["node_id"])
                    for item in medium.get("attachments", [])
                    if str(item["node_id"]) in dump_node_ids
                ]
                if medium is not None
                else []
            )
        else:
            source_node_id = str(event.get("node_id", ""))
            neighbors: set[str] = set()
            for medium in media:
                participants = {
                    str(item["node_id"])
                    for item in medium.get("attachments", [])
                }
                if source_node_id in participants:
                    neighbors.update(participants)
            candidates = sorted(neighbors)

    if not physical:
        source_node_id = str(event.get("node_id", ""))
        candidates = [
            node_id for node_id in candidates if node_id != source_node_id
        ]
    return tuple(
        node_id
        for node_id in dict.fromkeys(candidates)
        if node_id in dump_node_ids
    )


def load_scenario(path: Path | str) -> ScenarioDocument:
    try:
        source = resolve_regular_file(path, label="scenario project")
    except ValueError as error:
        raise ScenarioValidationError(str(error)) from error
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScenarioValidationError(f"cannot read scenario project: {error}") from error
    if not isinstance(value, Mapping):
        raise ScenarioValidationError("scenario project root must be an object")
    return scenario_from_dict(value)


def new_scenario() -> dict[str, Any]:
    """Return a blank editor project; no demo topology is embedded."""

    return {
        "schema_version": SCHEMA_VERSION,
        "schema_id": SCHEMA_ID,
        "scenario_id": "untitled-scenario",
        "name": "Untitled scenario",
        "seed": 1,
        "capture_time_ns": 60_000_000_000,
        "nodes": [],
        "media": [],
        "events": [],
        "metadata": {},
    }


def _issue(path: str, message: str, *, severity: str = "error") -> dict[str, str]:
    return {"severity": severity, "path": path, "message": message}


def validate_scenario(value: ScenarioDocument | Mapping[str, Any]) -> dict[str, Any]:
    """Return structured validation suitable for both the CLI and editor."""

    try:
        document = (
            value
            if isinstance(value, ScenarioDocument)
            else scenario_from_dict(value)
        )
    except (ScenarioValidationError, TypeError, ValueError) as error:
        return {
            "ok": False,
            "errors": [_issue("$", str(error))],
            "warnings": [],
        }
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    if document.schema_version != SCHEMA_VERSION:
        errors.append(
            _issue(
                "schema_version",
                f"unsupported schema_version {document.schema_version}; expected {SCHEMA_VERSION}",
            )
        )
    if not document.name.strip():
        errors.append(_issue("name", "scenario name cannot be empty"))
    if len(document.nodes) > MAX_NODES:
        errors.append(_issue("nodes", f"at most {MAX_NODES} nodes are supported"))
    if len(document.media) > MAX_MEDIA:
        errors.append(_issue("media", f"at most {MAX_MEDIA} media are supported"))
    if len(document.events) > MAX_EVENTS:
        errors.append(_issue("events", f"at most {MAX_EVENTS} events are supported"))

    node_ids = [str(node["node_id"]) for node in document.nodes]
    if len(node_ids) != len(set(node_ids)):
        errors.append(_issue("nodes", "node IDs must be unique"))
    medium_ids = [str(medium["medium_id"]) for medium in document.media]
    private_medium_ids = frozenset(medium_ids)
    dump_nodes = frozenset(
        str(node["node_id"])
        for node in document.nodes
        if node.get("dump_enabled", True)
    )
    if not dump_nodes:
        errors.append(
            _issue("nodes", "at least one dump-producing node is required")
        )
    for node_index, node in enumerate(document.nodes):
        node_id = str(node["node_id"])
        if node_id in dump_nodes:
            clock = node.get("clock", {})
            offset_ns = (
                int(clock.get("offset_ns", 0))
                if isinstance(clock, Mapping)
                else 0
            )
            if document.capture_time_ns + offset_ns < 0:
                errors.append(
                    _issue(
                        f"nodes[{node_index}].clock.offset_ns",
                        "clock offset makes the node snapshot timestamp negative",
                    )
                )
        for resource_index, resource in enumerate(
            node.get("initial_resources", [])
        ):
            issue = node_dump_projection_issue(
                resource,
                private_medium_ids,
                location=(
                    f"nodes[{node_index}].initial_resources"
                    f"[{resource_index}]"
                ),
            )
            if issue is not None:
                errors.append(_issue(*issue))
    if len(medium_ids) != len(set(medium_ids)):
        errors.append(_issue("media", "medium/link IDs must be unique"))
    for medium_index, medium in enumerate(document.media):
        attachments = medium["attachments"]
        if len(attachments) < 1:
            errors.append(
                _issue(
                    f"media[{medium_index}].attachments",
                    "a medium needs at least one attachment",
                )
            )
        seen_attachments: set[tuple[str, str]] = set()
        for attachment_index, attachment in enumerate(attachments):
            node_id = str(attachment["node_id"])
            key = (node_id, str(attachment["port_id"]))
            if node_id not in node_ids:
                errors.append(
                    _issue(
                        f"media[{medium_index}].attachments[{attachment_index}].node_id",
                        f"unknown node {node_id!r}",
                    )
                )
            if key in seen_attachments:
                errors.append(
                    _issue(
                        f"media[{medium_index}].attachments[{attachment_index}]",
                        "duplicate node/port attachment",
                    )
                )
            seen_attachments.add(key)
            node_local_observation = attachment["node_local_observation"]
            issue = node_dump_projection_issue(
                node_local_observation,
                private_medium_ids,
                location=(
                    f"media[{medium_index}].attachments"
                    f"[{attachment_index}].node_local_observation"
                ),
            )
            if issue is not None:
                errors.append(_issue(*issue))
    event_ids = [str(event["event_id"]) for event in document.events]
    if len(event_ids) != len(set(event_ids)):
        errors.append(_issue("events", "event IDs must be unique"))
    known_media = set(medium_ids)
    for event_index, event in enumerate(document.events):
        timestamp_ns = int(event["timestamp_ns"])
        if timestamp_ns > document.capture_time_ns:
            errors.append(
                _issue(
                    f"events[{event_index}].timestamp_ns",
                    "event occurs after the final snapshot capture",
                )
            )
        physical_event = _event_is_physical(event)
        node_id = event.get("node_id")
        if not physical_event and not str(node_id or "").strip():
            errors.append(
                _issue(
                    f"events[{event_index}].node_id",
                    "node-local events require a dump-producing node",
                )
            )
        elif node_id is not None and str(node_id) not in node_ids:
            errors.append(
                _issue(
                    f"events[{event_index}].node_id",
                    f"unknown node {node_id!r}",
                )
            )
        elif not physical_event and str(node_id) not in dump_nodes:
            errors.append(
                _issue(
                    f"events[{event_index}].node_id",
                    "node-local events must target a dump-producing node",
                )
            )
        target_id = event.get(
            "medium_id",
            event.get("link_id", event.get("target_id")),
        )
        if (
            physical_event
            and str(target_id or "") not in known_media
        ):
            errors.append(
                _issue(
                    f"events[{event_index}].target_id",
                    "physical events must reference a known medium/link",
                )
            )
        propagation = event.get("propagation", {})
        if isinstance(propagation, Mapping):
            mode = str(propagation.get("mode", "best-effort"))
            if mode not in {
                "best-effort",
                "best_effort",
                "manual",
                "suppressed",
                "failed",
                "none",
            }:
                errors.append(
                    _issue(
                        f"events[{event_index}].propagation.mode",
                        f"unsupported propagation mode {mode!r}",
                    )
                )
            targets = propagation.get(
                "targets",
                propagation.get("target_node_ids", []),
            )
            if isinstance(targets, Sequence) and not isinstance(targets, (str, bytes)):
                for target in targets:
                    if str(target) not in node_ids:
                        errors.append(
                            _issue(
                                f"events[{event_index}].propagation.targets",
                                f"unknown propagation target {target!r}",
                            )
                        )
                    elif str(target) not in dump_nodes:
                        errors.append(
                            _issue(
                                f"events[{event_index}].propagation.targets",
                                f"propagation target {target!r} does not produce a dump",
                            )
                        )
        properties = event.get("properties", {})
        issue = node_dump_projection_issue(
            properties,
            private_medium_ids,
            location=f"events[{event_index}].properties",
        )
        if issue is not None:
            errors.append(_issue(*issue))
        propagation_targets = _propagation_target_ids(
            document.media,
            event,
            dump_nodes,
        )
        if (
            timestamp_ns
            + _propagation_horizon_ns(
                propagation,
                target_count=len(propagation_targets),
            )
            > document.capture_time_ns
        ):
            warnings.append(
                _issue(
                    f"events[{event_index}].propagation",
                    "some delayed observations occur after capture and will not enter the dump",
                    severity="warning",
                )
            )
    return {"ok": not errors, "errors": errors, "warnings": warnings}


def _event_is_physical(event: Mapping[str, Any]) -> bool:
    kind = str(event.get("kind", "")).casefold().replace("_", "-")
    target_type = str(event.get("target_type", "")).casefold()
    return kind in {
        "link-state",
        "medium-state",
        "physical-link-state",
        "physical-state",
    } or target_type in {"link", "medium", "physical-link"}


__all__ = [
    "MAX_EVENTS",
    "MAX_MEDIA",
    "MAX_NODES",
    "SCHEMA_ID",
    "SCHEMA_VERSION",
    "ScenarioDocument",
    "ScenarioValidationError",
    "load_scenario",
    "new_scenario",
    "scenario_from_dict",
    "validate_scenario",
]
