"""Load the demo's canonical standalone-generator authoring save.

The saved JSON is a file boundary.  This module intentionally uses only the
standard library and never imports the standalone generator package.  It
consumes the small subset needed by the demo materializer and leaves all
device/protocol interpretation to the demo plug-in and generator.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping


SCENARIO_SCHEMA_ID = "state-dump-generator-scenario/v1"
SCENARIO_SCHEMA_VERSION = 1
_SOURCE_SCENARIO_PATH = (
    Path(__file__).resolve().parents[1]
    / "router-state-lab-default.scenario.json"
)
_PACKAGED_SCENARIO_PATH = (
    Path(__file__).resolve().with_name(
        "router-state-lab-default.scenario.json"
    )
)
DEFAULT_SCENARIO_PATH = (
    _SOURCE_SCENARIO_PATH
    if _SOURCE_SCENARIO_PATH.is_file()
    else _PACKAGED_SCENARIO_PATH
)
MAX_SCENARIO_BYTES = 16 * 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:@/+~-]{0,255})\Z")
_PHYSICAL_EVENT_KINDS = frozenset(
    {
        "link-state",
        "medium-state",
        "physical-link-state",
        "physical-state",
    }
)


class ScenarioSourceError(ValueError):
    """The canonical demo scenario does not satisfy its consumed contract."""


@dataclass(frozen=True, slots=True)
class SourceResource:
    """One plug-in-neutral resource authored in the saved project."""

    resource_id: str
    resource_type: str
    status: str
    properties_json: str
    updated_at_ns: int

    @property
    def properties(self) -> dict[str, Any]:
        value = json.loads(self.properties_json)
        assert isinstance(value, dict)
        return value


@dataclass(frozen=True, slots=True)
class NodeSpec:
    """One independently captured router described by the saved project."""

    node_id: str
    label: str
    role: str
    site: str
    clock_offset_ns: int = 0
    clock_uncertainty_ns: int = 5_000_000
    routing_groups: tuple[str, ...] = ()
    initial_resources: tuple[SourceResource, ...] = ()

    @property
    def revision_id(self) -> str:
        return f"demo/{self.node_id}/revision-0001"

    @property
    def identity_namespace(self) -> str:
        return f"{self.node_id}/"


@dataclass(frozen=True, slots=True)
class LinkSpec:
    """A shared domain derived from matching node-local attachment evidence."""

    segment_id: str
    label: str
    prefix: str
    participants: tuple[str, ...]
    attachment_resource_ids: tuple[str, ...]
    attachment_statuses: tuple[str, ...]
    attachment_kind: str
    vlan_id: int | None = None
    lag_id: str | None = None
    classification: str = "underlay"
    confidence: str = "exact"

    def attachment_resource_id(self, node_id: str) -> str:
        """Return the node-local attachment identity for *node_id*."""

        try:
            index = self.participants.index(node_id)
        except ValueError as error:
            raise KeyError(node_id) from error
        return self.attachment_resource_ids[index]

    def attachment_status(self, node_id: str) -> str:
        """Return the node's initial observation of this attachment."""

        try:
            index = self.participants.index(node_id)
        except ValueError as error:
            raise KeyError(node_id) from error
        return self.attachment_statuses[index]


@dataclass(frozen=True, slots=True)
class GenerationDefaults:
    """Demo materialization defaults retained in the authoring save."""

    assembly_id: str
    default_node_id: str
    events_per_node: int
    resources_per_node: int
    seed: int


@dataclass(frozen=True, slots=True)
class ExplicitObservation:
    """One editable node-local historical observation from the save."""

    event_id: str
    node_id: str
    relative_time_ns: int
    timestamp_ns: int
    order: int
    kind: str
    resource_id: str
    resource_type: str
    operation: str
    outcome: str
    status: str | None
    update_snapshot: bool
    message: str
    event_json: str

    def to_event(self) -> dict[str, Any]:
        """Return a detached JSON event for a future demo materializer."""

        value = json.loads(self.event_json)
        assert isinstance(value, dict)
        return value


@dataclass(frozen=True, slots=True)
class PhysicalChange:
    """Private physical truth retained only by the authoring source."""

    event_id: str
    relative_time_ns: int
    timestamp_ns: int
    order: int
    medium_id: str
    segment_id: str
    status: str


@dataclass(frozen=True, slots=True)
class DemoScenarioSource:
    """Validated, immutable inputs derived from one authoring save."""

    path: Path
    sha256: str
    scenario_id: str
    base_time_ns: int
    capture_offset_ns: int
    capture_time_ns: int
    defaults: GenerationDefaults
    nodes: tuple[NodeSpec, ...]
    links: tuple[LinkSpec, ...]
    observations_by_node: Mapping[str, tuple[ExplicitObservation, ...]]
    physical_changes: tuple[PhysicalChange, ...]

    @property
    def observations(self) -> tuple[ExplicitObservation, ...]:
        return tuple(
            observation
            for node in self.nodes
            for observation in self.observations_by_node[node.node_id]
        )

    def resources_at(
        self,
        node_id: str,
        *,
        timestamp_ns: int | None = None,
    ) -> tuple[SourceResource, ...]:
        """Replay one node's authored resources at an absolute timestamp."""

        selected_time = (
            self.capture_time_ns
            if timestamp_ns is None
            else int(timestamp_ns)
        )
        if not self.base_time_ns <= selected_time <= self.capture_time_ns:
            raise ScenarioSourceError(
                "resource reconstruction time is outside the scenario"
            )
        try:
            node = next(item for item in self.nodes if item.node_id == node_id)
        except StopIteration as error:
            raise ScenarioSourceError(f"unknown scenario node {node_id!r}") from error
        state: dict[str, SourceResource] = {
            item.resource_id: item for item in node.initial_resources
        }
        for link in self.links:
            if node_id not in link.participants:
                continue
            local_id = link.attachment_resource_id(node_id)
            initial_status = link.attachment_status(node_id)
            state[local_id] = SourceResource(
                resource_id=local_id,
                resource_type="VIRTUAL_INTERFACE",
                status=initial_status,
                properties_json=_canonical_json(
                    {
                        "admin_status": "up",
                        "oper_status": initial_status,
                        "attachment_kind": link.attachment_kind,
                        "segment_key": link.segment_id,
                        "subnet_prefix": link.prefix,
                        "classification": link.classification,
                        **(
                            {"vlan_id": link.vlan_id}
                            if link.vlan_id is not None
                            else {}
                        ),
                        **(
                            {"lag_id": link.lag_id}
                            if link.lag_id is not None
                            else {}
                        ),
                    }
                ),
                updated_at_ns=self.base_time_ns,
            )
        for observation in self.observations_by_node[node_id]:
            if observation.timestamp_ns > selected_time:
                break
            if not observation.update_snapshot:
                continue
            operation = observation.operation.casefold().replace("_", "-")
            if operation in {"delete", "remove", "withdraw"}:
                state.pop(observation.resource_id, None)
                continue
            previous = state.get(observation.resource_id)
            properties = previous.properties if previous is not None else {}
            properties.update(observation.to_event().get("properties", {}))
            state[observation.resource_id] = SourceResource(
                resource_id=observation.resource_id,
                resource_type=observation.resource_type,
                status=(
                    observation.status
                    if observation.status is not None
                    else previous.status
                    if previous is not None
                    else "unknown"
                ),
                properties_json=_canonical_json(properties),
                updated_at_ns=observation.timestamp_ns,
            )
        return tuple(state[key] for key in sorted(state))


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScenarioSourceError(f"{field} must be an object")
    return value


def _array(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ScenarioSourceError(f"{field} must be an array")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScenarioSourceError(f"{field} must be non-empty text")
    return value.strip()


def _identifier(value: Any, field: str) -> str:
    result = _text(value, field)
    if not _IDENTIFIER.fullmatch(result):
        raise ScenarioSourceError(f"{field} is not a safe identifier")
    return result


def _integer(
    value: Any,
    field: str,
    *,
    minimum: int | None = None,
) -> int:
    if isinstance(value, bool):
        raise ScenarioSourceError(f"{field} must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as error:
        raise ScenarioSourceError(f"{field} must be an integer") from error
    if minimum is not None and result < minimum:
        raise ScenarioSourceError(f"{field} must be at least {minimum}")
    return result


def _optional_integer(value: Any, field: str) -> int | None:
    return None if value is None else _integer(value, field, minimum=0)


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ScenarioSourceError(f"{field} must be boolean")
    return value


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _load_nodes(
    root: Mapping[str, Any],
    routing_groups_by_node: Mapping[str, Any],
    *,
    base_time_ns: int,
) -> tuple[NodeSpec, ...]:
    nodes: list[NodeSpec] = []
    seen: set[str] = set()
    for index, raw_node in enumerate(_array(root.get("nodes"), "nodes")):
        node = _object(raw_node, f"nodes[{index}]")
        node_id = _identifier(node.get("node_id"), f"nodes[{index}].node_id")
        if node_id in seen:
            raise ScenarioSourceError(f"duplicate node_id {node_id!r}")
        seen.add(node_id)
        dump_enabled = _boolean(
            node.get("dump_enabled", True),
            f"nodes[{index}].dump_enabled",
        )
        if not dump_enabled:
            continue
        clock = _object(node.get("clock", {}), f"nodes[{index}].clock")
        initial_resources: list[SourceResource] = []
        seen_resources: set[str] = set()
        for resource_index, raw_resource in enumerate(
            _array(
                node.get("initial_resources", []),
                f"nodes[{index}].initial_resources",
            )
        ):
            resource_field = (
                f"nodes[{index}].initial_resources[{resource_index}]"
            )
            resource = _object(raw_resource, resource_field)
            resource_id = _identifier(
                resource.get("resource_id"),
                f"{resource_field}.resource_id",
            )
            if resource_id in seen_resources:
                raise ScenarioSourceError(
                    f"{resource_field} repeats resource {resource_id!r}"
                )
            seen_resources.add(resource_id)
            initial_resources.append(
                SourceResource(
                    resource_id=resource_id,
                    resource_type=_identifier(
                        resource.get("resource_type"),
                        f"{resource_field}.resource_type",
                    ),
                    status=_identifier(
                        resource.get("status", "unknown"),
                        f"{resource_field}.status",
                    ),
                    properties_json=_canonical_json(
                        _object(
                            resource.get("properties", {}),
                            f"{resource_field}.properties",
                        )
                    ),
                    updated_at_ns=base_time_ns,
                )
            )
        raw_groups = routing_groups_by_node.get(node_id, [])
        groups = tuple(
            _identifier(
                value,
                f"metadata.demo_generation.routing_groups_by_node"
                f".{node_id}[{group_index}]",
            )
            for group_index, value in enumerate(
                _array(
                    raw_groups,
                    f"metadata.demo_generation.routing_groups_by_node.{node_id}",
                )
            )
        )
        nodes.append(
            NodeSpec(
                node_id=node_id,
                label=_text(node.get("name"), f"nodes[{index}].name"),
                role=_identifier(
                    node.get("profile"),
                    f"nodes[{index}].profile",
                ),
                site=_identifier(node.get("site"), f"nodes[{index}].site"),
                clock_offset_ns=_integer(
                    clock.get("offset_ns", 0),
                    f"nodes[{index}].clock.offset_ns",
                ),
                clock_uncertainty_ns=_integer(
                    clock.get("uncertainty_ns", 0),
                    f"nodes[{index}].clock.uncertainty_ns",
                    minimum=0,
                ),
                routing_groups=groups,
                initial_resources=tuple(initial_resources),
            )
        )
    if not nodes:
        raise ScenarioSourceError("nodes must contain a dump-producing router")
    return tuple(nodes)


def _attachment_evidence(
    attachment: Mapping[str, Any],
    field: str,
) -> dict[str, Any]:
    properties = _object(attachment.get("properties"), f"{field}.properties")
    resource_id = _identifier(
        properties.get("local_resource_id"),
        f"{field}.properties.local_resource_id",
    )
    port_id = _identifier(attachment.get("port_id"), f"{field}.port_id")
    if resource_id != port_id:
        raise ScenarioSourceError(
            f"{field} local_resource_id must equal its node-local port_id"
        )
    return {
        "segment_id": _identifier(
            properties.get("segment_key"),
            f"{field}.properties.segment_key",
        ),
        "label": _text(
            properties.get("segment_label"),
            f"{field}.properties.segment_label",
        ),
        "prefix": _text(
            properties.get("subnet_prefix"),
            f"{field}.properties.subnet_prefix",
        ),
        "attachment_kind": _identifier(
            properties.get("attachment_kind"),
            f"{field}.properties.attachment_kind",
        ),
        "vlan_id": _optional_integer(
            properties.get("vlan_id"),
            f"{field}.properties.vlan_id",
        ),
        "lag_id": (
            None
            if properties.get("lag_id") is None
            else _identifier(
                properties["lag_id"],
                f"{field}.properties.lag_id",
            )
        ),
        "classification": _identifier(
            properties.get("classification", "underlay"),
            f"{field}.properties.classification",
        ),
        "confidence": _identifier(
            properties.get("confidence", "exact"),
            f"{field}.properties.confidence",
        ),
    }


def _load_links(
    root: Mapping[str, Any],
    known_node_ids: set[str],
) -> tuple[tuple[LinkSpec, ...], dict[str, str]]:
    links: list[LinkSpec] = []
    medium_to_segment: dict[str, str] = {}
    seen_segments: set[str] = set()
    seen_media: set[str] = set()
    for medium_index, raw_medium in enumerate(
        _array(root.get("media"), "media")
    ):
        medium = _object(raw_medium, f"media[{medium_index}]")
        medium_id = _identifier(
            medium.get("medium_id"),
            f"media[{medium_index}].medium_id",
        )
        if medium_id in seen_media:
            raise ScenarioSourceError(f"duplicate medium_id {medium_id!r}")
        seen_media.add(medium_id)
        participants: list[str] = []
        attachment_resource_ids: list[str] = []
        attachment_statuses: list[str] = []
        evidence: dict[str, Any] | None = None
        attachments = _array(
            medium.get("attachments"),
            f"media[{medium_index}].attachments",
        )
        if not attachments:
            raise ScenarioSourceError(
                f"media[{medium_index}].attachments cannot be empty"
            )
        for attachment_index, raw_attachment in enumerate(attachments):
            field = f"media[{medium_index}].attachments[{attachment_index}]"
            attachment = _object(raw_attachment, field)
            node_id = _identifier(
                attachment.get("node_id"),
                f"{field}.node_id",
            )
            if node_id not in known_node_ids:
                raise ScenarioSourceError(
                    f"{field}.node_id references unknown node {node_id!r}"
                )
            if node_id in participants:
                raise ScenarioSourceError(
                    f"media[{medium_index}] repeats node {node_id!r}"
                )
            participants.append(node_id)
            attachment_resource_ids.append(
                _identifier(
                    attachment.get("port_id"),
                    f"{field}.port_id",
                )
            )
            attachment_statuses.append(
                _identifier(
                    attachment.get(
                        "observed_state",
                        medium.get("state", "up"),
                    ),
                    f"{field}.observed_state",
                )
            )
            local_evidence = _attachment_evidence(attachment, field)
            if evidence is None:
                evidence = local_evidence
            elif local_evidence != evidence:
                raise ScenarioSourceError(
                    f"{field} disagrees with the other node-local "
                    "connectivity evidence on this medium"
                )
        assert evidence is not None
        segment_id = str(evidence["segment_id"])
        if segment_id == medium_id:
            raise ScenarioSourceError(
                f"media[{medium_index}] must keep its private medium_id "
                "distinct from the plug-in-derived segment key"
            )
        if segment_id in seen_segments:
            raise ScenarioSourceError(
                f"duplicate derived segment key {segment_id!r}"
            )
        seen_segments.add(segment_id)
        medium_to_segment[medium_id] = segment_id
        links.append(
            LinkSpec(
                segment_id=segment_id,
                label=str(evidence["label"]),
                prefix=str(evidence["prefix"]),
                participants=tuple(participants),
                attachment_resource_ids=tuple(attachment_resource_ids),
                attachment_statuses=tuple(attachment_statuses),
                attachment_kind=str(evidence["attachment_kind"]),
                vlan_id=evidence["vlan_id"],
                lag_id=evidence["lag_id"],
                classification=str(evidence["classification"]),
                confidence=str(evidence["confidence"]),
            )
        )
    return tuple(links), medium_to_segment


def _load_events(
    root: Mapping[str, Any],
    *,
    base_time_ns: int,
    capture_offset_ns: int,
    known_node_ids: set[str],
    medium_to_segment: Mapping[str, str],
) -> tuple[
    dict[str, tuple[ExplicitObservation, ...]],
    tuple[PhysicalChange, ...],
]:
    observations: dict[str, list[ExplicitObservation]] = {
        node_id: [] for node_id in known_node_ids
    }
    physical_changes: list[PhysicalChange] = []
    seen: set[str] = set()
    for index, raw_event in enumerate(_array(root.get("events"), "events")):
        event = _object(raw_event, f"events[{index}]")
        event_id = _identifier(
            event.get("event_id"),
            f"events[{index}].event_id",
        )
        if event_id in seen:
            raise ScenarioSourceError(f"duplicate event_id {event_id!r}")
        seen.add(event_id)
        relative_time_ns = _integer(
            event.get("timestamp_ns"),
            f"events[{index}].timestamp_ns",
            minimum=0,
        )
        if relative_time_ns > capture_offset_ns:
            raise ScenarioSourceError(
                f"events[{index}] occurs after capture_time_ns"
            )
        timestamp_ns = base_time_ns + relative_time_ns
        order = _integer(event.get("order", index), f"events[{index}].order")
        kind = _identifier(event.get("kind"), f"events[{index}].kind")
        if kind in _PHYSICAL_EVENT_KINDS:
            medium_id = _identifier(
                event.get("medium_id", event.get("target_id")),
                f"events[{index}].medium_id",
            )
            try:
                segment_id = medium_to_segment[medium_id]
            except KeyError as error:
                raise ScenarioSourceError(
                    f"events[{index}] references unknown medium {medium_id!r}"
                ) from error
            physical_changes.append(
                PhysicalChange(
                    event_id=event_id,
                    relative_time_ns=relative_time_ns,
                    timestamp_ns=timestamp_ns,
                    order=order,
                    medium_id=medium_id,
                    segment_id=segment_id,
                    status=_identifier(
                        event.get("status"),
                        f"events[{index}].status",
                    ),
                )
            )
            continue
        node_id = _identifier(
            event.get("node_id"),
            f"events[{index}].node_id",
        )
        if node_id not in known_node_ids:
            raise ScenarioSourceError(
                f"events[{index}] references unknown node {node_id!r}"
            )
        resource_id = _identifier(
            event.get("resource_id"),
            f"events[{index}].resource_id",
        )
        properties = _object(
            event.get("properties", {}),
            f"events[{index}].properties",
        )
        normalized_event = {
            "event_id": event_id,
            "node_id": node_id,
            "relative_time_ns": relative_time_ns,
            "timestamp_ns": timestamp_ns,
            "order": order,
            "kind": kind,
            "resource_id": resource_id,
            "resource_type": _identifier(
                event.get("resource_type"),
                f"events[{index}].resource_type",
            ),
            "operation": _identifier(
                event.get("operation", event.get("action", kind)),
                f"events[{index}].operation",
            ),
            "outcome": _identifier(
                event.get("outcome", "success"),
                f"events[{index}].outcome",
            ),
            "status": (
                None
                if event.get("status") is None
                else _identifier(
                    event["status"],
                    f"events[{index}].status",
                )
            ),
            "update_snapshot": _boolean(
                event.get("update_snapshot", True),
                f"events[{index}].update_snapshot",
            ),
            "message": _text(
                event.get("message"),
                f"events[{index}].message",
            ),
            "properties": properties,
        }
        observations[node_id].append(
            ExplicitObservation(
                event_id=event_id,
                node_id=node_id,
                relative_time_ns=relative_time_ns,
                timestamp_ns=timestamp_ns,
                order=order,
                kind=kind,
                resource_id=resource_id,
                resource_type=str(normalized_event["resource_type"]),
                operation=str(normalized_event["operation"]),
                outcome=str(normalized_event["outcome"]),
                status=normalized_event["status"],
                update_snapshot=bool(normalized_event["update_snapshot"]),
                message=str(normalized_event["message"]),
                event_json=_canonical_json(normalized_event),
            )
        )
    for values in observations.values():
        values.sort(
            key=lambda item: (
                item.relative_time_ns,
                item.order,
                item.event_id,
            )
        )
    physical_changes.sort(
        key=lambda item: (
            item.relative_time_ns,
            item.order,
            item.event_id,
        )
    )
    return (
        {
            node_id: tuple(values)
            for node_id, values in observations.items()
        },
        tuple(physical_changes),
    )


def load_scenario_source(
    path: Path | str = DEFAULT_SCENARIO_PATH,
    *,
    fresh: bool = False,
) -> DemoScenarioSource:
    """Load a strict projection of one authoring save.

    Normal callers use the bounded metadata-keyed cache.  Launch preflight
    and publication checks pass ``fresh=True`` so a same-process edit cannot
    be hidden by an already imported catalog.
    """

    source = Path(path).expanduser().resolve()
    if source.is_symlink() or not source.is_file():
        raise ScenarioSourceError(
            f"scenario source must be a regular file: {source}"
        )
    stat = source.stat()
    if not 0 < stat.st_size <= MAX_SCENARIO_BYTES:
        raise ScenarioSourceError("scenario source size is invalid")
    if fresh:
        return _load_scenario_source_uncached(
            str(source),
            stat.st_mtime_ns,
            stat.st_size,
        )
    return _load_scenario_source_cached(
        str(source),
        stat.st_mtime_ns,
        stat.st_size,
    )


def _load_scenario_source_uncached(
    source_name: str,
    expected_mtime_ns: int,
    expected_size: int,
) -> DemoScenarioSource:
    source = Path(source_name)
    content = source.read_bytes()
    try:
        observed = source.stat()
    except OSError as error:
        raise ScenarioSourceError(
            "scenario source changed while it was being read"
        ) from error
    if (
        len(content) != expected_size
        or observed.st_size != expected_size
        or observed.st_mtime_ns != expected_mtime_ns
    ):
        raise ScenarioSourceError(
            "scenario source changed while it was being read"
        )
    try:
        root = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScenarioSourceError(
            f"scenario source is not valid UTF-8 JSON: {error}"
        ) from error
    root = _object(root, "$")
    if root.get("schema_id") != SCENARIO_SCHEMA_ID:
        raise ScenarioSourceError(
            f"schema_id must be {SCENARIO_SCHEMA_ID!r}"
        )
    if _integer(root.get("schema_version"), "schema_version") != (
        SCENARIO_SCHEMA_VERSION
    ):
        raise ScenarioSourceError(
            f"schema_version must be {SCENARIO_SCHEMA_VERSION}"
        )
    scenario_id = _identifier(root.get("scenario_id"), "scenario_id")
    capture_offset_ns = _integer(
        root.get("capture_time_ns"),
        "capture_time_ns",
        minimum=0,
    )
    metadata = _object(root.get("metadata"), "metadata")
    timeline = _object(metadata.get("timeline"), "metadata.timeline")
    if timeline.get("time_basis") != "relative_to_base":
        raise ScenarioSourceError(
            "metadata.timeline.time_basis must be relative_to_base"
        )
    base_time_ns = _integer(
        timeline.get("base_time_ns"),
        "metadata.timeline.base_time_ns",
        minimum=0,
    )
    generation = _object(
        metadata.get("demo_generation"),
        "metadata.demo_generation",
    )
    routing_groups = _object(
        generation.get("routing_groups_by_node", {}),
        "metadata.demo_generation.routing_groups_by_node",
    )
    nodes = _load_nodes(
        root,
        routing_groups,
        base_time_ns=base_time_ns,
    )
    known_node_ids = {node.node_id for node in nodes}
    default_node_id = _identifier(
        generation.get("default_node_id"),
        "metadata.demo_generation.default_node_id",
    )
    if default_node_id not in known_node_ids:
        raise ScenarioSourceError(
            "metadata.demo_generation.default_node_id is unknown"
        )
    defaults = GenerationDefaults(
        assembly_id=_identifier(
            generation.get("assembly_id"),
            "metadata.demo_generation.assembly_id",
        ),
        default_node_id=default_node_id,
        events_per_node=_integer(
            generation.get("events_per_node"),
            "metadata.demo_generation.events_per_node",
            minimum=1,
        ),
        resources_per_node=_integer(
            generation.get("resources_per_node"),
            "metadata.demo_generation.resources_per_node",
            minimum=1,
        ),
        seed=_integer(root.get("seed"), "seed", minimum=0),
    )
    links, medium_to_segment = _load_links(root, known_node_ids)
    observations, physical_changes = _load_events(
        root,
        base_time_ns=base_time_ns,
        capture_offset_ns=capture_offset_ns,
        known_node_ids=known_node_ids,
        medium_to_segment=medium_to_segment,
    )
    return DemoScenarioSource(
        path=source,
        sha256=hashlib.sha256(content).hexdigest(),
        scenario_id=scenario_id,
        base_time_ns=base_time_ns,
        capture_offset_ns=capture_offset_ns,
        capture_time_ns=base_time_ns + capture_offset_ns,
        defaults=defaults,
        nodes=nodes,
        links=links,
        observations_by_node=observations,
        physical_changes=physical_changes,
    )


_load_scenario_source_cached = lru_cache(maxsize=8)(
    _load_scenario_source_uncached
)


def load_default_scenario_source(
    *,
    fresh: bool = False,
) -> DemoScenarioSource:
    """Return the packaged canonical demo authoring source."""

    return load_scenario_source(
        DEFAULT_SCENARIO_PATH,
        fresh=fresh,
    )


__all__ = [
    "DEFAULT_SCENARIO_PATH",
    "SCENARIO_SCHEMA_ID",
    "DemoScenarioSource",
    "ExplicitObservation",
    "GenerationDefaults",
    "LinkSpec",
    "NodeSpec",
    "PhysicalChange",
    "ScenarioSourceError",
    "SourceResource",
    "load_default_scenario_source",
    "load_scenario_source",
]
