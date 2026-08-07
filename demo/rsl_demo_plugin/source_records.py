"""Example plug-in source-record presentation for the synthetic fixture.

The core treats these records as opaque timestamped text plus stable links to
normalized events.  Source names, labels, colors, and useful regex presets are
fixture plug-in policy and deliberately live outside the timeline/query core.
"""

from __future__ import annotations

from typing import Any

SOURCE_RECORD_GROUP_DESCRIPTORS: list[dict[str, Any]] = [
    {
        "group_id": "ctf",
        "label": "Synthetic CTF projections",
        "description": (
            "Precomputed demo projections synthesized from normalized events; "
            "these are not TraceDecoder output."
        ),
        "default_included": False,
        "copy_action_label": "Copy synthetic CTF text",
        "plugin_defined": True,
    },
    {
        "group_id": "external",
        "label": "Non-CTF records",
        "description": "Timestamped logs, callbacks, and status text outside CTF.",
        "default_included": False,
        "plugin_defined": True,
    },
]


SOURCE_RECORD_DESCRIPTORS: list[dict[str, Any]] = [
    {
        "source_type": "ctf",
        "label": "Synthetic CTF projections",
        "description": (
            "CTF-style presentation records synthesized from normalized demo "
            "events; no CTF decoder produced them."
        ),
        "color": "#66b8ff",
        "stream_group": "ctf",
        "plugin_defined": True,
    },
    {
        "source_type": "syslog",
        "label": "Syslog",
        "description": "Timestamped router and daemon text outside CTF.",
        "color": "#f5b85b",
        "stream_group": "external",
        "plugin_defined": True,
    },
    {
        "source_type": "agent-event",
        "label": "Agent events",
        "description": "Structured callbacks emitted by non-CTF agents.",
        "color": "#a58bff",
        "stream_group": "external",
        "plugin_defined": True,
    },
    {
        "source_type": "status-text",
        "label": "Status text",
        "description": "Timestamped records recovered from textual status streams.",
        "color": "#9bd66f",
        "stream_group": "external",
        "plugin_defined": True,
    },
]


RECORD_LANE_PRESETS: list[dict[str, Any]] = [
    {
        "lane_id": "plugin-unmatched-ctf",
        "label": "Unmatched CTF records",
        "pattern": ".+",
        "source_types": ["ctf"],
        "unmatched_only": True,
        "case_sensitive": False,
        "default_enabled": True,
        "plugin_defined": True,
        "description": "Every retained CTF record that produced no domain event.",
    },
    {
        "lane_id": "plugin-unmatched-external",
        "label": "Unmatched external records",
        "pattern": ".+",
        "source_types": ["syslog", "agent-event", "status-text"],
        "unmatched_only": True,
        "case_sensitive": False,
        "default_enabled": True,
        "plugin_defined": True,
        "description": "Non-CTF logs and callbacks without a normalization link.",
    },
    {
        "lane_id": "plugin-evpn-es-signals",
        "label": "EVPN ES signals",
        "pattern": "ESI|ethernet segment|DF|mass withdraw",
        "source_types": ["ctf", "syslog", "agent-event", "status-text"],
        "unmatched_only": False,
        "case_sensitive": False,
        "default_enabled": False,
        "plugin_defined": True,
        "description": "Plug-in vocabulary for Ethernet Segment activity.",
    },
    {
        "lane_id": "plugin-programming-errors",
        "label": "Programming errors",
        "pattern": "fail|error|timeout|retry|drop",
        "source_types": ["ctf", "syslog", "agent-event", "status-text"],
        "unmatched_only": False,
        "case_sensitive": False,
        "default_enabled": False,
        "plugin_defined": True,
        "description": "Plug-in vocabulary for failed or delayed programming.",
    },
]


def _event_subject(event: dict[str, Any]) -> dict[str, Any]:
    subject = event.get("subject")
    if isinstance(subject, dict):
        return subject
    subjects = event.get("subjects")
    if isinstance(subjects, list) and subjects and isinstance(subjects[0], dict):
        return subjects[0]
    return {}


def _sample_indices(event_count: int, target: int = 1_250) -> list[int]:
    count = min(target, event_count)
    if not count:
        return []
    return [(slot * event_count) // count for slot in range(count)]


def demo_ctf_copy_text(
    event: dict[str, Any],
    *,
    sequence: int | None = None,
) -> str:
    """Return the demo plug-in's canonical plain-text CTF representation."""

    event_uid = str(event.get("event_uid") or event.get("event_id") or "unknown")
    timestamp_ns = int(event.get("timestamp_ns", 0))
    event_name = str(
        event.get("event_type")
        or event.get("event_name")
        or event.get("label")
        or "event"
    )
    subject = _event_subject(event)
    resource = str(
        subject.get("raw_key")
        or subject.get("resource_id")
        or event.get("resource_id")
        or (event.get("affected_resources") or ["unknown"])[0]
    )
    action = str(event.get("action") or event.get("operation") or "observe")
    outcome = str(event.get("outcome") or "unknown")
    ordinal = (
        int(sequence)
        if sequence is not None
        else int(event.get("source_sequence", 0))
    )
    return (
        f"[{timestamp_ns} ns] {event_name}: {{ event_uid = \"{event_uid}\", "
        f"resource = \"{resource}\", action = \"{action}\", "
        f"outcome = \"{outcome}\", sequence = {ordinal} }}"
    )


def lazy_demo_ctf_source_record(event: dict[str, Any]) -> dict[str, Any]:
    """Materialize an on-demand copy projection without growing bootstrap JSON."""

    event_uid = str(event.get("event_uid") or event.get("event_id") or "unknown")
    subject = _event_subject(event)
    return {
        "source_record_uid": f"copy-ctf-{event_uid}",
        "timestamp_ns": str(int(event.get("timestamp_ns", 0))),
        "source_type": "ctf",
        "source_name": "packed-ctf/on-demand",
        "layer": str(subject.get("layer") or event.get("layer") or "unknown"),
        "record_name": str(
            event.get("event_type")
            or event.get("event_name")
            or event.get("label")
            or "event"
        ),
        "message": "CTF text is available through the explicit copy action.",
        "copy_text": demo_ctf_copy_text(event),
        "projection_origin": "synthetic_precomputed_normalized_event",
        "attributes": {
            "synthetic_projection": True,
            "source_basis": "normalized_event",
        },
        "matched_event_uid": event_uid,
        "matched_event_uids": [event_uid],
        "plugin_defined": True,
    }


def build_demo_source_records(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Synthesize representative presentation records from normalized events.

    This helper does not decode the fixture's synthetic CTF container. A
    bounded, explicitly precomputed projection is enough for interaction
    review and avoids duplicating every 125K event in browser memory.
    """

    records: list[dict[str, Any]] = []
    unmatched_ctf = (
        ("vendor_trace_unknown", "unknown vendor trace opcode=0x31 payload=opaque"),
        ("ctf_clock_pulse", "clock correlation pulse has no domain mapping"),
        ("evpn_es_telemetry", "EVPN ESI ethernet segment sample has no normalizer rule"),
        (
            "ctf_packet_notice",
            "synthetic packet-boundary marker was retained in the projection",
        ),
    )
    unmatched_external = (
        ("syslog", "daemon_warning", "EVPN ES peer timeout; retry scheduled"),
        ("agent-event", "sdk_callback", "hardware programming retry queue depth changed"),
        ("status-text", "status_row", "BFD peer diagnostic row was not claimed by a parser"),
        ("syslog", "kernel_notice", "interface carrier debounce message outside CTF"),
    )
    external_types = ("syslog", "agent-event", "status-text")

    for slot, event_index in enumerate(_sample_indices(len(events))):
        event = events[event_index]
        event_uid = str(event.get("event_uid") or event.get("event_id"))
        timestamp_ns = int(event.get("timestamp_ns", 0))
        event_name = str(
            event.get("event_type")
            or event.get("event_name")
            or event.get("label")
            or "event"
        )
        subject = _event_subject(event)
        layer = str(subject.get("layer") or event.get("layer") or "unknown")
        resource = str(
            subject.get("raw_key")
            or subject.get("resource_id")
            or event.get("resource_id")
            or "unknown"
        )
        origin = (
            "forwarding-multihome/trace.ctf2"
            if "bridge" in layer or "hardware" in layer
            else "evpn-control/trace.ctf2"
        )

        records.append(
            {
                "source_record_uid": f"source-ctf-matched-{slot:06d}",
                "timestamp_ns": str(timestamp_ns),
                "source_type": "ctf",
                "source_name": origin,
                "layer": layer,
                "record_name": event_name,
                "message": (
                    f"tracepoint={event_name} resource={resource} "
                    f"sequence={event_index} status=Ok"
                ),
                "copy_text": demo_ctf_copy_text(
                    event,
                    sequence=event_index,
                ),
                "projection_origin": "synthetic_precomputed_normalized_event",
                "attributes": {
                    "sequence": event_index,
                    "resource": resource,
                    "synthetic_projection": True,
                    "source_basis": "normalized_event",
                },
                "matched_event_uid": event_uid,
                "matched_event_uids": [event_uid],
                "matched": True,
                "plugin_defined": True,
            }
        )

        ctf_name, ctf_message = unmatched_ctf[slot % len(unmatched_ctf)]
        records.append(
            {
                "source_record_uid": f"source-ctf-unmatched-{slot:06d}",
                "timestamp_ns": str(timestamp_ns + 200_000),
                "source_type": "ctf",
                "source_name": origin,
                "layer": layer,
                "record_name": ctf_name,
                "message": f"{ctf_message}; stream_ordinal={event_index}",
                "copy_text": (
                    f"[{timestamp_ns + 200_000} ns] {ctf_name}: "
                    f"{{ stream_ordinal = {event_index}, matched = false }}"
                ),
                "projection_origin": "synthetic_precomputed_normalized_event",
                "attributes": {
                    "stream_ordinal": event_index,
                    "synthetic_projection": True,
                    "source_basis": "normalized_event",
                },
                "matched_event_uid": None,
                "matched": False,
                "plugin_defined": True,
            }
        )

        external_type = external_types[slot % len(external_types)]
        records.append(
            {
                "source_record_uid": f"source-external-matched-{slot:06d}",
                "timestamp_ns": str(timestamp_ns + 100_000),
                "source_type": external_type,
                "source_name": f"{external_type}/router-state-agent",
                "layer": layer,
                "record_name": "normalized_companion",
                "message": (
                    f"companion observation for {event_name}; resource={resource}"
                ),
                "attributes": {"resource": resource, "event_name": event_name},
                "matched_event_uid": event_uid,
                "matched": True,
                "plugin_defined": True,
            }
        )

        source_type, record_name, message = unmatched_external[
            slot % len(unmatched_external)
        ]
        records.append(
            {
                "source_record_uid": f"source-external-unmatched-{slot:06d}",
                "timestamp_ns": str(timestamp_ns + 400_000),
                "source_type": source_type,
                "source_name": f"{source_type}/unclaimed-input",
                "layer": layer,
                "record_name": record_name,
                "message": f"{message}; source_sequence={event_index}",
                "attributes": {"source_sequence": event_index},
                "matched_event_uid": None,
                "matched": False,
                "plugin_defined": True,
            }
        )

    records.sort(
        key=lambda item: (
            int(item["timestamp_ns"]),
            str(item["source_record_uid"]),
        )
    )
    return records
