"""Stream a deterministic EVPN multi-homing scale fixture with bounded memory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


BASE_TIME_NS = 1_759_680_000_000_000_000
EVENT_STEP_NS = 1_000_000
PHASE_GAP_NS = 120_000_000_000
SCENARIO_ID = "evpn-multihome-mass-failover-v2"
GENERATOR_VERSION = 2
OWNERSHIP_MARKER = b"router-dump-analyzer scale generator v1\n"
PHASES = (
    (
        "single_home_create",
        25,
        "Create ETG, primary ETE, and DTE resources in single-home mode.",
    ),
    (
        "multihome_add",
        15,
        "Add Ethernet Segments and backup ETE paths, then convert ETGs to all-active multi-home.",
    ),
    (
        "mass_es_withdraw",
        20,
        "Withdraw every Ethernet Segment and fail services over to backup paths and alternate DTE next hops.",
    ),
    (
        "mass_es_restore",
        20,
        "Restore every Ethernet Segment, primary ETE, selected egress, and original DTE dependency.",
    ),
    (
        "next_hop_churn",
        20,
        "Change DTE next-hop dependencies again after restoration, then emit failed reprogramming attempts with no state mutation.",
    ),
)


@dataclass(frozen=True)
class ScaleLayout:
    resource_count: int
    etg_count: int
    dte_count: int
    primary_ete_count: int
    backup_ete_count: int
    es_count: int
    vif_count: int
    ip_routing_count: int
    single_home_service_count: int
    multi_home_service_count: int

    @property
    def resource_counts(self) -> dict[str, int]:
        return {
            "ETG": self.etg_count,
            "DTE": self.dte_count,
            "ETE_PRIMARY": self.primary_ete_count,
            "ETE_BACKUP": self.backup_ete_count,
            "EVPN_ES": self.es_count,
            "VIRTUAL_INTERFACE": self.vif_count,
            "IP_ROUTING": self.ip_routing_count,
        }


def _layout(resource_count: int) -> ScaleLayout:
    if resource_count < 0:
        raise ValueError("resource count must be non-negative")
    etg_count = resource_count * 25 // 100
    dte_count = resource_count * 25 // 100
    primary_ete_count = resource_count * 25 // 100
    backup_ete_count = resource_count * 15 // 100
    es_count = resource_count * 5 // 100
    allocated = (
        etg_count
        + dte_count
        + primary_ete_count
        + backup_ete_count
        + es_count
    )
    remainder = resource_count - allocated
    ip_routing_count = 1 if remainder else 0
    vif_count = max(0, remainder - ip_routing_count)
    single_home_service_count = min(etg_count, dte_count, primary_ete_count)
    multi_home_service_count = min(
        single_home_service_count,
        backup_ete_count,
        es_count * 3,
    )
    return ScaleLayout(
        resource_count=resource_count,
        etg_count=etg_count,
        dte_count=dte_count,
        primary_ete_count=primary_ete_count,
        backup_ete_count=backup_ete_count,
        es_count=es_count,
        vif_count=vif_count,
        ip_routing_count=ip_routing_count,
        single_home_service_count=single_home_service_count,
        multi_home_service_count=multi_home_service_count,
    )


def _phase_event_counts(event_count: int) -> dict[str, int]:
    counts = {
        phase: event_count * weight // 100 for phase, weight, _description in PHASES
    }
    assigned = sum(counts.values())
    for phase, _weight, _description in PHASES[: event_count - assigned]:
        counts[phase] += 1
    return counts


def _phase_start_ns(phase: str) -> int:
    phase_index = next(
        index for index, (candidate, _weight, _description) in enumerate(PHASES)
        if candidate == phase
    )
    return BASE_TIME_NS + (phase_index + 1) * PHASE_GAP_NS


def _service_transition_time_ns(
    layout: ScaleLayout,
    phase: str,
    service_index: int,
) -> int:
    """Return the timestamp of a service event after the phase's ES event wave."""
    return _phase_start_ns(phase) + (
        layout.es_count + service_index
    ) * EVENT_STEP_NS


def _json_line(record: dict[str, object]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _write_lines(path: Path, lines: Iterable[str]) -> tuple[int, str]:
    digest = hashlib.sha256()
    count = 0
    with path.open("wb") as output:
        for line in lines:
            encoded = (line + "\n").encode("utf-8")
            output.write(encoded)
            digest.update(encoded)
            count += 1
    return count, digest.hexdigest()


def _write_text(path: Path, text: str) -> str:
    encoded = text.encode("utf-8")
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def _write_json(path: Path, value: object) -> str:
    return _write_text(
        path,
        json.dumps(value, indent=2, sort_keys=True) + "\n",
    )


def _service_id(index: int) -> str:
    return f"svc-{index:06d}"


def _etg_id(index: int) -> str:
    return f"data-bridge-layer/ETG/blue/etg-{index:06d}"


def _dte_id(index: int) -> str:
    return f"data-bridge-layer/DTE/blue/dte-{index:06d}"


def _primary_ete_id(index: int) -> str:
    return f"data-bridge-layer/ETE/etg-{index:06d}/primary"


def _backup_ete_id(index: int) -> str:
    return f"data-bridge-layer/ETE/etg-{index:06d}/backup"


def _es_id(index: int) -> str:
    return f"control-plane/EVPN_ES/es-{index:05d}"


def _vif_id(index: int) -> str:
    return f"data-bridge-layer/VIRTUAL_INTERFACE/ae-{index:05d}"


def _ip_routing_id() -> str:
    return "control-plane/IP_ROUTING/blue"


def _esi(index: int) -> str:
    value = f"{index:018x}"
    return "00:" + ":".join(value[offset : offset + 2] for offset in range(0, 18, 2))


def _overlay_destination(index: int) -> str:
    return f"198.18.{(index // 254) % 254}.{index % 254 + 1}/32"


def _neighbor(index: int, backup: bool = False) -> str:
    prefix = "198.51.100" if backup else "192.0.2"
    return f"{prefix}.{index % 254 + 1}"


def _vni(index: int) -> int:
    return 10_000 + index % 16_000


def _label(index: int) -> int:
    return 16_000 + index % 8_000


def _es_index(layout: ScaleLayout, service_index: int) -> int:
    return service_index % max(1, layout.es_count)


def _alternate_etg(layout: ScaleLayout, service_index: int, offset: int) -> str:
    if layout.etg_count <= 1:
        return _ip_routing_id()
    candidate = (service_index + offset) % layout.etg_count
    if candidate == service_index:
        candidate = (candidate + 1) % layout.etg_count
    return _etg_id(candidate)


def _failover_target(layout: ScaleLayout, service_index: int) -> str:
    return (
        _ip_routing_id()
        if service_index % 2 == 0
        else _alternate_etg(layout, service_index, 1)
    )


def _churn_target(layout: ScaleLayout, service_index: int) -> str:
    return (
        _alternate_etg(layout, service_index, 17)
        if service_index % 2 == 0
        else _ip_routing_id()
    )


def _effect(
    resource_id: str,
    kind: str,
    effect_type: str,
    after: dict[str, object],
) -> dict[str, object]:
    return {
        "resource_id": resource_id,
        "kind": kind,
        "effect_type": effect_type,
        "state_changed": True,
        "after": after,
    }


def _relationship_effect(
    operation: str,
    source: str,
    target: str,
    relation_type: str,
) -> dict[str, str]:
    return {
        "operation": operation,
        "source": source,
        "target": target,
        "type": relation_type,
    }


def _fallback_event(
    phase: str,
    sequence: int,
    local_index: int,
    timestamp_ns: int,
    layout: ScaleLayout,
) -> dict[str, object]:
    resource_id = _ip_routing_id() if layout.ip_routing_count else "scenario/metadata"
    return {
        "event_uid": f"scale-event-{sequence:08d}",
        "timestamp_ns": str(timestamp_ns),
        "clock_domain": "control-plane-realtime",
        "source_sequence": sequence,
        "phase": phase,
        "burst_id": f"{phase}-{local_index // 1000:04d}",
        "layer": "control-plane",
        "event_name": "scale_metadata_heartbeat",
        "resource": resource_id,
        "resource_id": resource_id,
        "resource_kind": "IP_ROUTING" if layout.ip_routing_count else "SCENARIO",
        "action": "modify",
        "properties": {"status": "ready", "phase": phase},
        "result": {"updateStatus": "Ok"},
        "outcome": "success",
        "state_changed": True,
        "effects": [
            _effect(resource_id, "IP_ROUTING", "modify", {"status": "ready"})
        ],
        "relationship_effects": [],
    }


def _event_for_phase(
    phase: str,
    sequence: int,
    local_index: int,
    timestamp_ns: int,
    layout: ScaleLayout,
) -> dict[str, object]:
    if not layout.single_home_service_count:
        return _fallback_event(phase, sequence, local_index, timestamp_ns, layout)

    common = {
        "event_uid": f"scale-event-{sequence:08d}",
        "timestamp_ns": str(timestamp_ns),
        "source_sequence": sequence,
        "phase": phase,
        "burst_id": f"{phase}-{local_index // 1000:04d}",
        "result": {"updateStatus": "Ok"},
        "outcome": "success",
        "state_changed": True,
    }

    if phase == "single_home_create":
        service_index = local_index % layout.single_home_service_count
        etg_id = _etg_id(service_index)
        dte_id = _dte_id(service_index)
        primary_id = _primary_ete_id(service_index)
        return {
            **common,
            "clock_domain": "data-bridge-layer-realtime",
            "layer": "data-bridge-layer",
            "event_name": "evpn_single_home_service_create",
            "resource": f"etg:{_service_id(service_index)}",
            "resource_id": etg_id,
            "resource_kind": "ETG",
            "action": "create",
            "properties": {
                "service_id": _service_id(service_index),
                "overlay_destination": _overlay_destination(service_index),
                "home_mode": "single-home",
                "encapsulation": {
                    "type": "VXLAN",
                    "vni": _vni(service_index),
                    "transport_label": _label(service_index),
                },
            },
            "effects": [
                _effect(
                    etg_id,
                    "ETG",
                    "create",
                    {"status": "active", "home_mode": "single-home"},
                ),
                _effect(
                    primary_id,
                    "ETE",
                    "create",
                    {
                        "status": "active",
                        "role": "primary",
                        "neighbor": _neighbor(service_index),
                    },
                ),
                _effect(
                    dte_id,
                    "DTE",
                    "create",
                    {
                        "status": "programmed",
                        "packet_action": "POP_VNI"
                        if service_index % 2 == 0
                        else "SWAP_LABEL",
                        "next_hop": etg_id,
                    },
                ),
            ],
            "relationship_effects": [
                _relationship_effect("add", etg_id, primary_id, "owns"),
                _relationship_effect(
                    "add", etg_id, primary_id, "selected_egress"
                ),
                _relationship_effect("add", dte_id, etg_id, "next_hop"),
            ],
        }

    if phase == "multihome_add" and layout.multi_home_service_count:
        service_index = local_index % layout.multi_home_service_count
        es_index = _es_index(layout, service_index)
        etg_id = _etg_id(service_index)
        es_id = _es_id(es_index)
        backup_id = _backup_ete_id(service_index)
        es_effect = "create" if service_index < layout.es_count else "modify"
        return {
            **common,
            "clock_domain": "control-plane-realtime",
            "layer": "control-plane",
            "event_name": "evpn_multihome_attachment_add",
            "resource": f"esi:{_esi(es_index)}",
            "resource_id": es_id,
            "resource_kind": "EVPN_ES",
            "action": "add",
            "properties": {
                "service_id": _service_id(service_index),
                "esi": _esi(es_index),
                "prior_home_mode": "single-home",
                "home_mode": "all-active",
                "primary_ete": _primary_ete_id(service_index),
                "backup_ete": backup_id,
            },
            "effects": [
                _effect(
                    es_id,
                    "EVPN_ES",
                    es_effect,
                    {"status": "up", "esi": _esi(es_index)},
                ),
                _effect(
                    backup_id,
                    "ETE",
                    "create",
                    {
                        "status": "standby",
                        "role": "backup",
                        "neighbor": _neighbor(service_index, backup=True),
                        "es_id": es_id,
                    },
                ),
                _effect(
                    etg_id,
                    "ETG",
                    "modify",
                    {
                        "status": "active",
                        "home_mode": "all-active",
                        "member_count": 2,
                    },
                ),
            ],
            "relationship_effects": [
                _relationship_effect("add", etg_id, backup_id, "owns"),
                _relationship_effect("add", etg_id, es_id, "member_of_es"),
                _relationship_effect(
                    "add", es_id, _primary_ete_id(service_index), "active_path"
                ),
            ],
        }

    if phase == "mass_es_withdraw" and layout.multi_home_service_count:
        cycle = max(1, layout.es_count + layout.multi_home_service_count)
        slot = local_index % cycle
        if slot < layout.es_count:
            es_index = slot
            es_id = _es_id(es_index)
            return {
                **common,
                "clock_domain": "control-plane-realtime",
                "layer": "control-plane",
                "event_name": "evpn_es_mass_withdraw",
                "resource": f"esi:{_esi(es_index)}",
                "resource_id": es_id,
                "resource_kind": "EVPN_ES",
                "action": "withdraw",
                "properties": {
                    "esi": _esi(es_index),
                    "prior_status": "up",
                    "status": "withdrawn",
                    "reason": "peer-link-loss",
                    "affected_services": 3,
                },
                "effects": [
                    _effect(
                        es_id,
                        "EVPN_ES",
                        "state-change",
                        {"status": "withdrawn", "reason": "peer-link-loss"},
                    )
                ],
                "relationship_effects": [],
            }
        service_index = (slot - layout.es_count) % layout.multi_home_service_count
        etg_id = _etg_id(service_index)
        dte_id = _dte_id(service_index)
        primary_id = _primary_ete_id(service_index)
        backup_id = _backup_ete_id(service_index)
        es_id = _es_id(_es_index(layout, service_index))
        fallback = _failover_target(layout, service_index)
        return {
            **common,
            "clock_domain": "hardware-driver-plane-realtime",
            "layer": "hardware-driver-plane",
            "event_name": "evpn_mass_service_failover",
            "resource": f"etg:{_service_id(service_index)}",
            "resource_id": etg_id,
            "resource_kind": "ETG",
            "action": "state-change",
            "properties": {
                "esi": _esi(_es_index(layout, service_index)),
                "selected_egress_before": primary_id,
                "selected_egress_after": backup_id,
                "dte_next_hop_before": etg_id,
                "dte_next_hop_after": fallback,
            },
            "effects": [
                _effect(
                    primary_id,
                    "ETE",
                    "state-change",
                    {"status": "down", "reason": "es-withdraw"},
                ),
                _effect(
                    backup_id,
                    "ETE",
                    "state-change",
                    {"status": "active", "reason": "fast-failover"},
                ),
                _effect(
                    etg_id,
                    "ETG",
                    "modify",
                    {"status": "degraded", "selected_egress": backup_id},
                ),
                _effect(
                    dte_id,
                    "DTE",
                    "modify",
                    {
                        "status": "programmed",
                        "next_hop": fallback,
                        "next_hop_mode": "IP_ROUTING"
                        if fallback == _ip_routing_id()
                        else "ETG",
                    },
                ),
            ],
            "relationship_effects": [
                _relationship_effect(
                    "remove", etg_id, primary_id, "selected_egress"
                ),
                _relationship_effect(
                    "add", etg_id, backup_id, "selected_egress"
                ),
                _relationship_effect("remove", dte_id, etg_id, "next_hop"),
                _relationship_effect("add", dte_id, fallback, "next_hop"),
                _relationship_effect("remove", es_id, primary_id, "active_path"),
                _relationship_effect("add", es_id, backup_id, "active_path"),
            ],
        }

    if phase == "mass_es_restore" and layout.multi_home_service_count:
        cycle = max(1, layout.es_count + layout.multi_home_service_count)
        slot = local_index % cycle
        if slot < layout.es_count:
            es_index = slot
            es_id = _es_id(es_index)
            return {
                **common,
                "clock_domain": "control-plane-realtime",
                "layer": "control-plane",
                "event_name": "evpn_es_mass_restore",
                "resource": f"esi:{_esi(es_index)}",
                "resource_id": es_id,
                "resource_kind": "EVPN_ES",
                "action": "restore",
                "properties": {
                    "esi": _esi(es_index),
                    "prior_status": "withdrawn",
                    "status": "up",
                    "reason": "peer-link-restored",
                    "affected_services": 3,
                },
                "effects": [
                    _effect(
                        es_id,
                        "EVPN_ES",
                        "state-change",
                        {"status": "up", "reason": "peer-link-restored"},
                    )
                ],
                "relationship_effects": [],
            }
        service_index = (slot - layout.es_count) % layout.multi_home_service_count
        etg_id = _etg_id(service_index)
        dte_id = _dte_id(service_index)
        primary_id = _primary_ete_id(service_index)
        backup_id = _backup_ete_id(service_index)
        es_id = _es_id(_es_index(layout, service_index))
        fallback = _failover_target(layout, service_index)
        return {
            **common,
            "clock_domain": "data-bridge-layer-realtime",
            "layer": "data-bridge-layer",
            "event_name": "evpn_mass_service_restore",
            "resource": f"etg:{_service_id(service_index)}",
            "resource_id": etg_id,
            "resource_kind": "ETG",
            "action": "state-change",
            "properties": {
                "esi": _esi(_es_index(layout, service_index)),
                "selected_egress_before": backup_id,
                "selected_egress_after": primary_id,
                "dte_next_hop_before": fallback,
                "dte_next_hop_after": etg_id,
            },
            "effects": [
                _effect(
                    primary_id,
                    "ETE",
                    "state-change",
                    {"status": "active", "reason": "es-restored"},
                ),
                _effect(
                    backup_id,
                    "ETE",
                    "state-change",
                    {"status": "standby", "reason": "primary-restored"},
                ),
                _effect(
                    etg_id,
                    "ETG",
                    "modify",
                    {"status": "active", "selected_egress": primary_id},
                ),
                _effect(
                    dte_id,
                    "DTE",
                    "modify",
                    {
                        "status": "programmed",
                        "next_hop": etg_id,
                        "next_hop_mode": "ETG",
                    },
                ),
            ],
            "relationship_effects": [
                _relationship_effect(
                    "remove", etg_id, backup_id, "selected_egress"
                ),
                _relationship_effect(
                    "add", etg_id, primary_id, "selected_egress"
                ),
                _relationship_effect("remove", dte_id, fallback, "next_hop"),
                _relationship_effect("add", dte_id, etg_id, "next_hop"),
                _relationship_effect("remove", es_id, backup_id, "active_path"),
                _relationship_effect("add", es_id, primary_id, "active_path"),
            ],
        }

    if phase == "next_hop_churn" and layout.multi_home_service_count:
        service_index = local_index % layout.multi_home_service_count
        dte_id = _dte_id(service_index)
        etg_id = _etg_id(service_index)
        current_target = _churn_target(layout, service_index)
        failed = local_index >= layout.multi_home_service_count
        attempted_target = (
            _failover_target(layout, service_index)
            if failed
            else current_target
        )
        return {
            **common,
            "clock_domain": "data-bridge-layer-realtime",
            "layer": "data-bridge-layer",
            "event_name": "dte_next_hop_dependency_change",
            "resource": f"dte:{_service_id(service_index)}",
            "resource_id": dte_id,
            "resource_kind": "DTE",
            "action": "modify",
            "properties": {
                "next_hop_before": current_target if failed else etg_id,
                "next_hop_after": attempted_target,
                "next_hop_mode_after": "IP_ROUTING"
                if attempted_target == _ip_routing_id()
                else "ETG",
            },
            "result": {
                "updateStatus": "SyntheticProgrammingError" if failed else "Ok"
            },
            "outcome": "failure" if failed else "success",
            "state_changed": not failed,
            "effects": []
            if failed
            else [
                _effect(
                    dte_id,
                    "DTE",
                    "modify",
                    {
                        "status": "programmed",
                        "next_hop": attempted_target,
                        "next_hop_mode": "IP_ROUTING"
                        if attempted_target == _ip_routing_id()
                        else "ETG",
                    },
                )
            ],
            "relationship_effects": []
            if failed
            else [
                _relationship_effect("remove", dte_id, etg_id, "next_hop"),
                _relationship_effect("add", dte_id, attempted_target, "next_hop"),
            ],
        }

    return _fallback_event(phase, sequence, local_index, timestamp_ns, layout)


def _event_lines(event_count: int, layout: ScaleLayout) -> Iterable[str]:
    phase_counts = _phase_event_counts(event_count)
    sequence = 0
    for phase, _weight, _description in PHASES:
        start_ns = _phase_start_ns(phase)
        for local_index in range(phase_counts[phase]):
            record = _event_for_phase(
                phase,
                sequence,
                local_index,
                start_ns + local_index * EVENT_STEP_NS,
                layout,
            )
            yield _json_line(record)
            sequence += 1


def _resource_lines(layout: ScaleLayout) -> Iterable[str]:
    yield (
        "KIND|RESOURCE_ID|LAYER|VRF|SERVICE_ID|PARENT_ID|ES_ID|ESI|"
        "HOME_MODE|ROLE|MATCH|PACKET_ACTION|NEXT_HOP|ENCAP|ADMIN|OPER|"
        "DF_STATE|NEIGHBOR"
    )
    for index in range(layout.etg_count):
        multi = index < layout.multi_home_service_count
        es_index = _es_index(layout, index)
        yield "|".join(
            [
                "ETG",
                _etg_id(index),
                "data-bridge-layer",
                "blue",
                _service_id(index),
                "",
                _es_id(es_index) if multi else "",
                _esi(es_index) if multi else "",
                "all-active" if multi else "single-home",
                "egress-group",
                _overlay_destination(index),
                "",
                _primary_ete_id(index),
                f"vxlan:vni={_vni(index)};mpls:label={_label(index)}",
                "up",
                "active",
                "df" if multi and index % 2 == 0 else "",
                "",
            ]
        )
    for index in range(layout.dte_count):
        multi = index < layout.multi_home_service_count
        target = _churn_target(layout, index) if multi else _etg_id(index % max(1, layout.etg_count))
        yield "|".join(
            [
                "DTE",
                _dte_id(index),
                "data-bridge-layer",
                "blue",
                _service_id(index),
                "",
                _es_id(_es_index(layout, index)) if multi else "",
                _esi(_es_index(layout, index)) if multi else "",
                "all-active" if multi else "single-home",
                "ingress-disposition",
                f"vni={_vni(index)};label={_label(index)}",
                "POP_VNI" if index % 2 == 0 else "SWAP_LABEL",
                target,
                "",
                "up",
                "programmed",
                "",
                "",
            ]
        )
    for index in range(layout.primary_ete_count):
        multi = index < layout.multi_home_service_count
        yield "|".join(
            [
                "ETE",
                _primary_ete_id(index),
                "data-bridge-layer",
                "blue",
                _service_id(index),
                _etg_id(index % max(1, layout.etg_count)),
                _es_id(_es_index(layout, index)) if multi else "",
                _esi(_es_index(layout, index)) if multi else "",
                "all-active" if multi else "single-home",
                "primary",
                "",
                "",
                _neighbor(index),
                f"vxlan:vni={_vni(index)};mpls:label={_label(index)}",
                "up",
                "active",
                "df" if multi and index % 2 == 0 else "",
                _neighbor(index),
            ]
        )
    for index in range(layout.backup_ete_count):
        multi = index < layout.multi_home_service_count
        yield "|".join(
            [
                "ETE",
                _backup_ete_id(index),
                "data-bridge-layer",
                "blue",
                _service_id(index),
                _etg_id(index % max(1, layout.etg_count)),
                _es_id(_es_index(layout, index)) if multi else "",
                _esi(_es_index(layout, index)) if multi else "",
                "all-active" if multi else "standby-only",
                "backup",
                "",
                "",
                _neighbor(index, backup=True),
                f"vxlan:vni={_vni(index)};mpls:label={_label(index) + 1}",
                "up",
                "standby",
                "non-df" if multi else "",
                _neighbor(index, backup=True),
            ]
        )
    for index in range(layout.es_count):
        yield "|".join(
            [
                "EVPN_ES",
                _es_id(index),
                "control-plane",
                "blue",
                "",
                "",
                _es_id(index),
                _esi(index),
                "all-active",
                "ethernet-segment",
                "",
                "",
                _vif_id(index % max(1, layout.vif_count))
                if layout.vif_count
                else "",
                "",
                "up",
                "restored",
                "df" if index % 2 == 0 else "non-df",
                "",
            ]
        )
    for index in range(layout.vif_count):
        es_index = index % max(1, layout.es_count)
        yield "|".join(
            [
                "VIRTUAL_INTERFACE",
                _vif_id(index),
                "data-bridge-layer",
                "blue",
                "",
                "",
                _es_id(es_index) if layout.es_count else "",
                _esi(es_index) if layout.es_count else "",
                "all-active" if layout.es_count else "single-home",
                "es-attachment",
                "",
                "",
                "",
                "",
                "up",
                "up",
                "df" if index % 2 == 0 else "non-df",
                f"Ethernet{index % 128 + 1}/{index // 128 + 1}",
            ]
        )
    if layout.ip_routing_count:
        yield "|".join(
            [
                "IP_ROUTING",
                _ip_routing_id(),
                "control-plane",
                "blue",
                "",
                "",
                "",
                "",
                "",
                "fallback-routing",
                "0.0.0.0/0",
                "",
                "",
                "",
                "up",
                "ready",
                "",
                "192.0.2.254",
            ]
        )


def _relationship_lines(layout: ScaleLayout) -> Iterable[str]:
    sequence = 0

    def record(
        source: str,
        target: str,
        relation_type: str,
        valid_from_ns: int,
        valid_to_ns: int | None,
        phase: str,
    ) -> str:
        nonlocal sequence
        value = {
            "relationship_id": f"scale-rel-{sequence:09d}",
            "source": source,
            "target": target,
            "type": relation_type,
            "relation_type": relation_type,
            "valid_from_ns": str(valid_from_ns),
            "valid_to_ns": None if valid_to_ns is None else str(valid_to_ns),
            "phase": phase,
            "quality": "exact",
            "provenance": "synthetic_plugin",
        }
        sequence += 1
        return _json_line(value)

    single_start = _phase_start_ns("single_home_create")
    multi_start = _phase_start_ns("multihome_add")
    withdraw_start = _phase_start_ns("mass_es_withdraw")
    restore_start = _phase_start_ns("mass_es_restore")
    churn_start = _phase_start_ns("next_hop_churn")

    for index in range(layout.etg_count):
        etg_id = _etg_id(index)
        primary_id = _primary_ete_id(index)
        yield record(etg_id, primary_id, "owns", single_start, None, "single_home_create")
        if index < layout.multi_home_service_count:
            yield record(
                etg_id,
                primary_id,
                "selected_egress",
                single_start,
                _service_transition_time_ns(layout, "mass_es_withdraw", index),
                "single_home_create",
            )
            yield record(
                etg_id,
                primary_id,
                "selected_egress",
                _service_transition_time_ns(layout, "mass_es_restore", index),
                None,
                "mass_es_restore",
            )
        else:
            yield record(
                etg_id,
                primary_id,
                "selected_egress",
                single_start,
                None,
                "single_home_create",
            )

    for index in range(layout.multi_home_service_count):
        etg_id = _etg_id(index)
        backup_id = _backup_ete_id(index)
        es_id = _es_id(_es_index(layout, index))
        withdraw_time = _service_transition_time_ns(
            layout, "mass_es_withdraw", index
        )
        restore_time = _service_transition_time_ns(
            layout, "mass_es_restore", index
        )
        yield record(etg_id, backup_id, "owns", multi_start, None, "multihome_add")
        yield record(etg_id, es_id, "member_of_es", multi_start, None, "multihome_add")
        yield record(
            etg_id,
            backup_id,
            "selected_egress",
            withdraw_time,
            restore_time,
            "mass_es_withdraw",
        )
        yield record(
            es_id,
            _primary_ete_id(index),
            "active_path",
            multi_start,
            withdraw_time,
            "multihome_add",
        )
        yield record(
            es_id,
            backup_id,
            "active_path",
            withdraw_time,
            restore_time,
            "mass_es_withdraw",
        )
        yield record(
            es_id,
            _primary_ete_id(index),
            "active_path",
            restore_time,
            None,
            "mass_es_restore",
        )

    for index in range(layout.dte_count):
        dte_id = _dte_id(index)
        etg_id = _etg_id(index % max(1, layout.etg_count))
        if index < layout.multi_home_service_count:
            withdraw_time = _service_transition_time_ns(
                layout, "mass_es_withdraw", index
            )
            restore_time = _service_transition_time_ns(
                layout, "mass_es_restore", index
            )
            churn_time = churn_start + index * EVENT_STEP_NS
            yield record(
                dte_id,
                etg_id,
                "next_hop",
                single_start,
                withdraw_time,
                "single_home_create",
            )
            yield record(
                dte_id,
                _failover_target(layout, index),
                "next_hop",
                withdraw_time,
                restore_time,
                "mass_es_withdraw",
            )
            yield record(
                dte_id,
                etg_id,
                "next_hop",
                restore_time,
                churn_time,
                "mass_es_restore",
            )
            yield record(
                dte_id,
                _churn_target(layout, index),
                "next_hop",
                churn_time,
                None,
                "next_hop_churn",
            )
        else:
            yield record(
                dte_id,
                etg_id,
                "next_hop",
                single_start,
                None,
                "single_home_create",
            )

    if layout.vif_count:
        for index in range(layout.primary_ete_count):
            yield record(
                _primary_ete_id(index),
                _vif_id(index % layout.vif_count),
                "egresses_via",
                single_start,
                None,
                "single_home_create",
            )
        for index in range(layout.multi_home_service_count):
            yield record(
                _backup_ete_id(index),
                _vif_id(index % layout.vif_count),
                "egresses_via",
                multi_start,
                None,
                "multihome_add",
            )
        for index in range(min(layout.es_count, layout.vif_count)):
            es_id = _es_id(index)
            vif_id = _vif_id(index)
            withdraw_time = withdraw_start + index * EVENT_STEP_NS
            restore_time = restore_start + index * EVENT_STEP_NS
            yield record(
                es_id,
                vif_id,
                "uses_interface",
                multi_start,
                withdraw_time,
                "multihome_add",
            )
            yield record(
                es_id,
                vif_id,
                "uses_interface",
                restore_time,
                None,
                "mass_es_restore",
            )


def _high_fanout_relationship_lines(
    count: int,
    layout: ScaleLayout,
) -> Iterable[str]:
    for index in range(count):
        target = (
            _etg_id(index % layout.etg_count)
            if layout.etg_count
            else _ip_routing_id()
        )
        yield _json_line(
            {
                "relationship_id": f"fanout-{index:09d}",
                "source": _ip_routing_id(),
                "target": target,
                "type": "resolves_via",
                "valid_from_ns": str(_phase_start_ns("single_home_create")),
                "valid_to_ns": None,
                "quality": "exact",
                "provenance": "synthetic_scale_stress",
            }
        )


def _relationship_mutation_lines(layout: ScaleLayout) -> Iterable[str]:
    sequence = 0

    def mutation(
        operation: str,
        source: str,
        target: str,
        relation_type: str,
        phase: str,
        effective_time_ns: int,
    ) -> str:
        nonlocal sequence
        value = {
            "mutation_id": f"scale-mutation-{sequence:09d}",
            "operation": operation,
            "source": source,
            "target": target,
            "type": relation_type,
            "relation_type": relation_type,
            "phase": phase,
            "effective_time_ns": str(effective_time_ns),
            "quality": "exact",
            "provenance": "synthetic_plugin",
        }
        sequence += 1
        return _json_line(value)

    withdraw_start = _phase_start_ns("mass_es_withdraw")
    restore_start = _phase_start_ns("mass_es_restore")
    churn_start = _phase_start_ns("next_hop_churn")

    for index in range(layout.multi_home_service_count):
        etg_id = _etg_id(index)
        dte_id = _dte_id(index)
        primary_id = _primary_ete_id(index)
        backup_id = _backup_ete_id(index)
        es_id = _es_id(_es_index(layout, index))
        fallback = _failover_target(layout, index)
        churn_target = _churn_target(layout, index)
        withdraw_time = _service_transition_time_ns(
            layout, "mass_es_withdraw", index
        )
        restore_time = _service_transition_time_ns(
            layout, "mass_es_restore", index
        )
        churn_time = churn_start + index * EVENT_STEP_NS
        for operation, source, target, relation_type in (
            ("remove", etg_id, primary_id, "selected_egress"),
            ("add", etg_id, backup_id, "selected_egress"),
            ("remove", dte_id, etg_id, "next_hop"),
            ("add", dte_id, fallback, "next_hop"),
            ("remove", es_id, primary_id, "active_path"),
            ("add", es_id, backup_id, "active_path"),
        ):
            yield mutation(
                operation,
                source,
                target,
                relation_type,
                "mass_es_withdraw",
                withdraw_time,
            )
        for operation, source, target, relation_type in (
            ("remove", etg_id, backup_id, "selected_egress"),
            ("add", etg_id, primary_id, "selected_egress"),
            ("remove", dte_id, fallback, "next_hop"),
            ("add", dte_id, etg_id, "next_hop"),
            ("remove", es_id, backup_id, "active_path"),
            ("add", es_id, primary_id, "active_path"),
        ):
            yield mutation(
                operation,
                source,
                target,
                relation_type,
                "mass_es_restore",
                restore_time,
            )
        yield mutation(
            "remove",
            dte_id,
            etg_id,
            "next_hop",
            "next_hop_churn",
            churn_time,
        )
        yield mutation(
            "add",
            dte_id,
            churn_target,
            "next_hop",
            "next_hop_churn",
            churn_time,
        )

    for index in range(min(layout.es_count, layout.vif_count)):
        es_id = _es_id(index)
        vif_id = _vif_id(index)
        yield mutation(
            "remove",
            es_id,
            vif_id,
            "uses_interface",
            "mass_es_withdraw",
            withdraw_start + index * EVENT_STEP_NS,
        )
        yield mutation(
            "add",
            es_id,
            vif_id,
            "uses_interface",
            "mass_es_restore",
            restore_start + index * EVENT_STEP_NS,
        )


def _plugin_schema() -> dict[str, object]:
    return {
        "semantic_owner": "plugin",
        "core_interprets_domain_types": False,
        "resource_kinds": [
            {"kind": "ETG", "layer": "data-bridge-layer"},
            {"kind": "ETE", "layer": "data-bridge-layer"},
            {"kind": "DTE", "layer": "data-bridge-layer"},
            {"kind": "EVPN_ES", "layer": "control-plane"},
            {"kind": "VIRTUAL_INTERFACE", "layer": "data-bridge-layer"},
            {"kind": "IP_ROUTING", "layer": "control-plane"},
        ],
        "relationship_types": [
            {"relation_type": "owns", "directed": True, "structural": True},
            {
                "relation_type": "member_of_es",
                "directed": True,
                "structural": True,
            },
            {
                "relation_type": "selected_egress",
                "directed": True,
                "structural": False,
            },
            {
                "relation_type": "next_hop",
                "directed": True,
                "structural": False,
            },
            {
                "relation_type": "active_path",
                "directed": True,
                "structural": False,
            },
            {
                "relation_type": "egresses_via",
                "directed": True,
                "structural": False,
            },
            {
                "relation_type": "uses_interface",
                "directed": True,
                "structural": True,
            },
            {
                "relation_type": "resolves_via",
                "directed": True,
                "structural": False,
            },
        ],
    }


def _walkthrough(layout: ScaleLayout) -> dict[str, object]:
    services = []
    for index in range(min(2, layout.multi_home_service_count)):
        etg_id = _etg_id(index)
        primary_id = _primary_ete_id(index)
        backup_id = _backup_ete_id(index)
        fallback = _failover_target(layout, index)
        services.append(
            {
                "service_id": _service_id(index),
                "resource_ids": {
                    "etg": etg_id,
                    "dte": _dte_id(index),
                    "primary_ete": primary_id,
                    "backup_ete": backup_id,
                    "ethernet_segment": _es_id(_es_index(layout, index)),
                },
                "states": [
                    {
                        "phase": "single_home_create",
                        "home_mode": "single-home",
                        "es_status": "absent",
                        "selected_egress": primary_id,
                        "dte_next_hop": etg_id,
                    },
                    {
                        "phase": "multihome_add",
                        "home_mode": "all-active",
                        "es_status": "up",
                        "selected_egress": primary_id,
                        "dte_next_hop": etg_id,
                    },
                    {
                        "phase": "mass_es_withdraw",
                        "home_mode": "all-active",
                        "es_status": "withdrawn",
                        "selected_egress": backup_id,
                        "dte_next_hop": fallback,
                    },
                    {
                        "phase": "mass_es_restore",
                        "home_mode": "all-active",
                        "es_status": "up",
                        "selected_egress": primary_id,
                        "dte_next_hop": etg_id,
                    },
                    {
                        "phase": "next_hop_churn",
                        "home_mode": "all-active",
                        "es_status": "up",
                        "selected_egress": primary_id,
                        "dte_next_hop": _churn_target(layout, index),
                    },
                ],
            }
        )
    return {
        "scenario_id": SCENARIO_ID,
        "purpose": "Review dependency changes for representative services without opening the full 100K+ streams.",
        "services": services,
    }


def _scenario_metadata(
    event_count: int,
    layout: ScaleLayout,
) -> dict[str, object]:
    phase_counts = _phase_event_counts(event_count)
    phases = []
    for phase, _weight, description in PHASES:
        phases.append(
            {
                "phase": phase,
                "description": description,
                "start_ns": str(_phase_start_ns(phase)),
                "events": phase_counts[phase],
            }
        )
    last_phase = PHASES[-1][0]
    capture_ns = (
        _phase_start_ns(last_phase)
        + max(1, phase_counts[last_phase]) * EVENT_STEP_NS
        + EVENT_STEP_NS
    )
    return {
        "scenario_id": SCENARIO_ID,
        "generator_version": GENERATOR_VERSION,
        "synthetic": True,
        "description": (
            "Large EVPN service population created single-home first, expanded "
            "to all-active multi-home, withdrawn and failed over in bulk, "
            "restored in bulk, then subjected to DTE next-hop dependency churn."
        ),
        "base_time_ns": str(BASE_TIME_NS),
        "capture_time_ns": str(capture_ns),
        "scale": {
            "events": event_count,
            "resources": layout.resource_count,
        },
        "resource_counts": layout.resource_counts,
        "single_home_services": layout.single_home_service_count,
        "multi_home_services": layout.multi_home_service_count,
        "ethernet_segments": layout.es_count,
        "phase_order": [phase for phase, _weight, _description in PHASES],
        "phases": phases,
        "expected_changes": {
            "mass_es_withdrawals": layout.es_count,
            "mass_es_restores": layout.es_count,
            "selected_egress_failovers": layout.multi_home_service_count,
            "selected_egress_restores": layout.multi_home_service_count,
            "dte_next_hop_failovers": layout.multi_home_service_count,
            "dte_next_hop_restores": layout.multi_home_service_count,
            "post_restore_next_hop_changes": layout.multi_home_service_count,
            "relationship_mutations": (
                layout.multi_home_service_count * 14
                + min(layout.es_count, layout.vif_count) * 2
            ),
        },
    }


def _generated_readme(
    event_count: int,
    layout: ScaleLayout,
    relationship_count: int,
    mutation_count: int,
) -> str:
    phase_counts = _phase_event_counts(event_count)
    lines = [
        "# EVPN multi-homing scale fixture",
        "",
        "This directory is synthetic and contains no product or customer data.",
        f"Scenario: {SCENARIO_ID}",
        f"Events: {event_count}",
        f"Resources: {layout.resource_count}",
        f"Time-valid relationship intervals: {relationship_count}",
        f"Relationship mutations: {mutation_count}",
        "",
        "## Lifecycle",
        "",
    ]
    for phase, _weight, description in PHASES:
        lines.append(
            f"1. {phase}: {phase_counts[phase]} events. {description}"
        )
    lines.extend(
        [
            "",
            "## Files",
            "",
            "- events.jsonl: normalized callbacks and all resource/relationship effects.",
            "- resources.table.txt: final status snapshot after restore and next-hop churn.",
            "- relationships.jsonl: non-overlapping time-valid relationship intervals.",
            "- relationship-mutations.jsonl: explicit remove/add operations for dependency changes.",
            "- high-fanout-relationships.jsonl: a separate 100K-style fan-out stress stream.",
            "- scenario.json: phase times, counts, and expected semantic changes.",
            "- walkthrough.json: two representative services across every phase.",
            "- plugin-schema.json: plugin-owned kinds and relationship types.",
            "- router-state-lab-100k.tgz: optional one-file packed form built by generate_packed_scale_bundle.py.",
            "",
            "Start with walkthrough.json, then search events.jsonl for its service IDs.",
            "The full files are intentionally line-oriented so plugins can stream them.",
            "Run python scripts/generate_packed_scale_bundle.py to add the outer TGZ used by the demo launcher.",
            "",
        ]
    )
    return "\n".join(lines)


def _generate_in_empty_output(
    output: Path,
    event_count: int,
    resource_count: int,
) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    (output / ".router-dump-analyzer-generated").write_bytes(OWNERSHIP_MARKER)
    layout = _layout(resource_count)
    scenario = _scenario_metadata(event_count, layout)

    event_lines, event_sha = _write_lines(
        output / "events.jsonl",
        _event_lines(event_count, layout),
    )
    resource_lines, resource_sha = _write_lines(
        output / "resources.table.txt",
        _resource_lines(layout),
    )
    relationship_lines, relationship_sha = _write_lines(
        output / "relationships.jsonl",
        _relationship_lines(layout),
    )
    high_fanout_lines, high_fanout_sha = _write_lines(
        output / "high-fanout-relationships.jsonl",
        _high_fanout_relationship_lines(resource_count, layout),
    )
    mutation_lines, mutation_sha = _write_lines(
        output / "relationship-mutations.jsonl",
        _relationship_mutation_lines(layout),
    )
    scenario_sha = _write_json(output / "scenario.json", scenario)
    schema_sha = _write_json(output / "plugin-schema.json", _plugin_schema())
    walkthrough_sha = _write_json(output / "walkthrough.json", _walkthrough(layout))
    readme_sha = _write_text(
        output / "README.md",
        _generated_readme(
            event_count,
            layout,
            relationship_lines,
            mutation_lines,
        ),
    )

    manifest = {
        "generator_version": GENERATOR_VERSION,
        "scenario_id": SCENARIO_ID,
        "events": {"records": event_lines, "sha256": event_sha},
        "resources": {
            "records": max(0, resource_lines - 1),
            "lines_including_header": resource_lines,
            "sha256": resource_sha,
            "by_kind": layout.resource_counts,
        },
        "relationships": {
            "records": relationship_lines,
            "sha256": relationship_sha,
        },
        "high_fanout_relationships": {
            "records": high_fanout_lines,
            "sha256": high_fanout_sha,
        },
        "relationship_mutations": {
            "records": mutation_lines,
            "sha256": mutation_sha,
        },
        "scenario": {"file": "scenario.json", "sha256": scenario_sha},
        "plugin_schema": {"file": "plugin-schema.json", "sha256": schema_sha},
        "walkthrough": {"file": "walkthrough.json", "sha256": walkthrough_sha},
        "readme": {"file": "README.md", "sha256": readme_sha},
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest_path


def _directory_fingerprint(directory: Path) -> str | None:
    if not directory.exists():
        return None
    if not directory.is_dir() or directory.is_symlink():
        raise RuntimeError(f"output is not a regular directory: {directory}")
    digest = hashlib.sha256()
    for candidate in sorted(directory.rglob("*"), key=lambda item: item.as_posix()):
        relative = candidate.relative_to(directory).as_posix().encode("utf-8")
        if candidate.is_symlink():
            raise RuntimeError(f"scale output contains a symbolic link: {candidate}")
        if candidate.is_dir():
            digest.update(b"D\x00" + relative + b"\x00")
        elif candidate.is_file():
            digest.update(b"F\x00" + relative + b"\x00")
            with candidate.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
            digest.update(b"\x00")
        else:
            raise RuntimeError(f"scale output contains a special file: {candidate}")
    return digest.hexdigest()


def generate(output: Path, event_count: int, resource_count: int) -> Path:
    if event_count < 0 or resource_count < 0:
        raise ValueError("counts must be non-negative")
    if output.is_symlink():
        raise RuntimeError(f"refusing symbolic-link output: {output}")
    output = output.resolve()
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)
    lock = parent / f".{output.name}.router-dump-analyzer.lock"
    lock_fd: int | None = None
    stage: Path | None = None
    backup: Path | None = None
    try:
        try:
            lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as error:
            raise RuntimeError(f"another generator is using output: {output}") from error
        marker = output / ".router-dump-analyzer-generated"
        if output.exists():
            if not output.is_dir():
                raise RuntimeError(f"output is not a directory: {output}")
            existing = list(output.iterdir())
            if existing and (
                marker.is_symlink()
                or not marker.is_file()
                or marker.read_bytes() != OWNERSHIP_MARKER
            ):
                raise RuntimeError(
                    f"refusing to replace non-empty unowned output directory: {output}"
                )
        initial_fingerprint = _directory_fingerprint(output)
        stage = Path(tempfile.mkdtemp(prefix=".rda-scale-stage-", dir=parent))
        _generate_in_empty_output(stage, event_count, resource_count)
        if _directory_fingerprint(output) != initial_fingerprint:
            raise RuntimeError(f"output changed while scale fixtures were built: {output}")
        if output.exists():
            backup = Path(tempfile.mkdtemp(prefix=".rda-scale-old-", dir=parent))
            backup.rmdir()
            output.replace(backup)
        stage.replace(output)
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
        return output / "manifest.json"
    except BaseException:
        if stage is not None and stage.exists():
            shutil.rmtree(stage)
        if backup is not None and backup.exists() and not output.exists():
            backup.replace(output)
        raise
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
            lock.unlink(missing_ok=True)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "samples" / "generated-scale",
    )
    parser.add_argument("--events", type=int, default=125_000)
    parser.add_argument("--resources", type=int, default=100_000)
    args = parser.parse_args()
    manifest_path = generate(
        args.output.resolve(),
        args.events,
        args.resources,
    )
    console_path = str(manifest_path).encode(
        "ascii", errors="backslashreplace"
    ).decode("ascii")
    print(f"Generated {SCENARIO_ID}: {console_path}")


if __name__ == "__main__":
    main()
