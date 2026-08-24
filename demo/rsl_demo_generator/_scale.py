"""Deterministic EVPN multi-homing history generator."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Final, Iterable

from rsl_demo_plugin.archive import (
    HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME,
    MANIFEST_MEMBER_NAME,
    RELATIONSHIP_MUTATIONS_MEMBER_NAME,
)
from rsl_demo_plugin import GENERATED_PROJECTION_POLICY
from .scenario_source import load_default_scenario_source


_DEFAULT_SCENARIO_SOURCE = load_default_scenario_source()
BASE_TIME_NS: Final[int] = _DEFAULT_SCENARIO_SOURCE.base_time_ns
# Keep each million-scale phase inside its authored 120-second slot.  The
# previous millisecond cadence was correct at 125K but made the 1.25M stream
# overlap later phases and therefore cease to be globally time ordered.
EVENT_STEP_NS = 100_000
PHASE_GAP_NS = 120_000_000_000
SCENARIO_ID = _DEFAULT_SCENARIO_SOURCE.scenario_id
GENERATOR_VERSION = 8
CHURN_FAILURE_PERIOD = 10
OWNERSHIP_MARKER = b"router-dump-analyzer scale generator v1\n"
WRITE_BUFFER_BYTES = 1 << 20
# A multi-node assembly repeats the same local scale identities before applying
# its node namespace.  Bound the reusable immutable values instead of
# rebuilding those strings hundreds of thousands of times per node.
PURE_VALUE_CACHE_SIZE = 32_768
PHASES = (
    (
        "single_home_create",
        25,
        "Create ETG, primary ETE, and DTE resources, then advance their programming generations.",
    ),
    (
        "multihome_add",
        15,
        "Add Ethernet Segments and backup ETE paths, convert ETGs to all-active multi-home, then advance multi-home generations.",
    ),
    (
        "mass_es_withdraw",
        20,
        "Withdraw every Ethernet Segment, fail services over, then advance withdrawal and failover generations.",
    ),
    (
        "mass_es_restore",
        20,
        "Restore every Ethernet Segment, primary path, and original DTE dependency, then advance recovery generations.",
    ),
    (
        "next_hop_churn",
        20,
        "Change DTE next-hop dependencies again after restoration, then emit failed reprogramming attempts with no state mutation.",
    ),
)
_PHASE_STARTS_NS = {
    phase: BASE_TIME_NS + (phase_index + 1) * PHASE_GAP_NS
    for phase_index, (phase, _weight, _description) in enumerate(PHASES)
}
_CANONICAL_JSON_ENCODE = json.JSONEncoder(
    sort_keys=True,
    separators=(",", ":"),
).encode


@dataclass(frozen=True)
class ScaleLayout:
    resource_count: int
    etg_count: int
    dte_count: int
    primary_ete_count: int
    backup_ete_count: int
    es_count: int
    neighbor_count: int
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
            "NEIGHBOR": self.neighbor_count,
            "VIRTUAL_INTERFACE": self.vif_count,
            "IP_ROUTING": self.ip_routing_count,
        }


def _layout(resource_count: int) -> ScaleLayout:
    if resource_count < 0:
        raise ValueError("resource count must be non-negative")
    etg_count = resource_count * 25 // 100
    dte_count = resource_count * 25 // 100
    primary_ete_count = resource_count * 25 // 100
    backup_ete_count = resource_count * 10 // 100
    es_count = resource_count * 5 // 100
    neighbor_count = resource_count * 5 // 100
    allocated = (
        etg_count
        + dte_count
        + primary_ete_count
        + backup_ete_count
        + es_count
        + neighbor_count
    )
    remainder = resource_count - allocated
    # Retain at least one interface whenever neighbor records are useful. Very
    # small developer fixtures may not have enough remainder for both an IP
    # routing fallback and an interface, so omit their neighbor population.
    if neighbor_count and remainder < 2:
        allocated -= neighbor_count
        neighbor_count = 0
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
        neighbor_count=neighbor_count,
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
    try:
        return _PHASE_STARTS_NS[phase]
    except KeyError:
        raise ValueError(f"unknown scale phase: {phase}") from None


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
    return _CANONICAL_JSON_ENCODE(record)


def _write_lines(path: Path, lines: Iterable[str]) -> tuple[int, str]:
    digest = hashlib.sha256()
    count = 0
    pending = bytearray()
    with path.open("wb") as output:
        for line in lines:
            pending.extend(line.encode("utf-8"))
            pending.append(0x0A)
            count += 1
            if len(pending) >= WRITE_BUFFER_BYTES:
                output.write(pending)
                digest.update(pending)
                pending.clear()
        if pending:
            output.write(pending)
            digest.update(pending)
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


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _service_id(index: int) -> str:
    return f"svc-{index:06d}"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _etg_id(index: int) -> str:
    return f"data-bridge-layer/ETG/blue/etg-{index:06d}"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _dte_id(index: int) -> str:
    return f"data-bridge-layer/DTE/blue/dte-{index:06d}"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _primary_ete_id(index: int) -> str:
    return f"data-bridge-layer/ETE/etg-{index:06d}/primary"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _backup_ete_id(index: int) -> str:
    return f"data-bridge-layer/ETE/etg-{index:06d}/backup"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _es_id(index: int) -> str:
    return f"control-plane/EVPN_ES/es-{index:05d}"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _vif_id(index: int) -> str:
    return f"data-bridge-layer/VIRTUAL_INTERFACE/ae-{index:05d}"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _neighbor_id(index: int) -> str:
    return f"control-plane/NEIGHBOR/blue/peer-{index:05d}"


def _ip_routing_id() -> str:
    return "control-plane/IP_ROUTING/blue"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _esi(index: int) -> str:
    value = f"{index:018x}"
    return "00:" + ":".join(value[offset : offset + 2] for offset in range(0, 18, 2))


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _overlay_destination(index: int) -> str:
    return f"198.18.{(index // 254) % 254}.{index % 254 + 1}/32"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _neighbor(index: int, backup: bool = False) -> str:
    prefix = "198.51.100" if backup else "192.0.2"
    return f"{prefix}.{index % 254 + 1}"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _interface_name(index: int) -> str:
    return f"Ethernet{index % 128 + 1}/{index // 128 + 1}"


def _neighbor_protocol(index: int) -> str:
    return ("LLDP", "IS-IS", "ARP", "IPv6-ND")[index % 4]


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _neighbor_peer_name(index: int) -> str:
    return f"fabric-peer-{index % 64 + 1:02d}"


@lru_cache(maxsize=PURE_VALUE_CACHE_SIZE)
def _neighbor_peer_address(index: int) -> str:
    protocol = _neighbor_protocol(index)
    if protocol == "IPv6-ND":
        return f"fe80::{index + 1:x}"
    return f"172.20.{(index // 254) % 254}.{index % 254 + 1}"


def _neighbor_typed_identity(index: int) -> dict[str, object]:
    protocol = _neighbor_protocol(index)
    if protocol == "LLDP":
        return {
            "type": "mac_address",
            "value": f"02:00:{(index >> 16) & 255:02x}:{(index >> 8) & 255:02x}:{index & 255:02x}:01",
        }
    if protocol == "IS-IS":
        return {
            "type": "isis_system_id",
            "value": f"0000.0000.{index + 1:04x}",
        }
    if protocol == "ARP":
        return {"type": "ipv4_address", "value": _neighbor_peer_address(index)}
    return {"type": "ipv6_address", "value": _neighbor_peer_address(index)}


def _neighbor_state(
    layout: ScaleLayout,
    index: int,
    *,
    reachable: bool = True,
) -> dict[str, object]:
    vif_index = index % max(1, layout.vif_count)
    protocol = _neighbor_protocol(index)
    return {
        "status": "up" if reachable else "down",
        "protocol": protocol,
        "peer_name": _neighbor_peer_name(index),
        "peer_identity": _neighbor_typed_identity(index)["value"],
        "peer_address": _neighbor_peer_address(index),
        "local_interface_id": _vif_id(vif_index),
        "local_interface": f"ae-{vif_index:05d}",
        "member_interface": _interface_name(vif_index),
        "adjacency_state": "established" if reachable else "expired",
        "reachability": "reachable" if reachable else "unreachable",
        "hold_time_seconds": (120, 90, 30, 30)[index % 4],
        "source": "synthetic_plugin.neighbor_resolver",
        "resolution_basis": (
            f"{protocol} adjacency observed on {_interface_name(vif_index)}"
        ),
    }


def _vif_neighbor_count(layout: ScaleLayout, index: int) -> int:
    """Return the final number of plug-in neighbor records for one VIF."""

    if not layout.vif_count:
        return 0
    return (
        layout.neighbor_count // layout.vif_count
        + int(index < layout.neighbor_count % layout.vif_count)
    )


def _vif_state(
    layout: ScaleLayout,
    index: int,
    *,
    multi_home: bool | None = None,
    neighbor_count: int | None = None,
) -> dict[str, object]:
    """Return a plug-in-owned VIF state for a specific lifecycle phase.

    The catalog calls this without overrides and therefore gets the final
    capture snapshot. Event effects pass explicit phase values so the temporal
    index does not expose a future Ethernet Segment or neighbor count at the
    single-home creation event.
    """

    es_index = index % max(1, layout.es_count)
    if multi_home is None:
        multi_home = index < min(layout.es_count, layout.vif_count)
    if neighbor_count is None:
        neighbor_count = _vif_neighbor_count(layout, index)
    return {
        "admin_state": "up",
        "df_state": (
            "df" if index % 2 == 0 else "non-df"
        ) if multi_home else "not-applicable",
        "es_id": _es_id(es_index) if multi_home else "",
        "esi": _esi(es_index) if multi_home else "",
        "home_mode": "all-active" if multi_home else "single-home",
        "interface_class": (
            "evpn-ethernet-segment" if multi_home else "ethernet-attachment"
        ),
        "interface_name": f"ae-{index:05d}",
        "member_interface": _interface_name(index),
        "neighbor_count": neighbor_count,
        "oper_state": "up",
        "role": "es-attachment" if multi_home else "local-attachment",
        "status": "up",
        "vrf": "blue",
    }


def _vni(index: int) -> int:
    return 10_000 + index % 16_000


def _label(index: int) -> int:
    return 16_000 + index % 8_000


def _encapsulation(index: int, *, backup: bool = False) -> dict[str, object]:
    """Return the plug-in-owned, stable encapsulation for one ETE path."""

    return {
        "type": "VXLAN",
        "vni": _vni(index),
        "transport_label": _label(index) + int(backup),
    }


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


def _churn_target_for_step(
    layout: ScaleLayout,
    service_index: int,
    step: int,
) -> str:
    return (
        _churn_target(layout, service_index)
        if step % 2 == 0
        else _failover_target(layout, service_index)
    )


def _churn_transition(
    layout: ScaleLayout,
    local_index: int,
) -> tuple[int, int, str, str, bool, int]:
    """Return one deterministic DTE dependency change or failed attempt."""

    service_count = layout.multi_home_service_count
    if service_count <= 0:
        raise ValueError("churn transitions require multi-home services")
    service_index = local_index % service_count
    occurrence = local_index // service_count
    first_failure = (-service_index) % CHURN_FAILURE_PERIOD
    if first_failure == 0:
        first_failure = CHURN_FAILURE_PERIOD
    failures_before = (
        0
        if occurrence <= first_failure
        else 1 + (occurrence - 1 - first_failure) // CHURN_FAILURE_PERIOD
    )
    failed = (
        occurrence >= first_failure
        and (occurrence - first_failure) % CHURN_FAILURE_PERIOD == 0
    )
    successful_before = occurrence - failures_before
    current_target = (
        _etg_id(service_index)
        if successful_before == 0
        else _churn_target_for_step(
            layout,
            service_index,
            successful_before - 1,
        )
    )
    attempted_target = _churn_target_for_step(
        layout,
        service_index,
        successful_before,
    )
    return (
        service_index,
        occurrence,
        current_target,
        attempted_target,
        failed,
        successful_before,
    )


def _churn_success_count(event_count: int, layout: ScaleLayout) -> int:
    service_count = layout.multi_home_service_count
    if not service_count:
        return 0
    churn_count = _phase_event_counts(event_count)["next_hop_churn"]
    failures = 0
    for service_index in range(min(service_count, churn_count)):
        # Churn visits services round-robin.  Count the arithmetic progression
        # of failed occurrences rather than scanning the entire event wave.
        occurrence_count = (
            (churn_count - 1 - service_index) // service_count + 1
        )
        first_failure = (-service_index) % CHURN_FAILURE_PERIOD
        if first_failure == 0:
            first_failure = CHURN_FAILURE_PERIOD
        if occurrence_count > first_failure:
            failures += (
                1
                + (
                    occurrence_count
                    - 1
                    - first_failure
                )
                // CHURN_FAILURE_PERIOD
            )
    return churn_count - failures


def _final_churn_target(
    event_count: int,
    layout: ScaleLayout,
    service_index: int,
) -> str:
    service_count = layout.multi_home_service_count
    churn_count = _phase_event_counts(event_count)["next_hop_churn"]
    if (
        not service_count
        or service_index >= service_count
        or service_index >= churn_count
    ):
        return _etg_id(service_index)
    occurrence_count = (
        (churn_count - 1 - service_index) // service_count + 1
    )
    first_failure = (-service_index) % CHURN_FAILURE_PERIOD
    if first_failure == 0:
        first_failure = CHURN_FAILURE_PERIOD
    failure_count = (
        0
        if occurrence_count <= first_failure
        else (
            1
            + (
                occurrence_count
                - 1
                - first_failure
            )
            // CHURN_FAILURE_PERIOD
        )
    )
    successful_count = occurrence_count - failure_count
    if successful_count <= 0:
        return _etg_id(service_index)
    return _churn_target_for_step(
        layout,
        service_index,
        successful_count - 1,
    )


@lru_cache(maxsize=4_096)
def _successful_churn_transitions(
    event_count: int,
    layout: ScaleLayout,
    service_index: int,
) -> tuple[tuple[int, str, str], ...]:
    churn_count = _phase_event_counts(event_count)["next_hop_churn"]
    service_count = layout.multi_home_service_count
    if not service_count:
        return ()
    transitions = []
    for local_index in range(service_index, churn_count, service_count):
        (
            _service_index,
            _occurrence,
            current_target,
            attempted_target,
            failed,
            _generation,
        ) = _churn_transition(layout, local_index)
        if not failed:
            transitions.append(
                (local_index, current_target, attempted_target)
            )
    return tuple(transitions)


def _effect(
    resource_id: str,
    kind: str,
    effect_type: str,
    after: dict[str, object],
) -> dict[str, object]:
    condition = str(after.get("status", "unknown"))
    normalized = condition.casefold()
    status_class = (
        "error"
        if normalized in {"down", "error", "failed", "unreachable", "withdrawn"}
        else "healthy"
        if normalized
        in {"active", "ready", "programmed", "standby", "up", "reachable"}
        else "degraded"
        if normalized == "degraded"
        else "absent"
        if normalized == "absent"
        else "unknown"
    )
    return {
        "resource_id": resource_id,
        "kind": kind,
        "effect_type": effect_type,
        "state_changed": True,
        "condition": condition,
        "status_class": status_class,
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


def _state_change_event(
    common: dict[str, object],
    *,
    clock_domain: str,
    layer: str,
    event_name: str,
    resource_id: str,
    resource_kind: str,
    properties: dict[str, object],
    after: dict[str, object],
) -> dict[str, object]:
    """Emit a distinct, resource-bound state update for surplus scale events."""

    return {
        **common,
        "clock_domain": clock_domain,
        "layer": layer,
        "event_name": event_name,
        "resource": resource_id,
        "resource_id": resource_id,
        "resource_kind": resource_kind,
        "action": "modify",
        "properties": properties,
        "result": {"updateStatus": "Ok"},
        "outcome": "success",
        "state_changed": True,
        "effects": [
            _effect(resource_id, resource_kind, "modify", after)
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
        if local_index >= layout.single_home_service_count:
            generation = local_index // layout.single_home_service_count
            return _state_change_event(
                common,
                clock_domain="data-bridge-layer-realtime",
                layer="data-bridge-layer",
                event_name="evpn_single_home_program_generation_change",
                resource_id=etg_id,
                resource_kind="ETG",
                properties={
                    "service_id": _service_id(service_index),
                    "home_mode": "single-home",
                    "generation_before": generation - 1,
                    "generation_after": generation,
                },
                after={
                    "status": "active",
                    "home_mode": "single-home",
                    "program_generation": generation,
                },
            )
        effects = [
            _effect(
                etg_id,
                "ETG",
                "create",
                {
                    "status": "active",
                    "home_mode": "single-home",
                    "overlay_destination": _overlay_destination(service_index),
                    "encapsulation": _encapsulation(service_index),
                },
            ),
            _effect(
                primary_id,
                "ETE",
                "create",
                {
                    "status": "active",
                    "role": "primary",
                    "neighbor": _neighbor(service_index),
                    "encapsulation": _encapsulation(service_index),
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
        ]
        relationship_effects = [
            _relationship_effect("add", etg_id, primary_id, "owns"),
            _relationship_effect(
                "add", etg_id, primary_id, "selected_egress"
            ),
            _relationship_effect("add", dte_id, etg_id, "next_hop"),
        ]
        if service_index < layout.vif_count:
            vif_index = service_index % layout.vif_count
            vif_id = _vif_id(vif_index)
            effects.append(
                _effect(
                    vif_id,
                    "VIRTUAL_INTERFACE",
                    "create",
                    _vif_state(
                        layout,
                        vif_index,
                        multi_home=False,
                        neighbor_count=int(service_index < layout.neighbor_count),
                    ),
                )
            )
        if service_index < layout.neighbor_count and layout.vif_count:
            vif_index = service_index % layout.vif_count
            vif_id = _vif_id(vif_index)
            neighbor_id = _neighbor_id(service_index)
            # More neighbor records than VIFs means this is an additional
            # adjacency on a VIF that already exists. Preserve the stable VIF
            # identity and record a modification at the exact discovery time.
            if service_index >= layout.vif_count:
                effects.append(
                    _effect(
                        vif_id,
                        "VIRTUAL_INTERFACE",
                        "modify",
                        _vif_state(
                            layout,
                            vif_index,
                            multi_home=False,
                            neighbor_count=service_index // layout.vif_count + 1,
                        ),
                    )
                )
            effects.append(
                _effect(
                    neighbor_id,
                    "NEIGHBOR",
                    "create",
                    _neighbor_state(layout, service_index),
                )
            )
            relationship_effects.append(
                _relationship_effect(
                    "add", vif_id, neighbor_id, "has_neighbor"
                )
            )
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
                "encapsulation": _encapsulation(service_index),
            },
            "effects": effects,
            "relationship_effects": relationship_effects,
        }

    if phase == "multihome_add" and layout.multi_home_service_count:
        service_index = local_index % layout.multi_home_service_count
        es_index = _es_index(layout, service_index)
        etg_id = _etg_id(service_index)
        es_id = _es_id(es_index)
        backup_id = _backup_ete_id(service_index)
        if local_index >= layout.multi_home_service_count:
            generation = local_index // layout.multi_home_service_count
            return _state_change_event(
                common,
                clock_domain="control-plane-realtime",
                layer="control-plane",
                event_name="evpn_multihome_generation_change",
                resource_id=etg_id,
                resource_kind="ETG",
                properties={
                    "service_id": _service_id(service_index),
                    "esi": _esi(es_index),
                    "home_mode": "all-active",
                    "generation_before": generation - 1,
                    "generation_after": generation,
                },
                after={
                    "status": "active",
                    "home_mode": "all-active",
                    "member_count": 2,
                    "multihome_generation": generation,
                },
            )
        es_effect = "create" if service_index < layout.es_count else "modify"
        effects = [
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
                    "encapsulation": _encapsulation(
                        service_index,
                        backup=True,
                    ),
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
        ]
        relationship_effects = [
            _relationship_effect("add", etg_id, backup_id, "owns"),
            _relationship_effect("add", etg_id, es_id, "member_of_es"),
            _relationship_effect(
                "add", es_id, _primary_ete_id(service_index), "active_path"
            ),
        ]
        # The first service mapped to an ES establishes its VIF attachment.
        # Later services sharing that ES must not replay the same VIF state or
        # structural relationship.
        if service_index < min(layout.es_count, layout.vif_count):
            vif_id = _vif_id(service_index)
            effects.append(
                _effect(
                    vif_id,
                    "VIRTUAL_INTERFACE",
                    "modify",
                    _vif_state(
                        layout,
                        service_index,
                        multi_home=True,
                    ),
                )
            )
            relationship_effects.append(
                _relationship_effect("add", es_id, vif_id, "uses_interface")
            )
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
            "effects": effects,
            "relationship_effects": relationship_effects,
        }

    if phase == "mass_es_withdraw" and layout.multi_home_service_count:
        cycle = max(1, layout.es_count + layout.multi_home_service_count)
        slot = local_index % cycle
        if local_index >= cycle:
            generation = local_index // cycle
            if slot < layout.es_count:
                es_id = _es_id(slot)
                return _state_change_event(
                    common,
                    clock_domain="control-plane-realtime",
                    layer="control-plane",
                    event_name="evpn_es_withdraw_generation_change",
                    resource_id=es_id,
                    resource_kind="EVPN_ES",
                    properties={
                        "esi": _esi(slot),
                        "status": "withdrawn",
                        "reason": "peer-link-loss",
                        "generation_before": generation - 1,
                        "generation_after": generation,
                    },
                    after={
                        "status": "withdrawn",
                        "reason": "peer-link-loss",
                        "withdraw_generation": generation,
                    },
                )
            service_index = slot - layout.es_count
            etg_id = _etg_id(service_index)
            return _state_change_event(
                common,
                clock_domain="hardware-driver-plane-realtime",
                layer="hardware-driver-plane",
                event_name="evpn_failover_generation_change",
                resource_id=etg_id,
                resource_kind="ETG",
                properties={
                    "service_id": _service_id(service_index),
                    "status": "degraded",
                    "selected_egress": _backup_ete_id(service_index),
                    "generation_before": generation - 1,
                    "generation_after": generation,
                },
                after={
                    "status": "degraded",
                    "selected_egress": _backup_ete_id(service_index),
                    "failover_generation": generation,
                },
            )
        if slot < layout.es_count:
            es_index = slot
            es_id = _es_id(es_index)
            effects = [
                _effect(
                    es_id,
                    "EVPN_ES",
                    "state-change",
                    {"status": "withdrawn", "reason": "peer-link-loss"},
                )
            ]
            if es_index < layout.neighbor_count and layout.vif_count:
                effects.append(
                    _effect(
                        _neighbor_id(es_index),
                        "NEIGHBOR",
                        "state-change",
                        _neighbor_state(layout, es_index, reachable=False),
                    )
                )
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
                "effects": effects,
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
        if local_index >= cycle:
            generation = local_index // cycle
            if slot < layout.es_count:
                es_id = _es_id(slot)
                return _state_change_event(
                    common,
                    clock_domain="control-plane-realtime",
                    layer="control-plane",
                    event_name="evpn_es_restore_generation_change",
                    resource_id=es_id,
                    resource_kind="EVPN_ES",
                    properties={
                        "esi": _esi(slot),
                        "status": "up",
                        "reason": "peer-link-restored",
                        "generation_before": generation - 1,
                        "generation_after": generation,
                    },
                    after={
                        "status": "up",
                        "reason": "peer-link-restored",
                        "restore_generation": generation,
                    },
                )
            service_index = slot - layout.es_count
            etg_id = _etg_id(service_index)
            return _state_change_event(
                common,
                clock_domain="data-bridge-layer-realtime",
                layer="data-bridge-layer",
                event_name="evpn_restore_generation_change",
                resource_id=etg_id,
                resource_kind="ETG",
                properties={
                    "service_id": _service_id(service_index),
                    "status": "active",
                    "selected_egress": _primary_ete_id(service_index),
                    "generation_before": generation - 1,
                    "generation_after": generation,
                },
                after={
                    "status": "active",
                    "selected_egress": _primary_ete_id(service_index),
                    "restore_generation": generation,
                },
            )
        if slot < layout.es_count:
            es_index = slot
            es_id = _es_id(es_index)
            effects = [
                _effect(
                    es_id,
                    "EVPN_ES",
                    "state-change",
                    {"status": "up", "reason": "peer-link-restored"},
                )
            ]
            if es_index < layout.neighbor_count and layout.vif_count:
                effects.append(
                    _effect(
                        _neighbor_id(es_index),
                        "NEIGHBOR",
                        "state-change",
                        _neighbor_state(layout, es_index, reachable=True),
                    )
                )
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
                "effects": effects,
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
        (
            service_index,
            occurrence,
            current_target,
            attempted_target,
            failed,
            successful_before,
        ) = _churn_transition(layout, local_index)
        dte_id = _dte_id(service_index)
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
                "next_hop_before": current_target,
                "next_hop_after": attempted_target,
                "next_hop_mode_after": "IP_ROUTING"
                if attempted_target == _ip_routing_id()
                else "ETG",
                "change_generation_before": successful_before,
                "change_generation_after": successful_before + 1,
                "attempt": occurrence,
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
                        "change_generation": successful_before + 1,
                    },
                )
            ],
            "relationship_effects": []
            if failed
            else [
                _relationship_effect(
                    "remove", dte_id, current_target, "next_hop"
                ),
                _relationship_effect("add", dte_id, attempted_target, "next_hop"),
            ],
        }

    return _fallback_event(phase, sequence, local_index, timestamp_ns, layout)


def _event_lines(
    event_count: int,
    layout: ScaleLayout,
) -> Iterable[str]:
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


def _resource_lines(
    event_count: int,
    layout: ScaleLayout,
) -> Iterable[str]:
    yield (
        "KIND|RESOURCE_ID|LAYER|VRF|SERVICE_ID|PARENT_ID|ES_ID|ESI|"
        "HOME_MODE|ROLE|MATCH|PACKET_ACTION|NEXT_HOP|ENCAP|ADMIN|OPER|"
        "DF_STATE|NEIGHBOR|KEY_JSON|STATE_JSON"
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
                _json_line(
                    {"service_id": _service_id(index), "vrf": "blue"}
                ),
                _json_line(
                    {
                        "admin_state": "up",
                        "df_state": "df" if multi and index % 2 == 0 else "",
                        "encapsulation": _encapsulation(index),
                        "es_id": _es_id(es_index) if multi else "",
                        "esi": _esi(es_index) if multi else "",
                        "home_mode": "all-active" if multi else "single-home",
                        "oper_state": "active",
                        "overlay_destination": _overlay_destination(index),
                        "role": "egress-group",
                        "service_id": _service_id(index),
                        "status": "active",
                        "vrf": "blue",
                    }
                ),
            ]
        )
    for index in range(layout.dte_count):
        multi = index < layout.multi_home_service_count
        target = (
            _final_churn_target(event_count, layout, index)
            if multi
            else _etg_id(index % max(1, layout.etg_count))
        )
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
                _json_line(
                    {"service_id": _service_id(index), "vrf": "blue"}
                ),
                _json_line(
                    {
                        "admin_state": "up",
                        "es_id": _es_id(_es_index(layout, index)) if multi else "",
                        "esi": _esi(_es_index(layout, index)) if multi else "",
                        "home_mode": "all-active" if multi else "single-home",
                        "match": {"vni": _vni(index), "label": _label(index)},
                        "next_hop": target,
                        "oper_state": "programmed",
                        "packet_action": "POP_VNI" if index % 2 == 0 else "SWAP_LABEL",
                        "role": "ingress-disposition",
                        "service_id": _service_id(index),
                        "status": "programmed",
                        "vrf": "blue",
                    }
                ),
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
                _json_line(
                    {
                        "parent_resource_id": _etg_id(
                            index % max(1, layout.etg_count)
                        ),
                        "path_id": "primary",
                    }
                ),
                _json_line(
                    {
                        "admin_state": "up",
                        "df_state": "df" if multi and index % 2 == 0 else "",
                        "encapsulation": _encapsulation(index),
                        "es_id": _es_id(_es_index(layout, index)) if multi else "",
                        "esi": _esi(_es_index(layout, index)) if multi else "",
                        "home_mode": "all-active" if multi else "single-home",
                        "neighbor": _neighbor(index),
                        "next_hop": _neighbor(index),
                        "oper_state": "active",
                        "parent_resource_id": _etg_id(
                            index % max(1, layout.etg_count)
                        ),
                        "path_id": "primary",
                        "role": "primary",
                        "service_id": _service_id(index),
                        "status": "active",
                        "vrf": "blue",
                    }
                ),
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
                _json_line(
                    {
                        "parent_resource_id": _etg_id(
                            index % max(1, layout.etg_count)
                        ),
                        "path_id": "backup",
                    }
                ),
                _json_line(
                    {
                        "admin_state": "up",
                        "df_state": "non-df" if multi else "",
                        "encapsulation": _encapsulation(index, backup=True),
                        "es_id": _es_id(_es_index(layout, index)) if multi else "",
                        "esi": _esi(_es_index(layout, index)) if multi else "",
                        "home_mode": "all-active" if multi else "standby-only",
                        "neighbor": _neighbor(index, backup=True),
                        "next_hop": _neighbor(index, backup=True),
                        "oper_state": "standby",
                        "parent_resource_id": _etg_id(
                            index % max(1, layout.etg_count)
                        ),
                        "path_id": "backup",
                        "role": "backup",
                        "service_id": _service_id(index),
                        "status": "standby",
                        "vrf": "blue",
                    }
                ),
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
                _json_line({"esi": _esi(index), "vrf": "blue"}),
                _json_line(
                    {
                        "admin_state": "up",
                        "df_state": "df" if index % 2 == 0 else "non-df",
                        "esi": _esi(index),
                        "home_mode": "all-active",
                        "oper_state": "restored",
                        "role": "ethernet-segment",
                        "status": "restored",
                        "virtual_interface_id": _vif_id(
                            index % max(1, layout.vif_count)
                        )
                        if layout.vif_count
                        else "",
                        "vrf": "blue",
                    }
                ),
            ]
        )
    for index in range(layout.vif_count):
        state = _vif_state(layout, index)
        yield "|".join(
            [
                "VIRTUAL_INTERFACE",
                _vif_id(index),
                "data-bridge-layer",
                "blue",
                "",
                "",
                str(state["es_id"]),
                str(state["esi"]),
                str(state["home_mode"]),
                str(state["role"]),
                "",
                "",
                "",
                "",
                "up",
                "up",
                str(state["df_state"]),
                "",
                _json_line(
                    {
                        "interface_name": f"ae-{index:05d}",
                        "vrf": "blue",
                    }
                ),
                _json_line(state),
            ]
        )
    for index in range(layout.neighbor_count):
        vif_index = index % max(1, layout.vif_count)
        yield "|".join(
            [
                "NEIGHBOR",
                _neighbor_id(index),
                "control-plane",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                _json_line(
                    {
                        "local_interface_id": {
                            "type": "resource_id",
                            "value": _vif_id(vif_index),
                        },
                        "peer_identity": _neighbor_typed_identity(index),
                        "protocol": {
                            "type": "enum",
                            "value": _neighbor_protocol(index),
                        },
                    }
                ),
                _json_line(_neighbor_state(layout, index)),
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
                _json_line({"vrf": "blue"}),
                _json_line(
                    {
                        "admin_state": "up",
                        "match": "0.0.0.0/0",
                        "neighbor": "192.0.2.254",
                        "oper_state": "ready",
                        "role": "fallback-routing",
                        "status": "ready",
                        "vrf": "blue",
                    }
                ),
            ]
        )


def _relationship_lines(
    event_count: int,
    layout: ScaleLayout,
) -> Iterable[str]:
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
        primary_next_hop = (
            _etg_id(index + 1)
            if index % 4 == 0 and index + 1 < layout.etg_count
            else _ip_routing_id()
        )
        yield record(
            primary_id,
            primary_next_hop,
            "next_hop",
            single_start,
            None,
            "single_home_create",
        )
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
        backup_next_hop = (
            _etg_id(index + 1)
            if index % 4 == 0 and index + 1 < layout.etg_count
            else _ip_routing_id()
        )
        yield record(
            backup_id,
            backup_next_hop,
            "next_hop",
            multi_start,
            None,
            "multihome_add",
        )
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
            churn_transitions = _successful_churn_transitions(
                event_count,
                layout,
                index,
            )
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
                (
                    churn_start + churn_transitions[0][0] * EVENT_STEP_NS
                    if churn_transitions
                    else None
                ),
                "mass_es_restore",
            )
            for transition_index, (local_index, _before, target) in enumerate(
                churn_transitions
            ):
                transition_time = churn_start + local_index * EVENT_STEP_NS
                valid_to_ns = (
                    churn_start
                    + churn_transitions[transition_index + 1][0] * EVENT_STEP_NS
                    if transition_index + 1 < len(churn_transitions)
                    else None
                )
                yield record(
                    dte_id,
                    target,
                    "next_hop",
                    transition_time,
                    valid_to_ns,
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
            multihome_time = multi_start + index * EVENT_STEP_NS
            withdraw_time = withdraw_start + index * EVENT_STEP_NS
            restore_time = restore_start + index * EVENT_STEP_NS
            yield record(
                es_id,
                vif_id,
                "uses_interface",
                multihome_time,
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

        for index in range(layout.neighbor_count):
            yield record(
                _vif_id(index % layout.vif_count),
                _neighbor_id(index),
                "has_neighbor",
                single_start + index * EVENT_STEP_NS,
                None,
                "single_home_create",
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


def _relationship_mutation_lines(
    event_count: int,
    layout: ScaleLayout,
) -> Iterable[str]:
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
        withdraw_time = _service_transition_time_ns(
            layout, "mass_es_withdraw", index
        )
        restore_time = _service_transition_time_ns(
            layout, "mass_es_restore", index
        )
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
        for (
            local_index,
            current_target,
            attempted_target,
        ) in _successful_churn_transitions(
            event_count,
            layout,
            index,
        ):
            churn_time = churn_start + local_index * EVENT_STEP_NS
            yield mutation(
                "remove",
                dte_id,
                current_target,
                "next_hop",
                "next_hop_churn",
                churn_time,
            )
            yield mutation(
                "add",
                dte_id,
                attempted_target,
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


_INTEGER_RESOURCE_PROPERTIES = frozenset(
    {
        "generation",
        "hold_time_seconds",
        "hold_timer",
        "neighbor_count",
        "vlan_id",
    }
)
_STRUCTURED_RESOURCE_PROPERTIES = frozenset({"encapsulation"})


def _public_resource_properties(*names: str) -> list[dict[str, object]]:
    """Declare the demo plug-in fields that may cross the client boundary."""

    return [
        {
            "name": name,
            "label": name.replace("_", " ").title(),
            "value_type": (
                "integer"
                if name in _INTEGER_RESOURCE_PROPERTIES
                else "object"
                if name in _STRUCTURED_RESOURCE_PROPERTIES
                else "string"
            ),
            "searchable": name not in _STRUCTURED_RESOURCE_PROPERTIES,
            "indexed": name
            in {
                "adjacency_state",
                "interface_name",
                "next_hop",
                "oper_state",
                "peer_address",
                "peer_name",
                "protocol",
                "reachability",
                "service_id",
                "status",
                "vrf",
            },
            "sensitive": False,
            "client_visible": True,
        }
        for name in names
    ]


def _plugin_schema() -> dict[str, object]:
    return {
        "semantic_owner": "plugin",
        "core_interprets_domain_types": False,
        "projection_capabilities": (
            GENERATED_PROJECTION_POLICY.base_projection_capabilities()
        ),
        "review_prompts": [
            (
                "Do ETG, ETE, DTE, Ethernet Segment, Virtual Interface, and "
                "Neighbor dependencies match the intended scale plug-in model?"
            ),
            (
                "Are single-home to all-active VIF transitions and additional "
                "neighbor discoveries clear at their exact event times?"
            ),
            (
                "Which plug-in-owned status, reachability, and protocol fields "
                "should drive Neighbor lane and table presentation?"
            ),
            (
                "Which raw evidence must be reachable from a forwarding, ES, "
                "VIF, or Neighbor state interval?"
            ),
            (
                "Which failover, restore, and next-hop aggregates are most useful "
                "for a selected range?"
            ),
        ],
        "record_lane_presets": [
            {
                "lane_id": "scale-neighbor-signals",
                "label": "Neighbor and adjacency signals",
                "pattern": "neighbor|adjacency|peer|LLDP|IS-IS|ARP|IPv6-ND|BFD",
                "source_types": [
                    "ctf",
                    "syslog",
                    "agent-event",
                    "status-text",
                ],
                "unmatched_only": False,
                "case_sensitive": False,
                "default_enabled": False,
                "plugin_defined": True,
                "description": (
                    "Scale plug-in vocabulary for discovered peers, protocol "
                    "adjacencies, and reachability changes."
                ),
            }
        ],
        "consistency_rules": [
            {
                "rule_id": "scale.neighbor.restore-reachability.v1",
                "label": "Neighbor reachability follows ES recovery",
                "description": (
                    "For the synthetic scale plug-in, neighbors linked to a "
                    "withdrawn Ethernet Segment become unreachable and return to "
                    "reachable when that segment is restored."
                ),
                "resource_kinds": [
                    "EVPN_ES",
                    "VIRTUAL_INTERFACE",
                    "NEIGHBOR",
                ],
                "semantic_owner": "plugin",
            }
        ],
        "dashboards": [
            {
                "dashboard_id": "neighbor-health",
                "title": "Neighbor health and reachability (final snapshot)",
                "description": (
                    "Precomputed final-snapshot protocol and reachability counts; "
                    "the table is a bounded visible point-in-time sample with "
                    "plug-in-defined calculation evidence."
                ),
                "default_open": True,
                "default_expanded": True,
                "collapsible": True,
                "movable": True,
                "plugin_defined": True,
                "statistics": [
                    {
                        "statistic_id": "neighbor-total",
                        "label": "Neighbors",
                        "aggregation": "precomputed",
                        "scale_metric": "by_kind.NEIGHBOR",
                    },
                    {
                        "statistic_id": "neighbor-reachable",
                        "label": "Final reachable",
                        "aggregation": "precomputed",
                        "scale_metric": "neighbor_reachability.reachable",
                    },
                    {
                        "statistic_id": "neighbor-isis",
                        "label": "IS-IS",
                        "aggregation": "precomputed",
                        "scale_metric": "neighbors_by_protocol.IS-IS",
                    },
                    {
                        "statistic_id": "neighbor-lldp",
                        "label": "LLDP",
                        "aggregation": "precomputed",
                        "scale_metric": "neighbors_by_protocol.LLDP",
                    },
                ],
                "tables": [
                    {
                        "table_id": "neighbor-health-table",
                        "title": "Neighbor sample",
                        "resource_kinds": ["NEIGHBOR"],
                        "sort_field": "label",
                        "sort_direction": "ascending",
                        "max_rows": 40,
                        "columns": [
                            {
                                "field": "label",
                                "label": "Neighbor",
                                "value_format": "resource",
                            },
                            {
                                "field": "state.protocol",
                                "label": "Protocol",
                                "value_format": "text",
                            },
                            {
                                "field": "state.peer_address",
                                "label": "Peer address",
                                "value_format": "text",
                            },
                            {
                                "field": "state.local_interface",
                                "label": "Local interface",
                                "value_format": "text",
                            },
                            {
                                "field": "state.reachability",
                                "label": "Reachability",
                                "value_format": "status",
                            },
                            {
                                "field": "state.resolution_basis",
                                "label": "How calculated",
                                "value_format": "text",
                            },
                        ],
                    }
                ],
            }
        ],
        "resource_kinds": [
            {
                "kind": "ETG",
                "layer": "data-bridge-layer",
                "key_fields": ["vrf", "service_id"],
                "properties": _public_resource_properties(
                    "status",
                    "status_class",
                    "admin_state",
                    "oper_state",
                    "role",
                    "vrf",
                    "service_id",
                    "es_id",
                    "esi",
                    "df_state",
                    "home_mode",
                    "match",
                    "next_hop",
                    "overlay_destination",
                    "encapsulation",
                ),
                "display_name_fields": ["service_id", "overlay_destination"],
                "default_table_fields": [
                    "status",
                    "home_mode",
                    "overlay_destination",
                    "encapsulation",
                ],
                "condition_field": "status",
            },
            {
                "kind": "ETE",
                "layer": "data-bridge-layer",
                "key_fields": ["parent_resource_id", "path_id"],
                "properties": _public_resource_properties(
                    "status",
                    "status_class",
                    "admin_state",
                    "oper_state",
                    "role",
                    "vrf",
                    "service_id",
                    "es_id",
                    "esi",
                    "df_state",
                    "home_mode",
                    "parent_id",
                    "parent_resource_id",
                    "path_id",
                    "neighbor",
                    "next_hop",
                    "encapsulation",
                ),
                "display_name_fields": ["path_id", "neighbor"],
                "default_table_fields": [
                    "status",
                    "role",
                    "neighbor",
                    "encapsulation",
                ],
                "condition_field": "status",
            },
            {
                "kind": "DTE",
                "layer": "data-bridge-layer",
                "key_fields": ["vrf", "service_id"],
                "properties": _public_resource_properties(
                    "status",
                    "status_class",
                    "admin_state",
                    "oper_state",
                    "role",
                    "vrf",
                    "service_id",
                    "es_id",
                    "esi",
                    "home_mode",
                    "match",
                    "next_hop",
                    "packet_action",
                ),
                "display_name_fields": ["service_id"],
                "default_table_fields": [
                    "status",
                    "packet_action",
                    "next_hop",
                ],
                "condition_field": "status",
            },
            {
                "kind": "EVPN_ES",
                "layer": "control-plane",
                "key_fields": ["vrf", "esi"],
                "properties": _public_resource_properties(
                    "status",
                    "status_class",
                    "admin_state",
                    "oper_state",
                    "role",
                    "vrf",
                    "es_id",
                    "esi",
                    "df_state",
                    "home_mode",
                    "next_hop",
                    "virtual_interface_id",
                    "reason",
                ),
                "display_name_fields": ["esi"],
                "default_table_fields": ["status", "esi", "reason"],
                "condition_field": "status",
            },
            {
                "kind": "VIRTUAL_INTERFACE",
                "layer": "data-bridge-layer",
                "key_fields": ["vrf", "interface_name"],
                "properties": _public_resource_properties(
                    "status",
                    "status_class",
                    "admin_state",
                    "admin_status",
                    "oper_state",
                    "oper_status",
                    "role",
                    "vrf",
                    "interface_name",
                    "interface_class",
                    "attachment_kind",
                    "classification",
                    "segment_key",
                    "subnet_prefix",
                    "lag_id",
                    "member_interface",
                    "neighbor_count",
                    "vlan_id",
                    "es_id",
                    "esi",
                    "df_state",
                    "home_mode",
                    "reason",
                ),
                "display_name_fields": ["interface_name", "es_id"],
                "default_table_fields": [
                    "status",
                    "oper_state",
                    "interface_name",
                    "member_interface",
                    "neighbor_count",
                    "home_mode",
                    "df_state",
                ],
                "condition_field": "status",
            },
            {
                "kind": "NEIGHBOR",
                "label": "Neighbor adjacency",
                "display_name": "Neighbors",
                "layer": "control-plane",
                "key_fields": [
                    "local_interface_id",
                    "protocol",
                    "peer_identity",
                ],
                "properties": _public_resource_properties(
                    "status",
                    "status_class",
                    "protocol",
                    "peer_identity",
                    "peer_name",
                    "peer_address",
                    "source",
                    "local_interface",
                    "local_interface_id",
                    "member_interface",
                    "adjacency_state",
                    "hold_time_seconds",
                    "reachability",
                    "resolution_basis",
                ),
                "default_timeline_fields": [
                    "status",
                    "reachability",
                    "adjacency_state",
                ],
                "display_name_fields": ["peer_name", "peer_address"],
                "default_table_fields": [
                    "status",
                    "protocol",
                    "peer_name",
                    "peer_address",
                    "local_interface",
                    "reachability",
                    "adjacency_state",
                    "resolution_basis",
                ],
                "condition_field": "status",
                "presentation_tags": ["adjacency", "peer", "expandable-child"],
                "icon": {
                    "path": "M 4 12 A 3 3 0 1 0 10 12 A 3 3 0 1 0 4 12 M 14 12 A 3 3 0 1 0 20 12 A 3 3 0 1 0 14 12 M 10 12 L 14 12",
                    "view_box": [0, 0, 24, 24],
                    "render_mode": "stroke",
                    "stroke_width": 1.8,
                },
            },
            {
                "kind": "IP_ROUTING",
                "layer": "control-plane",
                "key_fields": ["vrf"],
                "properties": _public_resource_properties(
                    "status",
                    "status_class",
                    "admin_state",
                    "oper_state",
                    "role",
                    "vrf",
                    "match",
                    "neighbor",
                ),
                "display_name_fields": ["vrf", "match"],
                "default_table_fields": ["status", "match", "neighbor"],
                "condition_field": "status",
            },
            {
                "kind": "IP_ROUTE",
                "label": "IP route",
                "display_name": "IP routes",
                "layer": "control-plane",
                "key_fields": ["vrf"],
                "properties": _public_resource_properties(
                    "status",
                    "status_class",
                    "oper_state",
                    "vrf",
                    "protocol",
                    "next_hop",
                    "interface",
                    "reason",
                    "generation",
                    "attempted_next_hop",
                    "error",
                ),
                "display_name_fields": ["vrf", "next_hop"],
                "default_table_fields": [
                    "status",
                    "vrf",
                    "protocol",
                    "next_hop",
                    "interface",
                ],
                "condition_field": "status",
                "presentation_tags": ["route", "control-plane"],
            },
            {
                "kind": "ADJACENCY",
                "label": "Protocol adjacency",
                "display_name": "Protocol adjacencies",
                "layer": "control-plane",
                "key_fields": ["interface", "protocol"],
                "properties": _public_resource_properties(
                    "status",
                    "status_class",
                    "oper_state",
                    "interface",
                    "protocol",
                    "hold_timer",
                    "reason",
                ),
                "display_name_fields": ["protocol", "interface"],
                "default_table_fields": [
                    "status",
                    "protocol",
                    "interface",
                    "oper_state",
                ],
                "condition_field": "status",
                "presentation_tags": ["adjacency", "control-plane"],
            },
        ],
        "relationship_types": [
            {"relation_type": "owns", "label": "Owns path", "directed": True, "structural": True},
            {
                "relation_type": "member_of_es",
                "label": "Member of Ethernet Segment",
                "directed": True,
                "structural": True,
            },
            {
                "relation_type": "selected_egress",
                "label": "Selected egress",
                "directed": True,
                "structural": False,
            },
            {
                "relation_type": "next_hop",
                "label": "Next hop",
                "directed": True,
                "structural": False,
            },
            {
                "relation_type": "active_path",
                "label": "Active path",
                "directed": True,
                "structural": False,
            },
            {
                "relation_type": "egresses_via",
                "label": "Egresses via",
                "directed": True,
                "structural": False,
            },
            {
                "relation_type": "uses_interface",
                "label": "Uses interface",
                "directed": True,
                "structural": True,
            },
            {
                "relation_type": "has_neighbor",
                "label": "Has neighbor",
                "directed": True,
                "structural": True,
            },
            {
                "relation_type": "resolves_via",
                "label": "Resolves via",
                "directed": True,
                "structural": False,
            },
        ],
        "resource_table_views": [
            {
                "view_id": "etg-path-bundles",
                "label": "ETG path bundles",
                "description": (
                    "Each ETG is followed by its active ETE paths and each path's "
                    "time-valid next hop."
                ),
                "root_kinds": ["ETG"],
                "levels": [
                    {
                        "label": "ETE path",
                        "relation_types": ["owns"],
                        "target_kinds": ["ETE"],
                        "direction": "outgoing",
                    },
                    {
                        "label": "Next hop",
                        "relation_types": ["next_hop"],
                        "target_kinds": [],
                        "direction": "outgoing",
                    },
                ],
                "columns": [
                    {
                        "field": "state.overlay_destination",
                        "label": "Overlay destination",
                        "value_format": "text",
                    },
                    {
                        "field": "state.role",
                        "label": "Path role",
                        "value_format": "text",
                    },
                    {
                        "field": "state.encapsulation",
                        "label": "Encapsulation",
                        "value_format": "text",
                    },
                ],
                "default_selected": True,
                "include_absent": False,
                "default_expanded_depth": 2,
                "max_roots": 100,
                "max_children_per_node": 8,
                "plugin_defined": True,
            },
            {
                "view_id": "interface-neighbor-bundles",
                "label": "Interface neighbors",
                "description": (
                    "Each plug-in-declared Virtual Interface is followed by its "
                    "time-valid neighbor resources. Peer identity, reachability, "
                    "and calculation details are supplied by the plug-in."
                ),
                "root_kinds": ["VIRTUAL_INTERFACE"],
                "levels": [
                    {
                        "label": "Discovered neighbor",
                        "relation_types": ["has_neighbor"],
                        "target_kinds": ["NEIGHBOR"],
                        "direction": "outgoing",
                    }
                ],
                "columns": [
                    {
                        "field": "state.member_interface",
                        "label": "Member interface",
                        "value_format": "text",
                    },
                    {
                        "field": "state.protocol",
                        "label": "Protocol",
                        "value_format": "text",
                    },
                    {
                        "field": "state.peer_name",
                        "label": "Peer",
                        "value_format": "text",
                    },
                    {
                        "field": "state.peer_address",
                        "label": "Peer address",
                        "value_format": "text",
                    },
                    {
                        "field": "state.reachability",
                        "label": "Reachability",
                        "value_format": "status",
                    },
                    {
                        "field": "state.resolution_basis",
                        "label": "How calculated",
                        "value_format": "text",
                    },
                ],
                "default_selected": False,
                "include_absent": False,
                "default_expanded_depth": 1,
                "max_roots": 100,
                "max_children_per_node": 4,
                "plugin_defined": True,
            },
        ],
    }


def _walkthrough(
    event_count: int,
    layout: ScaleLayout,
) -> dict[str, object]:
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
                        "dte_next_hop": _final_churn_target(
                            event_count,
                            layout,
                            index,
                        ),
                    },
                ],
            }
        )
    return {
        "scenario_id": SCENARIO_ID,
        "initial_focus_resource_id": (
            services[0]["resource_ids"]["etg"] if services else None
        ),
        "purpose": "Review dependency changes for representative services without opening the full event and resource streams.",
        "services": services,
    }


def _scenario_metadata(
    event_count: int,
    layout: ScaleLayout,
) -> dict[str, object]:
    phase_counts = _phase_event_counts(event_count)
    churn_successes = _churn_success_count(event_count, layout)
    churn_failures = phase_counts["next_hop_churn"] - churn_successes
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
            "restored in bulk, then subjected to repeated distinct DTE next-hop "
            "changes. Surplus phase events advance plugin-defined state generations."
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
            "post_restore_next_hop_changes": churn_successes,
            "failed_next_hop_changes": churn_failures,
            "state_change_events": event_count - churn_failures,
            "relationship_mutations": (
                layout.multi_home_service_count * 12
                + min(layout.es_count, layout.vif_count) * 2
                + churn_successes * 2
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
            f"- {RELATIONSHIP_MUTATIONS_MEMBER_NAME}: explicit remove/add operations for dependency changes.",
            f"- {HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME}: a separate high-fan-out stress stream.",
            "- scenario.json: phase times, counts, and expected semantic changes.",
            "- walkthrough.json: two representative services across every phase.",
            (
                "- plugin-schema.json: plugin-owned kinds, relationships, "
                "dashboards, lane presets, consistency rules, review prompts, "
                "and explicit route/topology capability availability."
            ),
            (
                "- the unified demo generator embeds this directory below "
                "normalized-scale/ in each node pack."
            ),
            "",
            "Start with walkthrough.json, then search events.jsonl for its service IDs.",
            "The full files are intentionally line-oriented so plugins can stream them.",
            (
                "The scale plug-in intentionally omits route resolution and an "
                "underlay projection because this corpus has no route, subnet, "
                "physical-interface, or link-status evidence."
            ),
            (
                "The package-level generator creates the node pack and outer "
                "multi-node assembly."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def generate_scale_tree(
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
        _resource_lines(event_count, layout),
    )
    relationship_lines, relationship_sha = _write_lines(
        output / "relationships.jsonl",
        _relationship_lines(event_count, layout),
    )
    high_fanout_lines, high_fanout_sha = _write_lines(
        output / HIGH_FANOUT_RELATIONSHIPS_MEMBER_NAME,
        _high_fanout_relationship_lines(resource_count, layout),
    )
    mutation_lines, mutation_sha = _write_lines(
        output / RELATIONSHIP_MUTATIONS_MEMBER_NAME,
        _relationship_mutation_lines(event_count, layout),
    )
    scenario_sha = _write_json(output / "scenario.json", scenario)
    plugin_schema = _plugin_schema()
    GENERATED_PROJECTION_POLICY.validate_generated_schema_template(
        plugin_schema
    )
    schema_sha = _write_json(output / "plugin-schema.json", plugin_schema)
    walkthrough_sha = _write_json(
        output / "walkthrough.json",
        _walkthrough(event_count, layout),
    )
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
    manifest_path = output / MANIFEST_MEMBER_NAME
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest_path


__all__ = [
    "BASE_TIME_NS",
    "generate_scale_tree",
]
