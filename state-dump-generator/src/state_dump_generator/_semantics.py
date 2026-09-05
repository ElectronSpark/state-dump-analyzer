"""Generator-owned event and propagation rules, independent of analyzer code.

The model uses these rules for validation and capture horizons; simulation and
the editor's server-authoritative preview use the same target/timing decisions.
The small classification vocabulary is also loaded by the browser.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

EVENT_SEMANTICS: dict[str, Any] = json.loads(
    Path(__file__)
    .with_name("web")
    .joinpath("semantics.json")
    .read_text(encoding="utf-8")
)


def integer(value: Any, label: str, *, minimum: int | None = 0) -> int:
    if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()):
        raise ValueError(f"{label} must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"{label} must be an integer") from error
    if minimum is not None and result < minimum:
        raise ValueError(f"{label} must be greater than or equal to {minimum}")
    return result


def event_is_physical(event: Mapping[str, Any]) -> bool:
    kind = str(event.get("kind", "")).casefold().replace("_", "-")
    target_type = str(event.get("target_type", "")).casefold().replace("_", "-")
    return (
        event.get("scope") == "physical"
        or kind in EVENT_SEMANTICS["physical_kinds"]
        or target_type in EVENT_SEMANTICS["physical_target_types"]
    )


def event_updates_snapshot(event: Mapping[str, Any]) -> bool:
    kind = str(event.get("kind", "status")).casefold().replace("_", "-")
    return bool(
        event.get(
            "update_snapshot",
            event.get("update_final_state", kind not in EVENT_SEMANTICS["log_only_kinds"]),
        )
    )


def event_target_resource(event: Mapping[str, Any]) -> str:
    return str(
        event.get("resource_id", event.get("subject", event.get("target_id", "event")))
    )


def propagation_mode(event: Mapping[str, Any]) -> str:
    propagation = event.get("propagation", {})
    default = "manual" if event_is_physical(event) else "best-effort"
    return str(propagation.get("mode", default)).casefold().replace("_", "-")


def propagation_target_ids(
    media: Sequence[Mapping[str, Any]],
    event: Mapping[str, Any],
    dump_node_ids: Sequence[str] | frozenset[str],
) -> tuple[str, ...]:
    propagation = event.get("propagation", {})
    if not isinstance(propagation, Mapping) or not propagation:
        return ()
    if propagation.get("materialized") is True or propagation.get("generated") is True:
        return ()
    if propagation_mode(event) in EVENT_SEMANTICS["disabled_propagation_modes"]:
        return ()
    physical = event_is_physical(event)
    eligible = frozenset(dump_node_ids)
    explicit = propagation.get("targets", propagation.get("target_node_ids"))
    if isinstance(explicit, Sequence) and not isinstance(explicit, (str, bytes)):
        candidates = [str(item) for item in explicit]
    else:
        target_mode = str(
            propagation.get("target_mode", propagation.get("targets_mode", "neighbors"))
        )
        target_mode = target_mode.casefold().replace("_", "-")
        if target_mode in {"all", "all-nodes"}:
            candidates = sorted(eligible)
        elif target_mode == "selected":
            candidates = []
        elif physical:
            medium_id = str(
                event.get("medium_id", event.get("link_id", event.get("target_id", "")))
            )
            medium = next(
                (item for item in media if str(item["medium_id"]) == medium_id), None
            )
            candidates = (
                [str(item["node_id"]) for item in medium.get("attachments", [])]
                if medium
                else []
            )
        else:
            source = str(event.get("node_id", ""))
            neighbors: set[str] = set()
            for medium in media:
                participants = {
                    str(item["node_id"]) for item in medium.get("attachments", [])
                }
                if source in participants:
                    neighbors.update(participants)
            candidates = sorted(neighbors)
    source = str(event.get("node_id", ""))
    return tuple(
        node_id
        for node_id in dict.fromkeys(candidates)
        if node_id in eligible and (physical or node_id != source)
    )


def _timing(propagation: Mapping[str, Any]) -> tuple[int, int]:
    if "delay_ns" in propagation or "jitter_ns" in propagation:
        return (
            integer(propagation.get("delay_ns", 0), "propagation.delay_ns"),
            integer(propagation.get("jitter_ns", 0), "propagation.jitter_ns"),
        )
    return (
        integer(
            propagation.get("delay_ms", propagation.get("base_delay_ms", 0)),
            "propagation.delay_ms",
        )
        * 1_000_000,
        integer(propagation.get("jitter_ms", 0), "propagation.jitter_ms") * 1_000_000,
    )


def _cadence_delay(propagation: Mapping[str, Any], ordinal: int) -> tuple[int, int]:
    delay, jitter = _timing(propagation)
    cadence = str(propagation.get("cadence", "parallel")).casefold()
    if cadence == "serial":
        delay += ordinal * max(delay, 1_000_000)
    elif cadence == "waves":
        delay += (ordinal // 2) * max(delay // 2, 1_000_000)
    elif cadence != "parallel":
        raise ValueError(f"unsupported propagation cadence {cadence!r}")
    return delay, jitter


def propagation_horizon_ns(value: Any, *, target_count: int) -> int:
    if not isinstance(value, Mapping):
        return 0
    delay, jitter = _cadence_delay(value, max(0, target_count - 1))
    return delay + jitter if target_count > 0 else 0


def _stable_unit_interval(seed: int, *parts: str) -> float:
    digest = hashlib.sha256(str(seed).encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return int.from_bytes(digest.digest()[:8], "big") / float(2**64 - 1)


def delay_ns(seed: int, event: Mapping[str, Any], node_id: str, ordinal: int) -> int:
    delay, jitter = _cadence_delay(event.get("propagation", {}), ordinal)
    if not jitter:
        return delay
    unit = _stable_unit_interval(seed, str(event["event_id"]), node_id, str(ordinal))
    return max(0, delay + round((unit * 2.0 - 1.0) * jitter))


def observation_outcome(
    seed: int, event: Mapping[str, Any], node_id: str, ordinal: int
) -> str:
    if propagation_mode(event) == "failed":
        return "failed"
    propagation = event.get("propagation", {})
    outcomes = propagation.get("outcomes", {})
    intended = (
        outcomes[node_id]
        if isinstance(outcomes, Mapping) and node_id in outcomes
        else propagation.get(
            "outcome",
            propagation.get("intended_outcome", event.get("outcome", "success")),
        )
    )
    intended = str(intended).casefold()
    if intended == "partial":
        return (
            "success"
            if _stable_unit_interval(
                seed, str(event["event_id"]), node_id, str(ordinal), "partial"
            )
            >= 0.5
            else "stale"
        )
    if intended in EVENT_SEMANTICS["failed_outcomes"]:
        return "failed"
    if intended in EVENT_SEMANTICS["successful_outcomes"]:
        return "success"
    return intended
