"""Strict external-style consumer of the standalone generator API."""

from __future__ import annotations

from typing import Any, Mapping

from state_dump_generator import (
    build_node_dump_bytes,
    compile_scenario,
    reconstruct_scenario,
)


def exercise_public_surface(document: Mapping[str, Any]) -> None:
    plans: dict[str, dict[str, Any]] = compile_scenario(document)
    reconstruction: dict[str, Any] = reconstruct_scenario(
        document,
        at_time_ns="capture",
    )
    first_plan = next(iter(plans.values()))
    node_dump: bytes = build_node_dump_bytes(first_plan)
    tuple((reconstruction, node_dump))
