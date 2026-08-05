"""Shared application-wire parsing and projection for private analysis.

This module is deliberately independent of HTTP and command-line adapters.
It admits only caller-owned request intent, projects only detached application
views, and renders terminal outcomes through the display-safe text boundary.
Transport adapters translate the two closed error classes into their own
status/exit vocabulary.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Final

from .private_analysis import (
    MAX_PRIVATE_ANALYSIS_REVISIONS,
    EvidenceScope,
    PrivateAnalysisClockMode,
    PrivateAnalysisLimits,
    PrivateAnalysisTaskKind,
    private_analysis_outcome_dict,
)
from .private_analysis_execution import PrivateAnalysisRegisteredRunner
from .private_analysis_service import (
    PrivateAnalysisRequestSpec,
    PrivateAnalysisRunReport,
    PrivateAnalysisRunView,
)
from .public_text import escape_unsafe_display_text
from .value_core import (
    MAX_JSON_SAFE_INTEGER,
    CanonicalIntegerError,
    CanonicalIntegerErrorReason,
    parse_canonical_decimal_integer,
)

PRIVATE_ANALYSIS_DISPLAY_CONTRACT: Final = (
    "router_dump_analyzer.private_analysis.display.v1"
)
MAX_PRIVATE_ANALYSIS_DISPLAY_BYTES: Final = 64 * 1024 * 1024

_MAX_SIGNED_64: Final = (1 << 63) - 1
_MIN_SIGNED_64: Final = -(1 << 63)
_REQUEST_FIELDS: Final = frozenset(
    {"revision_ids", "runner", "task_kind", "query", "clock", "limits"}
)
_RUNNER_FIELDS: Final = frozenset({"runner_id", "runner_version"})
_CLOCK_FIELDS: Final = frozenset({"mode", "selected_time_ns"})
_LIMIT_FIELDS: Final = frozenset(
    {
        "max_evidence_items",
        "max_evidence_bytes",
        "max_tool_calls",
        "max_output_bytes",
        "max_claims",
        "max_proposals",
        "deadline_ms",
    }
)


class PrivateAnalysisApplicationWireRequestError(ValueError):
    """Closed caller-intent admission failure with display-safe detail."""

    def __init__(self, detail: str) -> None:
        if type(detail) is not str or not detail:
            raise TypeError("private-analysis wire error detail must be text")
        super().__init__(detail)
        self.detail = detail


class PrivateAnalysisApplicationWireLimitError(RuntimeError):
    """The bounded application projection cannot be represented on the wire."""

    def __init__(self) -> None:
        super().__init__("private-analysis display projection exceeds its limit")


def _closed_object(
    value: object,
    label: str,
    *,
    allowed: frozenset[str],
    required: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if type(value) is not dict:
        raise PrivateAnalysisApplicationWireRequestError(
            f"{label} must be an object"
        )
    selected = value
    if any(type(key) is not str for key in selected):
        raise PrivateAnalysisApplicationWireRequestError(
            f"{label} has an invalid field set"
        )
    unknown = set(selected).difference(allowed)
    missing = required.difference(selected)
    if unknown or missing:
        raise PrivateAnalysisApplicationWireRequestError(
            f"{label} has an invalid field set"
        )
    return selected


def _required_text(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if type(value) is not str or not value:
        raise PrivateAnalysisApplicationWireRequestError(
            f"{field} must be a non-empty string"
        )
    return value


def _canonical_integer(
    value: object,
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    try:
        return parse_canonical_decimal_integer(
            value,
            field,
            minimum=minimum,
            maximum=maximum,
        )
    except CanonicalIntegerError as error:
        detail = (
            f"{field} must be a canonical decimal integer"
            if error.reason is CanonicalIntegerErrorReason.GRAMMAR
            else str(error)
        )
        raise PrivateAnalysisApplicationWireRequestError(detail) from error


def _parse_limits(value: object) -> PrivateAnalysisLimits:
    payload = _closed_object(value, "limits", allowed=_LIMIT_FIELDS)
    defaults = PrivateAnalysisLimits()
    minima = {
        "max_evidence_items": 1,
        "max_evidence_bytes": 1,
        "max_tool_calls": 0,
        "max_output_bytes": 1,
        "max_claims": 1,
        "max_proposals": 0,
        "deadline_ms": 1,
    }
    selected = {
        field_name: (
            getattr(defaults, field_name)
            if field_name not in payload
            else _canonical_integer(
                payload[field_name],
                field_name,
                minimum=minima[field_name],
                maximum=MAX_JSON_SAFE_INTEGER,
            )
        )
        for field_name in _LIMIT_FIELDS
    }
    try:
        return PrivateAnalysisLimits(**selected)
    except (TypeError, ValueError) as error:
        raise PrivateAnalysisApplicationWireRequestError(
            "private-analysis limits are invalid"
        ) from error


def parse_private_analysis_request_spec(
    scope: EvidenceScope,
    payload: object,
) -> PrivateAnalysisRequestSpec:
    """Parse one strict, closed caller-intent object into an application spec."""

    body = _closed_object(
        payload,
        "private-analysis request",
        allowed=_REQUEST_FIELDS,
        required=frozenset(
            {"revision_ids", "runner", "task_kind", "query", "clock"}
        ),
    )
    revision_values = body.get("revision_ids")
    if (
        type(revision_values) is not list
        or not 1 <= len(revision_values) <= MAX_PRIVATE_ANALYSIS_REVISIONS
        or any(type(value) is not str for value in revision_values)
        or len(set(revision_values)) != len(revision_values)
    ):
        raise PrivateAnalysisApplicationWireRequestError(
            "revision_ids must contain 1 to 128 unique strings"
        )
    runner = _closed_object(
        body.get("runner"),
        "runner",
        allowed=_RUNNER_FIELDS,
        required=_RUNNER_FIELDS,
    )
    clock = _closed_object(
        body.get("clock"),
        "clock",
        allowed=_CLOCK_FIELDS,
        required=frozenset({"mode"}),
    )
    try:
        clock_mode = PrivateAnalysisClockMode(_required_text(clock, "mode"))
        task_kind = PrivateAnalysisTaskKind(_required_text(body, "task_kind"))
    except PrivateAnalysisApplicationWireRequestError:
        raise
    except ValueError as error:
        raise PrivateAnalysisApplicationWireRequestError(
            "private-analysis request vocabulary is invalid"
        ) from error
    selected_time_wire = clock.get("selected_time_ns")
    if selected_time_wire is None:
        selected_time_ns = None
    else:
        if type(selected_time_wire) is not str:
            raise PrivateAnalysisApplicationWireRequestError(
                "selected_time_ns must be a canonical decimal string"
            )
        selected_time_ns = _canonical_integer(
            selected_time_wire,
            "selected_time_ns",
            minimum=(
                0
                if clock_mode is PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS
                else _MIN_SIGNED_64
            ),
            maximum=_MAX_SIGNED_64,
        )
    try:
        return PrivateAnalysisRequestSpec(
            scope=scope,
            revision_ids=tuple(sorted(revision_values)),
            runner_id=_required_text(runner, "runner_id"),
            runner_version=_required_text(runner, "runner_version"),
            task_kind=task_kind,
            query=_required_text(body, "query"),
            clock_mode=clock_mode,
            selected_time_ns=selected_time_ns,
            limits=_parse_limits(body.get("limits", {})),
        )
    except PrivateAnalysisApplicationWireRequestError:
        raise
    except (TypeError, ValueError) as error:
        raise PrivateAnalysisApplicationWireRequestError(
            "private-analysis request is invalid"
        ) from error


def private_analysis_runner_to_wire(
    value: PrivateAnalysisRegisteredRunner,
) -> dict[str, Any]:
    """Project one detached configured-runner identity."""

    if type(value) is not PrivateAnalysisRegisteredRunner:
        raise TypeError("private-analysis runner projection is invalid")
    selection = value.selection
    return {
        "runner_id": selection.runner_id,
        "runner_version": selection.runner_version,
        "transport": selection.transport.value,
        "configuration_digest": selection.configuration_digest,
        "instruction_profile_digest": value.instruction_profile_digest,
    }


def private_analysis_run_to_wire(value: PrivateAnalysisRunView) -> dict[str, Any]:
    """Project one payload-free durable run view with lossless integers."""

    if type(value) is not PrivateAnalysisRunView:
        raise TypeError("private-analysis run projection is invalid")
    return {
        "scope": {
            "tenant_id": value.scope.tenant_id,
            "project_id": value.scope.project_id,
            "workspace_id": value.scope.workspace_id,
        },
        "run_id": value.run_id,
        "state": value.state.value,
        "terminal": value.state.is_terminal,
        "version": str(value.version),
        "request_digest": value.request_digest,
        "task_kind": value.task_kind.value,
        "revision_ids": list(value.revision_ids),
        "node_ids": list(value.node_ids),
        "runner": {
            "runner_id": value.runner.runner_id,
            "runner_version": value.runner.runner_version,
            "transport": value.runner.transport.value,
            "configuration_digest": value.runner.configuration_digest,
        },
        "workspace_policy_digest": value.workspace_policy_digest,
        "instruction_profile_digest": value.instruction_profile_digest,
        "tool_catalog_digest": value.tool_catalog_digest,
        "clock": {
            "mode": value.clock_mode.value,
            "selected_time_ns": (
                None if value.selected_time_ns is None else str(value.selected_time_ns)
            ),
        },
        "limits": {
            "max_evidence_items": value.limits.max_evidence_items,
            "max_evidence_bytes": value.limits.max_evidence_bytes,
            "max_tool_calls": value.limits.max_tool_calls,
            "max_output_bytes": value.limits.max_output_bytes,
            "max_claims": value.limits.max_claims,
            "max_proposals": value.limits.max_proposals,
            "deadline_ms": value.limits.deadline_ms,
        },
        "evidence_ledger_digest": value.evidence_ledger_digest,
        "disclosed_reference_count": value.disclosed_reference_count,
        "budget": {
            "max_tool_calls": value.budget_state.max_tool_calls,
            "tool_calls_consumed": value.budget_state.tool_calls_consumed,
            "max_evidence_items": value.budget_state.max_evidence_items,
            "evidence_items_disclosed": value.budget_state.evidence_items_disclosed,
            "max_evidence_bytes": value.budget_state.max_evidence_bytes,
            "evidence_bytes_disclosed": value.budget_state.evidence_bytes_disclosed,
        },
        "outcome_digest": value.outcome_digest,
        "created_at_ns": str(value.created_at_ns),
        "updated_at_ns": str(value.updated_at_ns),
        "completed_at_ns": (
            None if value.completed_at_ns is None else str(value.completed_at_ns)
        ),
    }


def private_analysis_display_value(value: Any) -> Any:
    """Recursively escape unsafe display text without changing scalar meaning."""

    if type(value) is str:
        return escape_unsafe_display_text(value, make_escapes_unambiguous=True)
    if isinstance(value, dict):
        return {
            escape_unsafe_display_text(
                str(key),
                make_escapes_unambiguous=True,
            ): private_analysis_display_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [private_analysis_display_value(item) for item in value]
    return value


def private_analysis_report_to_wire(
    value: PrivateAnalysisRunReport,
) -> dict[str, Any]:
    """Project a terminal report and enforce the 64 MiB display boundary."""

    if type(value) is not PrivateAnalysisRunReport:
        raise TypeError("private-analysis report projection is invalid")
    result = {
        "display_contract": PRIVATE_ANALYSIS_DISPLAY_CONTRACT,
        "run": private_analysis_run_to_wire(value.run),
        "query": private_analysis_display_value(value.query),
        "outcome": private_analysis_display_value(
            private_analysis_outcome_dict(value.outcome)
        ),
    }
    serialized = json.dumps(
        result,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(serialized) > MAX_PRIVATE_ANALYSIS_DISPLAY_BYTES:
        raise PrivateAnalysisApplicationWireLimitError()
    return result


__all__ = [
    "MAX_PRIVATE_ANALYSIS_DISPLAY_BYTES",
    "PRIVATE_ANALYSIS_DISPLAY_CONTRACT",
    "PrivateAnalysisApplicationWireLimitError",
    "PrivateAnalysisApplicationWireRequestError",
    "parse_private_analysis_request_spec",
    "private_analysis_display_value",
    "private_analysis_report_to_wire",
    "private_analysis_run_to_wire",
    "private_analysis_runner_to_wire",
]
