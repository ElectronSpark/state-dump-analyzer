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
    PrivateAnalysisCapabilities,
    PrivateAnalysisCitedEvidenceReference,
    PrivateAnalysisLifecycleAction,
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
PRIVATE_ANALYSIS_CAPABILITIES_CONTRACT: Final = (
    "router_dump_analyzer.private_analysis.capabilities.v1"
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

_TASK_KIND_DESCRIPTORS: Final = {
    PrivateAnalysisTaskKind.CROSS_NODE_CORROBORATION: (
        "Cross-node corroboration",
        "Corroborate disclosed evidence across selected nodes and revisions.",
    ),
    PrivateAnalysisTaskKind.GENERAL_EVIDENCE_REVIEW: (
        "General evidence review",
        "Review the disclosed evidence selected for this private run.",
    ),
    PrivateAnalysisTaskKind.LTTNG_ANALYSIS: (
        "LTTng analysis",
        "Analyze disclosed LTTng events and their relationships.",
    ),
    PrivateAnalysisTaskKind.RESOURCE_CORRELATION: (
        "Resource correlation",
        "Correlate disclosed resources across selected revisions.",
    ),
    PrivateAnalysisTaskKind.ROUTE_TRACE_ANALYSIS: (
        "Route trace analysis",
        "Analyze disclosed route and trace evidence.",
    ),
}
_TRANSPORT_DESCRIPTORS: Final = {
    "in_process": (
        "In-process",
        "Use a deployment-configured private runner in the server process.",
    ),
    "local_subprocess": (
        "Local subprocess",
        "Use a deployment-configured private runner in a local child process.",
    ),
}
_STATE_DESCRIPTORS: Final = {
    "queued": ("Queued", "The admitted run is waiting to execute."),
    "running": ("Running", "The private runner is executing the run."),
    "cancel_requested": (
        "Cancellation requested",
        "Cancellation is requested for an active run.",
    ),
    "completed": ("Completed", "The run has a terminal report."),
    "cancelled": ("Cancelled", "The run ended by cancellation."),
}
_ACTION_DESCRIPTORS: Final = {
    PrivateAnalysisLifecycleAction.CREATE: (
        "Create run",
        "Admit a new workspace-scoped private-analysis run.",
        "POST",
        "runs",
        False,
        (),
    ),
    PrivateAnalysisLifecycleAction.LIST: (
        "List runs",
        "List durable private-analysis runs in this workspace.",
        "GET",
        "runs",
        False,
        (),
    ),
    PrivateAnalysisLifecycleAction.GET: (
        "Get run",
        "Read one payload-free durable run view.",
        "GET",
        "run",
        False,
        ("queued", "running", "cancel_requested", "completed", "cancelled"),
    ),
    PrivateAnalysisLifecycleAction.EXECUTE: (
        "Execute run",
        "Execute one admitted run with its current version precondition.",
        "POST",
        "run_execute",
        True,
        ("queued",),
    ),
    PrivateAnalysisLifecycleAction.CANCEL: (
        "Cancel run",
        "Request cancellation with the current version precondition.",
        "POST",
        "run_cancel",
        True,
        ("queued", "running", "cancel_requested", "cancelled"),
    ),
    PrivateAnalysisLifecycleAction.REPORT: (
        "Get report",
        "Read a terminal advisory report and its cited evidence metadata.",
        "GET",
        "run_report",
        False,
        ("completed", "cancelled"),
    ),
}


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


def private_analysis_capabilities_to_wire(
    value: PrivateAnalysisCapabilities,
) -> dict[str, Any]:
    """Project the closed, workspace-scoped browser workflow inventory."""

    if type(value) is not PrivateAnalysisCapabilities:
        raise TypeError("private-analysis capabilities projection is invalid")
    limits = value.request_limit_ceilings
    limit_values = {
        "deadline_ms": (
            "Deadline",
            "milliseconds",
            1,
            limits.deadline_ms,
        ),
        "max_claims": ("Claims", "claims", 1, limits.max_claims),
        "max_evidence_bytes": (
            "Evidence bytes",
            "bytes",
            1,
            limits.max_evidence_bytes,
        ),
        "max_evidence_items": (
            "Evidence items",
            "items",
            1,
            limits.max_evidence_items,
        ),
        "max_list_runs": (
            "Listed runs",
            "runs",
            1,
            value.max_list_runs,
        ),
        "max_output_bytes": (
            "Output bytes",
            "bytes",
            1,
            limits.max_output_bytes,
        ),
        "max_proposals": (
            "Proposals",
            "proposals",
            0,
            limits.max_proposals,
        ),
        "max_revisions": (
            "Selected revisions",
            "revisions",
            1,
            value.max_revisions,
        ),
        "max_tool_calls": (
            "Tool calls",
            "calls",
            0,
            limits.max_tool_calls,
        ),
    }
    return {
        "contract": PRIVATE_ANALYSIS_CAPABILITIES_CONTRACT,
        "scope": {
            "tenant_id": value.scope.tenant_id,
            "project_id": value.scope.project_id,
            "workspace_id": value.scope.workspace_id,
        },
        "enabled": value.enabled,
        "capabilities": [
            {
                "id": item.value,
                "label": _TASK_KIND_DESCRIPTORS[item][0],
                "description": _TASK_KIND_DESCRIPTORS[item][1],
            }
            for item in value.task_kinds
        ],
        "limits": [
            {
                "id": identifier,
                "label": descriptor[0],
                "unit": descriptor[1],
                "minimum": descriptor[2],
                "maximum": descriptor[3],
            }
            for identifier, descriptor in sorted(limit_values.items())
        ],
        "transports": [
            {
                "id": item.value,
                "label": _TRANSPORT_DESCRIPTORS[item.value][0],
                "description": _TRANSPORT_DESCRIPTORS[item.value][1],
            }
            for item in value.transports
        ],
        "states": [
            {
                "id": item.value,
                "label": _STATE_DESCRIPTORS[item.value][0],
                "description": _STATE_DESCRIPTORS[item.value][1],
                "terminal": item.is_terminal,
            }
            for item in value.states
        ],
        "actions": [
            {
                "id": item.value,
                "label": _ACTION_DESCRIPTORS[item][0],
                "description": _ACTION_DESCRIPTORS[item][1],
                "method": _ACTION_DESCRIPTORS[item][2],
                "resource": _ACTION_DESCRIPTORS[item][3],
                "requires_etag": _ACTION_DESCRIPTORS[item][4],
                "eligible_states": list(_ACTION_DESCRIPTORS[item][5]),
            }
            for item in value.actions
        ],
    }


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
        "evidence_service_digest": value.evidence_service_digest,
    }


def private_analysis_cited_evidence_to_wire(
    value: PrivateAnalysisCitedEvidenceReference,
) -> dict[str, Any]:
    """Project only display-safe identity metadata for one cited reference."""

    if type(value) is not PrivateAnalysisCitedEvidenceReference:
        raise TypeError("private-analysis cited evidence projection is invalid")
    producer = value.producer
    plugin_binding = (
        None
        if producer.plugin_instance_id is None
        else {
            "instance_id": producer.plugin_instance_id,
            "capability": producer.plugin_capability,
            "role": producer.plugin_role,
        }
    )
    time_range = value.time_range
    return {
        "reference_digest": value.reference_digest,
        "revision": {
            "revision_id": value.revision_id,
            "node_id": value.node_id,
        },
        "producer": {
            "authority": producer.authority.value,
            "producer_id": producer.producer_id,
            "plugin_binding": plugin_binding,
        },
        "kind": value.kind.value,
        "subject_kind": value.subject_kind,
        "evidence_class": value.evidence_class.value,
        "payload_schema": value.payload_schema,
        "fact_provenance": value.fact_provenance.value,
        "time_range": {
            "basis": time_range.basis.value,
            "start_ns": (
                None if time_range.start_ns is None else str(time_range.start_ns)
            ),
            "end_ns": None if time_range.end_ns is None else str(time_range.end_ns),
            "uncertainty_ns": (
                None
                if time_range.uncertainty_ns is None
                else str(time_range.uncertainty_ns)
            ),
            "clock_domain": time_range.clock_domain,
        },
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
        "cleanup_pending": value.cleanup_pending,
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
        "evidence_service_digest": value.evidence_service_digest,
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
        "evidence_references": private_analysis_display_value(
            [
                private_analysis_cited_evidence_to_wire(reference)
                for reference in value.evidence_references
            ]
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
    "PRIVATE_ANALYSIS_CAPABILITIES_CONTRACT",
    "PRIVATE_ANALYSIS_DISPLAY_CONTRACT",
    "PrivateAnalysisApplicationWireLimitError",
    "PrivateAnalysisApplicationWireRequestError",
    "parse_private_analysis_request_spec",
    "private_analysis_capabilities_to_wire",
    "private_analysis_cited_evidence_to_wire",
    "private_analysis_display_value",
    "private_analysis_report_to_wire",
    "private_analysis_run_to_wire",
    "private_analysis_runner_to_wire",
]
