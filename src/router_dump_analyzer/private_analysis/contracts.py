"""Typed, bounded contracts for advisory private-model analysis.

These values define what an operator may request and what an approved local
runner may return.  They do not retrieve evidence, authorize a caller, invoke
a runner, or persist a run.  Parsed model output remains untrusted until
``validate_private_analysis_result`` binds every citation to the exact
disclosed evidence ledger for the request.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from json import JSONDecodeError, loads
from typing import Any, Final

from ..canonical import strict_canonical_json, strict_canonical_json_sha256
from ..contract_validation import validate_bounded_json_value
from ..public_text import (
    contains_filesystem_identity_path,
    contains_unsafe_identifier_text,
    has_visible_identity_anchor,
)
from ..value_core import MAX_JSON_SAFE_INTEGER
from ._wire import SealedContractValue
from ._wire import bounded_canonical_decimal_integer as _bounded_decimal
from ._wire import bounded_utf8_text as _bounded_utf8_text
from ._wire import exact_contract_version as _contract_version
from ._wire import exact_json_object as _exact_dict
from ._wire import reject_duplicate_json_object_pairs as _reject_duplicate_pairs
from ._wire import strict_string_enum as _enum
from .evidence import (
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
    _revalidated_evidence_reference,
    evidence_revision_binding_dict,
    evidence_revision_binding_from_dict,
    evidence_scope_dict,
    evidence_scope_from_dict,
)
from .policy import PrivateAnalysisContributionKind, PrivateAnalysisTransport

PRIVATE_ANALYSIS_REQUEST_VERSION_V2: Final = (
    "router_dump_analyzer.private_analysis.request.v2"
)
PRIVATE_ANALYSIS_REQUEST_VERSION: Final = (
    "router_dump_analyzer.private_analysis.request.v3"
)
LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST: Final = "sha256:" + "0" * 64
PRIVATE_ANALYSIS_CITATION_VERSION: Final = (
    "router_dump_analyzer.private_analysis.citation.v1"
)
PRIVATE_ANALYSIS_CLAIM_VERSION: Final = "router_dump_analyzer.private_analysis.claim.v1"
PRIVATE_ANALYSIS_PROPOSAL_VERSION: Final = (
    "router_dump_analyzer.private_analysis.proposal.v1"
)
PRIVATE_ANALYSIS_RESULT_VERSION: Final = (
    "router_dump_analyzer.private_analysis.result.v1"
)
PRIVATE_ANALYSIS_ERROR_VERSION: Final = "router_dump_analyzer.private_analysis.error.v1"
PRIVATE_ANALYSIS_OUTCOME_VERSION: Final = (
    "router_dump_analyzer.private_analysis.outcome.v1"
)
MAX_PRIVATE_ANALYSIS_REVISIONS: Final = 128
MAX_PRIVATE_ANALYSIS_QUERY_CHARACTERS: Final = 32_768
MAX_PRIVATE_ANALYSIS_QUERY_BYTES: Final = 131_072
MAX_PRIVATE_ANALYSIS_CLAIM_CHARACTERS: Final = 16_384
MAX_PRIVATE_ANALYSIS_SUMMARY_CHARACTERS: Final[int] = (
    MAX_PRIVATE_ANALYSIS_CLAIM_CHARACTERS
)
MAX_PRIVATE_ANALYSIS_PROPOSAL_TEXT_CHARACTERS: Final = 16_384
MAX_PRIVATE_ANALYSIS_CLAIMS: Final = 512
MAX_PRIVATE_ANALYSIS_PROPOSALS: Final = 256
MAX_PRIVATE_ANALYSIS_CITATIONS_PER_ITEM: Final = 128
MAX_PRIVATE_ANALYSIS_PROPOSAL_PAYLOAD_BYTES: Final[int] = 256 * 1024
MAX_PRIVATE_ANALYSIS_WIRE_BYTES: Final[int] = 8 * 1024 * 1024
MAX_PRIVATE_ANALYSIS_IDENTIFIER_CHARACTERS: Final = 256

_MAX_CITATION_WIRE_UNITS: Final = 4
_MAX_CLAIM_WIRE_UNITS: Final = (
    7 + MAX_PRIVATE_ANALYSIS_CITATIONS_PER_ITEM * _MAX_CITATION_WIRE_UNITS
)
_MAX_PROPOSAL_WIRE_UNITS: Final = (
    12 + MAX_PRIVATE_ANALYSIS_CITATIONS_PER_ITEM * _MAX_CITATION_WIRE_UNITS + 4_096
)
_MAX_RESULT_WIRE_UNITS: Final = (
    7
    + MAX_PRIVATE_ANALYSIS_CLAIMS * _MAX_CLAIM_WIRE_UNITS
    + MAX_PRIVATE_ANALYSIS_PROPOSALS * _MAX_PROPOSAL_WIRE_UNITS
)

_MAX_SIGNED_NS: Final = (1 << 63) - 1
_MIN_SIGNED_NS: Final = -(1 << 63)
_MAX_EVIDENCE_ITEMS: Final = 100_000
_MAX_EVIDENCE_BYTES: Final = 512 * 1024 * 1024
_MAX_TOOL_CALLS: Final = 4_096
_MAX_OUTPUT_BYTES: Final = MAX_PRIVATE_ANALYSIS_WIRE_BYTES
_MAX_DEADLINE_MS: Final = 3_600_000


class PrivateAnalysisTaskKind(StrEnum):
    """Closed high-level intents understood by core orchestration."""

    LTTNG_ANALYSIS = "lttng_analysis"
    RESOURCE_CORRELATION = "resource_correlation"
    CROSS_NODE_CORROBORATION = "cross_node_corroboration"
    ROUTE_TRACE_ANALYSIS = "route_trace_analysis"
    GENERAL_EVIDENCE_REVIEW = "general_evidence_review"


class PrivateAnalysisClockMode(StrEnum):
    """How one request selects a comparable moment across revisions."""

    LATEST_PER_REVISION = "latest_per_revision"
    ABSOLUTE_UNIX_NS = "absolute_unix_ns"
    REVISION_END_RELATIVE_NS = "revision_end_relative_ns"


class PrivateAnalysisClaimSupport(StrEnum):
    """Whether a returned statement is grounded in disclosed evidence."""

    EVIDENCE_SUPPORTED = "evidence_supported"
    UNSUPPORTED_HYPOTHESIS = "unsupported_hypothesis"


class PrivateAnalysisProposalKind(StrEnum):
    """Advisory actions that later stages may validate or promote."""

    EVENT_INTERPRETATION = "event_interpretation"
    EVENT_CORRELATION = "event_correlation"
    RESOURCE_CORRELATION = "resource_correlation"
    IDENTITY_MAPPING = "identity_mapping"
    ROUTE_HYPOTHESIS = "route_hypothesis"
    TRACE_STEERING_RULE = "trace_steering_rule"
    REPORT_ANNOTATION = "report_annotation"


class PrivateAnalysisErrorStage(StrEnum):
    """Closed stages safe to expose without copying a diagnostic."""

    REQUEST_VALIDATION = "request_validation"
    AUTHORIZATION = "authorization"
    DISCLOSURE = "disclosure"
    EVIDENCE = "evidence"
    RUNNER = "runner"
    OUTPUT_VALIDATION = "output_validation"


class PrivateAnalysisErrorCode(StrEnum):
    """Closed, payload-free failure vocabulary."""

    INVALID_REQUEST = "invalid_request"
    POLICY_DENIED = "policy_denied"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    BUDGET_EXCEEDED = "budget_exceeded"
    RUNNER_UNAVAILABLE = "runner_unavailable"
    RUNNER_PROTOCOL_ERROR = "runner_protocol_error"
    RUNNER_FAILED = "runner_failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    INVALID_RESULT = "invalid_result"


class PrivateAnalysisOutcomeKind(StrEnum):
    RESULT = "result"
    ERROR = "error"


_RETRYABLE_ERROR_CODES: Final = frozenset(
    {
        PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE,
        PrivateAnalysisErrorCode.RUNNER_FAILED,
        PrivateAnalysisErrorCode.TIMEOUT,
    }
)
_SAFE_ERROR_MESSAGES: Final = {
    PrivateAnalysisErrorCode.INVALID_REQUEST: "Private analysis request is invalid.",
    PrivateAnalysisErrorCode.POLICY_DENIED: "Private analysis is not allowed.",
    PrivateAnalysisErrorCode.EVIDENCE_UNAVAILABLE: "Required evidence is unavailable.",
    PrivateAnalysisErrorCode.BUDGET_EXCEEDED: "Private analysis budget was exceeded.",
    PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE: "Private analysis runner is unavailable.",
    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR: "Private analysis runner protocol failed.",
    PrivateAnalysisErrorCode.RUNNER_FAILED: "Private analysis runner failed.",
    PrivateAnalysisErrorCode.TIMEOUT: "Private analysis timed out.",
    PrivateAnalysisErrorCode.CANCELLED: "Private analysis was cancelled.",
    PrivateAnalysisErrorCode.INVALID_RESULT: "Private analysis result is invalid.",
}
_ERROR_STAGES: Final = {
    PrivateAnalysisErrorCode.INVALID_REQUEST: frozenset(
        {PrivateAnalysisErrorStage.REQUEST_VALIDATION}
    ),
    PrivateAnalysisErrorCode.POLICY_DENIED: frozenset(
        {
            PrivateAnalysisErrorStage.AUTHORIZATION,
            PrivateAnalysisErrorStage.DISCLOSURE,
        }
    ),
    PrivateAnalysisErrorCode.EVIDENCE_UNAVAILABLE: frozenset(
        {PrivateAnalysisErrorStage.EVIDENCE}
    ),
    PrivateAnalysisErrorCode.BUDGET_EXCEEDED: frozenset(
        {
            PrivateAnalysisErrorStage.EVIDENCE,
            PrivateAnalysisErrorStage.RUNNER,
            PrivateAnalysisErrorStage.OUTPUT_VALIDATION,
        }
    ),
    PrivateAnalysisErrorCode.RUNNER_UNAVAILABLE: frozenset(
        {PrivateAnalysisErrorStage.RUNNER}
    ),
    PrivateAnalysisErrorCode.RUNNER_PROTOCOL_ERROR: frozenset(
        {PrivateAnalysisErrorStage.RUNNER}
    ),
    PrivateAnalysisErrorCode.RUNNER_FAILED: frozenset(
        {PrivateAnalysisErrorStage.RUNNER}
    ),
    PrivateAnalysisErrorCode.TIMEOUT: frozenset({PrivateAnalysisErrorStage.RUNNER}),
    PrivateAnalysisErrorCode.CANCELLED: frozenset({PrivateAnalysisErrorStage.RUNNER}),
    PrivateAnalysisErrorCode.INVALID_RESULT: frozenset(
        {PrivateAnalysisErrorStage.OUTPUT_VALIDATION}
    ),
}


class PrivateAnalysisContractError(ValueError):
    """A parsed or returned private-analysis value violates the v1 contract."""


def _identifier(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_PRIVATE_ANALYSIS_IDENTIFIER_CHARACTERS
        or value != value.strip()
        or contains_filesystem_identity_path(value)
        or contains_unsafe_identifier_text(value)
        or not has_visible_identity_anchor(value)
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{label} must be a safe bounded opaque token")
    return value


def _bare_sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _prefixed_sha256(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 71 or not value.startswith("sha256:"):
        raise ValueError(f"{label} must be a sha256-prefixed lowercase digest")
    _bare_sha256(value[7:], label)
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _bounded_wire_list(
    value: object,
    label: str,
    *,
    maximum_items: int,
) -> list[Any]:
    if type(value) is not list:
        raise TypeError(f"{label} must be a list")
    if len(value) > maximum_items:
        raise ValueError(f"{label} supports at most {maximum_items} items")
    return value


def _bounded_text(
    value: object,
    label: str,
    *,
    maximum_characters: int,
    maximum_bytes: int | None = None,
) -> str:
    if type(value) is not str or not value or len(value) > maximum_characters:
        raise ValueError(f"{label} must contain 1 to {maximum_characters} characters")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain Unicode scalar values") from error
    if maximum_bytes is not None and len(encoded) > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} encoded UTF-8 bytes")
    return value


def _canonical_payload_json(value: object) -> str:
    if type(value) is not dict:
        raise TypeError("proposal payload must be an exact JSON object")
    snapshot = validate_bounded_json_value(
        value,
        "proposal payload",
        maximum_depth=12,
        maximum_container_items=1_024,
        maximum_units=4_096,
        maximum_atom_units=65_536,
        maximum_integer_bits=53,
        exact_types=True,
        allow_exact_tuples=False,
        maximum_encoded_bytes=MAX_PRIVATE_ANALYSIS_PROPOSAL_PAYLOAD_BYTES,
        snapshot=True,
    )
    if type(snapshot) is not dict:
        raise TypeError("proposal payload must be an exact JSON object")

    def visit(item: object) -> None:
        if item is None or type(item) in {bool, str, float}:
            if type(item) is str:
                try:
                    item.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise ValueError(
                        "proposal payload strings require Unicode scalars"
                    ) from error
            return
        if type(item) is int:
            if not -MAX_JSON_SAFE_INTEGER <= item <= MAX_JSON_SAFE_INTEGER:
                raise ValueError(
                    "proposal payload integers must be JSON-safe; use decimal strings"
                )
            return
        if type(item) is list:
            for child in item:
                visit(child)
            return
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError("proposal payload keys must be exact strings")
                visit(key)
                visit(child)
            return
        raise ValueError("proposal payload contains a non-JSON value")

    visit(snapshot)
    encoded = strict_canonical_json(snapshot)
    if len(encoded.encode("utf-8")) > MAX_PRIVATE_ANALYSIS_PROPOSAL_PAYLOAD_BYTES:
        raise ValueError("proposal payload exceeds its encoded byte limit")
    return encoded


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant {value}")


def _load_strict_json(value: str, label: str) -> dict[str, Any]:
    if type(value) is not str:
        raise TypeError(f"{label} JSON must be a string")
    if len(value) > MAX_PRIVATE_ANALYSIS_WIRE_BYTES:
        raise ValueError(f"{label} JSON exceeds its encoded byte limit")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} JSON must contain Unicode scalars") from error
    if len(encoded) > MAX_PRIVATE_ANALYSIS_WIRE_BYTES:
        raise ValueError(f"{label} JSON exceeds its encoded byte limit")
    try:
        parsed = loads(
            value,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, JSONDecodeError, RecursionError) as error:
        raise ValueError(f"{label} is not strict JSON") from error
    if type(parsed) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    return parsed


def _canonical_wire_json(value: dict[str, object], label: str) -> str:
    encoded = strict_canonical_json(value)
    if len(encoded.encode("utf-8")) > MAX_PRIVATE_ANALYSIS_WIRE_BYTES:
        raise ValueError(f"{label} exceeds its encoded byte limit")
    return encoded


def _validate_complete_wire_size(
    payload: dict[str, object],
    *,
    digest_field: str,
    digest: str,
    label: str,
) -> None:
    complete = dict(payload)
    complete[digest_field] = digest
    _canonical_wire_json(complete, label)


def _validate_result_fits_outcome(
    result_payload: dict[str, object],
    result_digest: str,
) -> None:
    result_wire = dict(result_payload)
    result_wire["result_digest"] = result_digest
    outcome_payload: dict[str, object] = {
        "contract_version": PRIVATE_ANALYSIS_OUTCOME_VERSION,
        "kind": PrivateAnalysisOutcomeKind.RESULT.value,
        "result": result_wire,
        "error": None,
    }
    outcome_digest = "sha256:" + strict_canonical_json_sha256(outcome_payload)
    _validate_complete_wire_size(
        outcome_payload,
        digest_field="outcome_digest",
        digest=outcome_digest,
        label="private-analysis result outcome",
    )


_WIRE_DIGEST_PLACEHOLDER: Final = "sha256:" + "0" * 64


def _canonical_component_size(value: dict[str, object]) -> int:
    return len(strict_canonical_json(value).encode("utf-8"))


def _validate_result_wire_budget(
    result: PrivateAnalysisResult,
    *,
    maximum_bytes: int,
    include_outcome_wrapper: bool,
) -> int:
    """Bound an aggregate result before constructing its whole JSON object."""

    payload_skeleton: dict[str, object] = {
        "contract_version": result.contract_version,
        "request_digest": result.request_digest,
        "summary": None,
        "claims": [],
        "proposals": [],
    }
    payload_size = _canonical_component_size(payload_skeleton) - len("null")
    payload_size += _canonical_component_size(
        _private_analysis_claim_dict_unchecked(result.summary)
    )

    digest_member_increment = (
        _canonical_component_size({"result_digest": _WIRE_DIGEST_PLACEHOLDER}) - 1
    )
    outcome_increment = 0
    if include_outcome_wrapper:
        outcome_skeleton: dict[str, object] = {
            "contract_version": PRIVATE_ANALYSIS_OUTCOME_VERSION,
            "kind": PrivateAnalysisOutcomeKind.RESULT.value,
            "result": None,
            "error": None,
            "outcome_digest": _WIRE_DIGEST_PLACEHOLDER,
        }
        outcome_increment = _canonical_component_size(outcome_skeleton) - len("null")
    fixed_overhead = digest_member_increment + outcome_increment

    def require_room() -> None:
        if payload_size + fixed_overhead > maximum_bytes:
            raise ValueError("private-analysis result exceeds its wire byte limit")

    require_room()
    for index, claim in enumerate(result.claims):
        payload_size += _canonical_component_size(
            _private_analysis_claim_dict_unchecked(claim)
        )
        if index:
            payload_size += 1
        require_room()
    for index, proposal in enumerate(result.proposals):
        payload_size += _canonical_component_size(
            _private_analysis_proposal_dict_unchecked(proposal)
        )
        if index:
            payload_size += 1
        require_room()
    return payload_size + digest_member_increment


def _validate_result_input_wire_budget(
    value: dict[str, object],
) -> dict[str, Any]:
    """Return a bounded result snapshot before parsing nested contracts."""

    snapshot = validate_bounded_json_value(
        value,
        "private-analysis result",
        maximum_depth=16,
        maximum_container_items=1_024,
        maximum_units=_MAX_RESULT_WIRE_UNITS,
        maximum_atom_units=65_536,
        maximum_integer_bits=53,
        exact_types=True,
        allow_exact_tuples=False,
        maximum_encoded_bytes=MAX_PRIVATE_ANALYSIS_WIRE_BYTES,
        snapshot=True,
    )
    if type(snapshot) is not dict:
        raise TypeError("private-analysis result must be an exact dictionary")
    return snapshot


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRunnerSelection(SealedContractValue):
    runner_id: str
    runner_version: str
    transport: PrivateAnalysisTransport
    configuration_digest: str

    def __post_init__(self) -> None:
        _identifier(self.runner_id, "runner_id")
        _identifier(self.runner_version, "runner_version")
        if type(self.transport) is not PrivateAnalysisTransport:
            raise TypeError("transport must be PrivateAnalysisTransport")
        _prefixed_sha256(self.configuration_digest, "configuration_digest")


@dataclass(frozen=True, slots=True)
class PrivateAnalysisLimits(SealedContractValue):
    max_evidence_items: int = 10_000
    max_evidence_bytes: int = 64 * 1024 * 1024
    max_tool_calls: int = 256
    max_output_bytes: int = 4 * 1024 * 1024
    max_claims: int = 128
    max_proposals: int = 64
    deadline_ms: int = 300_000

    def __post_init__(self) -> None:
        _integer(self.max_evidence_items, "max_evidence_items", 1, _MAX_EVIDENCE_ITEMS)
        _integer(self.max_evidence_bytes, "max_evidence_bytes", 1, _MAX_EVIDENCE_BYTES)
        _integer(self.max_tool_calls, "max_tool_calls", 0, _MAX_TOOL_CALLS)
        _integer(self.max_output_bytes, "max_output_bytes", 1, _MAX_OUTPUT_BYTES)
        _integer(self.max_claims, "max_claims", 1, MAX_PRIVATE_ANALYSIS_CLAIMS)
        _integer(
            self.max_proposals,
            "max_proposals",
            0,
            MAX_PRIVATE_ANALYSIS_PROPOSALS,
        )
        _integer(self.deadline_ms, "deadline_ms", 1, _MAX_DEADLINE_MS)


def _revision_sort_key(
    value: EvidenceRevisionBinding,
) -> tuple[str, str, str, str]:
    return (
        value.node_id,
        value.revision_id,
        value.fixture_id,
        value.revision_identity_sha256,
    )


def _detached_scope(value: object) -> EvidenceScope:
    if type(value) is not EvidenceScope:
        raise TypeError("scope must be EvidenceScope")
    return EvidenceScope(
        tenant_id=value.tenant_id,
        project_id=value.project_id,
        workspace_id=value.workspace_id,
    )


def _detached_revision(value: object) -> EvidenceRevisionBinding:
    if type(value) is not EvidenceRevisionBinding:
        raise TypeError("revisions must contain EvidenceRevisionBinding values")
    return EvidenceRevisionBinding(
        fixture_id=value.fixture_id,
        fixture_content_sha256=value.fixture_content_sha256,
        node_id=value.node_id,
        revision_id=value.revision_id,
        revision_identity_sha256=value.revision_identity_sha256,
        plan_basis_revision_id=value.plan_basis_revision_id,
        execution_plan_digest=value.execution_plan_digest,
    )


def _detached_runner(value: object) -> PrivateAnalysisRunnerSelection:
    if type(value) is not PrivateAnalysisRunnerSelection:
        raise TypeError("runner must be PrivateAnalysisRunnerSelection")
    return PrivateAnalysisRunnerSelection(
        runner_id=value.runner_id,
        runner_version=value.runner_version,
        transport=value.transport,
        configuration_digest=value.configuration_digest,
    )


def _detached_limits(value: object) -> PrivateAnalysisLimits:
    if type(value) is not PrivateAnalysisLimits:
        raise TypeError("limits must be PrivateAnalysisLimits")
    return PrivateAnalysisLimits(
        max_evidence_items=value.max_evidence_items,
        max_evidence_bytes=value.max_evidence_bytes,
        max_tool_calls=value.max_tool_calls,
        max_output_bytes=value.max_output_bytes,
        max_claims=value.max_claims,
        max_proposals=value.max_proposals,
        deadline_ms=value.deadline_ms,
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisRequest(SealedContractValue):
    scope: EvidenceScope
    revisions: tuple[EvidenceRevisionBinding, ...]
    runner: PrivateAnalysisRunnerSelection
    workspace_policy_digest: str
    instruction_profile_digest: str
    tool_catalog_digest: str
    task_kind: PrivateAnalysisTaskKind
    query: str
    clock_mode: PrivateAnalysisClockMode
    selected_time_ns: int | None
    limits: PrivateAnalysisLimits
    evidence_service_digest: str = LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST
    contract_version: str = PRIVATE_ANALYSIS_REQUEST_VERSION
    request_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.contract_version) is not str:
            raise ValueError("contract_version must be an exact string")
        if self.contract_version not in (
            PRIVATE_ANALYSIS_REQUEST_VERSION_V2,
            PRIVATE_ANALYSIS_REQUEST_VERSION,
        ):
            raise ValueError("unsupported private-analysis request contract version")
        if type(self.scope) is not EvidenceScope:
            raise TypeError("scope must be EvidenceScope")
        if type(self.revisions) is not tuple:
            raise TypeError("revisions must be a tuple")
        if not 1 <= len(self.revisions) <= MAX_PRIVATE_ANALYSIS_REVISIONS:
            raise ValueError("request must bind 1 to 128 revisions")
        if any(type(item) is not EvidenceRevisionBinding for item in self.revisions):
            raise TypeError("revisions must contain EvidenceRevisionBinding values")
        scope = _detached_scope(self.scope)
        revisions = tuple(_detached_revision(item) for item in self.revisions)
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "revisions", revisions)
        if tuple(sorted(revisions, key=_revision_sort_key)) != revisions:
            raise ValueError("revisions must use canonical node/revision order")
        revision_keys = {(item.node_id, item.revision_id) for item in revisions}
        if len(revision_keys) != len(revisions):
            raise ValueError("revisions must be unique")
        runner = _detached_runner(self.runner)
        object.__setattr__(self, "runner", runner)
        _bare_sha256(self.workspace_policy_digest, "workspace_policy_digest")
        _prefixed_sha256(
            self.instruction_profile_digest,
            "instruction_profile_digest",
        )
        _prefixed_sha256(self.tool_catalog_digest, "tool_catalog_digest")
        _prefixed_sha256(
            self.evidence_service_digest,
            "evidence_service_digest",
        )
        if (
            self.contract_version == PRIVATE_ANALYSIS_REQUEST_VERSION_V2
            and self.evidence_service_digest
            != LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST
        ):
            raise ValueError(
                "v2 private-analysis requests cannot carry an evidence-service digest"
            )
        if type(self.task_kind) is not PrivateAnalysisTaskKind:
            raise TypeError("task_kind must be PrivateAnalysisTaskKind")
        _bounded_text(
            self.query,
            "query",
            maximum_characters=MAX_PRIVATE_ANALYSIS_QUERY_CHARACTERS,
            maximum_bytes=MAX_PRIVATE_ANALYSIS_QUERY_BYTES,
        )
        if type(self.clock_mode) is not PrivateAnalysisClockMode:
            raise TypeError("clock_mode must be PrivateAnalysisClockMode")
        if self.clock_mode is PrivateAnalysisClockMode.LATEST_PER_REVISION:
            if self.selected_time_ns is not None:
                raise ValueError("latest-per-revision clock must not carry a time")
        else:
            minimum = (
                0
                if self.clock_mode is PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS
                else _MIN_SIGNED_NS
            )
            _integer(
                self.selected_time_ns,
                "selected_time_ns",
                minimum,
                _MAX_SIGNED_NS,
            )
        limits = _detached_limits(self.limits)
        object.__setattr__(self, "limits", limits)
        if type(self.request_digest) is not str:
            raise TypeError("request_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _private_analysis_request_payload(self)
        )
        if self.request_digest:
            _prefixed_sha256(self.request_digest, "request_digest")
            if self.request_digest != expected:
                raise ValueError("private-analysis request digest does not match")
        else:
            object.__setattr__(self, "request_digest", expected)


@dataclass(frozen=True, slots=True)
class PrivateAnalysisCitation(SealedContractValue):
    evidence_reference_digest: str
    contract_version: str = PRIVATE_ANALYSIS_CITATION_VERSION
    citation_digest: str = ""

    def __post_init__(self) -> None:
        _contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_CITATION_VERSION,
            "private-analysis citation",
        )
        _prefixed_sha256(
            self.evidence_reference_digest,
            "evidence_reference_digest",
        )
        if type(self.citation_digest) is not str:
            raise TypeError("citation_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _private_analysis_citation_payload(self)
        )
        if self.citation_digest:
            _prefixed_sha256(self.citation_digest, "citation_digest")
            if self.citation_digest != expected:
                raise ValueError("private-analysis citation digest does not match")
        else:
            object.__setattr__(self, "citation_digest", expected)


def _validate_citations(
    value: object,
    *,
    required: bool,
) -> tuple[PrivateAnalysisCitation, ...]:
    if type(value) is not tuple:
        raise TypeError("citations must be a tuple")
    citations = value
    if len(citations) > MAX_PRIVATE_ANALYSIS_CITATIONS_PER_ITEM:
        raise ValueError("too many citations")
    if required and not citations:
        raise ValueError("evidence-supported output requires a citation")
    detached: list[PrivateAnalysisCitation] = []
    for item in citations:
        if type(item) is not PrivateAnalysisCitation:
            raise TypeError("citations must contain PrivateAnalysisCitation values")
        detached.append(
            PrivateAnalysisCitation(
                contract_version=item.contract_version,
                evidence_reference_digest=item.evidence_reference_digest,
                citation_digest=item.citation_digest,
            )
        )
    result = tuple(detached)
    digests = tuple(item.evidence_reference_digest for item in result)
    if digests != tuple(sorted(digests)) or len(set(digests)) != len(digests):
        raise ValueError("citations must be unique and canonically ordered")
    return result


@dataclass(frozen=True, slots=True)
class PrivateAnalysisClaim(SealedContractValue):
    claim_id: str
    support: PrivateAnalysisClaimSupport
    text: str
    citations: tuple[PrivateAnalysisCitation, ...]
    contract_version: str = PRIVATE_ANALYSIS_CLAIM_VERSION
    claim_digest: str = ""

    def __post_init__(self) -> None:
        _contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_CLAIM_VERSION,
            "private-analysis claim",
        )
        _identifier(self.claim_id, "claim_id")
        if type(self.support) is not PrivateAnalysisClaimSupport:
            raise TypeError("support must be PrivateAnalysisClaimSupport")
        _bounded_text(
            self.text,
            "claim text",
            maximum_characters=MAX_PRIVATE_ANALYSIS_CLAIM_CHARACTERS,
        )
        citations = _validate_citations(
            self.citations,
            required=self.support is PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
        )
        object.__setattr__(self, "citations", citations)
        if (
            self.support is PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS
            and citations
        ):
            raise ValueError("unsupported hypotheses must not claim evidence support")
        if type(self.claim_digest) is not str:
            raise TypeError("claim_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _private_analysis_claim_payload(self)
        )
        if self.claim_digest:
            _prefixed_sha256(self.claim_digest, "claim_digest")
            if self.claim_digest != expected:
                raise ValueError("private-analysis claim digest does not match")
        else:
            object.__setattr__(self, "claim_digest", expected)


@dataclass(frozen=True, slots=True)
class PrivateAnalysisProposal(SealedContractValue):
    proposal_id: str
    kind: PrivateAnalysisProposalKind
    title: str
    rationale: str
    confidence_basis_points: int
    citations: tuple[PrivateAnalysisCitation, ...]
    payload_schema: str
    payload_json: str
    provenance: PrivateAnalysisContributionKind = (
        PrivateAnalysisContributionKind.ASSISTANT_SUGGESTED
    )
    contract_version: str = PRIVATE_ANALYSIS_PROPOSAL_VERSION
    proposal_digest: str = ""

    def __post_init__(self) -> None:
        _contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_PROPOSAL_VERSION,
            "private-analysis proposal",
        )
        _identifier(self.proposal_id, "proposal_id")
        if type(self.kind) is not PrivateAnalysisProposalKind:
            raise TypeError("kind must be PrivateAnalysisProposalKind")
        _bounded_text(
            self.title,
            "proposal title",
            maximum_characters=512,
        )
        _bounded_text(
            self.rationale,
            "proposal rationale",
            maximum_characters=MAX_PRIVATE_ANALYSIS_PROPOSAL_TEXT_CHARACTERS,
        )
        _integer(
            self.confidence_basis_points,
            "confidence_basis_points",
            0,
            10_000,
        )
        citations = _validate_citations(self.citations, required=True)
        object.__setattr__(self, "citations", citations)
        _identifier(self.payload_schema, "payload_schema")
        if type(self.payload_json) is not str:
            raise TypeError("payload_json must be a string")
        _bounded_utf8_text(
            self.payload_json,
            "proposal payload JSON",
            MAX_PRIVATE_ANALYSIS_PROPOSAL_PAYLOAD_BYTES,
        )
        try:
            payload = loads(
                self.payload_json,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_json_constant,
            )
        except (TypeError, ValueError, JSONDecodeError, RecursionError) as error:
            raise ValueError("proposal payload is not strict JSON") from error
        canonical = _canonical_payload_json(payload)
        if canonical != self.payload_json:
            raise ValueError("proposal payload_json must use exact canonical JSON")
        if self.provenance is not PrivateAnalysisContributionKind.ASSISTANT_SUGGESTED:
            raise ValueError("proposal provenance must be assistant_suggested")
        if type(self.proposal_digest) is not str:
            raise TypeError("proposal_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _private_analysis_proposal_payload(self)
        )
        if self.proposal_digest:
            _prefixed_sha256(self.proposal_digest, "proposal_digest")
            if self.proposal_digest != expected:
                raise ValueError("private-analysis proposal digest does not match")
        else:
            object.__setattr__(self, "proposal_digest", expected)

    @property
    def payload(self) -> dict[str, Any]:
        value = loads(self.payload_json)
        if type(value) is not dict:  # constructor makes this unreachable
            raise ValueError("proposal payload must be an object")
        return value


def _detached_citation(value: object) -> PrivateAnalysisCitation:
    if type(value) is not PrivateAnalysisCitation:
        raise TypeError("value must be PrivateAnalysisCitation")
    return PrivateAnalysisCitation(
        contract_version=value.contract_version,
        evidence_reference_digest=value.evidence_reference_digest,
        citation_digest=value.citation_digest,
    )


def _detached_claim(value: object) -> PrivateAnalysisClaim:
    if type(value) is not PrivateAnalysisClaim:
        raise TypeError("value must be PrivateAnalysisClaim")
    return PrivateAnalysisClaim(
        contract_version=value.contract_version,
        claim_id=value.claim_id,
        support=value.support,
        text=value.text,
        citations=value.citations,
        claim_digest=value.claim_digest,
    )


def _detached_proposal(value: object) -> PrivateAnalysisProposal:
    if type(value) is not PrivateAnalysisProposal:
        raise TypeError("value must be PrivateAnalysisProposal")
    return PrivateAnalysisProposal(
        contract_version=value.contract_version,
        proposal_id=value.proposal_id,
        kind=value.kind,
        title=value.title,
        rationale=value.rationale,
        confidence_basis_points=value.confidence_basis_points,
        citations=value.citations,
        payload_schema=value.payload_schema,
        payload_json=value.payload_json,
        provenance=value.provenance,
        proposal_digest=value.proposal_digest,
    )


def _preflight_citations_without_hashing(
    value: object,
    *,
    required: bool,
) -> None:
    """Bound and type-check citations before aggregate size projection."""

    if type(value) is not tuple:
        raise TypeError("citations must be a tuple")
    if len(value) > MAX_PRIVATE_ANALYSIS_CITATIONS_PER_ITEM:
        raise ValueError("too many citations")
    if required and not value:
        raise ValueError("evidence-supported output requires a citation")
    for citation in value:
        if type(citation) is not PrivateAnalysisCitation:
            raise TypeError("citations must contain PrivateAnalysisCitation values")
        _contract_version(
            citation.contract_version,
            PRIVATE_ANALYSIS_CITATION_VERSION,
            "private-analysis citation",
        )
        _prefixed_sha256(
            citation.evidence_reference_digest,
            "evidence_reference_digest",
        )
        _prefixed_sha256(citation.citation_digest, "citation_digest")
    digests = tuple(item.evidence_reference_digest for item in value)
    if digests != tuple(sorted(digests)) or len(set(digests)) != len(digests):
        raise ValueError("citations must be unique and canonically ordered")


def _preflight_claim_without_hashing(
    value: object,
    *,
    summary: bool,
) -> None:
    """Validate every projection field without recomputing content digests."""

    if type(value) is not PrivateAnalysisClaim:
        raise TypeError("result claims must be PrivateAnalysisClaim values")
    _contract_version(
        value.contract_version,
        PRIVATE_ANALYSIS_CLAIM_VERSION,
        "private-analysis claim",
    )
    _identifier(value.claim_id, "claim_id")
    if type(value.support) is not PrivateAnalysisClaimSupport:
        raise TypeError("result claim support is invalid")
    _bounded_text(
        value.text,
        "claim text",
        maximum_characters=(
            MAX_PRIVATE_ANALYSIS_SUMMARY_CHARACTERS
            if summary
            else MAX_PRIVATE_ANALYSIS_CLAIM_CHARACTERS
        ),
    )
    _preflight_citations_without_hashing(
        value.citations,
        required=value.support is PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
    )
    if (
        value.support is PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS
        and value.citations
    ):
        raise ValueError("unsupported hypotheses must not claim evidence support")
    _prefixed_sha256(value.claim_digest, "claim_digest")


def _preflight_proposal_without_hashing(value: object) -> None:
    """Bound all proposal fields before aggregate wire projection."""

    if type(value) is not PrivateAnalysisProposal:
        raise TypeError("result proposals must be PrivateAnalysisProposal values")
    _contract_version(
        value.contract_version,
        PRIVATE_ANALYSIS_PROPOSAL_VERSION,
        "private-analysis proposal",
    )
    _identifier(value.proposal_id, "proposal_id")
    if type(value.kind) is not PrivateAnalysisProposalKind:
        raise TypeError("result proposal kind is invalid")
    _bounded_text(value.title, "proposal title", maximum_characters=512)
    _bounded_text(
        value.rationale,
        "proposal rationale",
        maximum_characters=MAX_PRIVATE_ANALYSIS_PROPOSAL_TEXT_CHARACTERS,
    )
    _integer(value.confidence_basis_points, "confidence_basis_points", 0, 10_000)
    _preflight_citations_without_hashing(value.citations, required=True)
    _identifier(value.payload_schema, "payload_schema")
    if type(value.payload_json) is not str:
        raise TypeError("result proposal payload_json must be a string")
    _bounded_utf8_text(
        value.payload_json,
        "proposal payload JSON",
        MAX_PRIVATE_ANALYSIS_PROPOSAL_PAYLOAD_BYTES,
    )
    try:
        payload = loads(
            value.payload_json,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, JSONDecodeError, RecursionError) as error:
        raise ValueError("proposal payload is not strict JSON") from error
    if _canonical_payload_json(payload) != value.payload_json:
        raise ValueError("proposal payload_json must use exact canonical JSON")
    if value.provenance is not PrivateAnalysisContributionKind.ASSISTANT_SUGGESTED:
        raise ValueError("result proposal provenance is invalid")
    _prefixed_sha256(value.proposal_digest, "proposal_digest")


def make_private_analysis_proposal(
    *,
    proposal_id: str,
    kind: PrivateAnalysisProposalKind,
    title: str,
    rationale: str,
    confidence_basis_points: int,
    citations: tuple[PrivateAnalysisCitation, ...],
    payload_schema: str,
    payload: dict[str, Any],
) -> PrivateAnalysisProposal:
    """Deep-detach one untrusted advisory payload into canonical JSON."""

    return PrivateAnalysisProposal(
        proposal_id=proposal_id,
        kind=kind,
        title=title,
        rationale=rationale,
        confidence_basis_points=confidence_basis_points,
        citations=citations,
        payload_schema=payload_schema,
        payload_json=_canonical_payload_json(payload),
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisResult(SealedContractValue):
    request_digest: str
    summary: PrivateAnalysisClaim
    claims: tuple[PrivateAnalysisClaim, ...]
    proposals: tuple[PrivateAnalysisProposal, ...]
    contract_version: str = PRIVATE_ANALYSIS_RESULT_VERSION
    result_digest: str = ""

    def __post_init__(self) -> None:
        _contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_RESULT_VERSION,
            "private-analysis result",
        )
        _prefixed_sha256(self.request_digest, "request_digest")
        _preflight_claim_without_hashing(self.summary, summary=True)
        if type(self.claims) is not tuple:
            raise TypeError("claims must be a tuple of PrivateAnalysisClaim values")
        if 1 + len(self.claims) > MAX_PRIVATE_ANALYSIS_CLAIMS:
            raise ValueError("too many private-analysis claims")
        if any(type(item) is not PrivateAnalysisClaim for item in self.claims):
            raise TypeError("claims must be a tuple of PrivateAnalysisClaim values")
        for claim_item in self.claims:
            _preflight_claim_without_hashing(claim_item, summary=False)
        if type(self.proposals) is not tuple:
            raise TypeError(
                "proposals must be a tuple of PrivateAnalysisProposal values"
            )
        if len(self.proposals) > MAX_PRIVATE_ANALYSIS_PROPOSALS:
            raise ValueError("too many private-analysis proposals")
        if any(type(item) is not PrivateAnalysisProposal for item in self.proposals):
            raise TypeError(
                "proposals must be a tuple of PrivateAnalysisProposal values"
            )
        for proposal_item in self.proposals:
            _preflight_proposal_without_hashing(proposal_item)
        _validate_result_wire_budget(
            self,
            maximum_bytes=MAX_PRIVATE_ANALYSIS_WIRE_BYTES,
            include_outcome_wrapper=True,
        )
        summary = _detached_claim(self.summary)
        claims = tuple(_detached_claim(item) for item in self.claims)
        proposals = tuple(_detached_proposal(item) for item in self.proposals)
        object.__setattr__(self, "summary", summary)
        object.__setattr__(self, "claims", claims)
        object.__setattr__(self, "proposals", proposals)
        identifiers = [summary.claim_id]
        identifiers.extend(item.claim_id for item in claims)
        identifiers.extend(item.proposal_id for item in proposals)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("claim and proposal IDs must be unique")
        result_payload = _private_analysis_result_payload(self)
        if type(self.result_digest) is not str:
            raise TypeError("result_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(result_payload)
        if self.result_digest:
            _prefixed_sha256(self.result_digest, "result_digest")
            if self.result_digest != expected:
                raise ValueError("private-analysis result digest does not match")
        else:
            object.__setattr__(self, "result_digest", expected)
        _validate_complete_wire_size(
            result_payload,
            digest_field="result_digest",
            digest=expected,
            label="private-analysis result",
        )
        _validate_result_fits_outcome(result_payload, expected)


def _detached_result(value: object) -> PrivateAnalysisResult:
    if type(value) is not PrivateAnalysisResult:
        raise TypeError("value must be PrivateAnalysisResult")
    return PrivateAnalysisResult(
        contract_version=value.contract_version,
        request_digest=value.request_digest,
        summary=value.summary,
        claims=value.claims,
        proposals=value.proposals,
        result_digest=value.result_digest,
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisError(SealedContractValue):
    request_digest: str | None
    stage: PrivateAnalysisErrorStage
    code: PrivateAnalysisErrorCode
    retryable: bool
    contract_version: str = PRIVATE_ANALYSIS_ERROR_VERSION
    error_digest: str = ""

    def __post_init__(self) -> None:
        _contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_ERROR_VERSION,
            "private-analysis error",
        )
        if self.request_digest is not None:
            _prefixed_sha256(self.request_digest, "request_digest")
        if type(self.stage) is not PrivateAnalysisErrorStage:
            raise TypeError("stage must be PrivateAnalysisErrorStage")
        if type(self.code) is not PrivateAnalysisErrorCode:
            raise TypeError("code must be PrivateAnalysisErrorCode")
        if type(self.retryable) is not bool:
            raise TypeError("retryable must be a boolean")
        if self.retryable is not (self.code in _RETRYABLE_ERROR_CODES):
            raise ValueError("retryable does not match the closed error policy")
        if self.stage not in _ERROR_STAGES[self.code]:
            raise ValueError("error stage and code disagree")
        if (
            self.request_digest is None
            and self.code is not PrivateAnalysisErrorCode.INVALID_REQUEST
        ):
            raise ValueError("post-request errors require request_digest")
        if type(self.error_digest) is not str:
            raise TypeError("error_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _private_analysis_error_payload(self)
        )
        if self.error_digest:
            _prefixed_sha256(self.error_digest, "error_digest")
            if self.error_digest != expected:
                raise ValueError("private-analysis error digest does not match")
        else:
            object.__setattr__(self, "error_digest", expected)

    @property
    def safe_message(self) -> str:
        return _SAFE_ERROR_MESSAGES[self.code]


def _detached_error(value: object) -> PrivateAnalysisError:
    if type(value) is not PrivateAnalysisError:
        raise TypeError("value must be PrivateAnalysisError")
    return PrivateAnalysisError(
        contract_version=value.contract_version,
        request_digest=value.request_digest,
        stage=value.stage,
        code=value.code,
        retryable=value.retryable,
        error_digest=value.error_digest,
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisOutcome(SealedContractValue):
    kind: PrivateAnalysisOutcomeKind
    result: PrivateAnalysisResult | None = None
    error: PrivateAnalysisError | None = None
    contract_version: str = PRIVATE_ANALYSIS_OUTCOME_VERSION
    outcome_digest: str = ""

    def __post_init__(self) -> None:
        _contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_OUTCOME_VERSION,
            "private-analysis outcome",
        )
        if type(self.kind) is not PrivateAnalysisOutcomeKind:
            raise TypeError("kind must be PrivateAnalysisOutcomeKind")
        if self.kind is PrivateAnalysisOutcomeKind.RESULT:
            if type(self.result) is not PrivateAnalysisResult or self.error is not None:
                raise ValueError("result outcome requires only a result")
            object.__setattr__(self, "result", _detached_result(self.result))
        elif type(self.error) is not PrivateAnalysisError or self.result is not None:
            raise ValueError("error outcome requires only an error")
        else:
            object.__setattr__(self, "error", _detached_error(self.error))
        if type(self.outcome_digest) is not str:
            raise TypeError("outcome_digest must be a string")
        outcome_payload = _private_analysis_outcome_payload(self)
        expected = "sha256:" + strict_canonical_json_sha256(outcome_payload)
        if self.outcome_digest:
            _prefixed_sha256(self.outcome_digest, "outcome_digest")
            if self.outcome_digest != expected:
                raise ValueError("private-analysis outcome digest does not match")
        else:
            object.__setattr__(self, "outcome_digest", expected)
        _validate_complete_wire_size(
            outcome_payload,
            digest_field="outcome_digest",
            digest=expected,
            label="private-analysis outcome",
        )


def _detached_request(value: object) -> PrivateAnalysisRequest:
    if type(value) is not PrivateAnalysisRequest:
        raise TypeError("value must be PrivateAnalysisRequest")
    return PrivateAnalysisRequest(
        contract_version=value.contract_version,
        scope=value.scope,
        revisions=value.revisions,
        runner=value.runner,
        workspace_policy_digest=value.workspace_policy_digest,
        instruction_profile_digest=value.instruction_profile_digest,
        tool_catalog_digest=value.tool_catalog_digest,
        evidence_service_digest=value.evidence_service_digest,
        task_kind=value.task_kind,
        query=value.query,
        clock_mode=value.clock_mode,
        selected_time_ns=value.selected_time_ns,
        limits=value.limits,
        request_digest=value.request_digest,
    )


def _detached_outcome(value: object) -> PrivateAnalysisOutcome:
    if type(value) is not PrivateAnalysisOutcome:
        raise TypeError("value must be PrivateAnalysisOutcome")
    return PrivateAnalysisOutcome(
        contract_version=value.contract_version,
        kind=value.kind,
        result=value.result,
        error=value.error,
        outcome_digest=value.outcome_digest,
    )


def _runner_selection_dict(
    value: PrivateAnalysisRunnerSelection,
) -> dict[str, object]:
    value = _detached_runner(value)
    return {
        "runner_id": value.runner_id,
        "runner_version": value.runner_version,
        "transport": value.transport.value,
        "configuration_digest": value.configuration_digest,
    }


def _limits_dict(value: PrivateAnalysisLimits) -> dict[str, object]:
    value = _detached_limits(value)
    return {
        "max_evidence_items": value.max_evidence_items,
        "max_evidence_bytes": value.max_evidence_bytes,
        "max_tool_calls": value.max_tool_calls,
        "max_output_bytes": value.max_output_bytes,
        "max_claims": value.max_claims,
        "max_proposals": value.max_proposals,
        "deadline_ms": value.deadline_ms,
    }


def _private_analysis_request_payload(
    value: PrivateAnalysisRequest,
) -> dict[str, object]:
    result = {
        "contract_version": value.contract_version,
        "scope": evidence_scope_dict(value.scope),
        "revisions": [evidence_revision_binding_dict(item) for item in value.revisions],
        "runner": _runner_selection_dict(value.runner),
        "workspace_policy_digest": value.workspace_policy_digest,
        "instruction_profile_digest": value.instruction_profile_digest,
        "tool_catalog_digest": value.tool_catalog_digest,
        "task_kind": value.task_kind.value,
        "query": value.query,
        "clock_mode": value.clock_mode.value,
        "selected_time_ns": (
            None if value.selected_time_ns is None else str(value.selected_time_ns)
        ),
        "limits": _limits_dict(value.limits),
    }
    if value.contract_version != PRIVATE_ANALYSIS_REQUEST_VERSION_V2:
        result["evidence_service_digest"] = value.evidence_service_digest
    return result


def private_analysis_request_dict(
    value: PrivateAnalysisRequest,
) -> dict[str, object]:
    value = _detached_request(value)
    result = _private_analysis_request_payload(value)
    result["request_digest"] = value.request_digest
    return result


def _private_analysis_citation_payload(
    value: PrivateAnalysisCitation,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "evidence_reference_digest": value.evidence_reference_digest,
    }


def _private_analysis_citation_dict_unchecked(
    value: PrivateAnalysisCitation,
) -> dict[str, object]:
    result = _private_analysis_citation_payload(value)
    result["citation_digest"] = value.citation_digest
    return result


def private_analysis_citation_dict(
    value: PrivateAnalysisCitation,
) -> dict[str, object]:
    value = _detached_citation(value)
    return _private_analysis_citation_dict_unchecked(value)


def _private_analysis_claim_payload(
    value: PrivateAnalysisClaim,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "claim_id": value.claim_id,
        "support": value.support.value,
        "text": value.text,
        "citations": [
            _private_analysis_citation_dict_unchecked(item) for item in value.citations
        ],
    }


def _private_analysis_claim_dict_unchecked(
    value: PrivateAnalysisClaim,
) -> dict[str, object]:
    result = _private_analysis_claim_payload(value)
    result["claim_digest"] = value.claim_digest
    return result


def private_analysis_claim_dict(
    value: PrivateAnalysisClaim,
) -> dict[str, object]:
    value = _detached_claim(value)
    return _private_analysis_claim_dict_unchecked(value)


def _private_analysis_proposal_payload(
    value: PrivateAnalysisProposal,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "proposal_id": value.proposal_id,
        "kind": value.kind.value,
        "title": value.title,
        "rationale": value.rationale,
        "confidence_basis_points": value.confidence_basis_points,
        "citations": [
            _private_analysis_citation_dict_unchecked(item) for item in value.citations
        ],
        "payload_schema": value.payload_schema,
        "payload": value.payload,
        "provenance": value.provenance.value,
    }


def _private_analysis_proposal_dict_unchecked(
    value: PrivateAnalysisProposal,
) -> dict[str, object]:
    result = _private_analysis_proposal_payload(value)
    result["proposal_digest"] = value.proposal_digest
    return result


def private_analysis_proposal_dict(
    value: PrivateAnalysisProposal,
) -> dict[str, object]:
    value = _detached_proposal(value)
    return _private_analysis_proposal_dict_unchecked(value)


def _private_analysis_result_payload(
    value: PrivateAnalysisResult,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "request_digest": value.request_digest,
        "summary": _private_analysis_claim_dict_unchecked(value.summary),
        "claims": [
            _private_analysis_claim_dict_unchecked(item) for item in value.claims
        ],
        "proposals": [
            _private_analysis_proposal_dict_unchecked(item) for item in value.proposals
        ],
    }


def _private_analysis_result_dict_unchecked(
    value: PrivateAnalysisResult,
) -> dict[str, object]:
    result = _private_analysis_result_payload(value)
    result["result_digest"] = value.result_digest
    return result


def private_analysis_result_dict(
    value: PrivateAnalysisResult,
) -> dict[str, object]:
    value = _detached_result(value)
    return _private_analysis_result_dict_unchecked(value)


def _private_analysis_error_payload(
    value: PrivateAnalysisError,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "request_digest": value.request_digest,
        "stage": value.stage.value,
        "code": value.code.value,
        "retryable": value.retryable,
    }


def _private_analysis_error_dict_unchecked(
    value: PrivateAnalysisError,
) -> dict[str, object]:
    result = _private_analysis_error_payload(value)
    result["error_digest"] = value.error_digest
    return result


def private_analysis_error_dict(
    value: PrivateAnalysisError,
) -> dict[str, object]:
    value = _detached_error(value)
    return _private_analysis_error_dict_unchecked(value)


def _private_analysis_outcome_payload(
    value: PrivateAnalysisOutcome,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "kind": value.kind.value,
        "result": (
            None
            if value.result is None
            else _private_analysis_result_dict_unchecked(value.result)
        ),
        "error": (
            None
            if value.error is None
            else _private_analysis_error_dict_unchecked(value.error)
        ),
    }


def _private_analysis_outcome_dict_unchecked(
    value: PrivateAnalysisOutcome,
) -> dict[str, object]:
    result = _private_analysis_outcome_payload(value)
    result["outcome_digest"] = value.outcome_digest
    return result


def private_analysis_outcome_dict(
    value: PrivateAnalysisOutcome,
) -> dict[str, object]:
    value = _detached_outcome(value)
    return _private_analysis_outcome_dict_unchecked(value)


def _runner_selection_from_dict(value: object) -> PrivateAnalysisRunnerSelection:
    item = _exact_dict(
        value,
        "runner selection",
        {"runner_id", "runner_version", "transport", "configuration_digest"},
    )
    return PrivateAnalysisRunnerSelection(
        runner_id=item["runner_id"],
        runner_version=item["runner_version"],
        transport=_enum(
            PrivateAnalysisTransport,
            item["transport"],
            "transport",
        ),
        configuration_digest=item["configuration_digest"],
    )


def _limits_from_dict(value: object) -> PrivateAnalysisLimits:
    item = _exact_dict(
        value,
        "private-analysis limits",
        {
            "max_evidence_items",
            "max_evidence_bytes",
            "max_tool_calls",
            "max_output_bytes",
            "max_claims",
            "max_proposals",
            "deadline_ms",
        },
    )
    return PrivateAnalysisLimits(
        max_evidence_items=item["max_evidence_items"],
        max_evidence_bytes=item["max_evidence_bytes"],
        max_tool_calls=item["max_tool_calls"],
        max_output_bytes=item["max_output_bytes"],
        max_claims=item["max_claims"],
        max_proposals=item["max_proposals"],
        deadline_ms=item["deadline_ms"],
    )


def _selected_time_from_wire(
    value: object,
    clock_mode: PrivateAnalysisClockMode,
) -> int | None:
    if value is None:
        return None
    minimum = (
        0 if clock_mode is PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS else _MIN_SIGNED_NS
    )
    return _bounded_decimal(
        value,
        "selected_time_ns",
        minimum=minimum,
        maximum=_MAX_SIGNED_NS,
    )


def private_analysis_request_from_dict(value: object) -> PrivateAnalysisRequest:
    if type(value) is not dict:
        raise ValueError("private-analysis request must be a JSON object")
    contract_version = value.get("contract_version")
    if type(contract_version) is not str or contract_version not in (
        PRIVATE_ANALYSIS_REQUEST_VERSION_V2,
        PRIVATE_ANALYSIS_REQUEST_VERSION,
    ):
        raise ValueError("unsupported private-analysis request contract version")
    keys = {
        "contract_version",
        "scope",
        "revisions",
        "runner",
        "workspace_policy_digest",
        "instruction_profile_digest",
        "tool_catalog_digest",
        "task_kind",
        "query",
        "clock_mode",
        "selected_time_ns",
        "limits",
        "request_digest",
    }
    if contract_version == PRIVATE_ANALYSIS_REQUEST_VERSION:
        keys.add("evidence_service_digest")
    item = _exact_dict(
        value,
        "private-analysis request",
        keys,
    )
    raw_revisions = _bounded_wire_list(
        item["revisions"],
        "revisions",
        maximum_items=MAX_PRIVATE_ANALYSIS_REVISIONS,
    )
    clock_mode = _enum(
        PrivateAnalysisClockMode,
        item["clock_mode"],
        "clock_mode",
    )
    request_digest = _prefixed_sha256(item["request_digest"], "request_digest")
    return PrivateAnalysisRequest(
        contract_version=item["contract_version"],
        scope=evidence_scope_from_dict(item["scope"]),
        revisions=tuple(
            evidence_revision_binding_from_dict(revision) for revision in raw_revisions
        ),
        runner=_runner_selection_from_dict(item["runner"]),
        workspace_policy_digest=item["workspace_policy_digest"],
        instruction_profile_digest=item["instruction_profile_digest"],
        tool_catalog_digest=item["tool_catalog_digest"],
        evidence_service_digest=(
            item["evidence_service_digest"]
            if contract_version == PRIVATE_ANALYSIS_REQUEST_VERSION
            else LEGACY_PRIVATE_ANALYSIS_EVIDENCE_SERVICE_DIGEST
        ),
        task_kind=_enum(
            PrivateAnalysisTaskKind,
            item["task_kind"],
            "task_kind",
        ),
        query=item["query"],
        clock_mode=clock_mode,
        selected_time_ns=_selected_time_from_wire(
            item["selected_time_ns"],
            clock_mode,
        ),
        limits=_limits_from_dict(item["limits"]),
        request_digest=request_digest,
    )


def private_analysis_citation_from_dict(value: object) -> PrivateAnalysisCitation:
    item = _exact_dict(
        value,
        "private-analysis citation",
        {"contract_version", "evidence_reference_digest", "citation_digest"},
    )
    return PrivateAnalysisCitation(
        contract_version=item["contract_version"],
        evidence_reference_digest=item["evidence_reference_digest"],
        citation_digest=_prefixed_sha256(
            item["citation_digest"],
            "citation_digest",
        ),
    )


def _citations_from_wire(value: object) -> tuple[PrivateAnalysisCitation, ...]:
    items = _bounded_wire_list(
        value,
        "citations",
        maximum_items=MAX_PRIVATE_ANALYSIS_CITATIONS_PER_ITEM,
    )
    return tuple(private_analysis_citation_from_dict(item) for item in items)


def private_analysis_claim_from_dict(value: object) -> PrivateAnalysisClaim:
    item = _exact_dict(
        value,
        "private-analysis claim",
        {
            "contract_version",
            "claim_id",
            "support",
            "text",
            "citations",
            "claim_digest",
        },
    )
    return PrivateAnalysisClaim(
        contract_version=item["contract_version"],
        claim_id=item["claim_id"],
        support=_enum(
            PrivateAnalysisClaimSupport,
            item["support"],
            "claim support",
        ),
        text=item["text"],
        citations=_citations_from_wire(item["citations"]),
        claim_digest=_prefixed_sha256(item["claim_digest"], "claim_digest"),
    )


def private_analysis_proposal_from_dict(value: object) -> PrivateAnalysisProposal:
    item = _exact_dict(
        value,
        "private-analysis proposal",
        {
            "contract_version",
            "proposal_id",
            "kind",
            "title",
            "rationale",
            "confidence_basis_points",
            "citations",
            "payload_schema",
            "payload",
            "provenance",
            "proposal_digest",
        },
    )
    provenance = _enum(
        PrivateAnalysisContributionKind,
        item["provenance"],
        "proposal provenance",
    )
    payload_json = _canonical_payload_json(item["payload"])
    return PrivateAnalysisProposal(
        contract_version=item["contract_version"],
        proposal_id=item["proposal_id"],
        kind=_enum(
            PrivateAnalysisProposalKind,
            item["kind"],
            "proposal kind",
        ),
        title=item["title"],
        rationale=item["rationale"],
        confidence_basis_points=item["confidence_basis_points"],
        citations=_citations_from_wire(item["citations"]),
        payload_schema=item["payload_schema"],
        payload_json=payload_json,
        provenance=provenance,
        proposal_digest=_prefixed_sha256(
            item["proposal_digest"],
            "proposal_digest",
        ),
    )


def private_analysis_result_from_dict(value: object) -> PrivateAnalysisResult:
    item = _exact_dict(
        value,
        "private-analysis result",
        {
            "contract_version",
            "request_digest",
            "summary",
            "claims",
            "proposals",
            "result_digest",
        },
    )
    item = _validate_result_input_wire_budget(item)
    raw_claims = _bounded_wire_list(
        item["claims"],
        "claims",
        maximum_items=MAX_PRIVATE_ANALYSIS_CLAIMS - 1,
    )
    raw_proposals = _bounded_wire_list(
        item["proposals"],
        "proposals",
        maximum_items=MAX_PRIVATE_ANALYSIS_PROPOSALS,
    )
    return PrivateAnalysisResult(
        contract_version=item["contract_version"],
        request_digest=item["request_digest"],
        summary=private_analysis_claim_from_dict(item["summary"]),
        claims=tuple(private_analysis_claim_from_dict(claim) for claim in raw_claims),
        proposals=tuple(
            private_analysis_proposal_from_dict(proposal) for proposal in raw_proposals
        ),
        result_digest=_prefixed_sha256(item["result_digest"], "result_digest"),
    )


def private_analysis_error_from_dict(value: object) -> PrivateAnalysisError:
    item = _exact_dict(
        value,
        "private-analysis error",
        {
            "contract_version",
            "request_digest",
            "stage",
            "code",
            "retryable",
            "error_digest",
        },
    )
    request_digest_value = item["request_digest"]
    request_digest = (
        None
        if request_digest_value is None
        else _prefixed_sha256(request_digest_value, "request_digest")
    )
    return PrivateAnalysisError(
        contract_version=item["contract_version"],
        request_digest=request_digest,
        stage=_enum(
            PrivateAnalysisErrorStage,
            item["stage"],
            "error stage",
        ),
        code=_enum(
            PrivateAnalysisErrorCode,
            item["code"],
            "error code",
        ),
        retryable=item["retryable"],
        error_digest=_prefixed_sha256(item["error_digest"], "error_digest"),
    )


def private_analysis_outcome_from_dict(value: object) -> PrivateAnalysisOutcome:
    item = _exact_dict(
        value,
        "private-analysis outcome",
        {"contract_version", "kind", "result", "error", "outcome_digest"},
    )
    kind = _enum(
        PrivateAnalysisOutcomeKind,
        item["kind"],
        "outcome kind",
    )
    raw_result = item["result"]
    raw_error = item["error"]
    return PrivateAnalysisOutcome(
        contract_version=item["contract_version"],
        kind=kind,
        result=(
            None
            if raw_result is None
            else private_analysis_result_from_dict(raw_result)
        ),
        error=(
            None if raw_error is None else private_analysis_error_from_dict(raw_error)
        ),
        outcome_digest=_prefixed_sha256(
            item["outcome_digest"],
            "outcome_digest",
        ),
    )


def private_analysis_request_json(value: PrivateAnalysisRequest) -> str:
    return _canonical_wire_json(
        private_analysis_request_dict(value),
        "private-analysis request",
    )


def private_analysis_result_json(value: PrivateAnalysisResult) -> str:
    return _canonical_wire_json(
        private_analysis_result_dict(value),
        "private-analysis result",
    )


def private_analysis_error_json(value: PrivateAnalysisError) -> str:
    return _canonical_wire_json(
        private_analysis_error_dict(value),
        "private-analysis error",
    )


def private_analysis_outcome_json(value: PrivateAnalysisOutcome) -> str:
    return _canonical_wire_json(
        private_analysis_outcome_dict(value),
        "private-analysis outcome",
    )


def _from_canonical_json[ValueType](
    value: str,
    *,
    label: str,
    parser: Callable[[object], ValueType],
    serializer: Callable[[ValueType], str],
) -> ValueType:
    parsed = _load_strict_json(value, label)
    result: ValueType = parser(parsed)
    if serializer(result) != value:
        raise ValueError(f"{label} must use exact canonical JSON")
    return result


def private_analysis_request_from_json(value: str) -> PrivateAnalysisRequest:
    return _from_canonical_json(
        value,
        label="private-analysis request",
        parser=private_analysis_request_from_dict,
        serializer=private_analysis_request_json,
    )


def private_analysis_result_from_json(value: str) -> PrivateAnalysisResult:
    return _from_canonical_json(
        value,
        label="private-analysis result",
        parser=private_analysis_result_from_dict,
        serializer=private_analysis_result_json,
    )


def private_analysis_error_from_json(value: str) -> PrivateAnalysisError:
    return _from_canonical_json(
        value,
        label="private-analysis error",
        parser=private_analysis_error_from_dict,
        serializer=private_analysis_error_json,
    )


def private_analysis_outcome_from_json(value: str) -> PrivateAnalysisOutcome:
    return _from_canonical_json(
        value,
        label="private-analysis outcome",
        parser=private_analysis_outcome_from_dict,
        serializer=private_analysis_outcome_json,
    )


def validate_private_analysis_result(
    result: PrivateAnalysisResult,
    request: PrivateAnalysisRequest,
    disclosed_references: tuple[EvidenceReference, ...],
) -> None:
    """Bind all assistant citations to the request's disclosed evidence set."""

    if type(result) is not PrivateAnalysisResult:
        raise TypeError("result must be PrivateAnalysisResult")
    if type(request) is not PrivateAnalysisRequest:
        raise TypeError("request must be PrivateAnalysisRequest")
    if type(disclosed_references) is not tuple:
        raise TypeError("disclosed_references must be a tuple of EvidenceReference")
    request = _revalidated_request(request)
    result = _revalidated_result(
        result,
        maximum_bytes=request.limits.max_output_bytes,
        maximum_claims=request.limits.max_claims,
        maximum_proposals=request.limits.max_proposals,
    )
    if len(disclosed_references) > request.limits.max_evidence_items:
        raise PrivateAnalysisContractError("disclosed evidence exceeds request budget")
    references = tuple(
        _revalidated_reference(reference) for reference in disclosed_references
    )
    if result.request_digest != request.request_digest:
        raise PrivateAnalysisContractError("result does not match the request")
    revision_set = set(request.revisions)
    disclosed: set[str] = set()
    for reference in references:
        if reference.scope != request.scope:
            raise PrivateAnalysisContractError(
                "disclosed evidence does not match request scope"
            )
        if reference.revision not in revision_set:
            raise PrivateAnalysisContractError(
                "disclosed evidence does not match request revision vector"
            )
        if reference.reference_digest in disclosed:
            raise PrivateAnalysisContractError(
                "disclosed evidence references must be unique"
            )
        disclosed.add(reference.reference_digest)
    for claim in result.claims:
        for citation in claim.citations:
            if citation.evidence_reference_digest not in disclosed:
                raise PrivateAnalysisContractError(
                    "claim cites evidence outside the disclosed ledger"
                )
    for citation in result.summary.citations:
        if citation.evidence_reference_digest not in disclosed:
            raise PrivateAnalysisContractError(
                "summary cites evidence outside the disclosed ledger"
            )
    for proposal in result.proposals:
        for citation in proposal.citations:
            if citation.evidence_reference_digest not in disclosed:
                raise PrivateAnalysisContractError(
                    "proposal cites evidence outside the disclosed ledger"
                )
    if 1 + len(result.claims) > request.limits.max_claims:
        raise PrivateAnalysisContractError("result exceeds request claim budget")
    if len(result.proposals) > request.limits.max_proposals:
        raise PrivateAnalysisContractError("result exceeds request proposal budget")
    try:
        _validate_result_wire_budget(
            result,
            maximum_bytes=request.limits.max_output_bytes,
            include_outcome_wrapper=False,
        )
    except ValueError:
        raise PrivateAnalysisContractError("result exceeds request output budget")


def _revalidated_request(value: PrivateAnalysisRequest) -> PrivateAnalysisRequest:
    """Recompute every cached request invariant before authority checks."""

    if (
        type(value.revisions) is not tuple
        or len(value.revisions) > MAX_PRIVATE_ANALYSIS_REVISIONS
    ):
        raise TypeError("request revisions must be a bounded tuple")
    if type(value.scope) is not EvidenceScope:
        raise TypeError("request scope must be EvidenceScope")
    value.scope.__post_init__()
    for revision in value.revisions:
        if type(revision) is not EvidenceRevisionBinding:
            raise TypeError(
                "request revisions must contain EvidenceRevisionBinding values"
            )
        revision.__post_init__()
    if type(value.runner) is not PrivateAnalysisRunnerSelection:
        raise TypeError("request runner must be PrivateAnalysisRunnerSelection")
    value.runner.__post_init__()
    if type(value.limits) is not PrivateAnalysisLimits:
        raise TypeError("request limits must be PrivateAnalysisLimits")
    value.limits.__post_init__()
    value.__post_init__()
    return private_analysis_request_from_dict(private_analysis_request_dict(value))


def _revalidate_citations(
    value: object,
) -> tuple[PrivateAnalysisCitation, ...]:
    return _validate_citations(value, required=False)


def _revalidate_claim(value: PrivateAnalysisClaim) -> None:
    if type(value) is not PrivateAnalysisClaim:
        raise TypeError("claims must contain PrivateAnalysisClaim values")
    _revalidate_citations(value.citations)
    value.__post_init__()


def _revalidate_proposal(value: PrivateAnalysisProposal) -> None:
    if type(value) is not PrivateAnalysisProposal:
        raise TypeError("proposals must contain PrivateAnalysisProposal values")
    _revalidate_citations(value.citations)
    value.__post_init__()


def _revalidated_result(
    value: PrivateAnalysisResult,
    *,
    maximum_bytes: int,
    maximum_claims: int,
    maximum_proposals: int,
) -> PrivateAnalysisResult:
    """Recompute nested result digests, then detach through the exact wire."""

    if type(value.summary) is not PrivateAnalysisClaim:
        raise TypeError("result summary must be PrivateAnalysisClaim")
    if (
        type(value.claims) is not tuple
        or len(value.claims) > MAX_PRIVATE_ANALYSIS_CLAIMS - 1
    ):
        raise TypeError("result claims must be a bounded tuple")
    if (
        type(value.proposals) is not tuple
        or len(value.proposals) > MAX_PRIVATE_ANALYSIS_PROPOSALS
    ):
        raise TypeError("result proposals must be a bounded tuple")
    if 1 + len(value.claims) > maximum_claims:
        raise PrivateAnalysisContractError("result exceeds request claim budget")
    if len(value.proposals) > maximum_proposals:
        raise PrivateAnalysisContractError("result exceeds request proposal budget")
    _revalidate_claim(value.summary)
    for claim in value.claims:
        _revalidate_claim(claim)
    for proposal in value.proposals:
        _revalidate_proposal(proposal)
    try:
        _validate_result_wire_budget(
            value,
            maximum_bytes=maximum_bytes,
            include_outcome_wrapper=False,
        )
    except ValueError:
        raise PrivateAnalysisContractError("result exceeds request output budget")
    value.__post_init__()
    return private_analysis_result_from_dict(private_analysis_result_dict(value))


def _revalidated_reference(value: object) -> EvidenceReference:
    """Recompute one evidence reference and every cached nested invariant."""

    try:
        return _revalidated_evidence_reference(value)
    except TypeError as error:
        raise TypeError(
            "disclosed_references must contain valid EvidenceReference values"
        ) from error


__all__ = [
    "MAX_PRIVATE_ANALYSIS_CITATIONS_PER_ITEM",
    "MAX_PRIVATE_ANALYSIS_CLAIMS",
    "MAX_PRIVATE_ANALYSIS_CLAIM_CHARACTERS",
    "MAX_PRIVATE_ANALYSIS_PROPOSALS",
    "MAX_PRIVATE_ANALYSIS_PROPOSAL_PAYLOAD_BYTES",
    "MAX_PRIVATE_ANALYSIS_PROPOSAL_TEXT_CHARACTERS",
    "MAX_PRIVATE_ANALYSIS_QUERY_BYTES",
    "MAX_PRIVATE_ANALYSIS_QUERY_CHARACTERS",
    "MAX_PRIVATE_ANALYSIS_REVISIONS",
    "MAX_PRIVATE_ANALYSIS_SUMMARY_CHARACTERS",
    "MAX_PRIVATE_ANALYSIS_WIRE_BYTES",
    "PRIVATE_ANALYSIS_CITATION_VERSION",
    "PRIVATE_ANALYSIS_CLAIM_VERSION",
    "PRIVATE_ANALYSIS_ERROR_VERSION",
    "PRIVATE_ANALYSIS_OUTCOME_VERSION",
    "PRIVATE_ANALYSIS_PROPOSAL_VERSION",
    "PRIVATE_ANALYSIS_REQUEST_VERSION",
    "PRIVATE_ANALYSIS_REQUEST_VERSION_V2",
    "PRIVATE_ANALYSIS_RESULT_VERSION",
    "PrivateAnalysisCitation",
    "PrivateAnalysisClaim",
    "PrivateAnalysisClaimSupport",
    "PrivateAnalysisClockMode",
    "PrivateAnalysisContractError",
    "PrivateAnalysisError",
    "PrivateAnalysisErrorCode",
    "PrivateAnalysisErrorStage",
    "PrivateAnalysisLimits",
    "PrivateAnalysisOutcome",
    "PrivateAnalysisOutcomeKind",
    "PrivateAnalysisProposal",
    "PrivateAnalysisProposalKind",
    "PrivateAnalysisRequest",
    "PrivateAnalysisResult",
    "PrivateAnalysisRunnerSelection",
    "PrivateAnalysisTaskKind",
    "make_private_analysis_proposal",
    "private_analysis_citation_dict",
    "private_analysis_citation_from_dict",
    "private_analysis_claim_dict",
    "private_analysis_claim_from_dict",
    "private_analysis_error_dict",
    "private_analysis_error_from_dict",
    "private_analysis_error_from_json",
    "private_analysis_error_json",
    "private_analysis_outcome_dict",
    "private_analysis_outcome_from_dict",
    "private_analysis_outcome_from_json",
    "private_analysis_outcome_json",
    "private_analysis_proposal_dict",
    "private_analysis_proposal_from_dict",
    "private_analysis_request_dict",
    "private_analysis_request_from_dict",
    "private_analysis_request_from_json",
    "private_analysis_request_json",
    "private_analysis_result_dict",
    "private_analysis_result_from_dict",
    "private_analysis_result_from_json",
    "private_analysis_result_json",
    "validate_private_analysis_result",
]
