"""Inert, read-only tool-wire values for private analysis.

This module deliberately contains no tool implementation.  The catalog and
messages below carry values only: no callable, database or filesystem handle,
shell, socket, dynamic loader, or plug-in callback.  A later trusted service
must authorize each call, resolve immutable evidence from durable state,
re-evaluate disclosure, charge budgets, and record the disclosure ledger.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from json import JSONDecodeError, loads
from typing import Any, Final

from ..canonical import (
    strict_canonical_json,
    strict_canonical_json_sha256,
)
from ..canonical import (
    validate_prefixed_lowercase_sha256 as _prefixed_sha256,
)
from ..contract_validation import validate_bounded_json_value
from ._wire import (
    SealedContractValue,
    bounded_canonical_decimal_integer,
    exact_contract_version,
    exact_json_object,
    reject_duplicate_json_object_pairs,
    strict_string_enum,
)
from .evidence import (
    EVIDENCE_REFERENCE_VERSION,
    MAX_EVIDENCE_SUBJECT_KIND_CHARACTERS,
    EvidenceAuthority,
    EvidenceEnvelope,
    EvidenceFactProvenance,
    EvidenceKind,
    EvidenceReference,
    EvidenceTimeBasis,
    EvidenceTimeRange,
    evidence_envelope_dict,
    evidence_envelope_from_dict,
    evidence_locator_digest,
    evidence_reference_dict,
    evidence_reference_from_dict,
    validate_evidence_identifier,
    validate_evidence_token,
)

PRIVATE_ANALYSIS_TOOL_DEFINITION_VERSION: Final = (
    "router_dump_analyzer.private_analysis.tool_definition.v2"
)
PRIVATE_ANALYSIS_TOOL_CATALOG_VERSION: Final = (
    "router_dump_analyzer.private_analysis.tool_catalog.v2"
)
PRIVATE_ANALYSIS_TOOL_BINDING_VERSION: Final = (
    "router_dump_analyzer.private_analysis.tool_binding.v2"
)
PRIVATE_ANALYSIS_QUERY_ARGUMENTS_VERSION: Final = (
    "router_dump_analyzer.private_analysis.query_evidence.arguments.v2"
)
PRIVATE_ANALYSIS_QUERY_PAGE_VERSION: Final = (
    "router_dump_analyzer.private_analysis.query_evidence.page.v1"
)
PRIVATE_ANALYSIS_READ_ARGUMENTS_VERSION: Final = (
    "router_dump_analyzer.private_analysis.read_evidence.arguments.v1"
)
PRIVATE_ANALYSIS_READ_RESULT_VERSION: Final = (
    "router_dump_analyzer.private_analysis.read_evidence.result.v1"
)
PRIVATE_ANALYSIS_CAPABILITY_ARGUMENTS_VERSION: Final = (
    "router_dump_analyzer.private_analysis.analyze_evidence.arguments.v1"
)
PRIVATE_ANALYSIS_CAPABILITY_RESULT_VERSION: Final = (
    "router_dump_analyzer.private_analysis.analyze_evidence.result.v1"
)
PRIVATE_ANALYSIS_CURSOR_VERSION: Final = (
    "router_dump_analyzer.private_analysis.query_evidence.cursor.v1"
)
PRIVATE_ANALYSIS_TOOL_CALL_VERSION: Final = (
    "router_dump_analyzer.private_analysis.tool_call.v2"
)
PRIVATE_ANALYSIS_TOOL_RESULT_VERSION: Final = (
    "router_dump_analyzer.private_analysis.tool_result.v2"
)
PRIVATE_ANALYSIS_TOOL_ERROR_VERSION: Final = (
    "router_dump_analyzer.private_analysis.tool_error.v2"
)
PRIVATE_ANALYSIS_EVIDENCE_SNAPSHOT_VERSION: Final = (
    "router_dump_analyzer.private_analysis.evidence_snapshot.v1"
)

MAX_PRIVATE_ANALYSIS_TOOL_WIRE_BYTES: Final[int] = 8 * 1024 * 1024
MAX_PRIVATE_ANALYSIS_QUERY_PAGE_SIZE: Final = 256
MAX_PRIVATE_ANALYSIS_QUERY_FILTER_ITEMS: Final = 64
MAX_PRIVATE_ANALYSIS_QUERY_REFERENCES: Final = MAX_PRIVATE_ANALYSIS_QUERY_PAGE_SIZE
MAX_PRIVATE_ANALYSIS_SNAPSHOT_REFERENCES: Final = 100_000
MAX_PRIVATE_ANALYSIS_TOOL_IDENTIFIER_CHARACTERS: Final = 256
MAX_PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_ITEMS: Final = 256
MAX_PRIVATE_ANALYSIS_CAPABILITY_OBSERVATIONS: Final = 64
PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_SUBJECT_KIND: Final = "evidence_analysis"
PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_PAYLOAD_SCHEMA: Final = (
    "router_dump_analyzer.plugin.evidence_analysis.result.v1"
)
_MIN_SIGNED_NS: Final = -(1 << 63)
_MAX_SIGNED_NS: Final = (1 << 63) - 1


class PrivateAnalysisToolName(StrEnum):
    """The complete tool vocabulary available to a private runner."""

    QUERY_EVIDENCE = "query_evidence"
    READ_EVIDENCE = "read_evidence"
    ANALYZE_EVIDENCE = "analyze_evidence"


class PrivateAnalysisCapabilityIntent(StrEnum):
    """Closed model-visible intents mapped to plug-in evidence analysis."""

    ROUTE_TRACE = "route_trace"
    TRACE_CORRELATION = "trace_correlation"
    EVIDENCE_CORRELATION = "evidence_correlation"
    EVIDENCE_INTERPRETATION = "evidence_interpretation"


class _PrivateAnalysisEvidenceQuality(StrEnum):
    """Closed wire vocabulary mirrored at the plug-in adapter boundary.

    The inert private-analysis package must not import the executable plug-in
    API merely to validate serialized result text.  The trusted adapter maps
    the public ``Quality`` enum to these exact wire values before a result
    reaches this package.
    """

    EXACT = "exact"
    BEST_EFFORT = "best_effort"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


class PrivateAnalysisToolResultKind(StrEnum):
    QUERY_PAGE = "query_page"
    EVIDENCE_ENVELOPE = "evidence_envelope"
    DERIVED_EVIDENCE_ENVELOPE = "derived_evidence_envelope"


class PrivateAnalysisToolErrorCode(StrEnum):
    """Closed, payload-free failures after a valid tool call exists."""

    CURSOR_INVALID = "cursor_invalid"
    EVIDENCE_NOT_FOUND = "evidence_not_found"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    BUDGET_EXCEEDED = "budget_exceeded"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"


class PrivateAnalysisEvidenceCursorInvalidError(ValueError):
    """A trusted query provider rejected an invalid or evicted cursor.

    This is the only callback failure that the generic tool service projects
    as ``cursor_invalid``.  All other provider failures remain retryable
    evidence-unavailable errors, even when the call happened to carry a
    syntactically valid cursor.
    """


_TOOL_CONTRACT_MATRIX: Final = {
    PrivateAnalysisToolName.QUERY_EVIDENCE: (
        PRIVATE_ANALYSIS_QUERY_ARGUMENTS_VERSION,
        PRIVATE_ANALYSIS_QUERY_PAGE_VERSION,
    ),
    PrivateAnalysisToolName.READ_EVIDENCE: (
        PRIVATE_ANALYSIS_READ_ARGUMENTS_VERSION,
        PRIVATE_ANALYSIS_READ_RESULT_VERSION,
    ),
    PrivateAnalysisToolName.ANALYZE_EVIDENCE: (
        PRIVATE_ANALYSIS_CAPABILITY_ARGUMENTS_VERSION,
        PRIVATE_ANALYSIS_CAPABILITY_RESULT_VERSION,
    ),
}
_TOOL_ORDER: Final = (
    PrivateAnalysisToolName.QUERY_EVIDENCE,
    PrivateAnalysisToolName.READ_EVIDENCE,
    PrivateAnalysisToolName.ANALYZE_EVIDENCE,
)
_RETRYABLE_TOOL_ERRORS: Final = frozenset(
    {PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE}
)
_SAFE_TOOL_ERROR_MESSAGES: Final = {
    PrivateAnalysisToolErrorCode.CURSOR_INVALID: (
        "Private analysis evidence cursor is invalid."
    ),
    PrivateAnalysisToolErrorCode.EVIDENCE_NOT_FOUND: (
        "Private analysis evidence was not found."
    ),
    PrivateAnalysisToolErrorCode.EVIDENCE_UNAVAILABLE: (
        "Private analysis evidence is unavailable."
    ),
    PrivateAnalysisToolErrorCode.BUDGET_EXCEEDED: (
        "Private analysis tool budget was exceeded."
    ),
    PrivateAnalysisToolErrorCode.CAPABILITY_UNAVAILABLE: (
        "Private analysis plug-in evidence analysis is unavailable."
    ),
}


def _exact_tuple(value: object, label: str, maximum: int) -> tuple[Any, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be a tuple")
    if len(value) > maximum:
        raise ValueError(f"{label} supports at most {maximum} items")
    return value


def _wire_list(value: object, label: str, maximum: int) -> list[Any]:
    if type(value) is not list:
        raise TypeError(f"{label} must be a list")
    if len(value) > maximum:
        raise ValueError(f"{label} supports at most {maximum} items")
    return value


def _canonical_identifiers(
    value: object,
    label: str,
    *,
    token: bool,
    maximum_characters: int = MAX_PRIVATE_ANALYSIS_TOOL_IDENTIFIER_CHARACTERS,
) -> tuple[str, ...]:
    items = _exact_tuple(value, label, MAX_PRIVATE_ANALYSIS_QUERY_FILTER_ITEMS)
    for item in items:
        validator = validate_evidence_token if token else validate_evidence_identifier
        validator(item, label, maximum=maximum_characters)
    if tuple(sorted(items)) != items or len(set(items)) != len(items):
        raise ValueError(f"{label} must be unique and canonically ordered")
    return items


def _canonical_evidence_kinds(value: object) -> tuple[EvidenceKind, ...]:
    items = _exact_tuple(value, "evidence_kinds", len(EvidenceKind))
    if any(type(item) is not EvidenceKind for item in items):
        raise TypeError("evidence_kinds must contain EvidenceKind values")
    if tuple(sorted(items, key=lambda item: item.value)) != items:
        raise ValueError("evidence_kinds must use canonical order")
    if len(set(items)) != len(items):
        raise ValueError("evidence_kinds must be unique")
    return items


def _exact_tool_name(value: object) -> PrivateAnalysisToolName:
    if type(value) is not PrivateAnalysisToolName:
        raise TypeError("tool name must be PrivateAnalysisToolName")
    return value


def _canonical_json(value: dict[str, object], label: str) -> str:
    encoded = strict_canonical_json(value)
    if len(encoded.encode("utf-8")) > MAX_PRIVATE_ANALYSIS_TOOL_WIRE_BYTES:
        raise ValueError(f"{label} exceeds its encoded byte limit")
    return encoded


def _load_canonical_json(value: object, label: str) -> dict[str, Any]:
    if type(value) is not str:
        raise TypeError(f"{label} JSON must be a string")
    if len(value) > MAX_PRIVATE_ANALYSIS_TOOL_WIRE_BYTES:
        raise ValueError(f"{label} JSON exceeds its encoded byte limit")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} JSON must contain Unicode scalars") from error
    if len(encoded) > MAX_PRIVATE_ANALYSIS_TOOL_WIRE_BYTES:
        raise ValueError(f"{label} JSON exceeds its encoded byte limit")

    def reject_constant(constant: str) -> None:
        raise ValueError(f"unsupported JSON constant {constant}")

    try:
        parsed = loads(
            value,
            object_pairs_hook=reject_duplicate_json_object_pairs,
            parse_constant=reject_constant,
        )
    except (TypeError, ValueError, JSONDecodeError, RecursionError) as error:
        raise ValueError(f"{label} is not strict JSON") from error
    if type(parsed) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    if strict_canonical_json(parsed) != value:
        raise ValueError(f"{label} JSON must be exact canonical JSON")
    return parsed


def _capability_parameters(value: object) -> dict[str, Any]:
    parsed = _load_canonical_json(value, "capability parameters")
    snapshot = validate_bounded_json_value(
        parsed,
        "capability parameters",
        maximum_depth=8,
        maximum_container_items=256,
        maximum_units=1_024,
        maximum_atom_units=8_192,
        maximum_integer_bits=53,
        exact_types=True,
        allow_exact_tuples=False,
        maximum_encoded_bytes=262_144,
        snapshot=True,
    )
    if type(snapshot) is not dict:
        raise TypeError("capability parameters must be an exact dictionary")
    return snapshot


@dataclass(frozen=True, slots=True)
class PrivateAnalysisToolDefinition(SealedContractValue):
    name: PrivateAnalysisToolName
    arguments_contract_version: str
    result_contract_version: str
    contract_version: str = PRIVATE_ANALYSIS_TOOL_DEFINITION_VERSION
    definition_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_TOOL_DEFINITION_VERSION,
            "private-analysis tool definition",
        )
        name = _exact_tool_name(self.name)
        expected_arguments, expected_result = _TOOL_CONTRACT_MATRIX[name]
        exact_contract_version(
            self.arguments_contract_version,
            expected_arguments,
            f"{name.value} arguments",
        )
        exact_contract_version(
            self.result_contract_version,
            expected_result,
            f"{name.value} result",
        )
        if type(self.definition_digest) is not str:
            raise TypeError("definition_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _tool_definition_payload(self)
        )
        if self.definition_digest:
            _prefixed_sha256(self.definition_digest, "definition_digest")
            if self.definition_digest != expected:
                raise ValueError("tool definition digest does not match")
        else:
            object.__setattr__(self, "definition_digest", expected)


def _new_tool_definition(
    name: PrivateAnalysisToolName,
) -> PrivateAnalysisToolDefinition:
    arguments_version, result_version = _TOOL_CONTRACT_MATRIX[name]
    return PrivateAnalysisToolDefinition(
        name=name,
        arguments_contract_version=arguments_version,
        result_contract_version=result_version,
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisToolCatalog(SealedContractValue):
    tools: tuple[PrivateAnalysisToolDefinition, ...]
    contract_version: str = PRIVATE_ANALYSIS_TOOL_CATALOG_VERSION
    catalog_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_TOOL_CATALOG_VERSION,
            "private-analysis tool catalog",
        )
        items = _exact_tuple(self.tools, "tools", len(_TOOL_ORDER))
        if len(items) != len(_TOOL_ORDER):
            raise ValueError(
                f"tool catalog must contain exactly {len(_TOOL_ORDER)} tools"
            )
        detached: list[PrivateAnalysisToolDefinition] = []
        for expected_name, item in zip(_TOOL_ORDER, items, strict=True):
            if type(item) is not PrivateAnalysisToolDefinition:
                raise TypeError(
                    "tools must contain PrivateAnalysisToolDefinition values"
                )
            copied = PrivateAnalysisToolDefinition(
                name=item.name,
                arguments_contract_version=item.arguments_contract_version,
                result_contract_version=item.result_contract_version,
                contract_version=item.contract_version,
                definition_digest=item.definition_digest,
            )
            if copied.name is not expected_name:
                raise ValueError("tool catalog must use its closed canonical order")
            detached.append(copied)
        object.__setattr__(self, "tools", tuple(detached))
        if type(self.catalog_digest) is not str:
            raise TypeError("catalog_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(_tool_catalog_payload(self))
        if self.catalog_digest:
            _prefixed_sha256(self.catalog_digest, "catalog_digest")
            if self.catalog_digest != expected:
                raise ValueError("tool catalog digest does not match")
        else:
            object.__setattr__(self, "catalog_digest", expected)


def default_private_analysis_tool_catalog() -> PrivateAnalysisToolCatalog:
    """Return a detached copy of the complete built-in read-only catalog."""

    return PrivateAnalysisToolCatalog(
        tools=tuple(_new_tool_definition(name) for name in _TOOL_ORDER)
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisToolBinding(SealedContractValue):
    request_digest: str
    tool_catalog_digest: str
    name: PrivateAnalysisToolName
    contract_version: str = PRIVATE_ANALYSIS_TOOL_BINDING_VERSION
    binding_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_TOOL_BINDING_VERSION,
            "private-analysis tool binding",
        )
        _prefixed_sha256(self.request_digest, "request_digest")
        _prefixed_sha256(self.tool_catalog_digest, "tool_catalog_digest")
        _exact_tool_name(self.name)
        if type(self.binding_digest) is not str:
            raise TypeError("binding_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(_tool_binding_payload(self))
        if self.binding_digest:
            _prefixed_sha256(self.binding_digest, "binding_digest")
            if self.binding_digest != expected:
                raise ValueError("tool binding digest does not match")
        else:
            object.__setattr__(self, "binding_digest", expected)


@dataclass(frozen=True, slots=True)
class PrivateAnalysisCursor(SealedContractValue):
    request_digest: str
    tool_catalog_digest: str
    query_digest: str
    snapshot_digest: str
    after_reference_digest: str
    contract_version: str = PRIVATE_ANALYSIS_CURSOR_VERSION
    cursor_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_CURSOR_VERSION,
            "private-analysis cursor",
        )
        for label, value in (
            ("request_digest", self.request_digest),
            ("tool_catalog_digest", self.tool_catalog_digest),
            ("query_digest", self.query_digest),
            ("snapshot_digest", self.snapshot_digest),
            ("after_reference_digest", self.after_reference_digest),
        ):
            _prefixed_sha256(value, label)
        if type(self.cursor_digest) is not str:
            raise TypeError("cursor_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(_cursor_payload(self))
        if self.cursor_digest:
            _prefixed_sha256(self.cursor_digest, "cursor_digest")
            if self.cursor_digest != expected:
                raise ValueError("private-analysis cursor digest does not match")
        else:
            object.__setattr__(self, "cursor_digest", expected)


def _detached_cursor(value: object) -> PrivateAnalysisCursor:
    if type(value) is not PrivateAnalysisCursor:
        raise TypeError("cursor must be PrivateAnalysisCursor")
    return PrivateAnalysisCursor(
        request_digest=value.request_digest,
        tool_catalog_digest=value.tool_catalog_digest,
        query_digest=value.query_digest,
        snapshot_digest=value.snapshot_digest,
        after_reference_digest=value.after_reference_digest,
        contract_version=value.contract_version,
        cursor_digest=value.cursor_digest,
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisQueryArguments(SealedContractValue):
    evidence_kinds: tuple[EvidenceKind, ...] = ()
    node_ids: tuple[str, ...] = ()
    producer_ids: tuple[str, ...] = ()
    subject_kinds: tuple[str, ...] = ()
    time_basis: EvidenceTimeBasis | None = None
    time_start_ns: int | None = None
    time_end_ns: int | None = None
    time_clock_domain: str | None = None
    page_size: int = 128
    cursor: PrivateAnalysisCursor | None = None
    contract_version: str = PRIVATE_ANALYSIS_QUERY_ARGUMENTS_VERSION
    query_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_QUERY_ARGUMENTS_VERSION,
            "query-evidence arguments",
        )
        evidence_kinds = _canonical_evidence_kinds(self.evidence_kinds)
        node_ids = _canonical_identifiers(self.node_ids, "node_ids", token=False)
        producer_ids = _canonical_identifiers(
            self.producer_ids,
            "producer_ids",
            token=True,
        )
        subject_kinds = _canonical_identifiers(
            self.subject_kinds,
            "subject_kinds",
            token=True,
            maximum_characters=MAX_EVIDENCE_SUBJECT_KIND_CHARACTERS,
        )
        object.__setattr__(self, "evidence_kinds", evidence_kinds)
        object.__setattr__(self, "node_ids", node_ids)
        object.__setattr__(self, "producer_ids", producer_ids)
        object.__setattr__(self, "subject_kinds", subject_kinds)
        time_values = (
            self.time_basis,
            self.time_start_ns,
            self.time_end_ns,
            self.time_clock_domain,
        )
        if all(value is None for value in time_values):
            pass
        elif (
            type(self.time_basis) is not EvidenceTimeBasis
            or type(self.time_start_ns) is not int
            or type(self.time_end_ns) is not int
        ):
            raise ValueError(
                "time_basis, time_start_ns, and time_end_ns must be supplied together"
            )
        else:
            # Reuse the evidence coordinate validator so query windows and
            # reference intervals have identical signedness/domain semantics.
            EvidenceTimeRange(
                basis=self.time_basis,
                start_ns=self.time_start_ns,
                end_ns=self.time_end_ns,
                clock_domain=self.time_clock_domain,
            )
        if (
            type(self.page_size) is not int
            or not 1 <= self.page_size <= MAX_PRIVATE_ANALYSIS_QUERY_PAGE_SIZE
        ):
            raise ValueError(
                "page_size must be between 1 and "
                f"{MAX_PRIVATE_ANALYSIS_QUERY_PAGE_SIZE}"
            )
        cursor = None if self.cursor is None else _detached_cursor(self.cursor)
        object.__setattr__(self, "cursor", cursor)
        if type(self.query_digest) is not str:
            raise TypeError("query_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _query_fingerprint_payload(self)
        )
        if self.query_digest:
            _prefixed_sha256(self.query_digest, "query_digest")
            if self.query_digest != expected:
                raise ValueError("query-evidence digest does not match")
        else:
            object.__setattr__(self, "query_digest", expected)
        if cursor is not None and cursor.query_digest != expected:
            raise ValueError("cursor and query arguments disagree")


@dataclass(frozen=True, slots=True)
class PrivateAnalysisEvidenceQueryPage:
    """One provider page from an immutable candidate snapshot."""

    snapshot_digest: str
    references: tuple[EvidenceReference, ...]
    has_more: bool

    def __post_init__(self) -> None:
        _prefixed_sha256(self.snapshot_digest, "snapshot_digest")
        references = _exact_tuple(
            self.references,
            "references",
            MAX_PRIVATE_ANALYSIS_QUERY_PAGE_SIZE,
        )
        if any(type(item) is not EvidenceReference for item in references):
            raise TypeError("references must contain EvidenceReference values")
        digests = tuple(item.reference_digest for item in references)
        if tuple(sorted(digests)) != digests or len(set(digests)) != len(digests):
            raise ValueError("references must be unique and canonically ordered")
        if type(self.has_more) is not bool:
            raise TypeError("has_more must be a boolean")
        if self.has_more and not references:
            raise ValueError("an empty query page cannot continue")


@dataclass(frozen=True, slots=True)
class PrivateAnalysisReadArguments(SealedContractValue):
    evidence_reference_digest: str
    contract_version: str = PRIVATE_ANALYSIS_READ_ARGUMENTS_VERSION
    arguments_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_READ_ARGUMENTS_VERSION,
            "read-evidence arguments",
        )
        _prefixed_sha256(
            self.evidence_reference_digest,
            "evidence_reference_digest",
        )
        if type(self.arguments_digest) is not str:
            raise TypeError("arguments_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _read_arguments_payload(self)
        )
        if self.arguments_digest:
            _prefixed_sha256(self.arguments_digest, "arguments_digest")
            if self.arguments_digest != expected:
                raise ValueError("read-evidence arguments digest does not match")
        else:
            object.__setattr__(self, "arguments_digest", expected)


@dataclass(frozen=True, slots=True)
class PrivateAnalysisCapabilityArguments(SealedContractValue):
    """One exact, bounded request for plug-in interpretation of evidence.

    The arguments contain no plug-in object, executable name, filesystem
    location, model configuration, network endpoint, or mutation handle.
    ``revision_id`` selects one immutable request member. The trusted host,
    never the model, resolves that member's exact configured provider.
    """

    node_id: str
    revision_id: str
    intent: PrivateAnalysisCapabilityIntent
    parent_reference_digests: tuple[str, ...]
    parameters_json: str = "{}"
    max_observations: int = MAX_PRIVATE_ANALYSIS_CAPABILITY_OBSERVATIONS
    contract_version: str = PRIVATE_ANALYSIS_CAPABILITY_ARGUMENTS_VERSION
    arguments_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_CAPABILITY_ARGUMENTS_VERSION,
            "analyze-evidence arguments",
        )
        validate_evidence_identifier(self.node_id, "node_id")
        validate_evidence_identifier(self.revision_id, "revision_id")
        if type(self.intent) is not PrivateAnalysisCapabilityIntent:
            raise TypeError("intent must be PrivateAnalysisCapabilityIntent")
        digests = _exact_tuple(
            self.parent_reference_digests,
            "parent_reference_digests",
            MAX_PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_ITEMS,
        )
        if not digests:
            raise ValueError("analyze_evidence requires at least one evidence item")
        for digest in digests:
            _prefixed_sha256(digest, "parent_reference_digest")
        if tuple(sorted(digests)) != digests or len(set(digests)) != len(digests):
            raise ValueError(
                "parent_reference_digests must be unique and canonically ordered"
            )
        _capability_parameters(self.parameters_json)
        if (
            type(self.max_observations) is not int
            or not 1
            <= self.max_observations
            <= MAX_PRIVATE_ANALYSIS_CAPABILITY_OBSERVATIONS
        ):
            raise ValueError(
                "max_observations must be between 1 and "
                f"{MAX_PRIVATE_ANALYSIS_CAPABILITY_OBSERVATIONS}"
            )
        if type(self.arguments_digest) is not str:
            raise TypeError("arguments_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _capability_arguments_payload(self)
        )
        if self.arguments_digest:
            _prefixed_sha256(self.arguments_digest, "arguments_digest")
            if self.arguments_digest != expected:
                raise ValueError("analyze-evidence arguments digest does not match")
        else:
            object.__setattr__(self, "arguments_digest", expected)

    @property
    def parameters(self) -> dict[str, Any]:
        return _capability_parameters(self.parameters_json)


PrivateAnalysisToolArguments = (
    PrivateAnalysisQueryArguments
    | PrivateAnalysisReadArguments
    | PrivateAnalysisCapabilityArguments
)


def _detached_binding(value: object) -> PrivateAnalysisToolBinding:
    if type(value) is not PrivateAnalysisToolBinding:
        raise TypeError("binding must be PrivateAnalysisToolBinding")
    return PrivateAnalysisToolBinding(
        request_digest=value.request_digest,
        tool_catalog_digest=value.tool_catalog_digest,
        name=value.name,
        contract_version=value.contract_version,
        binding_digest=value.binding_digest,
    )


def _detached_query_arguments(value: object) -> PrivateAnalysisQueryArguments:
    if type(value) is not PrivateAnalysisQueryArguments:
        raise TypeError("arguments must be PrivateAnalysisQueryArguments")
    return PrivateAnalysisQueryArguments(
        evidence_kinds=value.evidence_kinds,
        node_ids=value.node_ids,
        producer_ids=value.producer_ids,
        subject_kinds=value.subject_kinds,
        time_basis=value.time_basis,
        time_start_ns=value.time_start_ns,
        time_end_ns=value.time_end_ns,
        time_clock_domain=value.time_clock_domain,
        page_size=value.page_size,
        cursor=value.cursor,
        contract_version=value.contract_version,
        query_digest=value.query_digest,
    )


def _detached_read_arguments(value: object) -> PrivateAnalysisReadArguments:
    if type(value) is not PrivateAnalysisReadArguments:
        raise TypeError("arguments must be PrivateAnalysisReadArguments")
    return PrivateAnalysisReadArguments(
        evidence_reference_digest=value.evidence_reference_digest,
        contract_version=value.contract_version,
        arguments_digest=value.arguments_digest,
    )


def _detached_capability_arguments(
    value: object,
) -> PrivateAnalysisCapabilityArguments:
    if type(value) is not PrivateAnalysisCapabilityArguments:
        raise TypeError("arguments must be PrivateAnalysisCapabilityArguments")
    return PrivateAnalysisCapabilityArguments(
        node_id=value.node_id,
        revision_id=value.revision_id,
        intent=value.intent,
        parent_reference_digests=value.parent_reference_digests,
        parameters_json=value.parameters_json,
        max_observations=value.max_observations,
        contract_version=value.contract_version,
        arguments_digest=value.arguments_digest,
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisToolCall(SealedContractValue):
    call_id: str
    binding: PrivateAnalysisToolBinding
    arguments: PrivateAnalysisToolArguments
    contract_version: str = PRIVATE_ANALYSIS_TOOL_CALL_VERSION
    call_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_TOOL_CALL_VERSION,
            "private-analysis tool call",
        )
        validate_evidence_token(
            self.call_id,
            "call_id",
            maximum=MAX_PRIVATE_ANALYSIS_TOOL_IDENTIFIER_CHARACTERS,
        )
        binding = _detached_binding(self.binding)
        arguments: PrivateAnalysisToolArguments
        if binding.name is PrivateAnalysisToolName.QUERY_EVIDENCE:
            arguments = _detached_query_arguments(self.arguments)
            if arguments.cursor is not None:
                if arguments.cursor.request_digest != binding.request_digest:
                    raise ValueError("cursor belongs to another request")
                if arguments.cursor.tool_catalog_digest != binding.tool_catalog_digest:
                    raise ValueError("cursor belongs to another tool catalog")
        elif binding.name is PrivateAnalysisToolName.READ_EVIDENCE:
            arguments = _detached_read_arguments(self.arguments)
        else:
            arguments = _detached_capability_arguments(self.arguments)
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "arguments", arguments)
        if type(self.call_digest) is not str:
            raise TypeError("call_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(_tool_call_payload(self))
        if self.call_digest:
            _prefixed_sha256(self.call_digest, "call_digest")
            if self.call_digest != expected:
                raise ValueError("tool call digest does not match")
        else:
            object.__setattr__(self, "call_digest", expected)


def _detached_call(value: object) -> PrivateAnalysisToolCall:
    if type(value) is not PrivateAnalysisToolCall:
        raise TypeError("call must be PrivateAnalysisToolCall")
    return PrivateAnalysisToolCall(
        call_id=value.call_id,
        binding=value.binding,
        arguments=value.arguments,
        contract_version=value.contract_version,
        call_digest=value.call_digest,
    )


def _detached_reference(value: object) -> EvidenceReference:
    if type(value) is not EvidenceReference:
        raise TypeError("references must contain EvidenceReference values")
    return evidence_reference_from_dict(evidence_reference_dict(value))


def _detached_envelope(value: object) -> EvidenceEnvelope:
    if type(value) is not EvidenceEnvelope:
        raise TypeError("envelope must be EvidenceEnvelope")
    return evidence_envelope_from_dict(evidence_envelope_dict(value))


def _reference_matches_query(
    reference: EvidenceReference,
    arguments: PrivateAnalysisQueryArguments,
) -> bool:
    matches = (
        (not arguments.evidence_kinds or reference.kind in arguments.evidence_kinds)
        and (not arguments.node_ids or reference.revision.node_id in arguments.node_ids)
        and (
            not arguments.producer_ids
            or reference.producer.producer_id in arguments.producer_ids
        )
        and (
            not arguments.subject_kinds
            or reference.subject_kind in arguments.subject_kinds
        )
    )
    if not matches or arguments.time_basis is None:
        return matches
    time_range = reference.time_range
    if not (
        time_range.basis is arguments.time_basis
        and time_range.clock_domain == arguments.time_clock_domain
        and time_range.start_ns is not None
        and time_range.end_ns is not None
    ):
        return False
    uncertainty = time_range.uncertainty_ns or 0
    minimum = (
        0 if time_range.basis is EvidenceTimeBasis.ABSOLUTE_UNIX_NS else _MIN_SIGNED_NS
    )
    start = max(minimum, time_range.start_ns - uncertainty)
    end = min(_MAX_SIGNED_NS, time_range.end_ns + uncertainty)
    return start <= arguments.time_end_ns and end >= arguments.time_start_ns


def _validate_capability_result_payload(
    arguments: PrivateAnalysisCapabilityArguments,
    payload: object,
) -> None:
    item = exact_json_object(
        payload,
        "derived evidence payload",
        {
            "arguments_digest",
            "intent",
            "parent_reference_digests",
            "observations",
        },
    )
    if item["arguments_digest"] != arguments.arguments_digest:
        raise ValueError("derived evidence arguments digest does not match")
    if item["intent"] != arguments.intent.value:
        raise ValueError("derived evidence intent does not match")
    parents = _wire_list(
        item["parent_reference_digests"],
        "derived evidence parent_reference_digests",
        MAX_PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_ITEMS,
    )
    if tuple(parents) != arguments.parent_reference_digests:
        raise ValueError("derived evidence parent references do not match")
    observations = _wire_list(
        item["observations"],
        "derived evidence observations",
        arguments.max_observations,
    )
    observation_ids: list[str] = []
    admitted = frozenset(arguments.parent_reference_digests)
    for index, raw_observation in enumerate(observations):
        label = f"derived evidence observations[{index}]"
        observation = exact_json_object(
            raw_observation,
            label,
            {
                "observation_id",
                "category",
                "summary",
                "cited_reference_digests",
                "quality",
                "details",
            },
        )
        observation_id = validate_evidence_identifier(
            observation["observation_id"],
            f"{label}.observation_id",
        )
        validate_evidence_identifier(
            observation["category"],
            f"{label}.category",
        )
        summary = observation["summary"]
        if (
            type(summary) is not str
            or not 1 <= len(summary) <= 8_192
            or "\x00" in summary
        ):
            raise ValueError(f"{label}.summary is invalid")
        citations = _wire_list(
            observation["cited_reference_digests"],
            f"{label}.cited_reference_digests",
            MAX_PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_ITEMS,
        )
        if not citations:
            raise ValueError(f"{label} requires at least one citation")
        for digest in citations:
            _prefixed_sha256(digest, f"{label}.citation")
        if (
            tuple(sorted(citations)) != tuple(citations)
            or len(set(citations)) != len(citations)
        ):
            raise ValueError(f"{label}.citations must be unique and ordered")
        if any(digest not in admitted for digest in citations):
            raise ValueError(f"{label} cites evidence outside its request")
        strict_string_enum(
            _PrivateAnalysisEvidenceQuality,
            observation["quality"],
            f"{label}.quality",
        )
        details = validate_bounded_json_value(
            observation["details"],
            f"{label}.details",
            maximum_depth=12,
            maximum_container_items=512,
            maximum_units=2_048,
            maximum_atom_units=32_768,
            maximum_integer_bits=53,
            exact_types=True,
            allow_exact_tuples=False,
            maximum_encoded_bytes=524_288,
            snapshot=True,
        )
        if type(details) is not dict:
            raise TypeError(f"{label}.details must be an exact dictionary")
        observation_ids.append(observation_id)
    if (
        observation_ids != sorted(observation_ids)
        or len(set(observation_ids)) != len(observation_ids)
    ):
        raise ValueError("derived evidence observation IDs must be unique and ordered")


def _validate_capability_result_envelope(
    arguments: PrivateAnalysisCapabilityArguments,
    envelope: EvidenceEnvelope,
) -> None:
    reference = envelope.reference
    if reference.contract_version != EVIDENCE_REFERENCE_VERSION:
        raise ValueError("derived evidence requires the current reference contract")
    if (
        reference.kind is not EvidenceKind.PLUGIN_CAPABILITY_RESULT
        or reference.subject_kind
        != PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_SUBJECT_KIND
        or reference.payload_schema
        != PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_PAYLOAD_SCHEMA
        or reference.fact_provenance is not EvidenceFactProvenance.PLUGIN_ANALYZED
        or reference.producer.authority is not EvidenceAuthority.PLUGIN_INFERRED
        or reference.producer.plugin_instance_id is None
        or reference.producer.plugin_capability != "evidence_analysis"
        or reference.time_range.basis is not EvidenceTimeBasis.UNKNOWN
    ):
        raise ValueError("derived evidence has invalid capability provenance")
    if (
        reference.revision.revision_id != arguments.revision_id
        or reference.revision.node_id != arguments.node_id
        or reference.locator_digest
        != evidence_locator_digest(
            PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_SUBJECT_KIND,
            {"arguments_digest": arguments.arguments_digest},
        )
    ):
        raise ValueError("derived evidence does not match its capability request")
    _validate_capability_result_payload(arguments, envelope.payload)


@dataclass(frozen=True, slots=True)
class PrivateAnalysisToolResult(SealedContractValue):
    call: PrivateAnalysisToolCall
    kind: PrivateAnalysisToolResultKind
    snapshot_digest: str | None = None
    references: tuple[EvidenceReference, ...] = ()
    next_cursor: PrivateAnalysisCursor | None = None
    envelope: EvidenceEnvelope | None = None
    contract_version: str = PRIVATE_ANALYSIS_TOOL_RESULT_VERSION
    result_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_TOOL_RESULT_VERSION,
            "private-analysis tool result",
        )
        call = _detached_call(self.call)
        if type(self.kind) is not PrivateAnalysisToolResultKind:
            raise TypeError("kind must be PrivateAnalysisToolResultKind")
        references = _exact_tuple(
            self.references,
            "references",
            MAX_PRIVATE_ANALYSIS_QUERY_REFERENCES,
        )
        detached_references = tuple(_detached_reference(item) for item in references)
        reference_digests = tuple(item.reference_digest for item in detached_references)
        if tuple(sorted(reference_digests)) != reference_digests:
            raise ValueError("references must use canonical digest order")
        if len(set(reference_digests)) != len(reference_digests):
            raise ValueError("references must be unique")
        next_cursor = (
            None if self.next_cursor is None else _detached_cursor(self.next_cursor)
        )
        envelope = None if self.envelope is None else _detached_envelope(self.envelope)
        if self.kind is PrivateAnalysisToolResultKind.QUERY_PAGE:
            if call.binding.name is not PrivateAnalysisToolName.QUERY_EVIDENCE:
                raise ValueError("query-page result requires query_evidence")
            if type(call.arguments) is not PrivateAnalysisQueryArguments:
                raise TypeError("query-page call has invalid arguments")
            _prefixed_sha256(self.snapshot_digest, "snapshot_digest")
            if len(detached_references) > call.arguments.page_size:
                raise ValueError("query page exceeds the requested page_size")
            if any(
                not _reference_matches_query(reference, call.arguments)
                for reference in detached_references
            ):
                raise ValueError("query page contains a reference outside its filters")
            incoming_cursor = call.arguments.cursor
            if incoming_cursor is not None:
                if incoming_cursor.snapshot_digest != self.snapshot_digest:
                    raise ValueError("query page belongs to another evidence snapshot")
                if any(
                    digest <= incoming_cursor.after_reference_digest
                    for digest in reference_digests
                ):
                    raise ValueError("query page does not follow its input cursor")
            if envelope is not None:
                raise ValueError("query-page result must not contain an envelope")
            if not detached_references and next_cursor is not None:
                raise ValueError("an empty query page cannot continue")
            if next_cursor is not None:
                if next_cursor.request_digest != call.binding.request_digest:
                    raise ValueError("next cursor belongs to another request")
                if next_cursor.tool_catalog_digest != call.binding.tool_catalog_digest:
                    raise ValueError("next cursor belongs to another tool catalog")
                if next_cursor.query_digest != call.arguments.query_digest:
                    raise ValueError("next cursor belongs to another query")
                if next_cursor.snapshot_digest != self.snapshot_digest:
                    raise ValueError("next cursor belongs to another snapshot")
                if next_cursor.after_reference_digest != reference_digests[-1]:
                    raise ValueError("next cursor does not follow the query page")
        elif self.kind is PrivateAnalysisToolResultKind.EVIDENCE_ENVELOPE:
            if call.binding.name is not PrivateAnalysisToolName.READ_EVIDENCE:
                raise ValueError("evidence result requires read_evidence")
            if type(call.arguments) is not PrivateAnalysisReadArguments:
                raise TypeError("read result call has invalid arguments")
            if self.snapshot_digest is not None:
                raise ValueError("read result must not contain a snapshot digest")
            if detached_references or next_cursor is not None:
                raise ValueError("read result must not contain query-page values")
            if envelope is None:
                raise ValueError("read result requires an evidence envelope")
            if (
                envelope.reference.reference_digest
                != call.arguments.evidence_reference_digest
            ):
                raise ValueError("read result does not match the requested reference")
        else:
            if call.binding.name is not PrivateAnalysisToolName.ANALYZE_EVIDENCE:
                raise ValueError(
                    "derived-evidence result requires analyze_evidence"
                )
            if type(call.arguments) is not PrivateAnalysisCapabilityArguments:
                raise TypeError("derived-evidence result call has invalid arguments")
            if self.snapshot_digest is not None:
                raise ValueError(
                    "derived-evidence result must not contain a snapshot digest"
                )
            if detached_references or next_cursor is not None:
                raise ValueError(
                    "derived-evidence result must not contain query-page values"
                )
            if envelope is None:
                raise ValueError(
                    "derived-evidence result requires an evidence envelope"
                )
            _validate_capability_result_envelope(call.arguments, envelope)
        object.__setattr__(self, "call", call)
        object.__setattr__(self, "references", detached_references)
        object.__setattr__(self, "next_cursor", next_cursor)
        object.__setattr__(self, "envelope", envelope)
        if type(self.result_digest) is not str:
            raise TypeError("result_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(_tool_result_payload(self))
        if self.result_digest:
            _prefixed_sha256(self.result_digest, "result_digest")
            if self.result_digest != expected:
                raise ValueError("tool result digest does not match")
        else:
            object.__setattr__(self, "result_digest", expected)
        _canonical_json(
            _private_analysis_tool_result_dict_unchecked(self), "tool result"
        )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisToolError(SealedContractValue):
    call: PrivateAnalysisToolCall
    code: PrivateAnalysisToolErrorCode
    retryable: bool
    contract_version: str = PRIVATE_ANALYSIS_TOOL_ERROR_VERSION
    error_digest: str = ""

    def __post_init__(self) -> None:
        exact_contract_version(
            self.contract_version,
            PRIVATE_ANALYSIS_TOOL_ERROR_VERSION,
            "private-analysis tool error",
        )
        call = _detached_call(self.call)
        if type(self.code) is not PrivateAnalysisToolErrorCode:
            raise TypeError("code must be PrivateAnalysisToolErrorCode")
        if type(self.retryable) is not bool:
            raise TypeError("retryable must be a boolean")
        expected_retryable = self.code in _RETRYABLE_TOOL_ERRORS
        if self.retryable is not expected_retryable:
            raise ValueError("retryable does not match the tool error code")
        object.__setattr__(self, "call", call)
        if type(self.error_digest) is not str:
            raise TypeError("error_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(_tool_error_payload(self))
        if self.error_digest:
            _prefixed_sha256(self.error_digest, "error_digest")
            if self.error_digest != expected:
                raise ValueError("tool error digest does not match")
        else:
            object.__setattr__(self, "error_digest", expected)

    @property
    def safe_message(self) -> str:
        return _SAFE_TOOL_ERROR_MESSAGES[self.code]


def evidence_snapshot_digest(references: tuple[EvidenceReference, ...]) -> str:
    """Hash one immutable eligible reference set independent of input order."""

    items = _exact_tuple(
        references,
        "snapshot references",
        MAX_PRIVATE_ANALYSIS_SNAPSHOT_REFERENCES,
    )
    digests = sorted(_detached_reference(item).reference_digest for item in items)
    if len(set(digests)) != len(digests):
        raise ValueError("snapshot references must be unique")
    return "sha256:" + strict_canonical_json_sha256(
        {
            "snapshot_version": PRIVATE_ANALYSIS_EVIDENCE_SNAPSHOT_VERSION,
            "reference_digests": digests,
        }
    )


def make_private_analysis_cursor(
    call: PrivateAnalysisToolCall,
    *,
    snapshot_digest: str,
    after_reference_digest: str,
) -> PrivateAnalysisCursor:
    """Create a cursor for the exact query call and immutable snapshot."""

    call = _detached_call(call)
    if call.binding.name is not PrivateAnalysisToolName.QUERY_EVIDENCE:
        raise ValueError("cursor creation requires query_evidence")
    if type(call.arguments) is not PrivateAnalysisQueryArguments:
        raise TypeError("query call has invalid arguments")
    return PrivateAnalysisCursor(
        request_digest=call.binding.request_digest,
        tool_catalog_digest=call.binding.tool_catalog_digest,
        query_digest=call.arguments.query_digest,
        snapshot_digest=snapshot_digest,
        after_reference_digest=after_reference_digest,
    )


def make_private_analysis_query_page(
    call: PrivateAnalysisToolCall,
    eligible_references: tuple[EvidenceReference, ...],
) -> PrivateAnalysisToolResult:
    """Page an already-authorized, disclosure-eligible immutable reference set.

    The caller remains responsible for producing that eligible set from the
    exact request scope and current policy.  This pure helper performs no
    lookup and owns only deterministic ordering and cursor replay checks.
    """

    call = _detached_call(call)
    if call.binding.name is not PrivateAnalysisToolName.QUERY_EVIDENCE:
        raise ValueError("query paging requires query_evidence")
    if type(call.arguments) is not PrivateAnalysisQueryArguments:
        raise TypeError("query call has invalid arguments")
    raw_references = _exact_tuple(
        eligible_references,
        "eligible_references",
        MAX_PRIVATE_ANALYSIS_SNAPSHOT_REFERENCES,
    )
    references = tuple(
        sorted(
            (_detached_reference(item) for item in raw_references),
            key=lambda item: item.reference_digest,
        )
    )
    digests = tuple(item.reference_digest for item in references)
    if len(set(digests)) != len(digests):
        raise ValueError("eligible_references must be unique")
    if any(
        not _reference_matches_query(reference, call.arguments)
        for reference in references
    ):
        raise ValueError("eligible_references contain an item outside the query")
    snapshot_digest = evidence_snapshot_digest(references)
    start = 0
    cursor = call.arguments.cursor
    if cursor is not None:
        if cursor.snapshot_digest != snapshot_digest:
            raise ValueError("cursor belongs to another evidence snapshot")
        try:
            start = digests.index(cursor.after_reference_digest) + 1
        except ValueError as error:
            raise ValueError(
                "cursor boundary is not in the eligible evidence snapshot"
            ) from error
    stop = min(start + call.arguments.page_size, len(references))
    page = references[start:stop]
    next_cursor = None
    if stop < len(references) and page:
        next_cursor = make_private_analysis_cursor(
            call,
            snapshot_digest=snapshot_digest,
            after_reference_digest=page[-1].reference_digest,
        )
    return PrivateAnalysisToolResult(
        call=call,
        kind=PrivateAnalysisToolResultKind.QUERY_PAGE,
        snapshot_digest=snapshot_digest,
        references=page,
        next_cursor=next_cursor,
    )


def make_private_analysis_query_page_from_snapshot(
    call: PrivateAnalysisToolCall,
    page_references: tuple[EvidenceReference, ...],
    *,
    snapshot_digest: str,
    has_more: bool,
) -> PrivateAnalysisToolResult:
    """Build one page from an already-frozen, keyset-addressed snapshot.

    Unlike :func:`make_private_analysis_query_page`, this helper never receives
    or reconstructs the complete candidate set.  The trusted query adapter
    supplies the snapshot digest and whether a later key exists.
    """

    call = _detached_call(call)
    if call.binding.name is not PrivateAnalysisToolName.QUERY_EVIDENCE:
        raise ValueError("query paging requires query_evidence")
    if type(call.arguments) is not PrivateAnalysisQueryArguments:
        raise TypeError("query call has invalid arguments")
    _prefixed_sha256(snapshot_digest, "snapshot_digest")
    if type(has_more) is not bool:
        raise TypeError("has_more must be a boolean")
    raw_references = _exact_tuple(
        page_references,
        "page_references",
        MAX_PRIVATE_ANALYSIS_QUERY_REFERENCES,
    )
    references = tuple(_detached_reference(item) for item in raw_references)
    digests = tuple(item.reference_digest for item in references)
    if tuple(sorted(digests)) != digests or len(set(digests)) != len(digests):
        raise ValueError("page_references must be unique and canonically ordered")
    if len(references) > call.arguments.page_size:
        raise ValueError("page_references exceed the requested page_size")
    if any(
        not _reference_matches_query(reference, call.arguments)
        for reference in references
    ):
        raise ValueError("page_references contain an item outside the query")
    cursor = call.arguments.cursor
    if cursor is not None:
        if cursor.snapshot_digest != snapshot_digest:
            raise ValueError("cursor belongs to another evidence snapshot")
        if any(digest <= cursor.after_reference_digest for digest in digests):
            raise ValueError("page does not follow its input cursor")
    if has_more and not references:
        raise ValueError("an empty query page cannot continue")
    next_cursor = (
        make_private_analysis_cursor(
            call,
            snapshot_digest=snapshot_digest,
            after_reference_digest=references[-1].reference_digest,
        )
        if has_more
        else None
    )
    return PrivateAnalysisToolResult(
        call=call,
        kind=PrivateAnalysisToolResultKind.QUERY_PAGE,
        snapshot_digest=snapshot_digest,
        references=references,
        next_cursor=next_cursor,
    )


def _tool_definition_payload(
    value: PrivateAnalysisToolDefinition,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "name": value.name.value,
        "arguments_contract_version": value.arguments_contract_version,
        "result_contract_version": value.result_contract_version,
    }


def private_analysis_tool_definition_dict(
    value: PrivateAnalysisToolDefinition,
) -> dict[str, object]:
    if type(value) is not PrivateAnalysisToolDefinition:
        raise TypeError("value must be PrivateAnalysisToolDefinition")
    value = PrivateAnalysisToolDefinition(
        name=value.name,
        arguments_contract_version=value.arguments_contract_version,
        result_contract_version=value.result_contract_version,
        contract_version=value.contract_version,
        definition_digest=value.definition_digest,
    )
    result = _tool_definition_payload(value)
    result["definition_digest"] = value.definition_digest
    return result


def _tool_catalog_payload(value: PrivateAnalysisToolCatalog) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "tools": [private_analysis_tool_definition_dict(item) for item in value.tools],
    }


def private_analysis_tool_catalog_dict(
    value: PrivateAnalysisToolCatalog,
) -> dict[str, object]:
    if type(value) is not PrivateAnalysisToolCatalog:
        raise TypeError("value must be PrivateAnalysisToolCatalog")
    value = PrivateAnalysisToolCatalog(
        tools=value.tools,
        contract_version=value.contract_version,
        catalog_digest=value.catalog_digest,
    )
    result = _tool_catalog_payload(value)
    result["catalog_digest"] = value.catalog_digest
    return result


def _tool_binding_payload(value: PrivateAnalysisToolBinding) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "request_digest": value.request_digest,
        "tool_catalog_digest": value.tool_catalog_digest,
        "name": value.name.value,
    }


def private_analysis_tool_binding_dict(
    value: PrivateAnalysisToolBinding,
) -> dict[str, object]:
    value = _detached_binding(value)
    result = _tool_binding_payload(value)
    result["binding_digest"] = value.binding_digest
    return result


def _cursor_payload(value: PrivateAnalysisCursor) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "request_digest": value.request_digest,
        "tool_catalog_digest": value.tool_catalog_digest,
        "query_digest": value.query_digest,
        "snapshot_digest": value.snapshot_digest,
        "after_reference_digest": value.after_reference_digest,
    }


def private_analysis_cursor_dict(value: PrivateAnalysisCursor) -> dict[str, object]:
    value = _detached_cursor(value)
    result = _cursor_payload(value)
    result["cursor_digest"] = value.cursor_digest
    return result


def _query_fingerprint_payload(
    value: PrivateAnalysisQueryArguments,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "ordering": "reference_digest_ascending.v1",
        "evidence_kinds": [item.value for item in value.evidence_kinds],
        "node_ids": list(value.node_ids),
        "producer_ids": list(value.producer_ids),
        "subject_kinds": list(value.subject_kinds),
        "time_basis": None if value.time_basis is None else value.time_basis.value,
        "time_start_ns": (
            None if value.time_start_ns is None else str(value.time_start_ns)
        ),
        "time_end_ns": None if value.time_end_ns is None else str(value.time_end_ns),
        "time_clock_domain": value.time_clock_domain,
        "page_size": value.page_size,
    }


def private_analysis_query_arguments_dict(
    value: PrivateAnalysisQueryArguments,
) -> dict[str, object]:
    value = _detached_query_arguments(value)
    result = _query_fingerprint_payload(value)
    result.pop("ordering")
    result["cursor"] = (
        None if value.cursor is None else private_analysis_cursor_dict(value.cursor)
    )
    result["query_digest"] = value.query_digest
    return result


def _read_arguments_payload(
    value: PrivateAnalysisReadArguments,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "evidence_reference_digest": value.evidence_reference_digest,
    }


def private_analysis_read_arguments_dict(
    value: PrivateAnalysisReadArguments,
) -> dict[str, object]:
    value = _detached_read_arguments(value)
    result = _read_arguments_payload(value)
    result["arguments_digest"] = value.arguments_digest
    return result


def _capability_arguments_payload(
    value: PrivateAnalysisCapabilityArguments,
) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "node_id": value.node_id,
        "revision_id": value.revision_id,
        "intent": value.intent.value,
        "parent_reference_digests": list(value.parent_reference_digests),
        "parameters": value.parameters,
        "max_observations": value.max_observations,
    }


def private_analysis_capability_arguments_dict(
    value: PrivateAnalysisCapabilityArguments,
) -> dict[str, object]:
    value = _detached_capability_arguments(value)
    result = _capability_arguments_payload(value)
    result["arguments_digest"] = value.arguments_digest
    return result


def _tool_call_payload(value: PrivateAnalysisToolCall) -> dict[str, object]:
    if isinstance(value.arguments, PrivateAnalysisQueryArguments):
        arguments = private_analysis_query_arguments_dict(value.arguments)
    elif isinstance(value.arguments, PrivateAnalysisReadArguments):
        arguments = private_analysis_read_arguments_dict(value.arguments)
    elif isinstance(value.arguments, PrivateAnalysisCapabilityArguments):
        arguments = private_analysis_capability_arguments_dict(value.arguments)
    else:
        raise TypeError("tool call contains unsupported arguments")
    return {
        "contract_version": value.contract_version,
        "call_id": value.call_id,
        "binding": private_analysis_tool_binding_dict(value.binding),
        "arguments": arguments,
    }


def private_analysis_tool_call_dict(
    value: PrivateAnalysisToolCall,
) -> dict[str, object]:
    value = _detached_call(value)
    result = _tool_call_payload(value)
    result["call_digest"] = value.call_digest
    return result


def _tool_result_payload(value: PrivateAnalysisToolResult) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "call": private_analysis_tool_call_dict(value.call),
        "kind": value.kind.value,
        "payload_contract_version": (
            PRIVATE_ANALYSIS_QUERY_PAGE_VERSION
            if value.kind is PrivateAnalysisToolResultKind.QUERY_PAGE
            else (
                PRIVATE_ANALYSIS_READ_RESULT_VERSION
                if value.kind is PrivateAnalysisToolResultKind.EVIDENCE_ENVELOPE
                else PRIVATE_ANALYSIS_CAPABILITY_RESULT_VERSION
            )
        ),
        "snapshot_digest": value.snapshot_digest,
        "references": [evidence_reference_dict(item) for item in value.references],
        "next_cursor": (
            None
            if value.next_cursor is None
            else private_analysis_cursor_dict(value.next_cursor)
        ),
        "envelope": (
            None if value.envelope is None else evidence_envelope_dict(value.envelope)
        ),
    }


def _private_analysis_tool_result_dict_unchecked(
    value: PrivateAnalysisToolResult,
) -> dict[str, object]:
    result = _tool_result_payload(value)
    result["result_digest"] = value.result_digest
    return result


def private_analysis_tool_result_dict(
    value: PrivateAnalysisToolResult,
) -> dict[str, object]:
    if type(value) is not PrivateAnalysisToolResult:
        raise TypeError("value must be PrivateAnalysisToolResult")
    value.__post_init__()
    return _private_analysis_tool_result_dict_unchecked(value)


def _tool_error_payload(value: PrivateAnalysisToolError) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "call": private_analysis_tool_call_dict(value.call),
        "code": value.code.value,
        "retryable": value.retryable,
    }


def private_analysis_tool_error_dict(
    value: PrivateAnalysisToolError,
) -> dict[str, object]:
    if type(value) is not PrivateAnalysisToolError:
        raise TypeError("value must be PrivateAnalysisToolError")
    value.__post_init__()
    result = _tool_error_payload(value)
    result["error_digest"] = value.error_digest
    return result


def private_analysis_tool_definition_from_dict(
    value: object,
) -> PrivateAnalysisToolDefinition:
    item = exact_json_object(
        value,
        "tool definition",
        {
            "contract_version",
            "name",
            "arguments_contract_version",
            "result_contract_version",
            "definition_digest",
        },
    )
    return PrivateAnalysisToolDefinition(
        contract_version=item["contract_version"],
        name=strict_string_enum(
            PrivateAnalysisToolName,
            item["name"],
            "tool name",
        ),
        arguments_contract_version=item["arguments_contract_version"],
        result_contract_version=item["result_contract_version"],
        definition_digest=_prefixed_sha256(
            item["definition_digest"],
            "definition_digest",
        ),
    )


def private_analysis_tool_catalog_from_dict(
    value: object,
) -> PrivateAnalysisToolCatalog:
    item = exact_json_object(
        value,
        "tool catalog",
        {"contract_version", "tools", "catalog_digest"},
    )
    tools = _wire_list(item["tools"], "tools", len(_TOOL_ORDER))
    return PrivateAnalysisToolCatalog(
        contract_version=item["contract_version"],
        tools=tuple(private_analysis_tool_definition_from_dict(tool) for tool in tools),
        catalog_digest=_prefixed_sha256(item["catalog_digest"], "catalog_digest"),
    )


def private_analysis_tool_binding_from_dict(
    value: object,
) -> PrivateAnalysisToolBinding:
    item = exact_json_object(
        value,
        "tool binding",
        {
            "contract_version",
            "request_digest",
            "tool_catalog_digest",
            "name",
            "binding_digest",
        },
    )
    return PrivateAnalysisToolBinding(
        contract_version=item["contract_version"],
        request_digest=item["request_digest"],
        tool_catalog_digest=item["tool_catalog_digest"],
        name=strict_string_enum(
            PrivateAnalysisToolName,
            item["name"],
            "tool name",
        ),
        binding_digest=_prefixed_sha256(item["binding_digest"], "binding_digest"),
    )


def private_analysis_cursor_from_dict(value: object) -> PrivateAnalysisCursor:
    item = exact_json_object(
        value,
        "query cursor",
        {
            "contract_version",
            "request_digest",
            "tool_catalog_digest",
            "query_digest",
            "snapshot_digest",
            "after_reference_digest",
            "cursor_digest",
        },
    )
    return PrivateAnalysisCursor(
        contract_version=item["contract_version"],
        request_digest=item["request_digest"],
        tool_catalog_digest=item["tool_catalog_digest"],
        query_digest=item["query_digest"],
        snapshot_digest=item["snapshot_digest"],
        after_reference_digest=item["after_reference_digest"],
        cursor_digest=_prefixed_sha256(item["cursor_digest"], "cursor_digest"),
    )


def private_analysis_query_arguments_from_dict(
    value: object,
) -> PrivateAnalysisQueryArguments:
    item = exact_json_object(
        value,
        "query-evidence arguments",
        {
            "contract_version",
            "evidence_kinds",
            "node_ids",
            "producer_ids",
            "subject_kinds",
            "time_basis",
            "time_start_ns",
            "time_end_ns",
            "time_clock_domain",
            "page_size",
            "cursor",
            "query_digest",
        },
    )
    raw_kinds = _wire_list(
        item["evidence_kinds"],
        "evidence_kinds",
        len(EvidenceKind),
    )
    raw_nodes = _wire_list(
        item["node_ids"],
        "node_ids",
        MAX_PRIVATE_ANALYSIS_QUERY_FILTER_ITEMS,
    )
    raw_producers = _wire_list(
        item["producer_ids"],
        "producer_ids",
        MAX_PRIVATE_ANALYSIS_QUERY_FILTER_ITEMS,
    )
    raw_subjects = _wire_list(
        item["subject_kinds"],
        "subject_kinds",
        MAX_PRIVATE_ANALYSIS_QUERY_FILTER_ITEMS,
    )
    cursor_value = item["cursor"]
    raw_time_basis = item["time_basis"]
    return PrivateAnalysisQueryArguments(
        contract_version=item["contract_version"],
        evidence_kinds=tuple(
            strict_string_enum(EvidenceKind, kind, "evidence kind")
            for kind in raw_kinds
        ),
        node_ids=tuple(raw_nodes),
        producer_ids=tuple(raw_producers),
        subject_kinds=tuple(raw_subjects),
        time_basis=(
            None
            if raw_time_basis is None
            else strict_string_enum(
                EvidenceTimeBasis,
                raw_time_basis,
                "evidence time basis",
            )
        ),
        time_start_ns=(
            None
            if item["time_start_ns"] is None
            else bounded_canonical_decimal_integer(
                item["time_start_ns"],
                "time_start_ns",
                minimum=_MIN_SIGNED_NS,
                maximum=_MAX_SIGNED_NS,
            )
        ),
        time_end_ns=(
            None
            if item["time_end_ns"] is None
            else bounded_canonical_decimal_integer(
                item["time_end_ns"],
                "time_end_ns",
                minimum=_MIN_SIGNED_NS,
                maximum=_MAX_SIGNED_NS,
            )
        ),
        time_clock_domain=item["time_clock_domain"],
        page_size=item["page_size"],
        cursor=(
            None
            if cursor_value is None
            else private_analysis_cursor_from_dict(cursor_value)
        ),
        query_digest=_prefixed_sha256(item["query_digest"], "query_digest"),
    )


def private_analysis_read_arguments_from_dict(
    value: object,
) -> PrivateAnalysisReadArguments:
    item = exact_json_object(
        value,
        "read-evidence arguments",
        {
            "contract_version",
            "evidence_reference_digest",
            "arguments_digest",
        },
    )
    return PrivateAnalysisReadArguments(
        contract_version=item["contract_version"],
        evidence_reference_digest=item["evidence_reference_digest"],
        arguments_digest=_prefixed_sha256(
            item["arguments_digest"],
            "arguments_digest",
        ),
    )


def private_analysis_capability_arguments_from_dict(
    value: object,
) -> PrivateAnalysisCapabilityArguments:
    item = exact_json_object(
        value,
        "analyze-evidence arguments",
        {
            "contract_version",
            "node_id",
            "revision_id",
            "intent",
            "parent_reference_digests",
            "parameters",
            "max_observations",
            "arguments_digest",
        },
    )
    raw_digests = _wire_list(
        item["parent_reference_digests"],
        "parent_reference_digests",
        MAX_PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_ITEMS,
    )
    parameters = validate_bounded_json_value(
        item["parameters"],
        "capability parameters",
        maximum_depth=8,
        maximum_container_items=256,
        maximum_units=1_024,
        maximum_atom_units=8_192,
        maximum_integer_bits=53,
        exact_types=True,
        allow_exact_tuples=False,
        maximum_encoded_bytes=262_144,
        snapshot=True,
    )
    if type(parameters) is not dict:
        raise TypeError("capability parameters must be an exact dictionary")
    return PrivateAnalysisCapabilityArguments(
        contract_version=item["contract_version"],
        node_id=item["node_id"],
        revision_id=item["revision_id"],
        intent=strict_string_enum(
            PrivateAnalysisCapabilityIntent,
            item["intent"],
            "capability intent",
        ),
        parent_reference_digests=tuple(raw_digests),
        parameters_json=strict_canonical_json(parameters),
        max_observations=item["max_observations"],
        arguments_digest=_prefixed_sha256(
            item["arguments_digest"],
            "arguments_digest",
        ),
    )
def private_analysis_tool_call_from_dict(value: object) -> PrivateAnalysisToolCall:
    item = exact_json_object(
        value,
        "tool call",
        {"contract_version", "call_id", "binding", "arguments", "call_digest"},
    )
    binding = private_analysis_tool_binding_from_dict(item["binding"])
    arguments: PrivateAnalysisToolArguments
    if binding.name is PrivateAnalysisToolName.QUERY_EVIDENCE:
        arguments = private_analysis_query_arguments_from_dict(item["arguments"])
    elif binding.name is PrivateAnalysisToolName.READ_EVIDENCE:
        arguments = private_analysis_read_arguments_from_dict(item["arguments"])
    else:
        arguments = private_analysis_capability_arguments_from_dict(
            item["arguments"]
        )
    return PrivateAnalysisToolCall(
        contract_version=item["contract_version"],
        call_id=item["call_id"],
        binding=binding,
        arguments=arguments,
        call_digest=_prefixed_sha256(item["call_digest"], "call_digest"),
    )


def private_analysis_tool_result_from_dict(
    value: object,
) -> PrivateAnalysisToolResult:
    snapshot = validate_bounded_json_value(
        value,
        "tool result",
        maximum_depth=24,
        maximum_container_items=1_024,
        maximum_units=100_000,
        maximum_atom_units=1_048_576,
        maximum_integer_bits=53,
        exact_types=True,
        allow_exact_tuples=False,
        maximum_encoded_bytes=MAX_PRIVATE_ANALYSIS_TOOL_WIRE_BYTES,
        snapshot=True,
    )
    if type(snapshot) is not dict:
        raise TypeError("tool result must be an exact dictionary")
    item = exact_json_object(
        snapshot,
        "tool result",
        {
            "contract_version",
            "call",
            "kind",
            "payload_contract_version",
            "snapshot_digest",
            "references",
            "next_cursor",
            "envelope",
            "result_digest",
        },
    )
    call = private_analysis_tool_call_from_dict(item["call"])
    kind = strict_string_enum(
        PrivateAnalysisToolResultKind,
        item["kind"],
        "tool result kind",
    )
    expected_payload_version = {
        PrivateAnalysisToolResultKind.QUERY_PAGE: (
            PRIVATE_ANALYSIS_QUERY_PAGE_VERSION
        ),
        PrivateAnalysisToolResultKind.EVIDENCE_ENVELOPE: (
            PRIVATE_ANALYSIS_READ_RESULT_VERSION
        ),
        PrivateAnalysisToolResultKind.DERIVED_EVIDENCE_ENVELOPE: (
            PRIVATE_ANALYSIS_CAPABILITY_RESULT_VERSION
        ),
    }[kind]
    exact_contract_version(
        item["payload_contract_version"],
        expected_payload_version,
        "tool result payload",
    )
    raw_references = _wire_list(
        item["references"],
        "references",
        MAX_PRIVATE_ANALYSIS_QUERY_REFERENCES,
    )
    next_cursor_value = item["next_cursor"]
    envelope_value = item["envelope"]
    result = PrivateAnalysisToolResult(
        contract_version=item["contract_version"],
        call=call,
        kind=kind,
        snapshot_digest=item["snapshot_digest"],
        references=tuple(
            evidence_reference_from_dict(reference) for reference in raw_references
        ),
        next_cursor=(
            None
            if next_cursor_value is None
            else private_analysis_cursor_from_dict(next_cursor_value)
        ),
        envelope=(
            None
            if envelope_value is None
            else evidence_envelope_from_dict(envelope_value)
        ),
        result_digest=_prefixed_sha256(item["result_digest"], "result_digest"),
    )
    _canonical_json(private_analysis_tool_result_dict(result), "tool result")
    return result


def private_analysis_tool_error_from_dict(
    value: object,
) -> PrivateAnalysisToolError:
    item = exact_json_object(
        value,
        "tool error",
        {"contract_version", "call", "code", "retryable", "error_digest"},
    )
    return PrivateAnalysisToolError(
        contract_version=item["contract_version"],
        call=private_analysis_tool_call_from_dict(item["call"]),
        code=strict_string_enum(
            PrivateAnalysisToolErrorCode,
            item["code"],
            "tool error code",
        ),
        retryable=item["retryable"],
        error_digest=_prefixed_sha256(item["error_digest"], "error_digest"),
    )


def private_analysis_tool_catalog_json(value: PrivateAnalysisToolCatalog) -> str:
    return _canonical_json(
        private_analysis_tool_catalog_dict(value),
        "tool catalog",
    )


def private_analysis_tool_definition_json(
    value: PrivateAnalysisToolDefinition,
) -> str:
    return _canonical_json(
        private_analysis_tool_definition_dict(value),
        "tool definition",
    )


def private_analysis_tool_binding_json(
    value: PrivateAnalysisToolBinding,
) -> str:
    return _canonical_json(
        private_analysis_tool_binding_dict(value),
        "tool binding",
    )


def private_analysis_cursor_json(value: PrivateAnalysisCursor) -> str:
    return _canonical_json(private_analysis_cursor_dict(value), "cursor")


def private_analysis_query_arguments_json(
    value: PrivateAnalysisQueryArguments,
) -> str:
    return _canonical_json(
        private_analysis_query_arguments_dict(value),
        "query arguments",
    )


def private_analysis_read_arguments_json(
    value: PrivateAnalysisReadArguments,
) -> str:
    return _canonical_json(
        private_analysis_read_arguments_dict(value),
        "read arguments",
    )


def private_analysis_capability_arguments_json(
    value: PrivateAnalysisCapabilityArguments,
) -> str:
    return _canonical_json(
        private_analysis_capability_arguments_dict(value),
        "capability arguments",
    )


def private_analysis_tool_call_json(value: PrivateAnalysisToolCall) -> str:
    return _canonical_json(private_analysis_tool_call_dict(value), "tool call")


def private_analysis_tool_result_json(value: PrivateAnalysisToolResult) -> str:
    return _canonical_json(
        private_analysis_tool_result_dict(value),
        "tool result",
    )


def private_analysis_tool_error_json(value: PrivateAnalysisToolError) -> str:
    return _canonical_json(
        private_analysis_tool_error_dict(value),
        "tool error",
    )


def private_analysis_tool_catalog_from_json(value: str) -> PrivateAnalysisToolCatalog:
    return private_analysis_tool_catalog_from_dict(
        _load_canonical_json(value, "tool catalog")
    )


def private_analysis_tool_definition_from_json(
    value: str,
) -> PrivateAnalysisToolDefinition:
    return private_analysis_tool_definition_from_dict(
        _load_canonical_json(value, "tool definition")
    )


def private_analysis_tool_binding_from_json(
    value: str,
) -> PrivateAnalysisToolBinding:
    return private_analysis_tool_binding_from_dict(
        _load_canonical_json(value, "tool binding")
    )


def private_analysis_cursor_from_json(value: str) -> PrivateAnalysisCursor:
    return private_analysis_cursor_from_dict(_load_canonical_json(value, "cursor"))


def private_analysis_query_arguments_from_json(
    value: str,
) -> PrivateAnalysisQueryArguments:
    return private_analysis_query_arguments_from_dict(
        _load_canonical_json(value, "query arguments")
    )


def private_analysis_read_arguments_from_json(
    value: str,
) -> PrivateAnalysisReadArguments:
    return private_analysis_read_arguments_from_dict(
        _load_canonical_json(value, "read arguments")
    )


def private_analysis_capability_arguments_from_json(
    value: str,
) -> PrivateAnalysisCapabilityArguments:
    return private_analysis_capability_arguments_from_dict(
        _load_canonical_json(value, "capability arguments")
    )


def private_analysis_tool_call_from_json(value: str) -> PrivateAnalysisToolCall:
    return private_analysis_tool_call_from_dict(
        _load_canonical_json(value, "tool call")
    )


def private_analysis_tool_result_from_json(
    value: str,
) -> PrivateAnalysisToolResult:
    return private_analysis_tool_result_from_dict(
        _load_canonical_json(value, "tool result")
    )


def private_analysis_tool_error_from_json(value: str) -> PrivateAnalysisToolError:
    return private_analysis_tool_error_from_dict(
        _load_canonical_json(value, "tool error")
    )


__all__ = [
    "MAX_PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_ITEMS",
    "MAX_PRIVATE_ANALYSIS_CAPABILITY_OBSERVATIONS",
    "MAX_PRIVATE_ANALYSIS_QUERY_FILTER_ITEMS",
    "MAX_PRIVATE_ANALYSIS_QUERY_PAGE_SIZE",
    "MAX_PRIVATE_ANALYSIS_SNAPSHOT_REFERENCES",
    "MAX_PRIVATE_ANALYSIS_TOOL_WIRE_BYTES",
    "PRIVATE_ANALYSIS_CAPABILITY_ARGUMENTS_VERSION",
    "PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_PAYLOAD_SCHEMA",
    "PRIVATE_ANALYSIS_CAPABILITY_EVIDENCE_SUBJECT_KIND",
    "PRIVATE_ANALYSIS_CAPABILITY_RESULT_VERSION",
    "PRIVATE_ANALYSIS_CURSOR_VERSION",
    "PRIVATE_ANALYSIS_EVIDENCE_SNAPSHOT_VERSION",
    "PRIVATE_ANALYSIS_QUERY_ARGUMENTS_VERSION",
    "PRIVATE_ANALYSIS_QUERY_PAGE_VERSION",
    "PRIVATE_ANALYSIS_READ_ARGUMENTS_VERSION",
    "PRIVATE_ANALYSIS_READ_RESULT_VERSION",
    "PRIVATE_ANALYSIS_TOOL_BINDING_VERSION",
    "PRIVATE_ANALYSIS_TOOL_CALL_VERSION",
    "PRIVATE_ANALYSIS_TOOL_CATALOG_VERSION",
    "PRIVATE_ANALYSIS_TOOL_DEFINITION_VERSION",
    "PRIVATE_ANALYSIS_TOOL_ERROR_VERSION",
    "PRIVATE_ANALYSIS_TOOL_RESULT_VERSION",
    "PrivateAnalysisCapabilityArguments",
    "PrivateAnalysisCapabilityIntent",
    "PrivateAnalysisCursor",
    "PrivateAnalysisEvidenceCursorInvalidError",
    "PrivateAnalysisEvidenceQueryPage",
    "PrivateAnalysisQueryArguments",
    "PrivateAnalysisReadArguments",
    "PrivateAnalysisToolArguments",
    "PrivateAnalysisToolBinding",
    "PrivateAnalysisToolCall",
    "PrivateAnalysisToolCatalog",
    "PrivateAnalysisToolDefinition",
    "PrivateAnalysisToolError",
    "PrivateAnalysisToolErrorCode",
    "PrivateAnalysisToolName",
    "PrivateAnalysisToolResult",
    "PrivateAnalysisToolResultKind",
    "default_private_analysis_tool_catalog",
    "evidence_snapshot_digest",
    "make_private_analysis_cursor",
    "make_private_analysis_query_page",
    "make_private_analysis_query_page_from_snapshot",
    "private_analysis_capability_arguments_dict",
    "private_analysis_capability_arguments_from_dict",
    "private_analysis_capability_arguments_from_json",
    "private_analysis_capability_arguments_json",
    "private_analysis_cursor_dict",
    "private_analysis_cursor_from_dict",
    "private_analysis_cursor_from_json",
    "private_analysis_cursor_json",
    "private_analysis_query_arguments_dict",
    "private_analysis_query_arguments_from_dict",
    "private_analysis_query_arguments_from_json",
    "private_analysis_query_arguments_json",
    "private_analysis_read_arguments_dict",
    "private_analysis_read_arguments_from_dict",
    "private_analysis_read_arguments_from_json",
    "private_analysis_read_arguments_json",
    "private_analysis_tool_binding_dict",
    "private_analysis_tool_binding_from_dict",
    "private_analysis_tool_binding_from_json",
    "private_analysis_tool_binding_json",
    "private_analysis_tool_call_dict",
    "private_analysis_tool_call_from_dict",
    "private_analysis_tool_call_from_json",
    "private_analysis_tool_call_json",
    "private_analysis_tool_catalog_dict",
    "private_analysis_tool_catalog_from_dict",
    "private_analysis_tool_catalog_from_json",
    "private_analysis_tool_catalog_json",
    "private_analysis_tool_definition_dict",
    "private_analysis_tool_definition_from_dict",
    "private_analysis_tool_definition_from_json",
    "private_analysis_tool_definition_json",
    "private_analysis_tool_error_dict",
    "private_analysis_tool_error_from_dict",
    "private_analysis_tool_error_from_json",
    "private_analysis_tool_error_json",
    "private_analysis_tool_result_dict",
    "private_analysis_tool_result_from_dict",
    "private_analysis_tool_result_from_json",
    "private_analysis_tool_result_json",
]
