"""Immutable, revision-bound evidence contracts for private analysis.

This module defines portable values only.  It does not resolve a catalog
identifier, read evidence, authorize a caller, or invoke a model.  A later
tool service must resolve every scope against the durable catalog and evaluate
the workspace disclosure policy before it calls :func:`make_evidence_envelope`.

References deliberately contain only opaque content-addressed locators.  Raw
resource keys, source locators, filesystem paths, and payload text belong in
the disclosure-gated payload, never in the stable citation identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
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
from ._wire import (
    SealedContractValue,
)
from ._wire import (
    bounded_canonical_decimal_integer as _bounded_decimal,
)
from ._wire import (
    bounded_utf8_text as _bounded_utf8_text,
)
from ._wire import (
    exact_contract_version as _contract_version,
)
from ._wire import (
    exact_json_object as _exact_dict,
)
from ._wire import (
    reject_duplicate_json_object_pairs as _reject_duplicate_pairs,
)
from ._wire import (
    strict_string_enum as _enum,
)
from .disclosure import (
    DisclosureDecision,
    PrivateAnalysisEvidenceClass,
    _revalidated_disclosure_decision,
    disclosure_decision_dict,
    disclosure_decision_from_dict,
    disclosure_scope_digest,
)

EVIDENCE_REFERENCE_VERSION_V1: Final = (
    "router_dump_analyzer.private_analysis.evidence_reference.v1"
)
EVIDENCE_REFERENCE_VERSION_V2: Final = (
    "router_dump_analyzer.private_analysis.evidence_reference.v2"
)
EVIDENCE_REFERENCE_VERSION: Final = (
    "router_dump_analyzer.private_analysis.evidence_reference.v3"
)
_EVIDENCE_REFERENCE_VERSIONS: Final = frozenset(
    {
        EVIDENCE_REFERENCE_VERSION_V1,
        EVIDENCE_REFERENCE_VERSION_V2,
        EVIDENCE_REFERENCE_VERSION,
    }
)
EVIDENCE_ENVELOPE_VERSION: Final = (
    "router_dump_analyzer.private_analysis.evidence_envelope.v1"
)
EVIDENCE_LOCATOR_VERSION: Final = (
    "router_dump_analyzer.private_analysis.evidence_locator.v1"
)
EVIDENCE_PAYLOAD_VERSION: Final = (
    "router_dump_analyzer.private_analysis.evidence_payload.v1"
)

MAX_EVIDENCE_PAYLOAD_BYTES: Final = 1024 * 1024
MAX_EVIDENCE_ENVELOPE_BYTES: Final = MAX_EVIDENCE_PAYLOAD_BYTES + 64 * 1024
MAX_EVIDENCE_IDENTIFIER_CHARACTERS: Final = 256
MAX_EVIDENCE_SUBJECT_KIND_CHARACTERS: Final = 128
MAX_EVIDENCE_PAYLOAD_DEPTH: Final = 16
MAX_EVIDENCE_PAYLOAD_CONTAINER_ITEMS: Final = 1_024
MAX_EVIDENCE_PAYLOAD_UNITS: Final = 4_096
MAX_EVIDENCE_PAYLOAD_ATOM_CHARACTERS: Final = 65_536
MAX_EVIDENCE_LOCATOR_BYTES: Final = 256 * 1024
MAX_EVIDENCE_LOCATOR_UNITS: Final = 4_096

_MAX_SIGNED_NS = (1 << 63) - 1
_MIN_SIGNED_NS = -(1 << 63)


class EvidenceKind(StrEnum):
    """Core-actionable categories; plug-in vocabulary stays in subject_kind."""

    REVISION_METADATA = "revision_metadata"
    ARTIFACT_EXCERPT = "artifact_excerpt"
    SOURCE_RECORD = "source_record"
    EVENT = "event"
    RESOURCE_IDENTITY = "resource_identity"
    RESOURCE_STATE_INTERVAL = "resource_state_interval"
    RELATIONSHIP_INTERVAL = "relationship_interval"
    PLUGIN_SCHEMA = "plugin_schema"
    PLUGIN_CAPABILITY_RESULT = "plugin_capability_result"


class EvidenceTimeBasis(StrEnum):
    """Closed coordinate systems understood by the core."""

    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"
    ABSOLUTE_UNIX_NS = "absolute_unix_ns"
    REVISION_START_RELATIVE_NS = "revision_start_relative_ns"
    REVISION_END_RELATIVE_NS = "revision_end_relative_ns"
    SOURCE_CLOCK_NS = "source_clock_ns"


class EvidenceAuthority(StrEnum):
    """Who may assert a claim; distinct from its observation method."""

    PLUGIN_INFERRED = "plugin_inferred"
    CORE_CORROBORATION = "core_corroboration"


class EvidenceFactProvenance(StrEnum):
    """Closed deterministic origins; authority remains a separate field."""

    OBSERVED = "observed"
    SNAPSHOT_OBSERVED = "snapshot_observed"
    LOG_DERIVED = "log_derived"
    STATE_RECONSTRUCTED = "state_reconstructed"
    RELATIONSHIP_INFERRED = "relationship_inferred"
    ROUTE_RESOLVED = "route_resolved"
    TOPOLOGY_INFERRED = "topology_inferred"
    CORE_CORROBORATED = "core_corroborated"
    PLUGIN_ANALYZED = "plugin_analyzed"
    NOT_APPLICABLE = "not_applicable"


class CoreEvidenceProducer(StrEnum):
    """Closed core-owned producer identities; plug-in identities stay open."""

    REVISION_METADATA_V1 = "router_dump_analyzer.revision_metadata.v1"
    CORROBORATION_V1 = "router_dump_analyzer.corroboration.v1"


_CORE_EVIDENCE_PRODUCER_IDS: Final = frozenset(
    producer.value for producer in CoreEvidenceProducer
)
@lru_cache(maxsize=8_192)
def _valid_evidence_identifier(value: str, maximum: int) -> bool:
    """Cache the expensive Unicode/path safety scan for repeated identities.

    A large revision emits the same scope, revision, producer and subject
    coordinates on every evidence reference.  Those checks are pure, so a
    bounded cache avoids rescanning the same Unicode strings hundreds of
    thousands of times without weakening the exact-type boundary below.
    """

    return bool(
        value
        and len(value) <= maximum
        and value == value.strip()
        and not contains_filesystem_identity_path(value)
        and not contains_unsafe_identifier_text(value)
        and has_visible_identity_anchor(value)
    )


def validate_evidence_identifier(
    value: object,
    label: str,
    *,
    maximum: int = MAX_EVIDENCE_IDENTIFIER_CHARACTERS,
) -> str:
    if type(value) is not str or not _valid_evidence_identifier(value, maximum):
        raise ValueError(
            f"{label} must contain 1 to {maximum} visible characters "
            "without surrounding whitespace"
        )
    return value


def validate_evidence_token(
    value: object,
    label: str,
    *,
    maximum: int = MAX_EVIDENCE_IDENTIFIER_CHARACTERS,
) -> str:
    result = validate_evidence_identifier(value, label, maximum=maximum)
    if any(character.isspace() for character in result):
        raise ValueError(f"{label} must be an opaque token")
    return result


def _sha256(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _execution_plan_digest(value: object, label: str) -> str:
    if type(value) is not str or not value.startswith("sha256:") or len(value) != 71:
        raise ValueError(f"{label} must be a sha256-prefixed lowercase digest")
    _sha256(value[7:], label)
    return value


def _prefixed_sha256(value: object, label: str) -> str:
    if type(value) is not str or not value.startswith("sha256:"):
        raise ValueError(f"{label} must be a sha256-prefixed lowercase digest")
    if len(value) != 71:
        raise ValueError(f"{label} must be a sha256-prefixed lowercase digest")
    _sha256(value[7:], label)
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _wire_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    return _bounded_decimal(
        value,
        label,
        minimum=minimum,
        maximum=maximum,
    )


def _optional_wire_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int | None:
    if value is None:
        return None
    return _wire_integer(value, label, minimum=minimum, maximum=maximum)


def _wire_ns(value: int | None) -> str | None:
    return None if value is None else str(value)


def _validate_exact_json(
    value: object,
    label: str,
    *,
    maximum_depth: int = MAX_EVIDENCE_PAYLOAD_DEPTH,
    maximum_units: int = MAX_EVIDENCE_PAYLOAD_UNITS,
    maximum_encoded_bytes: int = MAX_EVIDENCE_PAYLOAD_BYTES,
) -> dict[str, Any]:
    """Return one bounded exact JSON snapshot for later canonicalization."""

    snapshot = validate_bounded_json_value(
        value,
        label,
        maximum_depth=maximum_depth,
        maximum_container_items=MAX_EVIDENCE_PAYLOAD_CONTAINER_ITEMS,
        maximum_units=maximum_units,
        maximum_atom_units=MAX_EVIDENCE_PAYLOAD_ATOM_CHARACTERS,
        maximum_integer_bits=53,
        exact_types=True,
        allow_exact_tuples=False,
        maximum_encoded_bytes=maximum_encoded_bytes,
        snapshot=True,
    )
    if type(snapshot) is not dict:
        raise TypeError(f"{label} must be an exact JSON object")

    def visit(nested: object) -> None:
        if nested is None or type(nested) is bool:
            return
        if type(nested) is int:
            if not -MAX_JSON_SAFE_INTEGER <= nested <= MAX_JSON_SAFE_INTEGER:
                raise ValueError(
                    f"{label} integers must be JSON-safe; encode larger values "
                    "as canonical decimal strings"
                )
            return
        if type(nested) is float:
            return
        if type(nested) is str:
            try:
                nested.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError(
                    f"{label} strings must contain Unicode scalars"
                ) from error
            return
        if type(nested) is list:
            for child in nested:
                visit(child)
            return
        if type(nested) is dict:
            for key, child in nested.items():
                if type(key) is not str:
                    raise ValueError(f"{label} mappings require exact string keys")
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise ValueError(
                        f"{label} mapping keys must contain Unicode scalars"
                    ) from error
                visit(child)
            return
        raise ValueError(
            f"{label} contains non-exact JSON type {type(nested).__name__}"
        )

    visit(snapshot)
    return snapshot


def _canonical_payload_json(value: object, label: str) -> str:
    if type(value) is not dict:
        raise TypeError(f"{label} must be an exact JSON object")
    snapshot = _validate_exact_json(value, label)
    try:
        encoded = strict_canonical_json(snapshot)
        encoded_bytes = encoded.encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from error
    if len(encoded_bytes) > MAX_EVIDENCE_PAYLOAD_BYTES:
        raise ValueError(
            f"{label} exceeds {MAX_EVIDENCE_PAYLOAD_BYTES} encoded UTF-8 bytes"
        )
    return encoded


def _canonical_locator_json(value: object) -> str:
    if type(value) is not dict:
        raise TypeError("locator identity must be an exact JSON object")
    snapshot = _validate_exact_json(
        value,
        "locator identity",
        maximum_depth=12,
        maximum_units=MAX_EVIDENCE_LOCATOR_UNITS,
        maximum_encoded_bytes=MAX_EVIDENCE_LOCATOR_BYTES,
    )
    try:
        encoded = strict_canonical_json(snapshot)
        encoded_bytes = encoded.encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("locator identity is not canonical UTF-8 JSON") from error
    if len(encoded_bytes) > MAX_EVIDENCE_LOCATOR_BYTES:
        raise ValueError(
            f"locator identity exceeds {MAX_EVIDENCE_LOCATOR_BYTES} encoded bytes"
        )
    return encoded


def evidence_locator_digest(subject_kind: str, identity: dict[str, Any]) -> str:
    """Return an opaque, type-preserving locator without exposing its key."""

    kind = validate_evidence_token(
        subject_kind,
        "subject_kind",
        maximum=MAX_EVIDENCE_SUBJECT_KIND_CHARACTERS,
    )
    identity_json = _canonical_locator_json(identity)
    return "sha256:" + strict_canonical_json_sha256(
        {
            "contract_version": EVIDENCE_LOCATOR_VERSION,
            "subject_kind": kind,
            "identity": loads(identity_json),
        }
    )


def evidence_payload_digest(
    payload_schema: str,
    payload: dict[str, Any],
) -> str:
    """Return the domain-separated digest stored in an evidence reference."""

    schema = validate_evidence_token(payload_schema, "payload_schema")
    payload_json = _canonical_payload_json(payload, "evidence payload")
    return "sha256:" + strict_canonical_json_sha256(
        {
            "contract_version": EVIDENCE_PAYLOAD_VERSION,
            "payload_schema": schema,
            "payload": loads(payload_json),
        }
    )


@dataclass(frozen=True, slots=True)
class EvidenceRevisionBinding(SealedContractValue):
    """Exact immutable catalog member and interpretation plan."""

    fixture_id: str
    fixture_content_sha256: str
    node_id: str
    revision_id: str
    revision_identity_sha256: str
    plan_basis_revision_id: str
    execution_plan_digest: str

    def __post_init__(self) -> None:
        validate_evidence_identifier(self.fixture_id, "fixture_id")
        _sha256(self.fixture_content_sha256, "fixture_content_sha256")
        validate_evidence_identifier(self.node_id, "node_id")
        validate_evidence_identifier(self.revision_id, "revision_id")
        _sha256(self.revision_identity_sha256, "revision_identity_sha256")
        validate_evidence_identifier(
            self.plan_basis_revision_id,
            "plan_basis_revision_id",
        )
        _execution_plan_digest(self.execution_plan_digest, "execution_plan_digest")


@dataclass(frozen=True, slots=True)
class EvidenceScope(SealedContractValue):
    """Authorization scope for one immutable atomic evidence record."""

    tenant_id: str
    project_id: str
    workspace_id: str

    def __post_init__(self) -> None:
        validate_evidence_identifier(self.tenant_id, "tenant_id")
        validate_evidence_identifier(self.project_id, "project_id")
        validate_evidence_identifier(self.workspace_id, "workspace_id")


@dataclass(frozen=True, slots=True)
class EvidenceProducer(SealedContractValue):
    """Authority and, for plug-ins, the exact executable interpretation."""

    authority: EvidenceAuthority
    producer_id: str
    plugin_instance_id: str | None = None
    plugin_capability: str | None = None
    plugin_role: str | None = None

    def __post_init__(self) -> None:
        if type(self.authority) is not EvidenceAuthority:
            raise TypeError("authority must be EvidenceAuthority")
        validate_evidence_token(self.producer_id, "producer_id")
        if self.authority is EvidenceAuthority.PLUGIN_INFERRED:
            if self.plugin_instance_id is None:
                raise ValueError(
                    "plugin-inferred evidence requires an exact plug-in instance"
                )
            validate_evidence_token(self.plugin_instance_id, "plugin_instance_id")
            if (self.plugin_capability is None) == (self.plugin_role is None):
                raise ValueError(
                    "plugin-inferred evidence requires exactly one capability or role"
                )
            if self.plugin_capability is not None:
                validate_evidence_token(self.plugin_capability, "plugin_capability")
            if self.plugin_role is not None:
                validate_evidence_token(self.plugin_role, "plugin_role")
        elif any(
            value is not None
            for value in (
                self.plugin_instance_id,
                self.plugin_capability,
                self.plugin_role,
            )
        ):
            raise ValueError(
                "only plugin-inferred evidence may carry a plug-in binding"
            )
        elif self.producer_id not in _CORE_EVIDENCE_PRODUCER_IDS:
            raise ValueError("core evidence producer is unsupported")


@dataclass(frozen=True, slots=True)
class EvidenceTimeRange(SealedContractValue):
    """Explicit interval and clock semantics for one evidence item."""

    basis: EvidenceTimeBasis
    start_ns: int | None = None
    end_ns: int | None = None
    uncertainty_ns: int | None = None
    clock_domain: str | None = None

    def __post_init__(self) -> None:
        if type(self.basis) is not EvidenceTimeBasis:
            raise TypeError("time basis must be EvidenceTimeBasis")
        if self.basis in {
            EvidenceTimeBasis.NOT_APPLICABLE,
            EvidenceTimeBasis.UNKNOWN,
        }:
            if any(
                value is not None
                for value in (
                    self.start_ns,
                    self.end_ns,
                    self.uncertainty_ns,
                    self.clock_domain,
                )
            ):
                label = self.basis.value.replace("_", "-")
                raise ValueError(f"{label} evidence time must not carry coordinates")
            return
        minimum = (
            0 if self.basis is EvidenceTimeBasis.ABSOLUTE_UNIX_NS else _MIN_SIGNED_NS
        )
        start = _integer(
            self.start_ns,
            "start_ns",
            minimum=minimum,
            maximum=_MAX_SIGNED_NS,
        )
        end = _integer(
            self.end_ns,
            "end_ns",
            minimum=minimum,
            maximum=_MAX_SIGNED_NS,
        )
        if start > end:
            raise ValueError("start_ns must not exceed end_ns")
        if self.uncertainty_ns is not None:
            _integer(
                self.uncertainty_ns,
                "uncertainty_ns",
                minimum=0,
                maximum=_MAX_SIGNED_NS,
            )
        if self.basis is EvidenceTimeBasis.SOURCE_CLOCK_NS:
            if self.clock_domain is None:
                raise ValueError("source-clock evidence requires clock_domain")
            validate_evidence_token(self.clock_domain, "clock_domain")
        elif self.clock_domain is not None:
            raise ValueError("clock_domain is valid only for source-clock evidence")

    @classmethod
    def not_applicable(cls) -> EvidenceTimeRange:
        return cls(EvidenceTimeBasis.NOT_APPLICABLE)

    @classmethod
    def unknown(cls) -> EvidenceTimeRange:
        """Represent a temporal fact whose producer supplied no timestamp."""

        return cls(EvidenceTimeBasis.UNKNOWN)


@dataclass(frozen=True, slots=True)
class EvidenceReference(SealedContractValue):
    """Stable citation identity for one immutable evidence projection."""

    scope: EvidenceScope
    revision: EvidenceRevisionBinding
    producer: EvidenceProducer
    kind: EvidenceKind
    subject_kind: str
    locator_digest: str
    evidence_class: PrivateAnalysisEvidenceClass
    payload_schema: str
    fact_provenance: EvidenceFactProvenance
    time_range: EvidenceTimeRange
    content_digest: str
    contract_version: str = EVIDENCE_REFERENCE_VERSION
    reference_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.contract_version) is not str:
            raise TypeError("contract_version must be an exact string")
        if self.contract_version not in _EVIDENCE_REFERENCE_VERSIONS:
            raise ValueError("evidence-reference contract version is unsupported")
        if type(self.scope) is not EvidenceScope:
            raise TypeError("scope must be EvidenceScope")
        if type(self.revision) is not EvidenceRevisionBinding:
            raise TypeError("revision must be EvidenceRevisionBinding")
        if type(self.producer) is not EvidenceProducer:
            raise TypeError("producer must be EvidenceProducer")
        if type(self.kind) is not EvidenceKind:
            raise TypeError("kind must be EvidenceKind")
        validate_evidence_token(
            self.subject_kind,
            "subject_kind",
            maximum=MAX_EVIDENCE_SUBJECT_KIND_CHARACTERS,
        )
        _prefixed_sha256(self.locator_digest, "locator_digest")
        if type(self.evidence_class) is not PrivateAnalysisEvidenceClass:
            raise TypeError("evidence_class must be PrivateAnalysisEvidenceClass")
        validate_evidence_token(self.payload_schema, "payload_schema")
        if type(self.fact_provenance) is not EvidenceFactProvenance:
            raise TypeError("fact_provenance must be EvidenceFactProvenance")
        if type(self.time_range) is not EvidenceTimeRange:
            raise TypeError("time_range must be EvidenceTimeRange")
        scope = EvidenceScope(
            tenant_id=self.scope.tenant_id,
            project_id=self.scope.project_id,
            workspace_id=self.scope.workspace_id,
        )
        revision = EvidenceRevisionBinding(
            fixture_id=self.revision.fixture_id,
            fixture_content_sha256=self.revision.fixture_content_sha256,
            node_id=self.revision.node_id,
            revision_id=self.revision.revision_id,
            revision_identity_sha256=self.revision.revision_identity_sha256,
            plan_basis_revision_id=self.revision.plan_basis_revision_id,
            execution_plan_digest=self.revision.execution_plan_digest,
        )
        producer = EvidenceProducer(
            authority=self.producer.authority,
            producer_id=self.producer.producer_id,
            plugin_instance_id=self.producer.plugin_instance_id,
            plugin_capability=self.producer.plugin_capability,
            plugin_role=self.producer.plugin_role,
        )
        if (
            self.contract_version == EVIDENCE_REFERENCE_VERSION_V1
            and producer.plugin_role is not None
        ):
            raise ValueError("v1 evidence references cannot carry a plug-in role")
        if (
            self.contract_version == EVIDENCE_REFERENCE_VERSION_V1
            and self.time_range.basis is EvidenceTimeBasis.UNKNOWN
        ):
            raise ValueError("v1 evidence references cannot carry unknown time")
        if self.contract_version in {
            EVIDENCE_REFERENCE_VERSION_V1,
            EVIDENCE_REFERENCE_VERSION_V2,
        } and (
            self.kind is EvidenceKind.PLUGIN_CAPABILITY_RESULT
            or self.fact_provenance is EvidenceFactProvenance.PLUGIN_ANALYZED
        ):
            raise ValueError(
                "legacy evidence references cannot carry plug-in analysis semantics"
            )
        time_range = EvidenceTimeRange(
            basis=self.time_range.basis,
            start_ns=self.time_range.start_ns,
            end_ns=self.time_range.end_ns,
            uncertainty_ns=self.time_range.uncertainty_ns,
            clock_domain=self.time_range.clock_domain,
        )
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "producer", producer)
        object.__setattr__(self, "time_range", time_range)
        _prefixed_sha256(self.content_digest, "content_digest")
        if type(self.reference_digest) is not str:
            raise TypeError("reference_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _evidence_reference_payload(self)
        )
        if self.reference_digest:
            _prefixed_sha256(self.reference_digest, "reference_digest")
            if self.reference_digest != expected:
                raise ValueError("evidence-reference digest does not match")
        else:
            object.__setattr__(self, "reference_digest", expected)


@dataclass(frozen=True, slots=True)
class EvidenceEnvelope(SealedContractValue):
    """One authorized, immutable payload passed through a private runner."""

    reference: EvidenceReference
    disclosure_decision: DisclosureDecision
    payload_json: str
    contract_version: str = EVIDENCE_ENVELOPE_VERSION
    envelope_digest: str = ""

    def __post_init__(self) -> None:
        _contract_version(
            self.contract_version,
            EVIDENCE_ENVELOPE_VERSION,
            "evidence-envelope",
        )
        if type(self.reference) is not EvidenceReference:
            raise TypeError("reference must be EvidenceReference")
        if type(self.disclosure_decision) is not DisclosureDecision:
            raise TypeError("disclosure_decision must be DisclosureDecision")
        reference = _revalidated_evidence_reference(self.reference)
        disclosure_decision = _revalidated_disclosure_decision(self.disclosure_decision)
        object.__setattr__(self, "reference", reference)
        object.__setattr__(self, "disclosure_decision", disclosure_decision)
        _validate_envelope_disclosure(reference, disclosure_decision)
        if type(self.payload_json) is not str:
            raise TypeError("payload_json must be a string")
        _bounded_utf8_text(
            self.payload_json,
            "evidence payload JSON",
            MAX_EVIDENCE_PAYLOAD_BYTES,
        )
        payload = _load_payload_json(self.payload_json)
        canonical = _canonical_payload_json(payload, "evidence payload")
        if canonical != self.payload_json:
            raise ValueError("payload_json must use exact canonical JSON")
        if (
            evidence_payload_digest(self.reference.payload_schema, payload)
            != self.reference.content_digest
        ):
            raise ValueError("evidence payload digest does not match its reference")
        if type(self.envelope_digest) is not str:
            raise TypeError("envelope_digest must be a string")
        expected = "sha256:" + strict_canonical_json_sha256(
            _evidence_envelope_payload(self)
        )
        if self.envelope_digest:
            _prefixed_sha256(self.envelope_digest, "envelope_digest")
            if self.envelope_digest != expected:
                raise ValueError("evidence-envelope digest does not match")
        else:
            object.__setattr__(self, "envelope_digest", expected)

    @property
    def payload(self) -> dict[str, Any]:
        """Return a detached JSON object; callers cannot mutate the envelope."""

        return _load_payload_json(self.payload_json)


def _revision_binding_dict(value: EvidenceRevisionBinding) -> dict[str, object]:
    if type(value) is not EvidenceRevisionBinding:
        raise TypeError("revision binding must be EvidenceRevisionBinding")
    value = EvidenceRevisionBinding(
        fixture_id=value.fixture_id,
        fixture_content_sha256=value.fixture_content_sha256,
        node_id=value.node_id,
        revision_id=value.revision_id,
        revision_identity_sha256=value.revision_identity_sha256,
        plan_basis_revision_id=value.plan_basis_revision_id,
        execution_plan_digest=value.execution_plan_digest,
    )
    return {
        "fixture_id": value.fixture_id,
        "fixture_content_sha256": value.fixture_content_sha256,
        "node_id": value.node_id,
        "revision_id": value.revision_id,
        "revision_identity_sha256": value.revision_identity_sha256,
        "plan_basis_revision_id": value.plan_basis_revision_id,
        "execution_plan_digest": value.execution_plan_digest,
    }


def evidence_revision_binding_dict(
    value: EvidenceRevisionBinding,
) -> dict[str, object]:
    """Return the exact immutable revision-binding wire object."""

    return _revision_binding_dict(value)


def _scope_dict(value: EvidenceScope) -> dict[str, object]:
    if type(value) is not EvidenceScope:
        raise TypeError("scope must be EvidenceScope")
    value = EvidenceScope(
        tenant_id=value.tenant_id,
        project_id=value.project_id,
        workspace_id=value.workspace_id,
    )
    return {
        "tenant_id": value.tenant_id,
        "project_id": value.project_id,
        "workspace_id": value.workspace_id,
    }


def evidence_scope_dict(value: EvidenceScope) -> dict[str, object]:
    """Return the exact authorization-scope wire object."""

    return _scope_dict(value)


def _producer_dict(
    value: EvidenceProducer,
    *,
    reference_version: str,
) -> dict[str, object]:
    if type(value) is not EvidenceProducer:
        raise TypeError("producer must be EvidenceProducer")
    value = EvidenceProducer(
        authority=value.authority,
        producer_id=value.producer_id,
        plugin_instance_id=value.plugin_instance_id,
        plugin_capability=value.plugin_capability,
        plugin_role=value.plugin_role,
    )
    result: dict[str, object] = {
        "authority": value.authority.value,
        "producer_id": value.producer_id,
        "plugin_instance_id": value.plugin_instance_id,
        "plugin_capability": value.plugin_capability,
    }
    if reference_version in {
        EVIDENCE_REFERENCE_VERSION_V2,
        EVIDENCE_REFERENCE_VERSION,
    }:
        result["plugin_role"] = value.plugin_role
    elif reference_version != EVIDENCE_REFERENCE_VERSION_V1:
        raise ValueError("evidence-reference contract version is unsupported")
    return result


def _time_range_dict(value: EvidenceTimeRange) -> dict[str, object]:
    if type(value) is not EvidenceTimeRange:
        raise TypeError("time_range must be EvidenceTimeRange")
    value = EvidenceTimeRange(
        basis=value.basis,
        start_ns=value.start_ns,
        end_ns=value.end_ns,
        uncertainty_ns=value.uncertainty_ns,
        clock_domain=value.clock_domain,
    )
    return {
        "basis": value.basis.value,
        "start_ns": _wire_ns(value.start_ns),
        "end_ns": _wire_ns(value.end_ns),
        "uncertainty_ns": _wire_ns(value.uncertainty_ns),
        "clock_domain": value.clock_domain,
    }


def _evidence_reference_payload(value: EvidenceReference) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "scope": _scope_dict(value.scope),
        "revision": _revision_binding_dict(value.revision),
        "producer": _producer_dict(
            value.producer,
            reference_version=value.contract_version,
        ),
        "kind": value.kind.value,
        "subject_kind": value.subject_kind,
        "locator_digest": value.locator_digest,
        "evidence_class": value.evidence_class.value,
        "payload_schema": value.payload_schema,
        "fact_provenance": value.fact_provenance.value,
        "time_range": _time_range_dict(value.time_range),
        "content_digest": value.content_digest,
    }


def evidence_reference_dict(value: EvidenceReference) -> dict[str, object]:
    """Return the exact self-authenticating wire projection."""

    value = _revalidated_evidence_reference(value)
    result = _evidence_reference_payload(value)
    result["reference_digest"] = value.reference_digest
    return result


def _evidence_envelope_payload(value: EvidenceEnvelope) -> dict[str, object]:
    return {
        "contract_version": value.contract_version,
        "reference": evidence_reference_dict(value.reference),
        "disclosure_decision": disclosure_decision_dict(value.disclosure_decision),
        "payload": value.payload,
    }


def evidence_envelope_dict(value: EvidenceEnvelope) -> dict[str, object]:
    """Return a detached exact wire object for a private runner."""

    if type(value) is not EvidenceEnvelope:
        raise TypeError("value must be EvidenceEnvelope")
    value.__post_init__()
    result = _evidence_envelope_payload(value)
    result["envelope_digest"] = value.envelope_digest
    return result


def evidence_envelope_json(value: EvidenceEnvelope) -> str:
    """Return bounded canonical UTF-8 JSON for the local runner protocol."""

    encoded = strict_canonical_json(evidence_envelope_dict(value))
    if len(encoded.encode("utf-8")) > MAX_EVIDENCE_ENVELOPE_BYTES:
        raise ValueError(
            f"evidence envelope exceeds {MAX_EVIDENCE_ENVELOPE_BYTES} bytes"
        )
    return encoded


def _revision_binding_from_dict(value: object) -> EvidenceRevisionBinding:
    item = _exact_dict(
        value,
        "revision binding",
        {
            "fixture_id",
            "fixture_content_sha256",
            "node_id",
            "revision_id",
            "revision_identity_sha256",
            "plan_basis_revision_id",
            "execution_plan_digest",
        },
    )
    return EvidenceRevisionBinding(
        fixture_id=item["fixture_id"],
        fixture_content_sha256=item["fixture_content_sha256"],
        node_id=item["node_id"],
        revision_id=item["revision_id"],
        revision_identity_sha256=item["revision_identity_sha256"],
        plan_basis_revision_id=item["plan_basis_revision_id"],
        execution_plan_digest=item["execution_plan_digest"],
    )


def evidence_revision_binding_from_dict(
    value: object,
) -> EvidenceRevisionBinding:
    """Parse one exact immutable revision-binding wire object."""

    return _revision_binding_from_dict(value)


def _scope_from_dict(value: object) -> EvidenceScope:
    item = _exact_dict(
        value,
        "evidence scope",
        {
            "tenant_id",
            "project_id",
            "workspace_id",
        },
    )
    return EvidenceScope(
        tenant_id=item["tenant_id"],
        project_id=item["project_id"],
        workspace_id=item["workspace_id"],
    )


def evidence_scope_from_dict(value: object) -> EvidenceScope:
    """Parse one exact authorization-scope wire object."""

    return _scope_from_dict(value)


def _producer_from_dict(
    value: object,
    *,
    reference_version: str,
) -> EvidenceProducer:
    expected = {
        "authority",
        "producer_id",
        "plugin_instance_id",
        "plugin_capability",
    }
    if reference_version in {
        EVIDENCE_REFERENCE_VERSION_V2,
        EVIDENCE_REFERENCE_VERSION,
    }:
        expected.add("plugin_role")
    elif reference_version != EVIDENCE_REFERENCE_VERSION_V1:
        raise ValueError("evidence-reference contract version is unsupported")
    item = _exact_dict(
        value,
        "evidence producer",
        expected,
    )
    return EvidenceProducer(
        authority=_enum(
            EvidenceAuthority,
            item["authority"],
            "evidence authority",
        ),
        producer_id=item["producer_id"],
        plugin_instance_id=item["plugin_instance_id"],
        plugin_capability=item["plugin_capability"],
        plugin_role=(
            item["plugin_role"]
            if reference_version
            in {EVIDENCE_REFERENCE_VERSION_V2, EVIDENCE_REFERENCE_VERSION}
            else None
        ),
    )


def _time_range_from_dict(value: object) -> EvidenceTimeRange:
    item = _exact_dict(
        value,
        "evidence time range",
        {"basis", "start_ns", "end_ns", "uncertainty_ns", "clock_domain"},
    )
    basis = _enum(EvidenceTimeBasis, item["basis"], "evidence time basis")
    return EvidenceTimeRange(
        basis=basis,
        start_ns=_optional_wire_integer(
            item["start_ns"],
            "start_ns",
            minimum=(
                0 if basis is EvidenceTimeBasis.ABSOLUTE_UNIX_NS else _MIN_SIGNED_NS
            ),
            maximum=_MAX_SIGNED_NS,
        ),
        end_ns=_optional_wire_integer(
            item["end_ns"],
            "end_ns",
            minimum=(
                0 if basis is EvidenceTimeBasis.ABSOLUTE_UNIX_NS else _MIN_SIGNED_NS
            ),
            maximum=_MAX_SIGNED_NS,
        ),
        uncertainty_ns=_optional_wire_integer(
            item["uncertainty_ns"],
            "uncertainty_ns",
            minimum=0,
            maximum=_MAX_SIGNED_NS,
        ),
        clock_domain=item["clock_domain"],
    )


def evidence_reference_from_dict(value: object) -> EvidenceReference:
    """Parse an exact reference and verify every digest-bearing field."""

    item = _exact_dict(
        value,
        "evidence reference",
        {
            "contract_version",
            "scope",
            "revision",
            "producer",
            "kind",
            "subject_kind",
            "locator_digest",
            "evidence_class",
            "payload_schema",
            "fact_provenance",
            "time_range",
            "content_digest",
            "reference_digest",
        },
    )
    reference_digest = _prefixed_sha256(
        item["reference_digest"],
        "reference_digest",
    )
    return EvidenceReference(
        contract_version=item["contract_version"],
        scope=_scope_from_dict(item["scope"]),
        revision=_revision_binding_from_dict(item["revision"]),
        producer=_producer_from_dict(
            item["producer"],
            reference_version=item["contract_version"],
        ),
        kind=_enum(EvidenceKind, item["kind"], "evidence kind"),
        subject_kind=item["subject_kind"],
        locator_digest=item["locator_digest"],
        evidence_class=_enum(
            PrivateAnalysisEvidenceClass,
            item["evidence_class"],
            "evidence_class",
        ),
        payload_schema=item["payload_schema"],
        fact_provenance=_enum(
            EvidenceFactProvenance,
            item["fact_provenance"],
            "fact_provenance",
        ),
        time_range=_time_range_from_dict(item["time_range"]),
        content_digest=item["content_digest"],
        reference_digest=reference_digest,
    )


def _revalidated_evidence_reference(value: object) -> EvidenceReference:
    """Recompute one reference and all nested cached invariants."""

    if type(value) is not EvidenceReference:
        raise TypeError("reference must be EvidenceReference")
    if type(value.scope) is not EvidenceScope:
        raise TypeError("evidence reference scope must be EvidenceScope")
    if type(value.revision) is not EvidenceRevisionBinding:
        raise TypeError("evidence reference revision must be EvidenceRevisionBinding")
    if type(value.producer) is not EvidenceProducer:
        raise TypeError("evidence reference producer must be EvidenceProducer")
    if type(value.time_range) is not EvidenceTimeRange:
        raise TypeError("evidence reference time_range must be EvidenceTimeRange")
    # Reconstruct once through the canonical value constructor.  The previous
    # implementation first re-ran every supplied object's ``__post_init__``
    # and then parsed a second wire projection, producing two complete nested
    # validation passes per snapshot.  This single constructor still snapshots
    # every nested value and verifies the supplied reference digest.
    return EvidenceReference(
        contract_version=value.contract_version,
        scope=value.scope,
        revision=value.revision,
        producer=value.producer,
        kind=value.kind,
        subject_kind=value.subject_kind,
        locator_digest=value.locator_digest,
        evidence_class=value.evidence_class,
        payload_schema=value.payload_schema,
        fact_provenance=value.fact_provenance,
        time_range=value.time_range,
        content_digest=value.content_digest,
        reference_digest=value.reference_digest,
    )


def snapshot_evidence_reference(value: EvidenceReference) -> EvidenceReference:
    """Return a detached reference with every cached invariant recomputed."""

    return _revalidated_evidence_reference(value)


def make_evidence_envelope(
    reference: EvidenceReference,
    disclosure_decision: DisclosureDecision,
    payload: dict[str, Any],
) -> EvidenceEnvelope:
    """Detach one authorized payload and bind it to its immutable reference."""

    reference = _revalidated_evidence_reference(reference)
    disclosure_decision = _revalidated_disclosure_decision(disclosure_decision)
    _validate_envelope_disclosure(reference, disclosure_decision)
    payload_json = _canonical_payload_json(payload, "evidence payload")
    return EvidenceEnvelope(
        reference=reference,
        disclosure_decision=disclosure_decision,
        payload_json=payload_json,
    )


def _validate_envelope_disclosure(
    reference: EvidenceReference,
    disclosure_decision: DisclosureDecision,
) -> None:
    """Reject delivery before a caller-provided payload is inspected."""

    if not disclosure_decision.allowed:
        raise ValueError("an evidence envelope requires an allowed decision")
    if reference.evidence_class is PrivateAnalysisEvidenceClass.NEVER_ASSISTANT:
        raise ValueError("never-assistant evidence cannot be materialized")
    if disclosure_decision.evidence_class is not reference.evidence_class:
        raise ValueError("disclosure decision and evidence class disagree")
    expected_scope_digest = disclosure_scope_digest(
        tenant_id=reference.scope.tenant_id,
        project_id=reference.scope.project_id,
        workspace_id=reference.scope.workspace_id,
    )
    if disclosure_decision.scope_digest != expected_scope_digest:
        raise ValueError("disclosure decision and evidence scope disagree")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant {value}")


def _load_payload_json(value: str) -> dict[str, Any]:
    try:
        parsed = loads(
            value,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, JSONDecodeError, RecursionError) as error:
        raise ValueError("evidence payload is not strict JSON") from error
    if type(parsed) is not dict:
        raise ValueError("evidence payload must be a JSON object")
    return parsed


def evidence_envelope_from_dict(value: object) -> EvidenceEnvelope:
    """Parse and verify an exact envelope without granting catalog access."""

    item = _exact_dict(
        value,
        "evidence envelope",
        {
            "contract_version",
            "reference",
            "disclosure_decision",
            "payload",
            "envelope_digest",
        },
    )
    decision_value = item["disclosure_decision"]
    if type(decision_value) is not dict:
        raise TypeError("disclosure_decision must be an exact object")
    reference = evidence_reference_from_dict(item["reference"])
    disclosure_decision = disclosure_decision_from_dict(decision_value)
    _validate_envelope_disclosure(reference, disclosure_decision)
    payload_json = _canonical_payload_json(item["payload"], "evidence payload")
    envelope_digest = _prefixed_sha256(
        item["envelope_digest"],
        "envelope_digest",
    )
    return EvidenceEnvelope(
        contract_version=item["contract_version"],
        reference=reference,
        disclosure_decision=disclosure_decision,
        payload_json=payload_json,
        envelope_digest=envelope_digest,
    )


def evidence_envelope_from_json(value: str) -> EvidenceEnvelope:
    """Parse one bounded canonical JSON envelope with duplicate-key rejection."""

    if type(value) is not str:
        raise TypeError("evidence envelope JSON must be a string")
    if len(value) > MAX_EVIDENCE_ENVELOPE_BYTES:
        raise ValueError(
            f"evidence envelope exceeds {MAX_EVIDENCE_ENVELOPE_BYTES} bytes"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(
            "evidence envelope JSON must contain Unicode scalars"
        ) from error
    if len(encoded) > MAX_EVIDENCE_ENVELOPE_BYTES:
        raise ValueError(
            f"evidence envelope exceeds {MAX_EVIDENCE_ENVELOPE_BYTES} bytes"
        )
    try:
        parsed = loads(
            value,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, JSONDecodeError, RecursionError) as error:
        raise ValueError("evidence envelope is not strict JSON") from error
    if type(parsed) is not dict:
        raise ValueError("evidence envelope must be a JSON object")
    result = evidence_envelope_from_dict(parsed)
    if evidence_envelope_json(result) != value:
        raise ValueError("evidence envelope must use exact canonical JSON")
    return result


__all__ = [
    "EVIDENCE_ENVELOPE_VERSION",
    "EVIDENCE_LOCATOR_VERSION",
    "EVIDENCE_PAYLOAD_VERSION",
    "EVIDENCE_REFERENCE_VERSION",
    "EVIDENCE_REFERENCE_VERSION_V1",
    "EVIDENCE_REFERENCE_VERSION_V2",
    "MAX_EVIDENCE_ENVELOPE_BYTES",
    "MAX_EVIDENCE_PAYLOAD_BYTES",
    "CoreEvidenceProducer",
    "EvidenceAuthority",
    "EvidenceEnvelope",
    "EvidenceFactProvenance",
    "EvidenceKind",
    "EvidenceProducer",
    "EvidenceReference",
    "EvidenceRevisionBinding",
    "EvidenceScope",
    "EvidenceTimeBasis",
    "EvidenceTimeRange",
    "evidence_envelope_dict",
    "evidence_envelope_from_dict",
    "evidence_envelope_from_json",
    "evidence_envelope_json",
    "evidence_locator_digest",
    "evidence_payload_digest",
    "evidence_reference_dict",
    "evidence_reference_from_dict",
    "evidence_revision_binding_dict",
    "evidence_revision_binding_from_dict",
    "evidence_scope_dict",
    "evidence_scope_from_dict",
    "make_evidence_envelope",
    "snapshot_evidence_reference",
]
