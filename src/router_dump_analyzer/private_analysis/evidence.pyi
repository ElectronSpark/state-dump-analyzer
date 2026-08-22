from typing import final
from ._wire import SealedContractValue
from .disclosure import DisclosureDecision, PrivateAnalysisEvidenceClass
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

__all__ = ['EVIDENCE_REFERENCE_VERSION_V1', 'EVIDENCE_REFERENCE_VERSION_V2', 'EVIDENCE_REFERENCE_VERSION', 'EVIDENCE_ENVELOPE_VERSION', 'EVIDENCE_LOCATOR_VERSION', 'EVIDENCE_PAYLOAD_VERSION', 'MAX_EVIDENCE_PAYLOAD_BYTES', 'MAX_EVIDENCE_ENVELOPE_BYTES', 'EvidenceKind', 'EvidenceTimeBasis', 'EvidenceAuthority', 'EvidenceFactProvenance', 'CoreEvidenceProducer', 'evidence_locator_digest', 'evidence_payload_digest', 'EvidenceRevisionBinding', 'EvidenceScope', 'EvidenceProducer', 'EvidenceTimeRange', 'EvidenceReference', 'EvidenceEnvelope', 'evidence_revision_binding_dict', 'evidence_scope_dict', 'evidence_reference_dict', 'evidence_envelope_dict', 'evidence_envelope_json', 'evidence_revision_binding_from_dict', 'evidence_scope_from_dict', 'evidence_reference_from_dict', 'snapshot_evidence_reference', 'make_evidence_envelope', 'evidence_envelope_from_dict', 'evidence_envelope_from_json']

EVIDENCE_REFERENCE_VERSION_V1: Final[str]
EVIDENCE_REFERENCE_VERSION_V2: Final[str]
EVIDENCE_REFERENCE_VERSION: Final[str]
EVIDENCE_ENVELOPE_VERSION: Final[str]
EVIDENCE_LOCATOR_VERSION: Final[str]
EVIDENCE_PAYLOAD_VERSION: Final[str]
MAX_EVIDENCE_PAYLOAD_BYTES: Final[int]
MAX_EVIDENCE_ENVELOPE_BYTES: Final[int]

class EvidenceKind(StrEnum):
    REVISION_METADATA = 'revision_metadata'
    ARTIFACT_EXCERPT = 'artifact_excerpt'
    SOURCE_RECORD = 'source_record'
    EVENT = 'event'
    RESOURCE_IDENTITY = 'resource_identity'
    RESOURCE_STATE_INTERVAL = 'resource_state_interval'
    RELATIONSHIP_INTERVAL = 'relationship_interval'
    PLUGIN_SCHEMA = 'plugin_schema'
    PLUGIN_CAPABILITY_RESULT = 'plugin_capability_result'

class EvidenceTimeBasis(StrEnum):
    NOT_APPLICABLE = 'not_applicable'
    UNKNOWN = 'unknown'
    ABSOLUTE_UNIX_NS = 'absolute_unix_ns'
    REVISION_START_RELATIVE_NS = 'revision_start_relative_ns'
    REVISION_END_RELATIVE_NS = 'revision_end_relative_ns'
    SOURCE_CLOCK_NS = 'source_clock_ns'

class EvidenceAuthority(StrEnum):
    PLUGIN_INFERRED = 'plugin_inferred'
    CORE_CORROBORATION = 'core_corroboration'

class EvidenceFactProvenance(StrEnum):
    OBSERVED = 'observed'
    SNAPSHOT_OBSERVED = 'snapshot_observed'
    LOG_DERIVED = 'log_derived'
    STATE_RECONSTRUCTED = 'state_reconstructed'
    RELATIONSHIP_INFERRED = 'relationship_inferred'
    ROUTE_RESOLVED = 'route_resolved'
    TOPOLOGY_INFERRED = 'topology_inferred'
    CORE_CORROBORATED = 'core_corroborated'
    PLUGIN_ANALYZED = 'plugin_analyzed'
    NOT_APPLICABLE = 'not_applicable'

class CoreEvidenceProducer(StrEnum):
    REVISION_METADATA_V1 = 'router_dump_analyzer.revision_metadata.v1'
    CORROBORATION_V1 = 'router_dump_analyzer.corroboration.v1'

def evidence_locator_digest(subject_kind: str, identity: dict[str, Any]) -> str: ...
def evidence_payload_digest(payload_schema: str, payload: dict[str, Any]) -> str: ...

@final
@dataclass(frozen=True, slots=True)
class EvidenceRevisionBinding(SealedContractValue):
    fixture_id: str
    fixture_content_sha256: str
    node_id: str
    revision_id: str
    revision_identity_sha256: str
    plan_basis_revision_id: str
    execution_plan_digest: str
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True)
class EvidenceScope(SealedContractValue):
    tenant_id: str
    project_id: str
    workspace_id: str
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True)
class EvidenceProducer(SealedContractValue):
    authority: EvidenceAuthority
    producer_id: str
    plugin_instance_id: str | None = ...
    plugin_capability: str | None = ...
    plugin_role: str | None = ...
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True)
class EvidenceTimeRange(SealedContractValue):
    basis: EvidenceTimeBasis
    start_ns: int | None = ...
    end_ns: int | None = ...
    uncertainty_ns: int | None = ...
    clock_domain: str | None = ...
    def __post_init__(self) -> None: ...
    @classmethod
    def not_applicable(cls) -> EvidenceTimeRange: ...
    @classmethod
    def unknown(cls) -> EvidenceTimeRange: ...

@final
@dataclass(frozen=True, slots=True)
class EvidenceReference(SealedContractValue):
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
    contract_version: str = ...
    reference_digest: str = ...
    def __post_init__(self) -> None: ...

@final
@dataclass(frozen=True, slots=True)
class EvidenceEnvelope(SealedContractValue):
    reference: EvidenceReference
    disclosure_decision: DisclosureDecision
    payload_json: str
    contract_version: str = ...
    envelope_digest: str = ...
    def __post_init__(self) -> None: ...
    @property
    def payload(self) -> dict[str, Any]: ...

def evidence_revision_binding_dict(value: EvidenceRevisionBinding) -> dict[str, object]: ...
def evidence_scope_dict(value: EvidenceScope) -> dict[str, object]: ...
def evidence_reference_dict(value: EvidenceReference) -> dict[str, object]: ...
def evidence_envelope_dict(value: EvidenceEnvelope) -> dict[str, object]: ...
def evidence_envelope_json(value: EvidenceEnvelope) -> str: ...
def evidence_revision_binding_from_dict(value: object) -> EvidenceRevisionBinding: ...
def evidence_scope_from_dict(value: object) -> EvidenceScope: ...
def evidence_reference_from_dict(value: object) -> EvidenceReference: ...
def snapshot_evidence_reference(value: EvidenceReference) -> EvidenceReference: ...
def make_evidence_envelope(reference: EvidenceReference, disclosure_decision: DisclosureDecision, payload: dict[str, Any]) -> EvidenceEnvelope: ...
def evidence_envelope_from_dict(value: object) -> EvidenceEnvelope: ...
def evidence_envelope_from_json(value: str) -> EvidenceEnvelope: ...
