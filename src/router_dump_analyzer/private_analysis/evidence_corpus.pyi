from .contracts import PrivateAnalysisRequest
from .disclosure import PrivateAnalysisEvidenceClass
from .evidence import EvidenceReference
from .query_cancellation import PrivateAnalysisEvidenceQueryCancellationProbeError as PrivateAnalysisEvidenceQueryCancellationProbeError, PrivateAnalysisEvidenceQueryCancellationProbeResultError as PrivateAnalysisEvidenceQueryCancellationProbeResultError, PrivateAnalysisEvidenceQueryCancelledError as PrivateAnalysisEvidenceQueryCancelledError
from .tool_catalog import PrivateAnalysisEvidenceQueryPage, PrivateAnalysisQueryArguments
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

__all__ = ['PrivateAnalysisEvidenceQueryCancellationProbeError', 'PrivateAnalysisEvidenceQueryCancellationProbeResultError', 'PrivateAnalysisEvidenceQueryCancelledError', 'DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES', 'MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES', 'DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES', 'MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES', 'PrivateAnalysisEvidenceEntry', 'PrivateAnalysisEvidenceQueryTooBroadError', 'PrivateAnalysisEvidenceCorpus']

DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES: Final[int]
MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_ENTRIES: Final[int]
DEFAULT_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES: Final[int]
MAX_PRIVATE_ANALYSIS_EVIDENCE_CORPUS_PAYLOAD_BYTES: Final[int]

@dataclass(frozen=True, slots=True, init=False)
class PrivateAnalysisEvidenceEntry:
    reference: EvidenceReference
    def __init__(self, reference: EvidenceReference, payload: dict[str, object]) -> None: ...
    @property
    def payload_bytes(self) -> int: ...
    @property
    def payload(self) -> dict[str, object]: ...

@dataclass(frozen=True, slots=True)
class _StoredEvidenceEntry:
    reference: EvidenceReference
    payload_json: str = field(repr=False)
    payload_bytes: int = field(repr=False)
    def payload(self) -> dict[str, object]: ...

class PrivateAnalysisEvidenceQueryTooBroadError(ValueError): ...

@dataclass(frozen=True, slots=True)
class _CachedQuerySnapshot:
    digests: tuple[str, ...]
    snapshot_digest: str

@dataclass(frozen=True, slots=True)
class _TrustedCorpusInitialization:
    entries: tuple[PrivateAnalysisEvidenceEntry, ...]
    construction_checkpoint: Callable[[], None] | None

@dataclass(frozen=True, slots=True, init=False)
class PrivateAnalysisEvidenceCorpus:
    maximum_entries: int
    maximum_payload_bytes: int
    payload_bytes: int
    def __init__(self, entries: tuple[PrivateAnalysisEvidenceEntry, ...] | _TrustedCorpusInitialization, *, maximum_entries: int = ..., maximum_payload_bytes: int = ...) -> None: ...
    def __len__(self) -> int: ...
    @property
    def entries(self) -> tuple[PrivateAnalysisEvidenceEntry, ...]: ...
    @property
    def reference_digests(self) -> tuple[str, ...]: ...
    def query_references(self, request: PrivateAnalysisRequest, arguments: PrivateAnalysisQueryArguments, evidence_classes: tuple[PrivateAnalysisEvidenceClass, ...] = ..., cancellation_probe: Callable[[], bool] | None = None) -> PrivateAnalysisEvidenceQueryPage: ...
    def resolve_reference(self, request: PrivateAnalysisRequest, reference_digest: str) -> EvidenceReference | None: ...
    def validate_reference(self, reference: EvidenceReference) -> bool: ...
    def validate_references(self, references: tuple[EvidenceReference, ...]) -> bool: ...
    def materialize_payload(self, reference: EvidenceReference) -> dict[str, object]: ...
