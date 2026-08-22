from .private_analysis.contracts import PrivateAnalysisRequest
from .private_analysis.disclosure import PrivateAnalysisEvidenceClass
from .private_analysis.evidence import EvidenceRevisionBinding, EvidenceTimeBasis
from .private_analysis.evidence_corpus import PrivateAnalysisEvidenceCorpus, PrivateAnalysisEvidenceEntry
from .session_store import AnalysisRevisionDescriptor, FixtureDescriptor, WorkspaceDescriptor
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = ['PrivateAnalysisRevisionEvidenceError', 'PrivateAnalysisRevisionEvidenceCancelled', 'TrustedPrivateAnalysisRevision', 'validate_private_analysis_timeline_metadata', 'private_analysis_revision_cutoff_ns', 'build_private_analysis_revision_evidence_corpus']

class PrivateAnalysisRevisionEvidenceError(ValueError): ...
class PrivateAnalysisRevisionEvidenceCancelled(PrivateAnalysisRevisionEvidenceError): ...

@dataclass(slots=True)
class _EvidenceEntryAccumulator:
    maximum_entries: int
    maximum_payload_bytes: int
    entries: list[PrivateAnalysisEvidenceEntry]
    payload_bytes: int = ...
    def __len__(self) -> int: ...
    def append(self, entry: PrivateAnalysisEvidenceEntry) -> None: ...

@dataclass(frozen=True, slots=True)
class TrustedPrivateAnalysisRevision:
    workspace: WorkspaceDescriptor
    fixture: FixtureDescriptor
    revision: AnalysisRevisionDescriptor
    dataset: Mapping[str, Any]
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class _TimelineClock:
    basis: EvidenceTimeBasis
    clock_domain: str | None = ...

def validate_private_analysis_timeline_metadata(dataset: Mapping[str, Any]) -> tuple[int, int, EvidenceTimeBasis, str | None]: ...
def private_analysis_revision_cutoff_ns(request: PrivateAnalysisRequest, revision_binding: EvidenceRevisionBinding, *, timeline_start_ns: int, timeline_end_ns: int, timeline_basis: EvidenceTimeBasis) -> int: ...
def build_private_analysis_revision_evidence_corpus(request: PrivateAnalysisRequest, revisions: tuple[TrustedPrivateAnalysisRevision, ...], *, maximum_entries: int = ..., maximum_payload_bytes: int = ..., plugin_evidence_class: PrivateAnalysisEvidenceClass = ..., cancellation_probe: Callable[[], bool] | None = None) -> PrivateAnalysisEvidenceCorpus: ...
