"""Generic revision lookup contracts shared by node and fabric views.

The core deliberately does not know how a vendor dump is encoded or which
resource kinds a plug-in emits.  It only needs a stable way to address the same
parsed node revision from a single-node workspace and from a multi-node
assembly.  Demo and production repositories can implement this protocol with
very different storage engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable


@dataclass(frozen=True, slots=True)
class RevisionDescriptor:
    """Public identity and bounded inventory facts for one node revision."""

    node_id: str
    revision_id: str
    label: str
    event_count: int
    resource_count: int
    plugin_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.node_id:
            raise ValueError("node_id must be non-empty")
        if not self.revision_id:
            raise ValueError("revision_id must be non-empty")
        if not self.label:
            raise ValueError("label must be non-empty")
        if self.event_count < 0:
            raise ValueError("event_count must be non-negative")
        if self.resource_count < 0:
            raise ValueError("resource_count must be non-negative")


@dataclass(frozen=True, slots=True)
class AssemblyDescriptor:
    """Manifest projection for one collection of independently timed nodes."""

    assembly_id: str
    revisions: tuple[RevisionDescriptor, ...]
    coverage_case_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.assembly_id:
            raise ValueError("assembly_id must be non-empty")
        node_ids = [item.node_id for item in self.revisions]
        revision_ids = [item.revision_id for item in self.revisions]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("assembly node_id values must be unique")
        if len(revision_ids) != len(set(revision_ids)):
            raise ValueError("assembly revision_id values must be unique")
        if len(self.coverage_case_ids) != len(set(self.coverage_case_ids)):
            raise ValueError("coverage case ids must be unique")


@runtime_checkable
class RevisionStore(Protocol):
    """Storage boundary consumed by generic web and correlation services.

    ``dataset_for_*`` returns the core-normalized mapping for a revision.  The
    mapping may carry private runtime indexes, but callers must not infer
    vendor semantics from it.  Implementations are expected to materialize
    large histories lazily rather than eagerly loading every member.
    """

    @property
    def assembly(self) -> AssemblyDescriptor:
        """Describe all addressable member revisions without loading them."""

    @property
    def default_revision_id(self) -> str:
        """Return the revision opened by the default single-node workspace."""

    def revision(self, revision_id: str) -> RevisionDescriptor:
        """Resolve one exact revision or raise ``KeyError``."""

    def revision_for_node(self, node_id: str) -> RevisionDescriptor:
        """Resolve the revision selected for one assembly member."""

    def dataset_for_revision(self, revision_id: str) -> Mapping[str, Any]:
        """Load or retrieve one normalized node revision."""

    def dataset_for_node(self, node_id: str) -> Mapping[str, Any]:
        """Load or retrieve the selected revision for one node."""

    def loaded_revision_ids(self) -> Sequence[str]:
        """Return currently materialized revisions for diagnostics/tests."""


__all__ = [
    "AssemblyDescriptor",
    "RevisionDescriptor",
    "RevisionStore",
]
