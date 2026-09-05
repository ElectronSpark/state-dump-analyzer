from .capability_router import CapabilityProviderRef, PlanBoundCapabilityRouter
from .materialization_contract import RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION as RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION
from .plugin_api import Evidence, PluginDiagnostic, PluginSchema, ReadOnlyWorld, RelationshipDeclaration, RelationshipView, StatusPerspectiveRef
from .plugin_execution_plan import PluginExecutionPin, PluginExecutionPlan
from .world_read_budget import AggregateReadWorld
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from uuid import UUID

__all__ = ['RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION', 'RelationshipProjectionMaterializationError', 'RelationshipProjectionMaterializationStatus', 'RelationshipProjectionMaterializationLimits', 'revision_relationship_projection_selected_pins', 'MaterializedRelationshipContribution', 'MaterializedRelationshipDeclaration', 'MaterializedRelationshipProjectionDiagnostic', 'MaterializedProjectedRelationship', 'RelationshipProjectionMaterializationResult', 'not_applicable_relationship_projection_materialization', 'materialize_revision_relationship_projection', 'validate_relationship_projection_storage_fragment', 'validate_relationship_projection_dataset_fragment']

class RelationshipProjectionMaterializationError(RuntimeError): ...

class RelationshipProjectionMaterializationStatus(StrEnum):
    COMPLETE = 'complete'
    NOT_APPLICABLE = 'not_applicable'

class _RelationshipProjectionScope(StrEnum):
    REVISION = 'revision'

class _RelationshipProjectionPropertyContainerType(StrEnum):
    MAPPING = 'mapping'

@dataclass(frozen=True, slots=True)
class RelationshipProjectionMaterializationLimits:
    max_providers: int = ...
    max_declarations: int = ...
    max_diagnostics: int = ...
    max_evidence_references: int = ...
    max_world_reads: int = ...
    max_base_resources: int = ...
    max_artifact_ids: int = ...
    max_serialized_bytes: int = ...
    def __post_init__(self) -> None: ...

class _AggregateWorld(AggregateReadWorld):
    def __init__(self, world: ReadOnlyWorld, maximum_reads: int, *, perspective_ref: StatusPerspectiveRef | None) -> None: ...

def revision_relationship_projection_selected_pins(plan: PluginExecutionPlan) -> tuple[PluginExecutionPin, ...]: ...

@dataclass(frozen=True, slots=True)
class MaterializedRelationshipContribution:
    provider: CapabilityProviderRef
    evidence: tuple[Evidence, ...]
    occurrence_count: int
    canonical_record: str
    def __post_init__(self) -> None: ...
    def client_projection(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class MaterializedRelationshipDeclaration:
    declaration_id: str
    semantic_claim_id: str
    ambiguity_group_id: str | None
    declaration: RelationshipDeclaration
    contributions: tuple[MaterializedRelationshipContribution, ...]
    canonical_record: str
    def __post_init__(self) -> None: ...
    def client_projection(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class MaterializedRelationshipProjectionDiagnostic:
    diagnostic_id: str
    provider: CapabilityProviderRef
    diagnostic: PluginDiagnostic
    canonical_record: str
    def client_projection(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class MaterializedProjectedRelationship:
    relationship_id: str
    view: RelationshipView
    ambiguity_group_id: str | None
    declaration_ids: tuple[str, ...]
    canonical_record: str
    def client_projection(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class RelationshipProjectionMaterializationResult:
    status: RelationshipProjectionMaterializationStatus
    plan_digest: str
    basis_digest: str | None
    basis_canonical_json: str | None
    providers: tuple[CapabilityProviderRef, ...]
    declarations: tuple[MaterializedRelationshipDeclaration, ...]
    resolved_relationships: tuple[MaterializedProjectedRelationship, ...]
    diagnostics: tuple[MaterializedRelationshipProjectionDiagnostic, ...]
    emitted_declarations: int
    emitted_diagnostics: int
    duplicate_emissions_collapsed: int
    semantic_conflict_groups: int
    world_reads: int
    base_resource_count: int
    @property
    def plugin_diagnostics(self) -> tuple[PluginDiagnostic, ...]: ...
    @property
    def augmented_declarations(self) -> tuple[RelationshipDeclaration, ...]: ...
    @property
    def augmented_relationships(self) -> tuple[RelationshipView, ...]: ...
    def dataset_fragment(self) -> dict[str, Any]: ...

@dataclass(slots=True)
class _ContributionBuilder:
    provider: CapabilityProviderRef
    evidence: tuple[Evidence, ...]
    projection: dict[str, Any]
    occurrences: int = ...

@dataclass(slots=True)
class _ClaimBuilder:
    declaration: RelationshipDeclaration
    semantic_payload: dict[str, Any]
    edge_payload: dict[str, Any]
    contributions: dict[str, _ContributionBuilder]

def not_applicable_relationship_projection_materialization(plan: PluginExecutionPlan) -> RelationshipProjectionMaterializationResult: ...
def materialize_revision_relationship_projection(*, plan: PluginExecutionPlan, router: PlanBoundCapabilityRouter, world: ReadOnlyWorld, primary_schema: PluginSchema, artifact_ids: Collection[UUID], limits: RelationshipProjectionMaterializationLimits | None = None) -> RelationshipProjectionMaterializationResult: ...
def validate_relationship_projection_storage_fragment(value: object, *, plan: PluginExecutionPlan, expected_basis_digest: str | None, base_resource_ids: Collection[str], relationship_type_directions: Mapping[str, bool], perspective_ids: Collection[str], artifact_ids: Collection[UUID], limits: RelationshipProjectionMaterializationLimits | None = None) -> dict[str, Any]: ...
def validate_relationship_projection_dataset_fragment(value: object, *, plan: PluginExecutionPlan, world: ReadOnlyWorld, primary_schema: PluginSchema, artifact_ids: Collection[UUID], limits: RelationshipProjectionMaterializationLimits | None = None) -> dict[str, Any]: ...
