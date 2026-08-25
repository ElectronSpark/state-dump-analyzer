"""Stable relationship-projector fixture shared by integration tests."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from router_dump_analyzer.plugin_api import (
    ConsistencyFinding,
    DiagnosticSeverity,
    FindingResult,
    PluginCapability,
    PropertyPatch,
    Provenance,
    Quality,
    RelationshipDeclaration,
    RelationshipObservation,
    RelationshipTypeDescriptor,
    SnapshotObservation,
)
from tests.test_ingestion import ParseOnlyPlugin


class RelationshipProjectionParsePlugin(ParseOnlyPlugin):
    """Parser whose revision hook relates two independently parsed rows."""

    manifest = replace(
        ParseOnlyPlugin.manifest,
        plugin_id="tests.relationship-projection-ingestion",
        capabilities=frozenset(
            {
                PluginCapability.STATUS_PARSE,
                PluginCapability.RELATIONSHIP_PROJECTION,
                PluginCapability.CONSISTENCY_CHECK,
            }
        ),
    )

    def describe(self):
        schema = super().describe()
        return replace(
            schema,
            relationship_types=(
                RelationshipTypeDescriptor(
                    relation_type="same_logical_interface",
                    label="Same logical interface",
                    directed=False,
                    structural=True,
                ),
            ),
        )

    def project_relationships(self, world: Any):
        states = tuple(world.iter_states(limit=3))
        if len(states) < 2:
            return ()
        first, second = states[:2]
        return (
            RelationshipDeclaration(
                source=first.resource,
                target=second.resource,
                relation_type="same_logical_interface",
                attributes=PropertyPatch(
                    set_values={"match_method": "fixture-key-reconciliation"},
                    complete=True,
                ),
                evidence=(*first.evidence, *second.evidence),
                provenance=Provenance.CORRELATED,
                quality=Quality.EXACT,
            ),
        )

    def check_consistency(self, world: Any):
        relationships = tuple(
            world.iter_relationships(
                relation_types=frozenset({"same_logical_interface"}),
                limit=2,
            )
        )
        if not relationships:
            return ()
        relationship = relationships[0]
        return (
            ConsistencyFinding(
                rule_id="tests.projected-edge-visible-to-consistency",
                severity=DiagnosticSeverity.INFO,
                result=FindingResult.PASS,
                summary="Consistency executed after relationship projection.",
                resources=(relationship.source, relationship.target),
                provenance=Provenance.RECONSTRUCTED,
                quality=Quality.EXACT,
                basis=world.basis,
                evidence=relationship.evidence,
                details={"relation_type": relationship.relation_type},
            ),
        )


class RelationshipProjectionAuxiliaryPlugin(RelationshipProjectionParsePlugin):
    """PROCESS-loadable projector/checker that owns no parser role."""

    manifest = replace(
        RelationshipProjectionParsePlugin.manifest,
        plugin_id="tests.relationship-projection-auxiliary",
        capabilities=frozenset(
            {
                PluginCapability.RELATIONSHIP_PROJECTION,
                PluginCapability.CONSISTENCY_CHECK,
            }
        ),
    )


class RelationshipProjectionTombstonePlugin(RelationshipProjectionParsePlugin):
    """Parser that explicitly suppresses the edge its projector also declares."""

    manifest = replace(
        RelationshipProjectionParsePlugin.manifest,
        plugin_id="tests.relationship-projection-tombstone",
    )

    def parse_status(self, reader: Any, spec: Any):
        snapshots: list[SnapshotObservation] = []
        for output in super().parse_status(reader, spec):
            if type(output) is SnapshotObservation:
                snapshots.append(output)
            yield output
        if len(snapshots) >= 2:
            first, second = snapshots[:2]
            yield RelationshipObservation(
                source=first.resource,
                target=second.resource,
                relation_type="same_logical_interface",
                observed_at_min_ns=second.observed_at_min_ns,
                observed_at_max_ns=second.observed_at_max_ns,
                present=False,
                attributes=PropertyPatch(set_values={}, complete=True),
                provenance=Provenance.OBSERVED,
                quality=Quality.EXACT,
                evidence=second.evidence,
            )


__all__ = [
    "RelationshipProjectionAuxiliaryPlugin",
    "RelationshipProjectionParsePlugin",
    "RelationshipProjectionTombstonePlugin",
]
