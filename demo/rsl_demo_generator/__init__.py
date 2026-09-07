"""Standalone public API for generating the Router State Lab demo assembly."""

from __future__ import annotations

from typing import TYPE_CHECKING

from router_dump_analyzer._lazy_exports import resolve_export as _resolve_export

if TYPE_CHECKING:
    from .assembly import (
        ASSEMBLY_FORMAT_VERSION,
        ASSEMBLY_GENERATOR,
        ASSEMBLY_ROOT,
        DEFAULT_ASSEMBLY_ID,
        DEFAULT_ASSEMBLY_NAME,
        DEFAULT_EVENT_COUNT,
        DEFAULT_PLUGIN_ID,
        DEFAULT_PLUGIN_VERSION,
        DEFAULT_RESOURCE_COUNT,
        DEFAULT_SEED,
        PROJECTION_ROOT,
        AssemblyConfig,
        EnsureLaunchReport,
        LaunchPreflightReport,
        ValidationReport,
        build_coverage,
        build_demo_fixture,
        ensure_demo_fixture_for_launch,
        parse_node_selection,
        probe_demo_fixture_for_launch,
        validate_demo_fixture,
    )
    from .catalog import (
        COVERAGE_CASES,
        DEMO_LINKS,
        DEMO_NODES,
        GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID,
        GENERATED_TOPOLOGY_PROFILE,
        GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID,
        PACKET_PROFILES,
        CoverageCaseSpec,
        LinkSpec,
        NodeSpec,
        TemporalEvidenceSelector,
        TopologyEvidenceSelector,
        TopologyProfileSpec,
    )
    from .conformance import (
        CONFORMANCE_CORPUS_FORMAT_VERSION,
        CONFORMANCE_CORPUS_NAME,
        CONFORMANCE_CORPUS_ROOT,
        build_ingestion_conformance_corpus,
        ingestion_conformance_members,
        ingestion_temporal_semantic_vector,
        render_ingestion_temporal_semantic_vector,
    )

# Keep concrete legacy exports without importing their engines for leaf users.
_EXPORT_MODULES = {
    'ASSEMBLY_FORMAT_VERSION': '.assembly',
    'ASSEMBLY_GENERATOR': '.assembly',
    'ASSEMBLY_ROOT': '.assembly',
    'CONFORMANCE_CORPUS_FORMAT_VERSION': '.conformance',
    'CONFORMANCE_CORPUS_NAME': '.conformance',
    'CONFORMANCE_CORPUS_ROOT': '.conformance',
    'COVERAGE_CASES': '.catalog',
    'DEFAULT_ASSEMBLY_ID': '.assembly',
    'DEFAULT_ASSEMBLY_NAME': '.assembly',
    'DEFAULT_EVENT_COUNT': '.assembly',
    'DEFAULT_PLUGIN_ID': '.assembly',
    'DEFAULT_PLUGIN_VERSION': '.assembly',
    'DEFAULT_RESOURCE_COUNT': '.assembly',
    'DEFAULT_SEED': '.assembly',
    'DEMO_LINKS': '.catalog',
    'DEMO_NODES': '.catalog',
    'GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID': '.catalog',
    'GENERATED_TOPOLOGY_PROFILE': '.catalog',
    'GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID': '.catalog',
    'PACKET_PROFILES': '.catalog',
    'PROJECTION_ROOT': '.assembly',
    'AssemblyConfig': '.assembly',
    'CoverageCaseSpec': '.catalog',
    'EnsureLaunchReport': '.assembly',
    'LaunchPreflightReport': '.assembly',
    'LinkSpec': '.catalog',
    'NodeSpec': '.catalog',
    'TemporalEvidenceSelector': '.catalog',
    'TopologyEvidenceSelector': '.catalog',
    'TopologyProfileSpec': '.catalog',
    'ValidationReport': '.assembly',
    'build_coverage': '.assembly',
    'build_demo_fixture': '.assembly',
    'build_ingestion_conformance_corpus': '.conformance',
    'ensure_demo_fixture_for_launch': '.assembly',
    'ingestion_conformance_members': '.conformance',
    'ingestion_temporal_semantic_vector': '.conformance',
    'parse_node_selection': '.assembly',
    'probe_demo_fixture_for_launch': '.assembly',
    'render_ingestion_temporal_semantic_vector': '.conformance',
    'validate_demo_fixture': '.assembly',
}

__all__ = [
    "ASSEMBLY_FORMAT_VERSION",
    "ASSEMBLY_GENERATOR",
    "ASSEMBLY_ROOT",
    "CONFORMANCE_CORPUS_FORMAT_VERSION",
    "CONFORMANCE_CORPUS_NAME",
    "CONFORMANCE_CORPUS_ROOT",
    "COVERAGE_CASES",
    "DEFAULT_ASSEMBLY_ID",
    "DEFAULT_ASSEMBLY_NAME",
    "DEFAULT_EVENT_COUNT",
    "DEFAULT_PLUGIN_ID",
    "DEFAULT_PLUGIN_VERSION",
    "DEFAULT_RESOURCE_COUNT",
    "DEFAULT_SEED",
    "DEMO_LINKS",
    "DEMO_NODES",
    "GENERATED_TOPOLOGY_FEDERATION_PLUGIN_ID",
    "GENERATED_TOPOLOGY_PROFILE",
    "GENERATED_TOPOLOGY_SEGMENT_MATCHER_ID",
    "PACKET_PROFILES",
    "PROJECTION_ROOT",
    "AssemblyConfig",
    "CoverageCaseSpec",
    "EnsureLaunchReport",
    "LaunchPreflightReport",
    "LinkSpec",
    "NodeSpec",
    "TemporalEvidenceSelector",
    "TopologyEvidenceSelector",
    "TopologyProfileSpec",
    "ValidationReport",
    "build_coverage",
    "build_demo_fixture",
    "build_ingestion_conformance_corpus",
    "ensure_demo_fixture_for_launch",
    "ingestion_conformance_members",
    "ingestion_temporal_semantic_vector",
    "parse_node_selection",
    "probe_demo_fixture_for_launch",
    "render_ingestion_temporal_semantic_vector",
    "validate_demo_fixture",
]


def __getattr__(name: str) -> object:
    return _resolve_export(name, globals(), _EXPORT_MODULES)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
