"""Strict consumer of representative APIs from every shipped distribution."""

from __future__ import annotations

from io import BytesIO
from pathlib import PurePosixPath
from typing import Any, BinaryIO, Mapping, Sequence
from uuid import UUID

from router_dump_analyzer import (
    ControlPlaneApplicationFactory,
    ControlPlaneApplicationRequest,
)
from router_dump_analyzer.plugin_api import AnalyzerPlugin, ArtifactReader
from rsl_demo_generator import AssemblyConfig, NodeSpec, parse_node_selection
from rsl_demo_plugin import ExampleRouterPlugin, plugin


class MemoryArtifactReader:
    """Minimal structural implementation of the public reader protocol."""

    def open_binary(self, artifact_id: UUID) -> BinaryIO:
        return BytesIO(artifact_id.bytes)

    def materialize_private_path(self, artifact_id: UUID) -> str:
        return f"private/{artifact_id}"

    def materialize_private_tree(
        self,
        artifact_ids: Sequence[UUID],
        logical_root: PurePosixPath | None = None,
    ) -> str:
        root = logical_root or PurePosixPath("artifacts")
        return f"{root}/{len(artifact_ids)}"


def _application_factory(request: ControlPlaneApplicationRequest) -> object:
    return request.control_plane


def exercise_public_surface(document: Mapping[str, Any]) -> None:
    reader: ArtifactReader = MemoryArtifactReader()
    analyzer: AnalyzerPlugin = ExampleRouterPlugin()
    entry_point: AnalyzerPlugin = plugin
    application_factory: ControlPlaneApplicationFactory = _application_factory

    nodes: tuple[NodeSpec, ...] = parse_node_selection(())
    config = AssemblyConfig(nodes=nodes)
    # Keep every imported contract live so mypy checks the complete assignment.
    tuple(
        (
            reader,
            analyzer,
            entry_point,
            application_factory,
            config,
        )
    )
