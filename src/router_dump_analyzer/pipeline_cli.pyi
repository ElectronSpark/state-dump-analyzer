import argparse
from .ingestion_pipeline import PipelineLimits
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

__all__ = ['HeadlessIngestionConfiguration', 'build_parser', 'parse_args', 'run', 'main']

@dataclass(frozen=True, slots=True)
class HeadlessIngestionConfiguration:
    state_dir: Path
    tenant_id: str
    project_id: str
    workspace_id: str
    project_label: str
    workspace_label: str
    plugin_names: tuple[str, ...]
    plugin_modules: tuple[str, ...]
    input_paths: tuple[Path, ...]
    timeout_seconds: float
    auto_select: bool
    preferred_plugin_id: str | None
    content_type: str | None
    node_hint: str | None
    metadata: dict[str, Any]
    output_path: Path | None
    pretty: bool
    retention_policy_path: Path | None = ...
    plugin_deployment_module: str | None = ...

def build_parser() -> argparse.ArgumentParser: ...
def parse_args(argv: Sequence[str] | None = None) -> HeadlessIngestionConfiguration: ...
def run(configuration: HeadlessIngestionConfiguration, *, entry_point_loader: Callable[[str], Any] = ..., module_loader: Callable[[str], Any] = ..., plugin_deployment_loader: Callable[..., Any] = ..., stdout: TextIO = ..., pipeline_limits: PipelineLimits | None = None, control_plane_factory: Callable[..., Any] = ...) -> int: ...
def main(argv: Sequence[str] | None = None) -> None: ...
