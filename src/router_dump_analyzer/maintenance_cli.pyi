import argparse
from .annotation_store import ReviewRetentionPolicy
from .control_plane import ControlPlaneRetentionResult
from .ingestion_pipeline import RetentionPolicy
from .session_store import CatalogRetentionPolicy
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

__all__ = ['POLICY_SCHEMA_VERSION', 'RESULT_SCHEMA_VERSION', 'RetentionMaintenanceInputError', 'RetentionMaintenanceScopeError', 'RetentionMaintenanceConfiguration', 'RetentionMaintenancePolicies', 'build_parser', 'parse_args', 'load_policy', 'result_document', 'run', 'main']

POLICY_SCHEMA_VERSION: str
RESULT_SCHEMA_VERSION: str

class RetentionMaintenanceInputError(ValueError): ...
class RetentionMaintenanceScopeError(LookupError): ...

@dataclass(frozen=True, slots=True)
class RetentionMaintenanceConfiguration:
    state_dir: Path
    tenant_id: str
    project_id: str
    workspace_id: str
    policy_path: Path
    execute: bool
    actor: str | None
    operation_id: str | None
    now_ns: int | None
    output_path: Path | None
    pretty: bool

@dataclass(frozen=True, slots=True)
class RetentionMaintenancePolicies:
    ingestion: RetentionPolicy
    catalog: CatalogRetentionPolicy
    review: ReviewRetentionPolicy

def build_parser() -> argparse.ArgumentParser: ...
def parse_args(argv: Sequence[str] | None = None) -> RetentionMaintenanceConfiguration: ...
def load_policy(path: Path) -> RetentionMaintenancePolicies: ...
def result_document(result: ControlPlaneRetentionResult, *, requested_mode: str) -> dict[str, Any]: ...
def run(configuration: RetentionMaintenanceConfiguration, *, stdout: TextIO = ...) -> int: ...
def main(argv: Sequence[str] | None = None) -> None: ...
