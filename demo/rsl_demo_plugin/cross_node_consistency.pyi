from collections.abc import Mapping, Sequence
from typing import Any

__all__ = ['evaluate_boundary_findings', 'revalidate_boundary_coverage']

def evaluate_boundary_findings(scenario_id: str, rule: Mapping[str, Any], candidate_paths: Sequence[Mapping[str, Any]], observations: Sequence[Mapping[str, Any]], revision_ids_by_node: Mapping[str, str]) -> list[dict[str, Any]]: ...
def revalidate_boundary_coverage(coverage: Mapping[str, Any], projections_by_node: Mapping[str, Mapping[str, Any]], revision_ids_by_node: Mapping[str, str], scenarios: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]: ...
