from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = ['BASE_TIME_NS', 'generate_scale_tree']

BASE_TIME_NS: Final[int]

@dataclass(frozen=True)
class ScaleLayout:
    resource_count: int
    etg_count: int
    dte_count: int
    primary_ete_count: int
    backup_ete_count: int
    es_count: int
    neighbor_count: int
    vif_count: int
    ip_routing_count: int
    single_home_service_count: int
    multi_home_service_count: int
    @property
    def resource_counts(self) -> dict[str, int]: ...

def generate_scale_tree(output: Path, event_count: int, resource_count: int) -> Path: ...
