from .assembly_store import DemoAssemblyStore
from typing import Any

__all__ = ['DEMO_TOPOLOGY_ID', 'build_topology_contract', 'build_topology_profiles', 'build_topology_metadata']

DEMO_TOPOLOGY_ID: str

def build_topology_contract(revision_store: DemoAssemblyStore) -> dict[str, Any]: ...
def build_topology_profiles(contract: dict[str, Any]) -> list[dict[str, Any]]: ...
def build_topology_metadata(dataset: dict[str, Any], revision_store: DemoAssemblyStore) -> dict[str, Any]: ...
