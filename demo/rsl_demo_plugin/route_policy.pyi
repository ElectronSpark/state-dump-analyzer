from .assembly_store import DemoAssemblyStore
from router_dump_analyzer.multi_node_route import RouteProjectionSet, RouteServicePolicy

__all__ = ['DEMO_ROUTE_POLICY', 'build_route_projection_set']

DEMO_ROUTE_POLICY: RouteServicePolicy

def build_route_projection_set(revision_store: DemoAssemblyStore) -> RouteProjectionSet: ...
