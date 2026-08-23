from .capability_router import CapabilityProviderRegistry
from .ingestion_pipeline import PluginRegistry
from .plugin_composition import PluginCompositionPolicy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

__all__ = ['PLUGIN_COMPOSITION_DEPLOYMENT_VERSION', 'PluginCompositionDeploymentLoadError', 'PluginCompositionDeploymentContext', 'PluginCompositionDeployment', 'load_plugin_composition_deployment']

PLUGIN_COMPOSITION_DEPLOYMENT_VERSION: Final[str]

class PluginCompositionDeploymentLoadError(RuntimeError): ...

@dataclass(frozen=True, slots=True)
class PluginCompositionDeploymentContext:
    state_dir: Path
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class PluginCompositionDeployment:
    primary_registry: PluginRegistry
    capability_providers: CapabilityProviderRegistry
    policy: PluginCompositionPolicy
    deployment_digest: str = ...
    allow_inline_only: bool = field(default=False, kw_only=True)
    requires_inline_execution: bool = field(init=False)
    def __post_init__(self) -> None: ...

def load_plugin_composition_deployment(target: str, *, context: PluginCompositionDeploymentContext) -> PluginCompositionDeployment: ...
