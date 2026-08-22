from dataclasses import dataclass
from typing import Final

__all__ = ['PLUGIN_COMPOSITION_POLICY_VERSION', 'MAX_PLUGIN_COMPOSITION_RULES', 'MAX_PLUGIN_COMPOSITION_AUXILIARIES', 'PluginParticipationSelection', 'PluginCompositionRule', 'PluginCompositionPolicy', 'DEFAULT_PLUGIN_COMPOSITION_POLICY_DIGEST']

PLUGIN_COMPOSITION_POLICY_VERSION: Final[str]
MAX_PLUGIN_COMPOSITION_RULES: Final[int]
MAX_PLUGIN_COMPOSITION_AUXILIARIES: Final[int]

@dataclass(frozen=True, slots=True)
class PluginParticipationSelection:
    instance_id: str
    registered_execution_identity: str
    roles: tuple[str, ...]
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class PluginCompositionRule:
    primary_instance_id: str
    primary_registered_execution_identity: str
    auxiliaries: tuple[PluginParticipationSelection, ...]
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class PluginCompositionPolicy:
    rules: tuple[PluginCompositionRule, ...] = ...
    contract_version: str = ...
    policy_digest: str = ...
    def __post_init__(self) -> None: ...
    def auxiliaries_for(self, *, primary_instance_id: str, primary_registered_execution_identity: str) -> tuple[PluginParticipationSelection, ...]: ...

DEFAULT_PLUGIN_COMPOSITION_POLICY_DIGEST: Final[str]
