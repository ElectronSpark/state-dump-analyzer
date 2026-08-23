from .plugin_api import ConnectorMatchPolicyDescriptor, FederatedConnectorClaim, FederationLinkRequest, FederationLinkResult, FederationLinkerPlugin, PluginDiagnostic
from _typeshed import Incomplete
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

__all__ = ['FederationExecutionError', 'FederationRegistrationError', 'FederationPolicyError', 'FederationLinkExecutionError', 'FederationLinkOutputError', 'FederationExecutionProvenance', 'FederationLinkerIdentity', 'FederationLinkerLimits', 'FederationExecutionResult', 'FederationLinkerRegistry', 'FederationLinkExecutor']

class FederationExecutionError(RuntimeError):
    linker_identity: FederationLinkerIdentity | None
    diagnostics: tuple[PluginDiagnostic, ...]
    def __init__(self, message: str, *, linker_identity: FederationLinkerIdentity | None = None, diagnostics: tuple[PluginDiagnostic, ...] = ()) -> None: ...

class FederationRegistrationError(FederationExecutionError): ...
class FederationPolicyError(FederationExecutionError): ...
class FederationLinkExecutionError(FederationExecutionError): ...
class FederationLinkOutputError(FederationLinkExecutionError): ...

class FederationExecutionProvenance(StrEnum):
    CORE_EXACT_TOKEN = 'core_exact_token'
    LINKER_PLUGIN = 'linker_plugin'

@dataclass(frozen=True, slots=True, order=True)
class FederationLinkerIdentity:
    plugin_id: str
    plugin_version: str
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class FederationLinkerLimits:
    max_linkers: int = ...
    max_policies_per_linker: int = ...
    max_claims: int = ...
    max_results: int = ...
    max_candidates_per_result: int = ...
    max_diagnostics: int = ...
    max_evidence_per_output: int = ...
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class FederationExecutionResult:
    results: tuple[FederationLinkResult, ...]
    diagnostics: tuple[PluginDiagnostic, ...]
    complete: bool
    truncated: bool
    provenance: FederationExecutionProvenance
    linker_identity: FederationLinkerIdentity | None
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class _Registration:
    identity: FederationLinkerIdentity
    plugin: FederationLinkerPlugin
    link_hook: Callable[[FederationLinkRequest], Iterable[object]]
    policies: tuple[ConnectorMatchPolicyDescriptor, ...]

class _PropertyBudget:
    units: int
    active: set[int]
    def __init__(self) -> None: ...

class FederationLinkerRegistry:
    limits: FederationLinkerLimits
    def __init__(self, linkers: tuple[FederationLinkerPlugin, ...] = (), *, limits: FederationLinkerLimits | None = None) -> None: ...
    @property
    def identities(self) -> tuple[FederationLinkerIdentity, ...]: ...
    @property
    def policies(self) -> tuple[ConnectorMatchPolicyDescriptor, ...]: ...
    def select(self, policy: ConnectorMatchPolicyDescriptor) -> FederationLinkerIdentity | None: ...

class FederationLinkExecutor:
    registry: FederationLinkerRegistry
    limits: FederationLinkerLimits
    def __init__(self, registry: FederationLinkerRegistry | None = None, *, limits: FederationLinkerLimits | None = None) -> None: ...
    def resolve(self, policy: ConnectorMatchPolicyDescriptor, claims: tuple[FederatedConnectorClaim, ...], *, max_results: int | None = None, max_candidates_per_result: int | None = None) -> FederationExecutionResult: ...

class _NonRecoverableDiagnostic(Exception):
    diagnostic: Incomplete
    diagnostics: Incomplete
    def __init__(self, diagnostic: PluginDiagnostic, diagnostics: tuple[PluginDiagnostic, ...]) -> None: ...

class _LinkerOutputFailure(ValueError):
    diagnostics: Incomplete
    def __init__(self, message: str, diagnostics: tuple[PluginDiagnostic, ...]) -> None: ...

class _LinkerHookFailure(Exception):
    diagnostics: Incomplete
    def __init__(self, diagnostics: tuple[PluginDiagnostic, ...]) -> None: ...
