from .private_analysis_execution import PrivateAnalysisExecutionLimits, PrivateAnalysisRunnerRegistration
from .private_analysis_service import PrivateAnalysisDeploymentCeilings
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = ['MAX_PRIVATE_ANALYSIS_DEPLOYMENT_RUNNERS', 'PrivateAnalysisDeploymentLoadError', 'PrivateAnalysisDeploymentContext', 'PrivateAnalysisDeployment', 'load_private_analysis_deployment']

MAX_PRIVATE_ANALYSIS_DEPLOYMENT_RUNNERS: Final[int]

class PrivateAnalysisDeploymentLoadError(RuntimeError): ...

@dataclass(frozen=True, slots=True)
class PrivateAnalysisDeploymentContext:
    state_dir: Path
    def __post_init__(self) -> None: ...

@dataclass(frozen=True, slots=True)
class PrivateAnalysisDeployment:
    registrations: tuple[PrivateAnalysisRunnerRegistration, ...]
    execution_limits: PrivateAnalysisExecutionLimits | None = ...
    ceilings: PrivateAnalysisDeploymentCeilings | None = ...
    def __post_init__(self) -> None: ...

def load_private_analysis_deployment(target: str, *, context: PrivateAnalysisDeploymentContext) -> PrivateAnalysisDeployment: ...
