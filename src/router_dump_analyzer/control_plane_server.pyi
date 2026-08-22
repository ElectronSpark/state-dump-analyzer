from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

__all__ = ['ControlPlaneApplicationRequest', 'ControlPlaneApplicationFactory', 'create_control_plane_application']

@dataclass(frozen=True, slots=True)
class ControlPlaneApplicationRequest:
    control_plane: Any
    identity_resolver: Callable[[Any], Any]
    expose_api_docs: bool = ...
    def __post_init__(self) -> None: ...

class ControlPlaneApplicationFactory(Protocol):
    def __call__(self, request: ControlPlaneApplicationRequest) -> Any: ...

def create_control_plane_application(request: ControlPlaneApplicationRequest) -> Any: ...
