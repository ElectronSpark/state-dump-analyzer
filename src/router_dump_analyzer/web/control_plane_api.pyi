from collections.abc import Callable, Iterable
from dataclasses import dataclass, field as dataclass_field
from enum import Enum
from fastapi import APIRouter, HTTPException as FastAPIHTTPException, Request
from fastapi.routing import APIRoute
from typing import Any, Protocol

__all__ = ['CONTROL_PLANE_READ_ROLE', 'CONTROL_PLANE_WRITE_ROLE', 'CONTROL_PLANE_ADMIN_ROLE', 'CONTROL_PLANE_INSTANCE_OPERATOR_ROLE', 'control_plane_router', 'ControlPlaneIdentity', 'ControlPlaneIdentityResolver', 'TrustedHeaderIdentityResolver']

CONTROL_PLANE_READ_ROLE: str
CONTROL_PLANE_WRITE_ROLE: str
CONTROL_PLANE_ADMIN_ROLE: str
CONTROL_PLANE_INSTANCE_OPERATOR_ROLE: str

class ControlPlaneAccessPhase(str, Enum):
    REQUEST_SOURCE = 'request_source'
    IDENTITY_VERIFICATION = 'identity_verification'
    IDENTITY_BINDING = 'identity_binding'
    ROLE_AUTHORIZATION = 'role_authorization'
    SCOPE_AUTHORIZATION = 'scope_authorization'

class ControlPlaneAccessReason(str, Enum):
    HOST_REJECTED = 'host_rejected'
    ORIGIN_REJECTED = 'origin_rejected'
    IDENTITY_VERIFICATION_FAILED = 'identity_verification_failed'
    TENANT_REQUIRED = 'tenant_required'
    TENANT_BINDING_MISMATCH = 'tenant_binding_mismatch'
    PRINCIPAL_REQUIRED = 'principal_required'
    PRINCIPAL_BINDING_MISMATCH = 'principal_binding_mismatch'
    REQUIRED_ROLE_MISSING = 'required_role_missing'
    PROJECT_SCOPE_DENIED = 'project_scope_denied'
    WORKSPACE_SCOPE_DENIED = 'workspace_scope_denied'
    PROJECT_CREATION_SCOPE_DENIED = 'project_creation_scope_denied'
    WORKSPACE_CREATION_SCOPE_DENIED = 'workspace_creation_scope_denied'

class _ControlPlaneAccessDenied(Exception):
    status_code: int
    public_detail: str
    phase: ControlPlaneAccessPhase
    reason: ControlPlaneAccessReason
    required_role: str | None
    tenant_correlation: str | None
    concealed: bool
    headers: object
    def __init__(self, *, status_code: int, public_detail: str, phase: ControlPlaneAccessPhase, reason: ControlPlaneAccessReason, required_role: str | None = None, tenant_correlation: str | None = None, concealed: bool = False, headers: object = None) -> None: ...

@dataclass(slots=True)
class _BoundedTenantMajority:
    total: int = ...
    counters: dict[str, int] = dataclass_field(default_factory=dict)
    def observe(self, correlation: str | None) -> None: ...
    def strict_majority(self) -> str | None: ...
    def clear(self) -> None: ...
    def merge(self, other: _BoundedTenantMajority) -> None: ...

@dataclass(slots=True)
class _AccessDenialSampleState:
    occurrences: int = ...
    suppressed_since_last: int = ...
    enqueue_failures_since_last: int = ...
    last_attempted_at: float = ...
    emission_in_flight: bool = ...
    tenant_majority: _BoundedTenantMajority = dataclass_field(default_factory=_BoundedTenantMajority)

@dataclass(frozen=True, slots=True)
class ControlPlaneAccessTelemetrySnapshot:
    observed_denials: int
    emitted_events: int
    intentionally_suppressed: int
    enqueue_failures: int
    invalid_denials: int
    admitted_keys: int
    key_capacity: int
    overflow_observations: int
    overflow_emitted_events: int
    global_suppressed: int

class ControlPlaneAccessDenialReporter:
    def __init__(self, *, emitter: Callable[..., bool] = ..., monotonic: Callable[[], float] = ..., minimum_interval_seconds: float = 5.0, maximum_interval_seconds: float = 60.0, max_keys: int = ..., global_burst: int = ..., global_refill_per_second: float = ...) -> None: ...
    def snapshot(self) -> ControlPlaneAccessTelemetrySnapshot: ...
    def report(self, *, denial: _ControlPlaneAccessDenied, request_method: str, route_name: str, mutating: bool, response_status: int | None = None) -> bool: ...

class _ControlPlaneHTTPResponse(FastAPIHTTPException):
    def __init__(self, status_code: int, detail: Any = None, headers: dict[str, str] | None = None) -> None: ...

class _BoundedControlPlaneRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Any]: ...

control_plane_router: APIRouter

@dataclass(frozen=True, slots=True)
class ControlPlaneIdentity:
    tenant_id: str
    principal_id: str
    roles: frozenset[str]
    project_ids: frozenset[str] | None = ...
    workspace_ids: frozenset[str] | None = ...
    def __post_init__(self) -> None: ...

class ControlPlaneIdentityResolver(Protocol):
    def __call__(self, request: Request) -> ControlPlaneIdentity: ...

class TrustedHeaderIdentityResolver:
    def __init__(self, *, allowed_hosts: Iterable[str], allowed_origins: Iterable[str] | None = None, grant_instance_operator: bool = False) -> None: ...
    def __call__(self, request: Request) -> ControlPlaneIdentity: ...

@dataclass(frozen=True, slots=True)
class _ApiErrorPolicy:
    status_code: int
    public_detail: str
    expose_message: bool = ...
