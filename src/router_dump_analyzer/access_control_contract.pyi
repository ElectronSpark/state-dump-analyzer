from collections.abc import Mapping
from enum import Enum

CONTROL_PLANE_READ_ROLE: str
CONTROL_PLANE_WRITE_ROLE: str
CONTROL_PLANE_ADMIN_ROLE: str
CONTROL_PLANE_INSTANCE_OPERATOR_ROLE: str
CONTROL_PLANE_ROLES: frozenset[str]

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

ACCESS_DENIAL_REASONS_BY_PHASE: Mapping[ControlPlaneAccessPhase, frozenset[ControlPlaneAccessReason]]
ACCESS_DENIAL_WIRE_REASONS: Mapping[str, frozenset[str]]
