"""Closed core authorization vocabulary shared with operational telemetry.

This module contains no HTTP or logging dependencies. Authorization owns the
decision; reporters only validate/project these same declared values.
"""

from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType

CONTROL_PLANE_READ_ROLE = "control-plane:read"
CONTROL_PLANE_WRITE_ROLE = "control-plane:write"
CONTROL_PLANE_ADMIN_ROLE = "control-plane:admin"
CONTROL_PLANE_INSTANCE_OPERATOR_ROLE = "control-plane:instance-operator"
CONTROL_PLANE_ROLES: frozenset[str] = frozenset(
    {
        CONTROL_PLANE_READ_ROLE,
        CONTROL_PLANE_WRITE_ROLE,
        CONTROL_PLANE_ADMIN_ROLE,
        CONTROL_PLANE_INSTANCE_OPERATOR_ROLE,
    }
)


class ControlPlaneAccessPhase(str, Enum):
    """Closed ownership phase for one rejected control-plane request."""

    REQUEST_SOURCE = "request_source"
    IDENTITY_VERIFICATION = "identity_verification"
    IDENTITY_BINDING = "identity_binding"
    ROLE_AUTHORIZATION = "role_authorization"
    SCOPE_AUTHORIZATION = "scope_authorization"


class ControlPlaneAccessReason(str, Enum):
    """Closed, caller-independent reason vocabulary for access telemetry."""

    HOST_REJECTED = "host_rejected"
    ORIGIN_REJECTED = "origin_rejected"
    IDENTITY_VERIFICATION_FAILED = "identity_verification_failed"
    TENANT_REQUIRED = "tenant_required"
    TENANT_BINDING_MISMATCH = "tenant_binding_mismatch"
    PRINCIPAL_REQUIRED = "principal_required"
    PRINCIPAL_BINDING_MISMATCH = "principal_binding_mismatch"
    REQUIRED_ROLE_MISSING = "required_role_missing"
    PROJECT_SCOPE_DENIED = "project_scope_denied"
    WORKSPACE_SCOPE_DENIED = "workspace_scope_denied"
    PROJECT_CREATION_SCOPE_DENIED = "project_creation_scope_denied"
    WORKSPACE_CREATION_SCOPE_DENIED = "workspace_creation_scope_denied"


ACCESS_DENIAL_REASONS_BY_PHASE: Mapping[
    ControlPlaneAccessPhase, frozenset[ControlPlaneAccessReason]
] = MappingProxyType(
    {
        ControlPlaneAccessPhase.REQUEST_SOURCE: frozenset(
            {
                ControlPlaneAccessReason.HOST_REJECTED,
                ControlPlaneAccessReason.ORIGIN_REJECTED,
            }
        ),
        ControlPlaneAccessPhase.IDENTITY_VERIFICATION: frozenset(
            {ControlPlaneAccessReason.IDENTITY_VERIFICATION_FAILED}
        ),
        ControlPlaneAccessPhase.IDENTITY_BINDING: frozenset(
            {
                ControlPlaneAccessReason.TENANT_REQUIRED,
                ControlPlaneAccessReason.TENANT_BINDING_MISMATCH,
                ControlPlaneAccessReason.PRINCIPAL_REQUIRED,
                ControlPlaneAccessReason.PRINCIPAL_BINDING_MISMATCH,
            }
        ),
        ControlPlaneAccessPhase.ROLE_AUTHORIZATION: frozenset(
            {ControlPlaneAccessReason.REQUIRED_ROLE_MISSING}
        ),
        ControlPlaneAccessPhase.SCOPE_AUTHORIZATION: frozenset(
            {
                ControlPlaneAccessReason.PROJECT_SCOPE_DENIED,
                ControlPlaneAccessReason.WORKSPACE_SCOPE_DENIED,
                ControlPlaneAccessReason.PROJECT_CREATION_SCOPE_DENIED,
                ControlPlaneAccessReason.WORKSPACE_CREATION_SCOPE_DENIED,
            }
        ),
    }
)
ACCESS_DENIAL_WIRE_REASONS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        phase.value: frozenset(reason.value for reason in reasons)
        for phase, reasons in ACCESS_DENIAL_REASONS_BY_PHASE.items()
    }
)
