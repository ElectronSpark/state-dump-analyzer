"""Shared control-plane boundary errors, independent of the composition root."""

__all__ = [
    "ControlPlaneError",
    "ControlPlaneScopeError",
    "DatasetIntegrityError",
    "HiddenSubjectResolutionError",
    "SubjectResolutionError",
]


class ControlPlaneError(RuntimeError):
    """Base error for cross-store composition failures."""


class ControlPlaneScopeError(ValueError, ControlPlaneError):
    """A project/workspace scope is not a valid catalog boundary."""


class DatasetIntegrityError(ControlPlaneError):
    """An immutable dataset no longer matches its catalog publication."""


class SubjectResolutionError(ValueError, ControlPlaneError):
    """A review subject does not exist in its exact immutable revision."""


class HiddenSubjectResolutionError(KeyError, SubjectResolutionError):
    """An absent or out-of-scope subject hidden as a lookup miss."""
