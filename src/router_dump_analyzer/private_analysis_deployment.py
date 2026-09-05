"""Trusted, local-only composition for private-analysis runners.

The core deliberately does not know how a proprietary model is hosted or how
its evidence adapter is implemented.  A deployment may expose one exact
descriptor, or a factory receiving only the resolved durable state directory.
Loading that deployment is an explicit process-trust boundary: process-control
signals retain their native semantics, while every other extension failure is
replaced with a static error.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Final

from .deployment_core import _StateDirectoryContext, _deployment_target
from .private_analysis_execution import (
    PrivateAnalysisExecutionLimits,
    PrivateAnalysisRunnerRegistration,
)
from .private_analysis_service import PrivateAnalysisDeploymentCeilings
from .process_control import PROCESS_CONTROL_EXCEPTIONS

MAX_PRIVATE_ANALYSIS_DEPLOYMENT_RUNNERS: Final = 256


class PrivateAnalysisDeploymentLoadError(RuntimeError):
    """A trusted deployment target could not produce a valid descriptor."""


@dataclass(frozen=True, slots=True)
class PrivateAnalysisDeploymentContext(_StateDirectoryContext):
    """The complete core context disclosed to a deployment factory.

    No request, tenant, credential, plug-in, network, or model configuration is
    ambiently supplied.  The deployment receives only the canonical durable
    state root from which it can construct request-bound evidence services.
    """


def _detached_execution_limits(
    value: PrivateAnalysisExecutionLimits | None,
) -> PrivateAnalysisExecutionLimits | None:
    if value is None:
        return None
    if type(value) is not PrivateAnalysisExecutionLimits:
        raise TypeError(
            "execution_limits must be PrivateAnalysisExecutionLimits or None"
        )
    return PrivateAnalysisExecutionLimits(
        max_concurrent_runs=value.max_concurrent_runs,
        lease_duration_ns=value.lease_duration_ns,
        heartbeat_interval_ns=value.heartbeat_interval_ns,
        cancellation_poll_interval_ns=value.cancellation_poll_interval_ns,
        monitor_join_timeout_ns=value.monitor_join_timeout_ns,
    )


def _detached_ceilings(
    value: PrivateAnalysisDeploymentCeilings | None,
) -> PrivateAnalysisDeploymentCeilings | None:
    if value is None:
        return None
    if type(value) is not PrivateAnalysisDeploymentCeilings:
        raise TypeError("ceilings must be PrivateAnalysisDeploymentCeilings or None")
    return PrivateAnalysisDeploymentCeilings(
        request_limits=value.request_limits,
        max_revisions=value.max_revisions,
        max_list_runs=value.max_list_runs,
    )


@dataclass(frozen=True, slots=True)
class PrivateAnalysisDeployment:
    """A bounded, immutable deployment-owned private-analysis composition."""

    registrations: tuple[PrivateAnalysisRunnerRegistration, ...]
    execution_limits: PrivateAnalysisExecutionLimits | None = None
    ceilings: PrivateAnalysisDeploymentCeilings | None = None

    def __post_init__(self) -> None:
        if type(self.registrations) is not tuple:
            raise TypeError("registrations must be a tuple")
        if (
            not 1
            <= len(self.registrations)
            <= (MAX_PRIVATE_ANALYSIS_DEPLOYMENT_RUNNERS)
        ):
            raise ValueError("registrations must be a bounded non-empty tuple")

        detached: list[PrivateAnalysisRunnerRegistration] = []
        exact_selections: set[tuple[object, ...]] = set()
        public_selections: set[tuple[str, str]] = set()
        for registration in self.registrations:
            if type(registration) is not PrivateAnalysisRunnerRegistration:
                raise TypeError(
                    "registrations must contain PrivateAnalysisRunnerRegistration"
                )
            copy = registration.detached()
            selection = copy.runner.selection
            exact_key = (
                selection.runner_id,
                selection.runner_version,
                selection.transport,
                selection.configuration_digest,
            )
            public_key = (selection.runner_id, selection.runner_version)
            if exact_key in exact_selections:
                raise ValueError("private-analysis runner selection is duplicated")
            if public_key in public_selections:
                raise ValueError(
                    "private-analysis runner ID and version are duplicated"
                )
            exact_selections.add(exact_key)
            public_selections.add(public_key)
            detached.append(copy)

        object.__setattr__(
            self,
            "registrations",
            tuple(
                sorted(
                    detached,
                    key=lambda item: (
                        item.runner.selection.runner_id,
                        item.runner.selection.runner_version,
                        item.runner.selection.transport.value,
                        item.runner.selection.configuration_digest,
                    ),
                )
            ),
        )
        object.__setattr__(
            self,
            "execution_limits",
            _detached_execution_limits(self.execution_limits),
        )
        object.__setattr__(self, "ceilings", _detached_ceilings(self.ceilings))


def _detached_context(
    value: PrivateAnalysisDeploymentContext,
) -> PrivateAnalysisDeploymentContext:
    if type(value) is not PrivateAnalysisDeploymentContext:
        raise TypeError("context must be PrivateAnalysisDeploymentContext")
    return PrivateAnalysisDeploymentContext(state_dir=value.state_dir)


def _detached_deployment(value: object) -> PrivateAnalysisDeployment:
    if type(value) is not PrivateAnalysisDeployment:
        raise TypeError("deployment target must return PrivateAnalysisDeployment")
    return PrivateAnalysisDeployment(
        registrations=value.registrations,
        execution_limits=value.execution_limits,
        ceilings=value.ceilings,
    )


def load_private_analysis_deployment(
    target: str,
    *,
    context: PrivateAnalysisDeploymentContext,
) -> PrivateAnalysisDeployment:
    """Load and detach one explicitly trusted ``PACKAGE:ATTRIBUTE`` target.

    A callable target is invoked exactly once with a detached
    :class:`PrivateAnalysisDeploymentContext`.  The callable has the authority
    of the hosting process; this function contains its failures but is not a
    sandbox.
    """

    module_name, attribute = _deployment_target(target)
    private_context = _detached_context(context)
    try:
        module = importlib.import_module(module_name)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - deployment module initialization is code.
        raise PrivateAnalysisDeploymentLoadError(
            "private-analysis deployment module could not be imported"
        ) from None
    try:
        candidate = getattr(module, attribute)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - module attributes may be dynamic.
        raise PrivateAnalysisDeploymentLoadError(
            "private-analysis deployment target could not be resolved"
        ) from None

    if type(candidate) is PrivateAnalysisDeployment:
        produced: object = candidate
    elif callable(candidate):
        try:
            produced = candidate(private_context)
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException:  # noqa: BLE001 - deployment factories are trusted code.
            raise PrivateAnalysisDeploymentLoadError(
                "private-analysis deployment factory failed"
            ) from None
    else:
        raise PrivateAnalysisDeploymentLoadError(
            "private-analysis deployment target must be a descriptor or factory"
        )

    try:
        return _detached_deployment(produced)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - exact values can still be tampered in-process.
        raise PrivateAnalysisDeploymentLoadError(
            "private-analysis deployment descriptor is invalid"
        ) from None


__all__ = [
    "MAX_PRIVATE_ANALYSIS_DEPLOYMENT_RUNNERS",
    "PrivateAnalysisDeployment",
    "PrivateAnalysisDeploymentContext",
    "PrivateAnalysisDeploymentLoadError",
    "load_private_analysis_deployment",
]
