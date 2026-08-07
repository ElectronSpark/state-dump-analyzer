"""Strict cooperative cancellation for private-analysis evidence queries."""

from __future__ import annotations

from collections.abc import Callable

from ..process_control import PROCESS_CONTROL_EXCEPTIONS


class PrivateAnalysisEvidenceQueryCancelledError(RuntimeError):
    """A cooperative cancellation or deadline stopped snapshot construction."""


class PrivateAnalysisEvidenceQueryCancellationProbeError(RuntimeError):
    """The query cancellation/deadline probe failed safely."""


class PrivateAnalysisEvidenceQueryCancellationProbeResultError(
    PrivateAnalysisEvidenceQueryCancellationProbeError
):
    """The query cancellation/deadline probe returned a non-boolean value."""


def check_private_analysis_evidence_query_cancellation(
    cancellation_probe: Callable[[], bool] | None,
) -> None:
    """Evaluate one query probe with static, typed fail-closed errors."""

    if cancellation_probe is None:
        return
    try:
        cancelled = cancellation_probe()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise PrivateAnalysisEvidenceQueryCancellationProbeError(
            "private-analysis evidence-query cancellation state is unavailable"
        ) from error
    if type(cancelled) is not bool:
        raise PrivateAnalysisEvidenceQueryCancellationProbeResultError(
            "private-analysis evidence-query cancellation probe returned an "
            "invalid value"
        )
    if cancelled:
        raise PrivateAnalysisEvidenceQueryCancelledError(
            "private-analysis evidence query was cancelled"
        )


__all__ = [
    "PrivateAnalysisEvidenceQueryCancellationProbeError",
    "PrivateAnalysisEvidenceQueryCancellationProbeResultError",
    "PrivateAnalysisEvidenceQueryCancelledError",
    "check_private_analysis_evidence_query_cancellation",
]
