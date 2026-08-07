"""Shared HTTP/CLI wire contract for explicit private-analysis proposal review."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from .annotation_store import (
    ManualCorrelationEdge,
    ReviewAnnotationKind,
    ReviewSubject,
    ReviewValidationError,
)
from .private_analysis_promotion import (
    AnnotationPromotionTarget,
    CorrelationPromotionTarget,
    PromotionTarget,
    ProposalReviewDecision,
    ProposalReviewDisposition,
    ProposalReviewValidationError,
)
from .value_core import parse_canonical_decimal_integer

PROPOSAL_REVIEW_WIRE_CONTRACT: Final = (
    "router_dump_analyzer.private_analysis.proposal_review.v1"
)
_MAX_SIGNED_64: Final = (1 << 63) - 1
_OUTER_FIELDS: Final = frozenset(
    {"proposal_digest", "result_digest", "disposition", "rationale", "target"}
)
_SUBJECT_FIELDS: Final = frozenset(
    {"revision_id", "kind", "subject_id", "node_id", "start_ns", "end_ns"}
)


class ProposalReviewWireError(ValueError):
    """A proposal-review request does not satisfy the shared wire contract."""


@dataclass(frozen=True, slots=True)
class ProposalReviewRequest:
    proposal_digest: str
    result_digest: str
    disposition: ProposalReviewDisposition
    rationale: str
    target: PromotionTarget | None


def _closed_object(
    value: object,
    label: str,
    *,
    allowed: frozenset[str],
    required: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if type(value) is not dict:
        raise ProposalReviewWireError(f"{label} must be an object")
    selected = value
    if set(selected).difference(allowed) or required.difference(selected):
        raise ProposalReviewWireError(f"{label} has an invalid field set")
    if any(type(key) is not str for key in selected):
        raise ProposalReviewWireError(f"{label} keys must be strings")
    return selected


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ProposalReviewWireError(f"{label} must be {qualifier}")
    return value


def _canonical_ns(value: object, label: str) -> int:
    if type(value) is not str:
        raise ProposalReviewWireError(f"{label} must be a canonical decimal string")
    try:
        return parse_canonical_decimal_integer(
            value,
            label,
            minimum=0,
            maximum=_MAX_SIGNED_64,
        )
    except ValueError as error:
        raise ProposalReviewWireError(
            f"{label} must be a canonical non-negative signed-64 integer"
        ) from error


def _subjects(value: object) -> tuple[ReviewSubject, ...]:
    if type(value) is not list:
        raise ProposalReviewWireError("subjects must be an array")
    result: list[ReviewSubject] = []
    for raw in value:
        subject = _closed_object(
            raw,
            "review subject",
            allowed=_SUBJECT_FIELDS,
            required=frozenset({"revision_id", "kind"}),
        )
        normalized = dict(subject)
        for field in ("start_ns", "end_ns"):
            if field in normalized and normalized[field] is not None:
                normalized[field] = _canonical_ns(normalized[field], field)
        result.append(ReviewSubject.from_dict(normalized))
    return tuple(result)


def _tags(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ProposalReviewWireError("tags must be an array of strings")
    return tuple(value)


def _edges(value: object) -> tuple[ManualCorrelationEdge, ...]:
    if type(value) is not list:
        raise ProposalReviewWireError("edges must be an array")
    result: list[ManualCorrelationEdge] = []
    allowed = frozenset({"source_ordinal", "target_ordinal", "link_type", "directed"})
    required = frozenset({"source_ordinal", "target_ordinal", "link_type"})
    for raw in value:
        edge = _closed_object(
            raw,
            "manual correlation edge",
            allowed=allowed,
            required=required,
        )
        result.append(
            ManualCorrelationEdge(
                source_ordinal=edge["source_ordinal"],
                target_ordinal=edge["target_ordinal"],
                link_type=edge["link_type"],
                directed=edge.get("directed", True),
            )
        )
    return tuple(result)


def _target(value: object) -> PromotionTarget | None:
    if value is None:
        return None
    base = _closed_object(
        value,
        "proposal review target",
        allowed=frozenset(
            {
                "kind",
                "annotation_kind",
                "subjects",
                "edges",
                "title",
                "body",
                "rationale",
                "tags",
                "confidence",
            }
        ),
        required=frozenset({"kind"}),
    )
    kind = _text(base["kind"], "target kind")
    if kind == "annotation":
        allowed = frozenset(
            {"kind", "annotation_kind", "subjects", "title", "body", "tags"}
        )
        required = frozenset({"kind", "annotation_kind", "subjects"})
        target = _closed_object(
            base,
            "annotation promotion target",
            allowed=allowed,
            required=required,
        )
        try:
            annotation_kind = ReviewAnnotationKind(target["annotation_kind"])
        except (TypeError, ValueError) as error:
            raise ProposalReviewWireError(
                "annotation_kind is unsupported"
            ) from error
        return AnnotationPromotionTarget(
            kind=annotation_kind,
            subjects=_subjects(target["subjects"]),
            title=_text(target.get("title", ""), "title", allow_empty=True),
            body=_text(target.get("body", ""), "body", allow_empty=True),
            tags=_tags(target.get("tags")),
        )
    if kind == "manual_event_correlation":
        allowed = frozenset(
            {"kind", "subjects", "edges", "rationale", "tags", "confidence"}
        )
        required = frozenset({"kind", "subjects", "edges"})
        target = _closed_object(
            base,
            "manual correlation promotion target",
            allowed=allowed,
            required=required,
        )
        return CorrelationPromotionTarget(
            subjects=_subjects(target["subjects"]),
            edges=_edges(target["edges"]),
            rationale=_text(
                target.get("rationale", ""),
                "target rationale",
                allow_empty=True,
            ),
            tags=_tags(target.get("tags")),
            confidence=target.get("confidence"),
        )
    raise ProposalReviewWireError("proposal review target kind is unsupported")


def parse_proposal_review_request(value: object) -> ProposalReviewRequest:
    """Parse one exact, caller-authored decision without interpreting AI payload."""

    body = _closed_object(
        value,
        "proposal review request",
        allowed=_OUTER_FIELDS,
        required=frozenset({"proposal_digest", "result_digest", "disposition"}),
    )
    try:
        disposition = ProposalReviewDisposition(body["disposition"])
        return ProposalReviewRequest(
            proposal_digest=_text(body["proposal_digest"], "proposal_digest"),
            result_digest=_text(body["result_digest"], "result_digest"),
            disposition=disposition,
            rationale=_text(
                body.get("rationale", ""),
                "rationale",
                allow_empty=True,
            ),
            target=_target(body.get("target")),
        )
    except ProposalReviewWireError:
        raise
    except (
        ProposalReviewValidationError,
        ReviewValidationError,
        TypeError,
        ValueError,
    ) as error:
        raise ProposalReviewWireError("proposal review request is invalid") from error


def proposal_review_decision_to_wire(
    value: ProposalReviewDecision,
) -> dict[str, Any]:
    """Project one decision using lossless wire integers and a stable contract."""

    if type(value) is not ProposalReviewDecision:
        raise TypeError("proposal review decision projection is invalid")
    return {
        "contract": PROPOSAL_REVIEW_WIRE_CONTRACT,
        "scope": value.scope.to_dict(),
        "decision_id": value.decision_id,
        "run_id": value.run_id,
        "proposal_id": value.proposal_id,
        "proposal_digest": value.proposal_digest,
        "result_digest": value.result_digest,
        "run_version": str(value.run_version),
        "disposition": value.disposition.value,
        "state": value.state.value,
        "actor": value.actor,
        "rationale": value.rationale,
        "request_digest": value.request_digest,
        "target_kind": (
            None if value.target_kind is None else value.target_kind.value
        ),
        "target_id": value.target_id,
        "created_at_ns": str(value.created_at_ns),
        "updated_at_ns": str(value.updated_at_ns),
        "version": str(value.version),
    }


__all__ = [
    "PROPOSAL_REVIEW_WIRE_CONTRACT",
    "ProposalReviewRequest",
    "ProposalReviewWireError",
    "parse_proposal_review_request",
    "proposal_review_decision_to_wire",
]
