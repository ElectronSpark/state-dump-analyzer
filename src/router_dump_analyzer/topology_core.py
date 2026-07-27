"""Generic, fail-closed joins between route decisions and topology evidence.

Plug-ins own the meaning of matcher IDs, opaque keys, attachment resources,
and normalized usability.  The core only compares an advertised exact
reference with an already-normalized topology snapshot and verifies that the
two endpoint attachments are current and usable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import canonical_json


@dataclass(frozen=True, slots=True)
class ConnectivityDomainBinding:
    """Result of resolving one plug-in-declared next-hop topology reference."""

    state: str
    reason_code: str
    domain: Mapping[str, Any] | None = None
    source_attachment: Mapping[str, Any] | None = None
    target_attachment: Mapping[str, Any] | None = None
    candidate_domain_ids: tuple[str, ...] = ()

    @property
    def resolved(self) -> bool:
        return self.state == "resolved"

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reason_code": self.reason_code,
            "network_segment_id": (
                str(self.domain["segment_id"]) if self.domain else None
            ),
            "source_attachment_id": (
                str(self.source_attachment["attachment_id"])
                if self.source_attachment
                else None
            ),
            "target_attachment_id": (
                str(self.target_attachment["attachment_id"])
                if self.target_attachment
                else None
            ),
            "candidate_domain_ids": list(self.candidate_domain_ids),
        }


def _canonical_topology_key(value: Any) -> str:
    """Use the shared canonical serializer with this API's error contract."""

    try:
        return canonical_json(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "topology match arguments must be JSON-serializable"
        ) from error


def _unresolved(
    reason_code: str,
    *,
    state: str = "unresolved",
    candidate_domain_ids: tuple[str, ...] = (),
) -> ConnectivityDomainBinding:
    return ConnectivityDomainBinding(
        state=state,
        reason_code=reason_code,
        candidate_domain_ids=candidate_domain_ids,
    )


def _current_usable_attachment(item: Mapping[str, Any]) -> bool:
    return (
        item.get("exists") is True
        and item.get("claim_valid_at_basis") is True
        and item.get("endpoint_exists_at_basis") is True
        and item.get("operational_status") == "usable"
    )


def resolve_connectivity_domain_reference(
    snapshot: Mapping[str, Any],
    topology_reference: Mapping[str, Any],
    *,
    source_node_id: str,
    target_node_id: str,
    source_resource_id: str,
    target_resource_id: str | None = None,
) -> ConnectivityDomainBinding:
    """Resolve one exact opaque domain reference against a normalized snapshot.

    No prefix, address, VLAN, label, or node-pair inference is performed.  A
    missing, ambiguous, truncated, conflicting, or unusable declaration stays
    unresolved so route reachability cannot be promoted by presentation data.
    """

    if not isinstance(snapshot, Mapping):
        raise ValueError("topology snapshot must be an object")
    if not isinstance(topology_reference, Mapping):
        raise ValueError("topology_reference must be an object")
    if topology_reference.get("reference_kind") != "connectivity_domain":
        raise ValueError(
            "topology_reference.reference_kind must be connectivity_domain"
        )
    if not source_node_id or not target_node_id:
        raise ValueError("source and target node IDs are required")
    if not source_resource_id:
        raise ValueError("source attachment resource ID is required")

    match = topology_reference.get("match")
    if not isinstance(match, Mapping):
        raise ValueError("topology_reference.match must be an object")
    matcher_id = match.get("matcher_id")
    arguments = match.get("arguments")
    if not isinstance(matcher_id, str) or not matcher_id:
        raise ValueError("topology reference matcher_id is required")
    if not isinstance(arguments, Mapping) or "segment_key" not in arguments:
        raise ValueError(
            "topology reference requires arguments.segment_key"
        )
    requested_key = _canonical_topology_key(arguments["segment_key"])
    requested_contract_version = match.get("matcher_contract_version")
    if requested_contract_version is not None and (
        not isinstance(requested_contract_version, str)
        or not requested_contract_version
    ):
        raise ValueError(
            "topology matcher_contract_version must be a non-empty string"
        )

    completeness = snapshot.get("completeness")
    if isinstance(completeness, Mapping) and (
        completeness.get("network_segments_truncated") is True
        or completeness.get("segment_attachments_truncated") is True
    ):
        return _unresolved("topology_evidence_truncated")

    candidates: list[Mapping[str, Any]] = []
    for raw_domain in snapshot.get("network_segments", ()):
        if not isinstance(raw_domain, Mapping):
            continue
        normalized_match = raw_domain.get("match")
        if not isinstance(normalized_match, Mapping):
            continue
        if normalized_match.get("matcher_id") != matcher_id:
            continue
        if (
            requested_contract_version is not None
            and normalized_match.get("matcher_contract_version")
            != requested_contract_version
        ):
            continue
        if (
            _canonical_topology_key(normalized_match.get("segment_key"))
            != requested_key
        ):
            continue
        candidates.append(raw_domain)

    candidate_ids = tuple(
        str(item.get("segment_id", "")) for item in candidates
    )
    if not candidates:
        return _unresolved("connectivity_domain_not_found")
    if len(candidates) != 1:
        return _unresolved(
            "connectivity_domain_ambiguous",
            state="ambiguous",
            candidate_domain_ids=candidate_ids,
        )

    domain = candidates[0]
    domain_id = str(domain.get("segment_id", ""))
    if (
        not domain_id
        or domain.get("connectivity_enabled") is not True
        or domain.get("exists") is not True
        or domain.get("semantic_conflict") is True
        or domain.get("operational_status") != "usable"
    ):
        return _unresolved(
            "connectivity_domain_not_usable",
            candidate_domain_ids=candidate_ids,
        )

    attachments = [
        item
        for item in snapshot.get("segment_attachments", ())
        if isinstance(item, Mapping)
        and str(item.get("segment_id", "")) == domain_id
    ]
    source_candidates = [
        item
        for item in attachments
        if str(item.get("node_id", "")) == source_node_id
        and str(item.get("resource_id", "")) == source_resource_id
    ]
    target_candidates = [
        item
        for item in attachments
        if str(item.get("node_id", "")) == target_node_id
        and (
            target_resource_id is None
            or str(item.get("resource_id", "")) == target_resource_id
        )
    ]
    if len(source_candidates) != 1:
        return _unresolved(
            (
                "source_attachment_ambiguous"
                if len(source_candidates) > 1
                else "source_attachment_not_found"
            ),
            state="ambiguous" if len(source_candidates) > 1 else "unresolved",
            candidate_domain_ids=candidate_ids,
        )
    if len(target_candidates) != 1:
        return _unresolved(
            (
                "target_attachment_ambiguous"
                if len(target_candidates) > 1
                else "target_attachment_not_found"
            ),
            state="ambiguous" if len(target_candidates) > 1 else "unresolved",
            candidate_domain_ids=candidate_ids,
        )
    source_attachment = source_candidates[0]
    target_attachment = target_candidates[0]
    if not _current_usable_attachment(source_attachment):
        return _unresolved(
            "source_attachment_not_usable",
            candidate_domain_ids=candidate_ids,
        )
    if not _current_usable_attachment(target_attachment):
        return _unresolved(
            "target_attachment_not_usable",
            candidate_domain_ids=candidate_ids,
        )

    return ConnectivityDomainBinding(
        state="resolved",
        reason_code="exact_connectivity_domain_and_attachments",
        domain=domain,
        source_attachment=source_attachment,
        target_attachment=target_attachment,
        candidate_domain_ids=candidate_ids,
    )


__all__ = [
    "ConnectivityDomainBinding",
    "resolve_connectivity_domain_reference",
]
