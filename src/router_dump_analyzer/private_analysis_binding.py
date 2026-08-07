"""Catalog-aware construction and verification for private evidence values.

The pure values in :mod:`router_dump_analyzer.private_analysis.evidence` prove
their own canonical shape and digests.  This adapter proves that their scope,
revision content, and plug-in producer exist in trusted durable descriptors.
It performs no retrieval, authorization, or model invocation.
"""

from __future__ import annotations

import hashlib

from .plugin_execution_plan import plugin_execution_plan_is_executable
from .private_analysis import (
    EvidenceAuthority,
    EvidenceProducer,
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
)
from .private_analysis.evidence import validate_evidence_identifier
from .session_store import (
    AnalysisRevisionDescriptor,
    FixtureDescriptor,
    WorkspaceDescriptor,
)


class PrivateAnalysisEvidenceBindingError(ValueError):
    """An evidence identity does not match its trusted catalog descriptors."""


def _private_analysis_plan_basis_id(value: str) -> str:
    """Project a potentially path-shaped parser basis into a safe opaque ID.

    Ingestion source revision IDs intentionally use structured slash-separated
    names.  Private evidence identifiers deliberately reject path syntax, and
    the exact raw execution plan is already committed by ``plan_digest``.
    Preserve an already safe opaque basis for wire compatibility; otherwise
    use a domain-separated digest without exposing the structured source name.
    """

    try:
        return validate_evidence_identifier(value, "plan_basis_revision_id")
    except ValueError:
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise PrivateAnalysisEvidenceBindingError(
                "execution-plan basis is not valid Unicode"
            ) from error
        digest = hashlib.sha256(
            b"router-dump-analyzer:private-analysis-plan-basis:v1\x00" + encoded
        ).hexdigest()
        return f"plan-basis-sha256-{digest}"


def bind_private_analysis_revision(
    workspace: WorkspaceDescriptor,
    fixture: FixtureDescriptor,
    revision: AnalysisRevisionDescriptor,
) -> tuple[EvidenceScope, EvidenceRevisionBinding]:
    """Bind one plan-bearing immutable revision to its authorization scope."""

    if type(workspace) is not WorkspaceDescriptor:
        raise TypeError("workspace must be WorkspaceDescriptor")
    if type(fixture) is not FixtureDescriptor:
        raise TypeError("fixture must be FixtureDescriptor")
    if type(revision) is not AnalysisRevisionDescriptor:
        raise TypeError("revision must be AnalysisRevisionDescriptor")
    if fixture.tenant_id != workspace.tenant_id:
        raise PrivateAnalysisEvidenceBindingError(
            "fixture tenant does not match workspace"
        )
    if fixture.workspace_id != workspace.workspace_id:
        raise PrivateAnalysisEvidenceBindingError(
            "fixture workspace does not match workspace"
        )
    if revision.tenant_id != workspace.tenant_id:
        raise PrivateAnalysisEvidenceBindingError(
            "revision tenant does not match workspace"
        )
    if revision.workspace_id != workspace.workspace_id:
        raise PrivateAnalysisEvidenceBindingError(
            "revision workspace does not match workspace"
        )
    if revision.fixture_id != fixture.fixture_id:
        raise PrivateAnalysisEvidenceBindingError(
            "revision fixture does not match fixture"
        )
    plan = revision.execution_plan
    if plan is None:
        raise PrivateAnalysisEvidenceBindingError(
            "private analysis requires an immutable plug-in execution plan"
        )
    try:
        executable_plan = plugin_execution_plan_is_executable(plan)
    except (TypeError, ValueError) as error:
        raise PrivateAnalysisEvidenceBindingError(
            "private analysis requires a valid current plug-in execution plan"
        ) from error
    if not executable_plan:
        raise PrivateAnalysisEvidenceBindingError(
            "retained v1 plug-in execution plans cannot produce private-analysis "
            "evidence"
        )
    if plan.node_id != revision.node_id:
        raise PrivateAnalysisEvidenceBindingError(
            "revision node does not match execution plan"
        )
    scope = EvidenceScope(
        tenant_id=workspace.tenant_id,
        project_id=workspace.project_id,
        workspace_id=workspace.workspace_id,
    )
    binding = EvidenceRevisionBinding(
        fixture_id=fixture.fixture_id,
        fixture_content_sha256=fixture.content_digest,
        node_id=revision.node_id,
        revision_id=revision.revision_id,
        revision_identity_sha256=revision.identity_digest,
        plan_basis_revision_id=_private_analysis_plan_basis_id(plan.basis_revision_id),
        execution_plan_digest=plan.plan_digest,
    )
    return scope, binding


def bind_private_analysis_plugin_producer(
    revision: AnalysisRevisionDescriptor,
    *,
    plugin_instance_id: str,
    capability: str | None = None,
    role: str | None = None,
) -> EvidenceProducer:
    """Resolve one exact plan pin and declared capability or core role."""

    if type(revision) is not AnalysisRevisionDescriptor:
        raise TypeError("revision must be AnalysisRevisionDescriptor")
    if type(plugin_instance_id) is not str or not plugin_instance_id:
        raise TypeError("plugin_instance_id must be a non-empty string")
    if (capability is None) == (role is None):
        raise ValueError("exactly one capability or role must be selected")
    if capability is not None and (type(capability) is not str or not capability):
        raise TypeError("capability must be a non-empty string")
    if role is not None and (type(role) is not str or not role):
        raise TypeError("role must be a non-empty string")
    plan = revision.execution_plan
    if plan is None:
        raise PrivateAnalysisEvidenceBindingError(
            "private analysis requires an immutable plug-in execution plan"
        )
    try:
        executable_plan = plugin_execution_plan_is_executable(plan)
    except (TypeError, ValueError) as error:
        raise PrivateAnalysisEvidenceBindingError(
            "private analysis requires a valid current plug-in execution plan"
        ) from error
    if not executable_plan:
        raise PrivateAnalysisEvidenceBindingError(
            "retained v1 plug-in execution plans cannot produce private-analysis "
            "evidence"
        )
    pins = tuple(pin for pin in plan.plugins if pin.instance_id == plugin_instance_id)
    if len(pins) != 1:
        raise PrivateAnalysisEvidenceBindingError(
            "plug-in instance is not present in the revision execution plan"
        )
    pin = pins[0]
    if capability is not None and capability not in pin.capabilities:
        raise PrivateAnalysisEvidenceBindingError(
            "plug-in capability is not declared by the selected instance"
        )
    if role is not None and role not in pin.roles:
        raise PrivateAnalysisEvidenceBindingError(
            "plug-in role is not assigned to the selected instance"
        )
    return EvidenceProducer(
        authority=EvidenceAuthority.PLUGIN_INFERRED,
        producer_id=pin.plugin_id,
        plugin_instance_id=pin.instance_id,
        plugin_capability=capability,
        plugin_role=role,
    )


def verify_private_analysis_evidence_binding(
    reference: EvidenceReference,
    workspace: WorkspaceDescriptor,
    fixture: FixtureDescriptor,
    revision: AnalysisRevisionDescriptor,
) -> None:
    """Fail closed unless one reference exactly matches trusted descriptors."""

    if type(reference) is not EvidenceReference:
        raise TypeError("reference must be EvidenceReference")
    expected_scope, expected_revision = bind_private_analysis_revision(
        workspace,
        fixture,
        revision,
    )
    if reference.scope != expected_scope:
        raise PrivateAnalysisEvidenceBindingError(
            "evidence scope does not match the durable workspace"
        )
    if reference.revision != expected_revision:
        raise PrivateAnalysisEvidenceBindingError(
            "evidence revision does not match durable content and plan identity"
        )
    if reference.producer.authority is EvidenceAuthority.PLUGIN_INFERRED:
        instance_id = reference.producer.plugin_instance_id
        capability = reference.producer.plugin_capability
        role = reference.producer.plugin_role
        if instance_id is None or (capability is None) == (role is None):
            raise PrivateAnalysisEvidenceBindingError(
                "plug-in evidence lacks a qualified producer"
            )
        expected_producer = bind_private_analysis_plugin_producer(
            revision,
            plugin_instance_id=instance_id,
            capability=capability,
            role=role,
        )
        if reference.producer != expected_producer:
            raise PrivateAnalysisEvidenceBindingError(
                "evidence producer does not match the selected plug-in pin"
            )


__all__ = [
    "PrivateAnalysisEvidenceBindingError",
    "bind_private_analysis_plugin_producer",
    "bind_private_analysis_revision",
    "verify_private_analysis_evidence_binding",
]
