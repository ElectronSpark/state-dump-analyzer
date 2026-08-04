"""Catalog-aware construction and verification for private evidence values.

The pure values in :mod:`router_dump_analyzer.private_analysis.evidence` prove
their own canonical shape and digests.  This adapter proves that their scope,
revision content, and plug-in producer exist in trusted durable descriptors.
It performs no retrieval, authorization, or model invocation.
"""

from __future__ import annotations

from .private_analysis import (
    EvidenceAuthority,
    EvidenceProducer,
    EvidenceReference,
    EvidenceRevisionBinding,
    EvidenceScope,
)
from .session_store import (
    AnalysisRevisionDescriptor,
    FixtureDescriptor,
    WorkspaceDescriptor,
)


class PrivateAnalysisEvidenceBindingError(ValueError):
    """An evidence identity does not match its trusted catalog descriptors."""


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
        plan_basis_revision_id=plan.basis_revision_id,
        execution_plan_digest=plan.plan_digest,
    )
    return scope, binding


def bind_private_analysis_plugin_producer(
    revision: AnalysisRevisionDescriptor,
    *,
    plugin_instance_id: str,
    capability: str,
) -> EvidenceProducer:
    """Resolve one exact plan pin and declared capability as a producer."""

    if type(revision) is not AnalysisRevisionDescriptor:
        raise TypeError("revision must be AnalysisRevisionDescriptor")
    if type(plugin_instance_id) is not str or not plugin_instance_id:
        raise TypeError("plugin_instance_id must be a non-empty string")
    if type(capability) is not str or not capability:
        raise TypeError("capability must be a non-empty string")
    plan = revision.execution_plan
    if plan is None:
        raise PrivateAnalysisEvidenceBindingError(
            "private analysis requires an immutable plug-in execution plan"
        )
    pins = tuple(
        pin for pin in plan.plugins if pin.instance_id == plugin_instance_id
    )
    if len(pins) != 1:
        raise PrivateAnalysisEvidenceBindingError(
            "plug-in instance is not present in the revision execution plan"
        )
    pin = pins[0]
    if capability not in pin.capabilities:
        raise PrivateAnalysisEvidenceBindingError(
            "plug-in capability is not declared by the selected instance"
        )
    return EvidenceProducer(
        authority=EvidenceAuthority.PLUGIN_INFERRED,
        producer_id=pin.plugin_id,
        plugin_instance_id=pin.instance_id,
        plugin_capability=capability,
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
        if instance_id is None or capability is None:  # constructor is fail closed
            raise PrivateAnalysisEvidenceBindingError(
                "plug-in evidence lacks a qualified producer"
            )
        expected_producer = bind_private_analysis_plugin_producer(
            revision,
            plugin_instance_id=instance_id,
            capability=capability,
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
