"""Spawn-importable evidence-service factories for process-boundary tests."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from router_dump_analyzer.private_analysis import (
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisPolicy,
    WorkspaceDisclosurePolicy,
)
from router_dump_analyzer.private_analysis.contracts import PrivateAnalysisRequest
from router_dump_analyzer.private_analysis.evidence import (
    EvidenceReference,
    EvidenceScope,
    evidence_reference_from_dict,
)
from router_dump_analyzer.private_analysis.tool_catalog import (
    PrivateAnalysisQueryArguments,
)
from router_dump_analyzer.private_analysis_tool_service import (
    PrivateAnalysisAuthorizationDecision,
    PrivateAnalysisToolService,
    PrivateAnalysisWorkspacePolicySnapshot,
)


def configured_service_factory(
    request: PrivateAnalysisRequest,
    configuration: dict[str, Any],
) -> PrivateAnalysisToolService:
    references = tuple(
        evidence_reference_from_dict(value)
        for value in configuration.get("references", [])
    )
    payloads = configuration.get("payloads", {})
    policy = WorkspaceDisclosurePolicy(
        mode=PrivateAnalysisDisclosureMode(
            configuration.get("disclosure_mode", "full_fidelity")
        ),
        transports=(request.runner.transport,),
    )

    def authorize(
        selected: PrivateAnalysisRequest,
    ) -> PrivateAnalysisAuthorizationDecision:
        return PrivateAnalysisAuthorizationDecision.allow(selected)

    def resolve_policy(scope: EvidenceScope) -> PrivateAnalysisWorkspacePolicySnapshot:
        return PrivateAnalysisWorkspacePolicySnapshot(
            scope=scope,
            policy_version=1,
            policy=policy,
            policy_digest=policy.digest,
        )

    def query_references(
        _request: PrivateAnalysisRequest,
        _arguments: PrivateAnalysisQueryArguments,
    ) -> tuple[EvidenceReference, ...]:
        return references

    def resolve_reference(
        _request: PrivateAnalysisRequest,
        digest: str,
    ) -> EvidenceReference | None:
        return next(
            (item for item in references if item.reference_digest == digest),
            None,
        )

    def materialize_payload(reference: EvidenceReference) -> dict[str, Any]:
        selected = payloads.get(reference.reference_digest, {})
        if type(selected) is not dict:
            raise TypeError("fixture payload must be an object")
        return selected

    return PrivateAnalysisToolService(
        request,
        runner_policy=PrivateAnalysisPolicy(transport=request.runner.transport),
        authorize=authorize,
        resolve_policy=resolve_policy,
        query_references=query_references,
        resolve_reference=resolve_reference,
        validate_reference=lambda _reference: True,
        materialize_payload=materialize_payload,
    )


def non_returning_service_factory(
    _request: PrivateAnalysisRequest,
    configuration: dict[str, Any],
) -> PrivateAnalysisToolService:
    marker = configuration.get("marker")
    if type(marker) is str:
        Path(marker).write_text("started", encoding="utf-8")
    while True:
        time.sleep(60)


def malformed_service_factory(
    _request: PrivateAnalysisRequest,
    _configuration: dict[str, Any],
) -> PrivateAnalysisToolService:
    return object.__new__(PrivateAnalysisToolService)


def process_control_service_factory(
    _request: PrivateAnalysisRequest,
    _configuration: dict[str, Any],
) -> PrivateAnalysisToolService:
    raise KeyboardInterrupt("C:\\deployment\\secret-provider.py")


def malformed_ipc_service_factory(
    request: PrivateAnalysisRequest,
    configuration: dict[str, Any],
) -> PrivateAnalysisToolService:
    from router_dump_analyzer import private_analysis_factory_process

    def send_malformed(connection: Any, _value: dict[str, Any]) -> None:
        connection.send_bytes(b'{"kind":"hostile"}')

    private_analysis_factory_process._send_message = send_malformed
    return configured_service_factory(request, configuration)
