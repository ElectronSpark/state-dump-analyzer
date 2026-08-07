from __future__ import annotations

import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path
from unittest.mock import patch

from rsl_demo_plugin import (
    EVIDENCE_PLUGIN_ID,
    PLATFORM_ID,
    SOFTWARE_VERSION,
    render_conformance_status_fixture,
)

from router_dump_analyzer.control_plane import ControlPlane, ControlPlaneLimits
from router_dump_analyzer.ingestion_pipeline import (
    ImportState,
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
)
from router_dump_analyzer.plugin_api import (
    EvidenceAnalysisObservation,
    PluginCapability,
    Quality,
)
from router_dump_analyzer.plugin_composition_deployment import (
    PluginCompositionDeploymentContext,
    load_plugin_composition_deployment,
)
from router_dump_analyzer.private_analysis import (
    EvidenceKind,
    EvidenceScope,
    PrivateAnalysisCapabilityArguments,
    PrivateAnalysisCapabilityIntent,
    PrivateAnalysisCitation,
    PrivateAnalysisClaim,
    PrivateAnalysisClaimSupport,
    PrivateAnalysisClockMode,
    PrivateAnalysisDisclosureMode,
    PrivateAnalysisLimits,
    PrivateAnalysisPolicy,
    PrivateAnalysisQueryArguments,
    PrivateAnalysisReadArguments,
    PrivateAnalysisResult,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTaskKind,
    PrivateAnalysisToolBinding,
    PrivateAnalysisToolCall,
    PrivateAnalysisToolName,
    PrivateAnalysisToolResultKind,
    PrivateAnalysisTransport,
    WorkspaceDisclosurePolicy,
    private_analysis_result_json,
    private_analysis_tool_call_json,
)
from router_dump_analyzer.private_analysis_execution import (
    PrivateAnalysisRunnerRegistration,
)
from router_dump_analyzer.private_analysis_in_process_runner import (
    ConfiguredPrivateAnalysisInProcessRunner,
    PrivateAnalysisInProcessContext,
    PrivateAnalysisInProcessToolGateway,
    PrivateAnalysisInProcessToolResponseKind,
)
from router_dump_analyzer.private_analysis_run_store import PrivateAnalysisRunState
from router_dump_analyzer.private_analysis_service import PrivateAnalysisRequestSpec
from tests.test_control_plane import _EventPlugin, _fixture_bytes

_CONFIGURATION_DIGEST = "sha256:" + "a" * 64
_INSTRUCTION_PROFILE_DIGEST = "sha256:" + "b" * 64


class _EvidenceEventPlugin(_EventPlugin):
    manifest = replace(
        _EventPlugin.manifest,
        plugin_id="tests.control-plane-evidence-analysis",
        capabilities=frozenset(
            {
                PluginCapability.TEXT_TRACE_PARSE,
                PluginCapability.EVIDENCE_ANALYSIS,
            }
        ),
    )

    def analyze_evidence(self, request):
        yield EvidenceAnalysisObservation(
            observation_id="interface-status-correlation",
            category="trace_correlation",
            summary="The selected trace record belongs to an interface transition.",
            cited_reference_digests=tuple(
                sorted(fact.reference_digest for fact in request.facts)
            ),
            quality=Quality.EXACT,
            details={"analysis_kind": request.analysis_kind.value},
        )


def _core_revision_evidence_model_callback(
    context: PrivateAnalysisInProcessContext,
    gateway: PrivateAnalysisInProcessToolGateway,
) -> str:
    """Exercise core query/read evidence without retaining mutable test state."""

    query_call = PrivateAnalysisToolCall(
        call_id="events",
        binding=PrivateAnalysisToolBinding(
            request_digest=context.request.request_digest,
            tool_catalog_digest=context.request.tool_catalog_digest,
            name=PrivateAnalysisToolName.QUERY_EVIDENCE,
        ),
        arguments=PrivateAnalysisQueryArguments(
            evidence_kinds=(EvidenceKind.SOURCE_RECORD,),
            page_size=8,
        ),
    )
    query_response = gateway.execute(private_analysis_tool_call_json(query_call))
    if (
        query_response.kind is not PrivateAnalysisInProcessToolResponseKind.RESULT
        or query_response.result is None
        or query_response.result.kind is not PrivateAnalysisToolResultKind.QUERY_PAGE
        or len(query_response.result.references) != 2
    ):
        raise AssertionError("core evidence query returned the wrong reference page")
    reference = query_response.result.references[0]
    if reference.producer.plugin_role != "primary_parser":
        raise AssertionError("core evidence query lost the primary parser producer")

    read_call = PrivateAnalysisToolCall(
        call_id="read-event",
        binding=PrivateAnalysisToolBinding(
            request_digest=context.request.request_digest,
            tool_catalog_digest=context.request.tool_catalog_digest,
            name=PrivateAnalysisToolName.READ_EVIDENCE,
        ),
        arguments=PrivateAnalysisReadArguments(
            evidence_reference_digest=reference.reference_digest,
        ),
    )
    read_response = gateway.execute(private_analysis_tool_call_json(read_call))
    if (
        read_response.kind is not PrivateAnalysisInProcessToolResponseKind.RESULT
        or read_response.result is None
        or read_response.result.envelope is None
    ):
        raise AssertionError("core evidence read returned no envelope")
    payload = read_response.result.envelope.payload
    if payload.get("source_type") != "status-json" or "copy_text" not in payload:
        raise AssertionError("core evidence read returned the wrong source payload")

    result = PrivateAnalysisResult(
        request_digest=context.request.request_digest,
        summary=PrivateAnalysisClaim(
            claim_id="summary",
            support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
            text="The selected revision contains a retained source record.",
            citations=(
                PrivateAnalysisCitation(
                    evidence_reference_digest=reference.reference_digest,
                ),
            ),
        ),
        claims=(),
        proposals=(),
    )
    return private_analysis_result_json(result)


def _core_capability_evidence_model_callback(
    context: PrivateAnalysisInProcessContext,
    gateway: PrivateAnalysisInProcessToolGateway,
) -> str:
    """Read one fact, request host-routed analysis, then reread its result."""

    binding = lambda name: PrivateAnalysisToolBinding(
        request_digest=context.request.request_digest,
        tool_catalog_digest=context.request.tool_catalog_digest,
        name=name,
    )
    query_response = gateway.execute(
        private_analysis_tool_call_json(
            PrivateAnalysisToolCall(
                call_id="query-source-records",
                binding=binding(PrivateAnalysisToolName.QUERY_EVIDENCE),
                arguments=PrivateAnalysisQueryArguments(
                    evidence_kinds=(EvidenceKind.SOURCE_RECORD,),
                    page_size=8,
                ),
            )
        )
    )
    if (
        query_response.kind is not PrivateAnalysisInProcessToolResponseKind.RESULT
        or query_response.result is None
        or not query_response.result.references
    ):
        raise AssertionError("source evidence query failed")
    source = query_response.result.references[0]
    read_response = gateway.execute(
        private_analysis_tool_call_json(
            PrivateAnalysisToolCall(
                call_id="read-source-record",
                binding=binding(PrivateAnalysisToolName.READ_EVIDENCE),
                arguments=PrivateAnalysisReadArguments(
                    evidence_reference_digest=source.reference_digest,
                ),
            )
        )
    )
    if read_response.result is None or read_response.result.envelope is None:
        raise AssertionError("source evidence was not materialized")
    analyze_response = gateway.execute(
        private_analysis_tool_call_json(
            PrivateAnalysisToolCall(
                call_id="analyze-source-record",
                binding=binding(PrivateAnalysisToolName.ANALYZE_EVIDENCE),
                arguments=PrivateAnalysisCapabilityArguments(
                    node_id=source.revision.node_id,
                    revision_id=source.revision.revision_id,
                    intent=PrivateAnalysisCapabilityIntent.TRACE_CORRELATION,
                    parent_reference_digests=(source.reference_digest,),
                    parameters_json='{"focus":"interface"}',
                    max_observations=4,
                ),
            )
        )
    )
    if (
        analyze_response.kind
        is not PrivateAnalysisInProcessToolResponseKind.RESULT
        or analyze_response.result is None
        or analyze_response.result.kind
        is not PrivateAnalysisToolResultKind.DERIVED_EVIDENCE_ENVELOPE
        or analyze_response.result.envelope is None
    ):
        raise AssertionError("host-routed evidence analysis failed")
    derived = analyze_response.result.envelope
    if (
        derived.reference.kind is not EvidenceKind.PLUGIN_CAPABILITY_RESULT
        or derived.reference.producer.plugin_capability != "evidence_analysis"
        or derived.payload["observations"][0]["observation_id"]
        != "interface-status-correlation"
    ):
        raise AssertionError("derived evidence lost its exact provider result")
    overlay_read = gateway.execute(
        private_analysis_tool_call_json(
            PrivateAnalysisToolCall(
                call_id="read-derived-evidence",
                binding=binding(PrivateAnalysisToolName.READ_EVIDENCE),
                arguments=PrivateAnalysisReadArguments(
                    evidence_reference_digest=(
                        derived.reference.reference_digest
                    ),
                ),
            )
        )
    )
    if (
        overlay_read.result is None
        or overlay_read.result.envelope is None
        or overlay_read.result.envelope.envelope_digest != derived.envelope_digest
    ):
        raise AssertionError("derived evidence was not available for exact reread")
    return private_analysis_result_json(
        PrivateAnalysisResult(
            request_digest=context.request.request_digest,
            summary=PrivateAnalysisClaim(
                claim_id="summary",
                support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
                text="The private plug-in correlated the selected trace record.",
                citations=(
                    PrivateAnalysisCitation(
                        evidence_reference_digest=(
                            derived.reference.reference_digest
                        ),
                    ),
                ),
            ),
            claims=(),
            proposals=(),
        )
    )


def _demo_composed_evidence_model_callback(
    context: PrivateAnalysisInProcessContext,
    gateway: PrivateAnalysisInProcessToolGateway,
) -> str:
    """Exercise every closed intent through the real demo auxiliary."""

    def binding(name: PrivateAnalysisToolName) -> PrivateAnalysisToolBinding:
        return PrivateAnalysisToolBinding(
            request_digest=context.request.request_digest,
            tool_catalog_digest=context.request.tool_catalog_digest,
            name=name,
        )

    query_response = gateway.execute(
        private_analysis_tool_call_json(
            PrivateAnalysisToolCall(
                call_id="query-demo-sources",
                binding=binding(PrivateAnalysisToolName.QUERY_EVIDENCE),
                arguments=PrivateAnalysisQueryArguments(
                    evidence_kinds=(EvidenceKind.SOURCE_RECORD,),
                    page_size=16,
                ),
            )
        )
    )
    if query_response.result is None:
        raise AssertionError("demo source evidence query failed")
    source_by_node = {}
    for reference in query_response.result.references:
        if reference.producer.plugin_role != "primary_parser":
            raise AssertionError("demo source evidence lost its primary role")
        source_by_node.setdefault(reference.revision.node_id, reference)
    if set(source_by_node) != {"node-a", "node-b"}:
        raise AssertionError("demo source evidence lost a target node")

    for index, reference in enumerate(source_by_node.values()):
        read = gateway.execute(
            private_analysis_tool_call_json(
                PrivateAnalysisToolCall(
                    call_id=f"read-demo-source-{index}",
                    binding=binding(PrivateAnalysisToolName.READ_EVIDENCE),
                    arguments=PrivateAnalysisReadArguments(
                        evidence_reference_digest=reference.reference_digest,
                    ),
                )
            )
        )
        if read.result is None or read.result.envelope is None:
            raise AssertionError("demo source evidence was not materialized")

    intents = (
        PrivateAnalysisCapabilityIntent.ROUTE_TRACE,
        PrivateAnalysisCapabilityIntent.TRACE_CORRELATION,
        PrivateAnalysisCapabilityIntent.EVIDENCE_CORRELATION,
        PrivateAnalysisCapabilityIntent.EVIDENCE_INTERPRETATION,
    )
    sources = tuple(source_by_node[node_id] for node_id in sorted(source_by_node))
    derived_references = []
    for index, intent in enumerate(intents):
        source = sources[index % len(sources)]
        analyzed = gateway.execute(
            private_analysis_tool_call_json(
                PrivateAnalysisToolCall(
                    call_id=f"analyze-demo-{intent.value}",
                    binding=binding(PrivateAnalysisToolName.ANALYZE_EVIDENCE),
                    arguments=PrivateAnalysisCapabilityArguments(
                        node_id=source.revision.node_id,
                        revision_id=source.revision.revision_id,
                        intent=intent,
                        parent_reference_digests=(source.reference_digest,),
                        parameters_json='{"scope":"demo"}',
                        max_observations=4,
                    ),
                )
            )
        )
        if analyzed.result is None or analyzed.result.envelope is None:
            raise AssertionError("demo evidence analysis returned no envelope")
        envelope = analyzed.result.envelope
        if (
            envelope.reference.producer.plugin_instance_id
            != "demo.example-router.evidence-analysis"
            or envelope.reference.producer.producer_id != EVIDENCE_PLUGIN_ID
            or envelope.reference.producer.plugin_capability
            != PluginCapability.EVIDENCE_ANALYSIS.value
            or envelope.reference.revision != source.revision
            or envelope.payload["observations"][0]["observation_id"]
            != "demo-analysis-" + intent.value.replace("_", "-")
        ):
            raise AssertionError("demo derived evidence lost its exact producer")
        derived_references.append(envelope.reference)

    return private_analysis_result_json(
        PrivateAnalysisResult(
            request_digest=context.request.request_digest,
            summary=PrivateAnalysisClaim(
                claim_id="summary",
                support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
                text="The composed demo provider analyzed every closed intent.",
                citations=tuple(
                    PrivateAnalysisCitation(
                        evidence_reference_digest=reference.reference_digest,
                    )
                    for reference in sorted(
                        derived_references,
                        key=lambda item: item.reference_digest,
                    )
                ),
            ),
            claims=(),
            proposals=(),
        )
    )
class ControlPlanePrivateAnalysisEvidenceTests(unittest.TestCase):
    def test_core_revision_evidence_runs_end_to_end_without_custom_factory(
        self,
    ) -> None:
        selection = PrivateAnalysisRunnerSelection(
            runner_id="tests.core-revision-evidence",
            runner_version="1.0.0",
            transport=PrivateAnalysisTransport.IN_PROCESS,
            configuration_digest=_CONFIGURATION_DIGEST,
        )

        runner = ConfiguredPrivateAnalysisInProcessRunner(
            selection,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=_core_revision_evidence_model_callback,
        )
        registration = PrivateAnalysisRunnerRegistration(
            runner=runner,
            core_revision_evidence_policy=PrivateAnalysisPolicy(
                transport=PrivateAnalysisTransport.IN_PROCESS,
                full_fidelity_workspace_data=True,
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            control = ControlPlane(
                Path(directory),
                registry=PluginRegistry((_EventPlugin(),)),
                pipeline_limits=PipelineLimits(
                    max_upload_bytes=1024 * 1024,
                    max_workers=1,
                    lease_seconds=30,
                    poll_interval_seconds=0.01,
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                ),
                limits=ControlPlaneLimits(
                    max_dataset_bytes=1024 * 1024,
                    dataset_cache_entries=2,
                ),
                private_analysis_runners=(registration,),
            )
            try:
                control.sessions.create_project(
                    "tenant-a",
                    "Project A",
                    project_id="project-a",
                )
                control.sessions.create_workspace(
                    "tenant-a",
                    "project-a",
                    "Workspace A",
                    workspace_id="workspace-a",
                )
                control.sessions.set_workspace_disclosure_policy(
                    "tenant-a",
                    "workspace-a",
                    WorkspaceDisclosurePolicy(
                        PrivateAnalysisDisclosureMode.FULL_FIDELITY,
                        (PrivateAnalysisTransport.IN_PROCESS,),
                    ),
                    actor_id="admin",
                    expected_version=0,
                )
                scope = control.import_scope(
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                )
                control.start()
                admitted = control.ingestion.submit_bytes(
                    scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                    idempotency_key="fixture-a",
                )
                completed = control.ingestion.wait(
                    scope,
                    admitted.import_id,
                    timeout=10,
                )
                self.assertIs(completed.state, ImportState.COMPLETED)
                assert completed.revision_id is not None

                evidence_scope = EvidenceScope("tenant-a", "project-a", "workspace-a")
                spec = PrivateAnalysisRequestSpec(
                    scope=evidence_scope,
                    revision_ids=(completed.revision_id,),
                    runner_id=selection.runner_id,
                    runner_version=selection.runner_version,
                    task_kind=PrivateAnalysisTaskKind.LTTNG_ANALYSIS,
                    query="Explain the observed interface status change.",
                    clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
                    selected_time_ns=None,
                    limits=PrivateAnalysisLimits(
                        max_evidence_items=32,
                        max_evidence_bytes=1024 * 1024,
                        max_tool_calls=8,
                        max_output_bytes=64 * 1024,
                        max_claims=8,
                        max_proposals=4,
                        deadline_ms=30_000,
                    ),
                )
                created = control.private_analysis.create(
                    spec,
                    actor_id="analyst",
                    idempotency_key="analysis-a",
                    run_id="analysis-a",
                )
                with (
                    patch.object(
                        control.sessions,
                        "get_fixture",
                        wraps=control.sessions.get_fixture,
                    ) as get_fixture,
                    patch.object(
                        control.sessions,
                        "get_revision",
                        wraps=control.sessions.get_revision,
                    ) as get_revision,
                ):
                    executed = control.private_analysis.execute(
                        evidence_scope,
                        created.run_id,
                        expected_version=created.version,
                        actor_id="analyst",
                    )
                self.assertIs(executed.state, PrivateAnalysisRunState.COMPLETED)
                report = control.private_analysis.get_report(
                    evidence_scope,
                    created.run_id,
                )
                self.assertIsNotNone(
                    report.outcome.result,
                    report.outcome.error,
                )
                assert report.outcome.result is not None
                self.assertEqual(
                    report.outcome.result.summary.text,
                    "The selected revision contains a retained source record.",
                )
                self.assertEqual(executed.disclosed_reference_count, 2)
                self.assertEqual(executed.budget_state.tool_calls_consumed, 2)
                cited_digests = tuple(
                    sorted(
                        citation.evidence_reference_digest
                        for citation in report.outcome.result.summary.citations
                    )
                )
                self.assertEqual(
                    tuple(
                        reference.reference_digest
                        for reference in report.evidence_references
                    ),
                    cited_digests,
                )
                self.assertEqual(len(report.evidence_references), 1)
                self.assertEqual(
                    report.evidence_references[0].producer.plugin_role,
                    "primary_parser",
                )
                self.assertTrue(
                    {
                        "content_digest",
                        "locator",
                        "locator_digest",
                        "payload",
                        "payload_json",
                        "fixture_id",
                        "execution_plan_digest",
                    }.isdisjoint(
                        {
                            item.name
                            for item in fields(report.evidence_references[0])
                        }
                    )
                )
                # Count the complete execution boundary now that observation
                # lives outside the sealed callback. Request preparation,
                # evidence-corpus construction, query validation, and the read
                # each revalidate the same revision; the two-reference query
                # page remains batched rather than adding per-reference reads.
                self.assertEqual(
                    (get_fixture.call_count, get_revision.call_count),
                    (12, 12),
                )
            finally:
                control.close(timeout=5)

    def test_core_revision_evidence_routes_plugin_analysis_from_retained_plan(
        self,
    ) -> None:
        selection = PrivateAnalysisRunnerSelection(
            runner_id="tests.core-capability-evidence",
            runner_version="1.0.0",
            transport=PrivateAnalysisTransport.IN_PROCESS,
            configuration_digest=_CONFIGURATION_DIGEST,
        )
        registration = PrivateAnalysisRunnerRegistration(
            runner=ConfiguredPrivateAnalysisInProcessRunner(
                selection,
                instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                model_callback=_core_capability_evidence_model_callback,
            ),
            core_revision_evidence_policy=PrivateAnalysisPolicy(
                transport=PrivateAnalysisTransport.IN_PROCESS,
                full_fidelity_workspace_data=True,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            control = ControlPlane(
                Path(directory),
                registry=PluginRegistry((_EvidenceEventPlugin(),)),
                pipeline_limits=PipelineLimits(
                    max_upload_bytes=1024 * 1024,
                    max_workers=1,
                    lease_seconds=30,
                    poll_interval_seconds=0.01,
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                ),
                limits=ControlPlaneLimits(
                    max_dataset_bytes=1024 * 1024,
                    dataset_cache_entries=2,
                ),
                private_analysis_runners=(registration,),
            )
            try:
                control.sessions.create_project(
                    "tenant-a",
                    "Project A",
                    project_id="project-a",
                )
                control.sessions.create_workspace(
                    "tenant-a",
                    "project-a",
                    "Workspace A",
                    workspace_id="workspace-a",
                )
                control.sessions.set_workspace_disclosure_policy(
                    "tenant-a",
                    "workspace-a",
                    WorkspaceDisclosurePolicy(
                        PrivateAnalysisDisclosureMode.FULL_FIDELITY,
                        (PrivateAnalysisTransport.IN_PROCESS,),
                    ),
                    actor_id="admin",
                    expected_version=0,
                )
                scope = control.import_scope(
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                )
                control.start()
                admitted = control.ingestion.submit_bytes(
                    scope,
                    _fixture_bytes(),
                    original_name="status.jsonl",
                    idempotency_key="fixture-capability",
                )
                completed = control.ingestion.wait(
                    scope,
                    admitted.import_id,
                    timeout=10,
                )
                self.assertIs(completed.state, ImportState.COMPLETED)
                assert completed.revision_id is not None

                evidence_scope = EvidenceScope(
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                )
                created = control.private_analysis.create(
                    PrivateAnalysisRequestSpec(
                        scope=evidence_scope,
                        revision_ids=(completed.revision_id,),
                        runner_id=selection.runner_id,
                        runner_version=selection.runner_version,
                        task_kind=PrivateAnalysisTaskKind.LTTNG_ANALYSIS,
                        query="Correlate the selected trace evidence.",
                        clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
                        selected_time_ns=None,
                        limits=PrivateAnalysisLimits(
                            max_evidence_items=32,
                            max_evidence_bytes=1024 * 1024,
                            max_tool_calls=8,
                            max_output_bytes=64 * 1024,
                            max_claims=8,
                            max_proposals=4,
                            deadline_ms=30_000,
                        ),
                    ),
                    actor_id="analyst",
                    idempotency_key="analysis-capability",
                    run_id="analysis-capability",
                )
                executed = control.private_analysis.execute(
                    evidence_scope,
                    created.run_id,
                    expected_version=created.version,
                    actor_id="analyst",
                )
                self.assertIs(executed.state, PrivateAnalysisRunState.COMPLETED)
                self.assertEqual(executed.budget_state.tool_calls_consumed, 4)
                report = control.private_analysis.get_report(
                    evidence_scope,
                    created.run_id,
                )
                assert report.outcome.result is not None
                self.assertEqual(
                    report.outcome.result.summary.text,
                    "The private plug-in correlated the selected trace record.",
                )
                self.assertEqual(len(report.evidence_references), 1)
                derived = report.evidence_references[0]
                self.assertIs(derived.kind, EvidenceKind.PLUGIN_CAPABILITY_RESULT)
                self.assertEqual(
                    derived.producer.plugin_instance_id,
                    f"{_EvidenceEventPlugin.manifest.plugin_id}.default",
                )
                self.assertEqual(
                    derived.producer.plugin_capability,
                    PluginCapability.EVIDENCE_ANALYSIS.value,
                )
            finally:
                control.close(timeout=5)

    def test_real_demo_composition_routes_all_intents_across_two_nodes(
        self,
    ) -> None:
        selection = PrivateAnalysisRunnerSelection(
            runner_id="tests.demo-composed-evidence",
            runner_version="1.0.0",
            transport=PrivateAnalysisTransport.IN_PROCESS,
            configuration_digest=_CONFIGURATION_DIGEST,
        )
        registration = PrivateAnalysisRunnerRegistration(
            runner=ConfiguredPrivateAnalysisInProcessRunner(
                selection,
                instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
                model_callback=_demo_composed_evidence_model_callback,
            ),
            core_revision_evidence_policy=PrivateAnalysisPolicy(
                transport=PrivateAnalysisTransport.IN_PROCESS,
                full_fidelity_workspace_data=True,
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deployment = load_plugin_composition_deployment(
                "rsl_demo_plugin.deployment:build_plugin_deployment",
                context=PluginCompositionDeploymentContext(
                    root / "deployment-state"
                ),
            )
            control = ControlPlane(
                root / "control-plane",
                registry=deployment.primary_registry,
                plugin_composition_policy=deployment.policy,
                capability_providers=deployment.capability_providers,
                pipeline_limits=PipelineLimits(
                    max_upload_bytes=1024 * 1024,
                    max_workers=1,
                    lease_seconds=30,
                    poll_interval_seconds=0.01,
                    plugin_execution_mode=PluginExecutionMode.INLINE,
                ),
                limits=ControlPlaneLimits(
                    max_dataset_bytes=1024 * 1024,
                    dataset_cache_entries=4,
                ),
                private_analysis_runners=(registration,),
            )
            try:
                control.sessions.create_project(
                    "tenant-a",
                    "Project A",
                    project_id="project-a",
                )
                control.sessions.create_workspace(
                    "tenant-a",
                    "project-a",
                    "Workspace A",
                    workspace_id="workspace-a",
                )
                control.sessions.set_workspace_disclosure_policy(
                    "tenant-a",
                    "workspace-a",
                    WorkspaceDisclosurePolicy(
                        PrivateAnalysisDisclosureMode.FULL_FIDELITY,
                        (PrivateAnalysisTransport.IN_PROCESS,),
                    ),
                    actor_id="admin",
                    expected_version=0,
                )
                import_scope = control.import_scope(
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                )
                control.start()
                revision_ids = []
                for node_id in ("node-a", "node-b"):
                    fixture = render_conformance_status_fixture()
                    if node_id == "node-b":
                        # Keep the generated schema while giving node-b a
                        # distinct normalized state/revision identity.
                        fixture = fixture.replace(
                            b'"description":"core uplink"',
                            b'"description":"core uplink node-b"',
                            1,
                        )
                    admitted = control.ingestion.submit_bytes(
                        import_scope,
                        fixture,
                        original_name="minimal-status.jsonl",
                        idempotency_key=f"demo-fixture-{node_id}",
                        node_hint=node_id,
                        metadata={
                            "platform": PLATFORM_ID,
                            "software_version": SOFTWARE_VERSION,
                        },
                    )
                    completed = control.ingestion.wait(
                        import_scope,
                        admitted.import_id,
                        timeout=30,
                    )
                    self.assertIs(completed.state, ImportState.COMPLETED)
                    assert completed.revision_id is not None
                    revision_ids.append(completed.revision_id)

                evidence_scope = EvidenceScope(
                    "tenant-a",
                    "project-a",
                    "workspace-a",
                )
                created = control.private_analysis.create(
                    PrivateAnalysisRequestSpec(
                        scope=evidence_scope,
                        revision_ids=tuple(sorted(revision_ids)),
                        runner_id=selection.runner_id,
                        runner_version=selection.runner_version,
                        task_kind=(
                            PrivateAnalysisTaskKind.GENERAL_EVIDENCE_REVIEW
                        ),
                        query=(
                            "Exercise route and trace correlation across the "
                            "two generated demo revisions."
                        ),
                        clock_mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
                        selected_time_ns=None,
                        limits=PrivateAnalysisLimits(
                            max_evidence_items=32,
                            max_evidence_bytes=1024 * 1024,
                            max_tool_calls=16,
                            max_output_bytes=64 * 1024,
                            max_claims=8,
                            max_proposals=4,
                            deadline_ms=30_000,
                        ),
                    ),
                    actor_id="analyst",
                    idempotency_key="demo-composed-analysis",
                    run_id="demo-composed-analysis",
                )
                executed = control.private_analysis.execute(
                    evidence_scope,
                    created.run_id,
                    expected_version=created.version,
                    actor_id="analyst",
                )
                self.assertIs(executed.state, PrivateAnalysisRunState.COMPLETED)
                report = control.private_analysis.get_report(
                    evidence_scope,
                    created.run_id,
                )
                self.assertIsNotNone(
                    report.outcome.result,
                    report.outcome.error,
                )
                assert report.outcome.result is not None
                self.assertEqual(
                    report.outcome.result.summary.text,
                    "The composed demo provider analyzed every closed intent.",
                )
                self.assertEqual(executed.budget_state.tool_calls_consumed, 7)
                self.assertEqual(len(report.evidence_references), 4)
                self.assertEqual(
                    {
                        reference.node_id
                        for reference in report.evidence_references
                    },
                    {"node-a", "node-b"},
                )
                self.assertTrue(
                    all(
                        reference.producer.plugin_instance_id
                        == "demo.example-router.evidence-analysis"
                        and reference.producer.producer_id == EVIDENCE_PLUGIN_ID
                        for reference in report.evidence_references
                    )
                )
            finally:
                control.close(timeout=5)

    def test_core_registration_rejects_ambiguous_or_wrong_transport_policy(
        self,
    ) -> None:
        selection = PrivateAnalysisRunnerSelection(
            runner_id="tests.core-registration",
            runner_version="1.0.0",
            transport=PrivateAnalysisTransport.IN_PROCESS,
            configuration_digest=_CONFIGURATION_DIGEST,
        )
        runner = ConfiguredPrivateAnalysisInProcessRunner(
            selection,
            instruction_profile_digest=_INSTRUCTION_PROFILE_DIGEST,
            model_callback=lambda context, _gateway: private_analysis_result_json(
                PrivateAnalysisResult(
                    request_digest=context.request.request_digest,
                    summary=PrivateAnalysisClaim(
                        claim_id="summary",
                        support=(PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS),
                        text="No evidence was requested.",
                        citations=(),
                    ),
                    claims=(),
                    proposals=(),
                )
            ),
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            PrivateAnalysisRunnerRegistration(
                runner=runner,
                trusted_inline_tool_service_factory=lambda _request: None,  # type: ignore[return-value]
                custom_evidence_service_digest="sha256:" + "f" * 64,
                core_revision_evidence_policy=PrivateAnalysisPolicy(
                    transport=PrivateAnalysisTransport.IN_PROCESS
                ),
            )
        with self.assertRaisesRegex(ValueError, "transport"):
            PrivateAnalysisRunnerRegistration(
                runner=runner,
                core_revision_evidence_policy=PrivateAnalysisPolicy(
                    transport=PrivateAnalysisTransport.LOCAL_SUBPROCESS
                ),
            )


if __name__ == "__main__":
    unittest.main()
