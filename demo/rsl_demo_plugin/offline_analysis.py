"""Explicit offline workbench runner: scripted evidence walk, NOT an AI model.

Only the opt-in deployment factory installs this callback. It has no network
client, credentials, filesystem access or direct plug-in call. The core gateway
enforces workspace disclosure and dispatches to the retained provider plan.
"""

from router_dump_analyzer.private_analysis import (
    EvidenceKind,
    PrivateAnalysisCapabilityArguments,
    PrivateAnalysisCapabilityIntent,
    PrivateAnalysisCitation,
    PrivateAnalysisClaim,
    PrivateAnalysisClaimSupport,
    PrivateAnalysisPolicy,
    PrivateAnalysisQueryArguments,
    PrivateAnalysisReadArguments,
    PrivateAnalysisResult,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisToolBinding,
    PrivateAnalysisToolCall,
    PrivateAnalysisToolName,
    PrivateAnalysisTransport,
    private_analysis_result_json,
    private_analysis_tool_call_json,
)
from router_dump_analyzer.private_analysis_deployment import (
    PrivateAnalysisDeployment,
    PrivateAnalysisDeploymentContext,
)
from router_dump_analyzer.private_analysis_execution import (
    PrivateAnalysisRunnerRegistration,
)
from router_dump_analyzer.private_analysis_in_process_runner import (
    ConfiguredPrivateAnalysisInProcessRunner,
    PrivateAnalysisInProcessContext,
    PrivateAnalysisInProcessToolGateway,
)


def scripted_evidence_walk(
    context: PrivateAnalysisInProcessContext,
    gateway: PrivateAnalysisInProcessToolGateway,
) -> str:
    """Query, read and analyze one real source; never manufacture a citation."""

    def invoke(call_id, name, arguments):
        response = gateway.execute(
            private_analysis_tool_call_json(
                PrivateAnalysisToolCall(
                    call_id=call_id,
                    binding=PrivateAnalysisToolBinding(
                        request_digest=context.request.request_digest,
                        tool_catalog_digest=context.request.tool_catalog_digest,
                        name=name,
                    ),
                    arguments=arguments,
                )
            )
        )
        if response.result is None:
            raise RuntimeError(
                "The scripted evidence walk could not obtain authorized evidence."
            )
        return response.result

    page = invoke(
        "find-source",
        PrivateAnalysisToolName.QUERY_EVIDENCE,
        PrivateAnalysisQueryArguments(
            evidence_kinds=(EvidenceKind.SOURCE_RECORD,), page_size=1
        ),
    )
    if not page.references:
        return private_analysis_result_json(
            PrivateAnalysisResult(
                request_digest=context.request.request_digest,
                summary=PrivateAnalysisClaim(
                    claim_id="summary",
                    support=PrivateAnalysisClaimSupport.UNSUPPORTED_HYPOTHESIS,
                    text="Scripted demonstration, not a model: no source record was available in the authorized selection. No network or device conclusion was drawn.",
                    citations=(),
                ),
                claims=(),
                proposals=(),
            )
        )
    source = page.references[0]
    read = invoke(
        "read-source",
        PrivateAnalysisToolName.READ_EVIDENCE,
        PrivateAnalysisReadArguments(evidence_reference_digest=source.reference_digest),
    )
    if read.envelope is None:
        raise RuntimeError(
            "The scripted evidence walk received no readable source envelope."
        )
    analysis = invoke(
        "provider-analysis",
        PrivateAnalysisToolName.ANALYZE_EVIDENCE,
        PrivateAnalysisCapabilityArguments(
            node_id=source.revision.node_id,
            revision_id=source.revision.revision_id,
            intent=PrivateAnalysisCapabilityIntent.TRACE_CORRELATION,
            parent_reference_digests=(source.reference_digest,),
            parameters_json='{"focus":"interface"}',
            max_observations=4,
        ),
    )
    if analysis.envelope is None:
        raise RuntimeError(
            "The scripted evidence walk received no provider evidence envelope."
        )
    return private_analysis_result_json(
        PrivateAnalysisResult(
            request_digest=context.request.request_digest,
            summary=PrivateAnalysisClaim(
                claim_id="summary",
                support=PrivateAnalysisClaimSupport.EVIDENCE_SUPPORTED,
                text="Scripted demonstration, not a model: one retained source was read and passed to the revision's authorized evidence provider. This demonstrates evidence plumbing, not a diagnosis or route-reachability verdict.",
                citations=(
                    PrivateAnalysisCitation(
                        evidence_reference_digest=source.reference_digest
                    ),
                    PrivateAnalysisCitation(
                        evidence_reference_digest=analysis.envelope.reference.reference_digest
                    ),
                ),
            ),
            claims=(),
            proposals=(),
        )
    )


def build_offline_analysis_deployment(
    context: PrivateAnalysisDeploymentContext,
) -> PrivateAnalysisDeployment:
    """Register one client-safe-only runner; this grants no workspace access."""
    del context
    runner = ConfiguredPrivateAnalysisInProcessRunner(
        PrivateAnalysisRunnerSelection(
            runner_id="demo.scripted-evidence-walk",
            runner_version="1.0.0",
            transport=PrivateAnalysisTransport.IN_PROCESS,
            configuration_digest="sha256:" + "d" * 64,
        ),
        instruction_profile_digest="sha256:" + "e" * 64,
        model_callback=scripted_evidence_walk,
    )
    return PrivateAnalysisDeployment(
        registrations=(
            PrivateAnalysisRunnerRegistration(
                runner=runner,
                core_revision_evidence_policy=PrivateAnalysisPolicy(
                    transport=PrivateAnalysisTransport.IN_PROCESS,
                    full_fidelity_workspace_data=False,
                ),
            ),
        )
    )
