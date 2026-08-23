"""Run the executable acceptance gate for typed cross-node topology.

This fail-fast gate proves the complete connector-claim chain across the
backend, browser model, and public type surface.  Every phase has a separate
wall-clock deadline and bytecode cache; timeout cleanup terminates the whole
phase process tree so a failed gate cannot leave workers behind.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT_SECONDS = 300


@dataclass(frozen=True, slots=True)
class GatePhase:
    """One independently timed, directly executable acceptance phase."""

    label: str
    tool: str
    arguments: tuple[str, ...]
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


PHASES: tuple[GatePhase, ...] = (
    GatePhase(
        "typed contract, author documentation, and bounded execution",
        "python",
        (
            "-m",
            "unittest",
            "tests.test_plugin_api",
            "tests.test_capability_executor",
            "tests.test_capability_router",
            "tests.test_plugin_authoring_docs",
        ),
    ),
    GatePhase(
        "frozen federation and directed route semantics",
        "python",
        (
            "-m",
            "unittest",
            "tests.test_federation_executor",
            "tests.test_topology_federation",
            "tests.test_multi_node_topology.TypedProjectionTemporalGateTests",
            "tests.test_multi_node_route.RouteTraceCoreCompletenessTests",
            (
                "tests.test_multi_node_route.MultiNodeRouteTests."
                "test_boundary_link_selection_never_falls_back_to_an_"
                "unrelated_candidate"
            ),
            (
                "tests.test_multi_node_route.MultiNodeRouteTests."
                "test_route_trace_exact_joins_runtime_tagged_four_level_"
                "segment_keys"
            ),
            (
                "tests.test_multi_node_route.MultiNodeRouteTests."
                "test_selected_topology_scope_does_not_fabricate_missing_"
                "outer_hop"
            ),
        ),
    ),
    GatePhase(
        "browser-facing topology API integration",
        "python",
        (
            "-m",
            "unittest",
            (
                "tests.test_generated_assembly_api_integration."
                "GeneratedAssemblyApiIntegrationTests."
                "test_generated_topology_is_independent_of_static_contract_nodes"
            ),
            (
                "tests.test_multi_node_topology.MultiNodeTopologyTests."
                "test_generated_demo_executes_typed_connector_claims_through_core"
            ),
            (
                "tests.test_multi_node_topology.MultiNodeTopologyTests."
                "test_resource_preview_limit_does_not_prune_topology_claims"
            ),
            (
                "tests.test_multi_node_topology.MultiNodeTopologyTests."
                "test_single_member_query_preserves_single_sided_segment_claims"
            ),
            (
                "tests.test_demo_fixture_generator.DemoFixtureGeneratorTests."
                "test_typed_next_hop_endpoint_pair_survives_plugin_validation"
            ),
        ),
    ),
    GatePhase(
        "generated typed route HTTP integration",
        "python",
        (
            "-m",
            "unittest",
            (
                "tests.test_multi_node_route.MultiNodeRouteTests."
                "test_route_trace_uses_declared_exact_typed_boundaries_fail_closed"
            ),
        ),
    ),
    GatePhase(
        "inline-only executable identity compatibility",
        "python",
        (
            "-m",
            "unittest",
            (
                "tests.test_ingestion_pipeline.DurableIngestionPipelineTests."
                "test_non_strict_derived_identity_can_register_inline_without_"
                "target_attestation"
            ),
            (
                "tests.test_ingestion_pipeline.DurableIngestionPipelineTests."
                "test_target_attestation_failure_stays_strict_for_required_and_"
                "explicit_hashes"
            ),
            (
                "tests.test_ingestion_pipeline.DurableIngestionPipelineTests."
                "test_inline_only_target_compatibility_is_rejected_for_process_and_"
                "durable_use"
            ),
            (
                "tests.test_ingestion_pipeline.DurableIngestionPipelineTests."
                "test_non_strict_registry_keeps_normal_process_bootstrap_unchanged"
            ),
            (
                "tests.test_ingestion_pipeline.DurableIngestionPipelineTests."
                "test_durable_pipeline_seals_registry_against_late_inline_only_"
                "registration"
            ),
            (
                "tests.test_ingestion_pipeline.DurableIngestionPipelineTests."
                "test_inline_only_primary_cannot_be_frozen_into_execution_plan"
            ),
            (
                "tests.test_capability_router.CapabilityRouterTests."
                "test_plan_bound_router_rejects_inline_only_primary_and_auxiliary"
            ),
            (
                "tests.test_pipeline_cli.PipelineCliTests."
                "test_durable_control_plane_rejects_inline_only_auxiliary_atomically"
            ),
            (
                "tests.test_plugin_composition.PluginCompositionTests."
                "test_inline_only_auxiliary_is_local_route_only_and_cannot_be_frozen"
            ),
            (
                "tests.test_plugin_composition.PluginCompositionTests."
                "test_durable_pipeline_seals_provider_snapshot_against_late_auxiliary"
            ),
            (
                "tests.test_plugin_composition_deployment."
                "PluginCompositionDeploymentTests."
                "test_inline_only_auxiliary_is_rejected_at_deployment_boundary"
            ),
            (
                "tests.test_plugin_composition_deployment."
                "PluginCompositionDeploymentTests."
                "test_deployment_seals_exact_registry_snapshots_against_late_mutation"
            ),
            (
                "tests.test_demo_plugin_semantic_contract."
                "DemoPluginSemanticContractTests."
                "test_real_entry_point_registers_with_strict_executable_identity"
            ),
            (
                "tests.test_demo_plugin_semantic_contract."
                "DemoPluginSemanticContractTests."
                "test_process_child_ingests_without_parent_runtime_attachment"
            ),
            (
                "tests.test_demo_plugin_semantic_contract."
                "DemoPluginSemanticContractTests."
                "test_fresh_process_entry_point_registers_with_strict_identity"
            ),
            (
                "tests.test_plugin_loading.PluginModuleLoadingTests."
                "test_exact_class_descriptor_selects_process_constructor"
            ),
            (
                "tests.test_plugin_loading.PluginModuleLoadingTests."
                "test_process_descriptor_is_exact_local_and_immutable"
            ),
            (
                "tests.test_demo_plugin_semantic_contract."
                "DemoPluginSemanticContractTests."
                "test_final_verification_rejects_process_class_mutation"
            ),
            (
                "tests.test_demo_plugin_semantic_contract."
                "DemoPluginSemanticContractTests."
                "test_runtime_bearing_live_target_remains_inline_only"
            ),
        ),
    ),
    GatePhase(
        "checked-in public stub drift",
        "python",
        ("scripts/export_type_stubs.py", "--check"),
    ),
    GatePhase(
        "public stub structural parity",
        "python",
        ("-m", "unittest", "tests.test_typing_contract"),
    ),
    GatePhase(
        "strict public type consumers",
        "python",
        (
            "-m",
            "mypy",
            "--python-version",
            "3.12",
            "--strict",
            "--no-incremental",
            "tests/typing/public_api.py",
            "state-dump-generator/tests/typing/generator_public_api.py",
        ),
    ),
    GatePhase(
        "executable browser contract and frontend tests",
        "npm",
        ("--prefix", "frontend", "run", "check"),
    ),
)


def _phase_command(phase: GatePhase) -> tuple[str, ...]:
    if phase.tool == "python":
        return (sys.executable, *phase.arguments)
    if phase.tool == "npm":
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if npm is None:
            npm = shutil.which("npm")
        if npm is None:
            raise FileNotFoundError("npm was not found on PATH")
        return (npm, *phase.arguments)
    raise ValueError(f"unsupported gate tool: {phase.tool}")


def _stop_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Bound cleanup to the phase tree so a timed-out test cannot linger."""

    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ("taskkill", "/PID", str(process.pid), "/T", "/F"),
                check=False,
                timeout=15,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=15)


def _run_phase(
    phase: GatePhase,
    *,
    environment: dict[str, str],
) -> int:
    command = _phase_command(phase)
    print(
        f"RUN: {subprocess.list2cmdline(command)} "
        f"(timeout {phase.timeout_seconds}s)",
        flush=True,
    )
    creationflags = (
        subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    )
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        creationflags=creationflags,
        start_new_session=os.name != "nt",
    )
    try:
        return process.wait(timeout=phase.timeout_seconds)
    except subprocess.TimeoutExpired:
        _stop_process_tree(process)
        raise
    except BaseException:
        _stop_process_tree(process)
        raise


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="router-dump-federation-gate-") as cache:
        for index, phase in enumerate(PHASES, start=1):
            print(f"[{index}/{len(PHASES)}] {phase.label}", flush=True)
            environment = os.environ.copy()
            environment["PYTHONPYCACHEPREFIX"] = str(
                Path(cache) / f"phase-{index}"
            )
            try:
                returncode = _run_phase(phase, environment=environment)
            except FileNotFoundError as error:
                print(f"FAIL: {phase.label}: {error}", file=sys.stderr)
                return 127
            except subprocess.TimeoutExpired:
                print(
                    f"FAIL: {phase.label} exceeded "
                    f"{phase.timeout_seconds} seconds",
                    file=sys.stderr,
                )
                return 124
            if returncode != 0:
                print(
                    f"FAIL: {phase.label} exited {returncode}",
                    file=sys.stderr,
                )
                return returncode or 1
            print(f"PASS: {phase.label}", flush=True)
    print("PASS: typed topology federation gate", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
