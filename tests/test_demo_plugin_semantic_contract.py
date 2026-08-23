from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from importlib.metadata import entry_points
from pathlib import Path
from unittest.mock import patch

from rsl_demo_generator import (
    ASSEMBLY_ROOT,
    DEMO_NODES,
    AssemblyConfig,
    build_demo_fixture,
)
from rsl_demo_generator._scale import _plugin_schema
from rsl_demo_plugin import (
    GENERATED_PROJECTION_POLICY,
    PLATFORM_ID,
    PLUGIN_ENTRY_POINT_NAME,
    SOFTWARE_VERSION,
    STATUS_FILENAME,
    render_conformance_status_fixture,
)
from rsl_demo_plugin.assembly_store import DemoAssemblyStore

from router_dump_analyzer import plugin_identity
from router_dump_analyzer.ingestion_pipeline import (
    PluginExecutionProcessError,
    PluginExecutionTimeoutError,
    PluginRegistry,
    _execution_plan_for_result,
    _ingest_plugin_child,
    _run_isolated_child,
)
from router_dump_analyzer.plugin_api import TimelineTimeBasis
from router_dump_analyzer.plugin_composition_deployment import (
    PluginCompositionDeploymentContext,
    load_plugin_composition_deployment,
)
from router_dump_analyzer.plugin_identity import (
    PluginExecutableIdentityError,
    executable_module_target_fingerprint,
)
from router_dump_analyzer.plugin_execution_plan import (
    PluginExecutionPlanAuthority,
)
from router_dump_analyzer.plugin_loading import (
    load_plugin_entry_point_with_coordinates,
)
from router_dump_analyzer.runtime import require_plugin_runtime

NODE_PACK_ROOT = "router-state-lab-100k"


def _member_bytes(archive: tarfile.TarFile, name: str) -> bytes:
    source = archive.extractfile(name)
    if source is None:
        raise AssertionError(f"missing archive member: {name}")
    return source.read()


class DemoPluginSemanticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        matches = [
            item
            for item in entry_points(group="router_dump_analyzer.plugins")
            if item.name == PLUGIN_ENTRY_POINT_NAME
        ]
        if len(matches) != 1:
            raise AssertionError(
                "the demo distribution must install exactly one demo_router "
                f"entry point; found {len(matches)}"
            )
        cls.entry_point = matches[0]
        cls.installed_plugin = cls.entry_point.load()
        cls.temporary = tempfile.TemporaryDirectory()
        cls.archive_path = Path(cls.temporary.name) / "semantic-contract.tgz"
        build_demo_fixture(
            cls.archive_path,
            config=AssemblyConfig(
                nodes=DEMO_NODES[:1],
                events_per_node=120,
                resources_per_node=120,
                seed=77,
                allow_small=True,
            ),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_installed_entry_point_exposes_the_offline_capability(self) -> None:
        self.assertEqual(
            self.entry_point.value,
            "rsl_demo_plugin:plugin",
        )
        self.assertIs(
            self.installed_plugin.generated_projection_policy,
            GENERATED_PROJECTION_POLICY,
        )
        self.assertIs(
            self.installed_plugin.manifest.timeline_time_basis,
            TimelineTimeBasis.ABSOLUTE_UNIX_NS,
        )
        self.assertIsNone(self.installed_plugin.manifest.timeline_clock_domain)
        descriptor = self.installed_plugin.describe_generated_fixture()
        self.assertEqual(
            descriptor["schema_contract"],
            GENERATED_PROJECTION_POLICY.generated_schema_contract_descriptor(),
        )
        self.assertEqual(
            descriptor["projection_capability"],
            GENERATED_PROJECTION_POLICY.projection_capability_descriptor(),
        )
        self.assertEqual(
            descriptor["runtime_load"],
            GENERATED_PROJECTION_POLICY.runtime_load_descriptor(),
        )
        self.assertTrue(descriptor["projection_capability"]["immutable"])
        self.assertFalse(descriptor["runtime_load"]["parser_replayed"])

    def test_real_entry_point_registers_with_strict_executable_identity(self) -> None:
        loaded = load_plugin_entry_point_with_coordinates(
            PLUGIN_ENTRY_POINT_NAME
        )
        self.assertEqual(
            loaded.process_module_target,
            "rsl_demo_plugin:ExampleRouterPlugin",
        )
        self.assertTrue(loaded.process_construct_class)
        self.assertIn("runtime", vars(loaded.plugin))
        self.assertNotIn("runtime", vars(type(loaded.plugin)()))
        registered = loaded.register(
            PluginRegistry(require_executable_identity=True)
        )
        self.assertEqual(registered.plugin_id, "demo.example-router")
        self.assertEqual(
            registered.process_bootstrap.plugin_loader_kind,
            "class_constructor",
        )
        self.assertEqual(
            registered.process_bootstrap.plugin_target,
            "rsl_demo_plugin:ExampleRouterPlugin",
        )

    def test_process_child_ingests_without_parent_runtime_attachment(self) -> None:
        loaded = load_plugin_entry_point_with_coordinates(
            PLUGIN_ENTRY_POINT_NAME
        )
        registry = PluginRegistry(require_executable_identity=True)
        registered = loaded.register(registry)
        fixture_path = Path(self.temporary.name) / STATUS_FILENAME
        fixture_path.write_bytes(render_conformance_status_fixture())
        staged_path = Path(self.temporary.name) / "process-result.json"

        result = _run_isolated_child(
            _ingest_plugin_child,
            (
                registered.process_bootstrap,
                str(fixture_path),
                "node-a",
                {
                    "platform": PLATFORM_ID,
                    "software_version": SOFTWARE_VERSION,
                },
                str(staged_path),
            ),
            timeout_seconds=30,
            stage="ingest",
            expected_kind="ingest",
            subject="demo plug-in",
            process_name_prefix="demo-process-contract",
            timeout_error=PluginExecutionTimeoutError,
            process_error=PluginExecutionProcessError,
        )

        self.assertEqual(result["kind"], "ingest")
        self.assertGreater(result["resource_count"], 0)
        self.assertTrue(staged_path.is_file())

    def test_demo_exposes_runnable_core_composition_deployment(self) -> None:
        deployment = load_plugin_composition_deployment(
            "rsl_demo_plugin.deployment:build_plugin_deployment",
            context=PluginCompositionDeploymentContext(
                Path(self.temporary.name) / "deployment-state"
            ),
        )
        records = deployment.primary_registry.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].instance_id, "demo.example-router.primary")
        providers = deployment.capability_providers.records()
        self.assertEqual(len(providers), 2)
        provider_by_instance = {
            record.instance_id: record for record in providers
        }
        self.assertEqual(
            provider_by_instance[
                "demo.example-router.evidence-analysis"
            ].instance_id,
            "demo.example-router.evidence-analysis",
        )
        self.assertEqual(records[0].capabilities, ("status_parse",))
        self.assertEqual(
            provider_by_instance[
                "demo.example-router.evidence-analysis"
            ].capabilities,
            ("evidence_analysis",),
        )
        for record in providers:
            self.assertIs(
                deployment.capability_providers.get_by_execution_identity(
                    record.instance_id,
                    record.registered_execution_identity,
                ),
                record,
            )
        self.assertEqual(
            deployment.policy.auxiliaries_for(
                primary_instance_id=records[0].instance_id,
                primary_registered_execution_identity=(
                    records[0].registered_execution_identity
                ),
            )[0].instance_id,
            "demo.example-router.evidence-analysis",
        )

    def test_demo_ingestion_plan_pins_parser_and_evidence_auxiliary(self) -> None:
        deployment = load_plugin_composition_deployment(
            "rsl_demo_plugin.deployment:build_plugin_deployment",
            context=PluginCompositionDeploymentContext(
                Path(self.temporary.name) / "plan-proof-state"
            ),
        )
        fixture_path = Path(self.temporary.name) / "minimal-status.jsonl"
        fixture_path.write_bytes(render_conformance_status_fixture())
        metadata = {
            "platform": PLATFORM_ID,
            "software_version": SOFTWARE_VERSION,
        }

        candidates = deployment.primary_registry.probe(
            fixture_path,
            node_hint="node-a",
            metadata=metadata,
        )
        self.assertEqual(
            tuple(candidate.instance_id for candidate in candidates),
            ("demo.example-router.primary",),
        )
        records = deployment.primary_registry.records()
        primary = next(
            record
            for record in records
            if record.instance_id == "demo.example-router.primary"
        )
        result = primary.coordinator.ingest(
            primary.execution_plugin,
            fixture_path,
            node_hint="node-a",
            metadata=metadata,
        )
        plan = _execution_plan_for_result(
            primary,
            result,
            capability_providers=deployment.capability_providers,
            composition_policy=deployment.policy,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )

        self.assertEqual(
            tuple(pin.instance_id for pin in plan.plugins),
            (
                "demo.example-router.primary",
                "demo.example-router.evidence-analysis",
            ),
        )
        self.assertEqual(plan.plugins[0].roles, ("primary_parser",))
        self.assertEqual(plan.plugins[0].capabilities, ("status_parse",))
        self.assertEqual(
            plan.plugins[1].roles,
            ("private_analysis_evidence",),
        )
        self.assertEqual(
            plan.plugins[1].capabilities,
            ("evidence_analysis",),
        )
        self.assertEqual(
            plan.composition_policy_digest,
            deployment.policy.policy_digest,
        )

    def test_fresh_process_entry_point_registers_with_strict_identity(self) -> None:
        script = """\
import sys
from pathlib import Path

from router_dump_analyzer.ingestion_pipeline import PluginRegistry
from router_dump_analyzer.plugin_identity import PluginExecutableIdentityError, executable_module_target_fingerprint
from router_dump_analyzer.plugin_loading import load_plugin_entry_point_with_coordinates
from router_dump_analyzer.runtime import require_plugin_runtime

loaded = load_plugin_entry_point_with_coordinates("demo_router")
implementation = type(loaded.plugin)
assert "runtime" in vars(loaded.plugin)
assert "runtime" not in vars(implementation())
before = executable_module_target_fingerprint(
    "rsl_demo_plugin",
    "ExampleRouterPlugin",
    implementation,
)
runtime = require_plugin_runtime(loaded.plugin)
assert runtime.capability_id == "router_dump_analyzer.runtime.v1"
with runtime.open(Path(sys.argv[1])) as session:
    assert session.topology_provider.get() is not None
from rsl_demo_plugin.typed_topology import demo_topology_projection_plugin
typed_identity = executable_module_target_fingerprint(
    "rsl_demo_plugin.typed_topology",
    "demo_topology_projection_plugin",
    demo_topology_projection_plugin,
)
assert typed_identity.startswith("target-sha256:")
after = executable_module_target_fingerprint(
    "rsl_demo_plugin",
    "ExampleRouterPlugin",
    implementation,
)
assert after == before
try:
    executable_module_target_fingerprint(
        "rsl_demo_plugin",
        "plugin",
        loaded.plugin,
    )
except PluginExecutableIdentityError:
    pass
else:
    raise AssertionError("the runtime-bearing live target must remain rejected")
assert loaded.process_module_target == "rsl_demo_plugin:ExampleRouterPlugin"
assert loaded.process_construct_class is True
registered = loaded.register(PluginRegistry(require_executable_identity=True))
assert registered.plugin_id == "demo.example-router"
assert registered.process_bootstrap.plugin_loader_kind == "class_constructor"
"""
        completed = subprocess.run(
            [sys.executable, "-c", script, str(self.archive_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_final_verification_rejects_process_class_mutation(
        self,
    ) -> None:
        loaded = load_plugin_entry_point_with_coordinates(
            PLUGIN_ENTRY_POINT_NAME
        )
        implementation = type(loaded.plugin)
        original_describe = implementation.describe
        original_verify = plugin_identity._verify_derived_cache_slots

        def mutate_class(budget: object) -> None:
            original_verify(budget)  # type: ignore[arg-type]
            implementation.describe = lambda _self: None  # type: ignore[method-assign]

        try:
            with (
                patch.object(
                    plugin_identity,
                    "_verify_derived_cache_slots",
                    side_effect=mutate_class,
                ),
                self.assertRaises(PluginExecutableIdentityError),
            ):
                executable_module_target_fingerprint(
                    "rsl_demo_plugin",
                    "ExampleRouterPlugin",
                    implementation,
                )
        finally:
            implementation.describe = original_describe  # type: ignore[method-assign]

    def test_runtime_bearing_live_target_remains_inline_only(self) -> None:
        loaded = load_plugin_entry_point_with_coordinates(
            PLUGIN_ENTRY_POINT_NAME
        )
        require_plugin_runtime(loaded.plugin)
        with self.assertRaises(PluginExecutableIdentityError):
            executable_module_target_fingerprint(
                "rsl_demo_plugin",
                "plugin",
                loaded.plugin,
            )

    def test_generator_schema_is_accepted_and_schema_drift_is_rejected(
        self,
    ) -> None:
        template = _plugin_schema()
        GENERATED_PROJECTION_POLICY.validate_generated_schema_template(
            template
        )
        self.assertEqual(
            template["projection_capabilities"],
            GENERATED_PROJECTION_POLICY.base_projection_capabilities(),
        )

        drifted = json.loads(json.dumps(template))
        drifted["resource_kinds"][0]["key_fields"] = ["opaque_id"]
        with self.assertRaisesRegex(
            ValueError,
            "schema body disagrees",
        ):
            GENERATED_PROJECTION_POLICY.validate_generated_schema_template(
                drifted
            )

        materialized = (
            GENERATED_PROJECTION_POLICY.materialize_generated_schema(
                template,
                node_identity={
                    "node_id": "node-a",
                    "revision_id": "demo/node-a/revision-0001",
                },
            )
        )
        materialized["precomputed_projection_capability"]["members"][
            "topology"
        ]["path"] = "wrong-topology.json"
        with self.assertRaisesRegex(
            ValueError,
            "precomputed_projection_capability",
        ):
            GENERATED_PROJECTION_POLICY.validate_materialized_generated_schema(
                materialized,
                node_id="node-a",
                revision_id="demo/node-a/revision-0001",
            )

    def test_archive_and_lazy_runtime_use_the_entry_point_contract(
        self,
    ) -> None:
        with tarfile.open(self.archive_path, mode="r:gz") as outer:
            outer_manifest = json.loads(
                _member_bytes(
                    outer,
                    f"{ASSEMBLY_ROOT}/manifest.json",
                )
            )
            node_bytes = _member_bytes(
                outer,
                f"{ASSEMBLY_ROOT}/nodes/node-a.tgz",
            )
        with tarfile.open(
            fileobj=io.BytesIO(node_bytes),
            mode="r:gz",
        ) as node_archive:
            generated_schema = json.loads(
                _member_bytes(
                    node_archive,
                    (
                        f"{NODE_PACK_ROOT}/normalized-scale/"
                        "plugin-schema.json"
                    ),
                )
            )
            projection_manifest = json.loads(
                _member_bytes(
                    node_archive,
                    (
                        f"{NODE_PACK_ROOT}/"
                        f"{GENERATED_PROJECTION_POLICY.projection_root}/"
                        "manifest.json"
                    ),
                )
            )

        entry_contract = (
            self.installed_plugin.describe_generated_fixture()
        )
        self.assertEqual(
            outer_manifest["plugin"],
            GENERATED_PROJECTION_POLICY.archive_plugin_descriptor(),
        )
        self.assertEqual(
            generated_schema["generated_schema_contract"],
            entry_contract["schema_contract"],
        )
        self.assertEqual(
            generated_schema["precomputed_projection_capability"],
            entry_contract["projection_capability"],
        )
        self.assertEqual(
            generated_schema["projection_capabilities"],
            GENERATED_PROJECTION_POLICY
            .materialized_projection_capabilities(),
        )
        GENERATED_PROJECTION_POLICY.validate_materialized_generated_schema(
            generated_schema,
            node_id="node-a",
            revision_id="demo/node-a/revision-0001",
        )

        expected_members = (
            GENERATED_PROJECTION_POLICY.projection_member_registry()
        )
        self.assertEqual(
            set(projection_manifest["files"]),
            set(expected_members),
        )
        for member_id, expected in expected_members.items():
            actual = projection_manifest["files"][member_id]
            self.assertTrue(
                all(actual[field] == value for field, value in expected.items())
            )
        drifted_manifest = json.loads(json.dumps(projection_manifest))
        drifted_manifest["files"]["routes"]["media_type"] = "text/plain"
        with self.assertRaisesRegex(
            ValueError,
            "routes disagrees at media_type",
        ):
            GENERATED_PROJECTION_POLICY.validate_projection_manifest(
                drifted_manifest,
                node_id="node-a",
                revision_id="demo/node-a/revision-0001",
            )

        with DemoAssemblyStore(self.archive_path) as store:
            self.assertEqual(
                store.assembly.metadata["plugin_projection"],
                entry_contract["runtime_load"],
            )
            self.assertEqual(
                store.projection_for_node("node-a")["runtime_load"],
                entry_contract["runtime_load"],
            )


if __name__ == "__main__":
    unittest.main()
