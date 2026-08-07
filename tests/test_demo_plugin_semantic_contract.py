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
from types import FunctionType
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
    render_conformance_status_fixture,
)
from rsl_demo_plugin import scale_data as demo_scale_data
from rsl_demo_plugin import session as demo_session
from rsl_demo_plugin.assembly_store import DemoAssemblyStore

from router_dump_analyzer import plugin_identity
from router_dump_analyzer.ingestion_pipeline import (
    PluginRegistry,
    _execution_plan_for_result,
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
        registered = loaded.register(
            PluginRegistry(require_executable_identity=True)
        )
        self.assertEqual(registered.plugin_id, "demo.example-router")

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
from router_dump_analyzer.ingestion_pipeline import PluginRegistry
from router_dump_analyzer.plugin_loading import load_plugin_entry_point_with_coordinates

loaded = load_plugin_entry_point_with_coordinates("demo_router")
registered = loaded.register(PluginRegistry(require_executable_identity=True))
assert registered.plugin_id == "demo.example-router"
"""
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_final_verification_rejects_root_class_and_instance_mutation(
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
                    "plugin",
                    loaded.plugin,
                )
        finally:
            implementation.describe = original_describe  # type: ignore[method-assign]

        marker_name = "_identity_mutation_probe"

        def mutate_instance(budget: object) -> None:
            original_verify(budget)  # type: ignore[arg-type]
            setattr(loaded.plugin, marker_name, object())

        try:
            with (
                patch.object(
                    plugin_identity,
                    "_verify_derived_cache_slots",
                    side_effect=mutate_instance,
                ),
                self.assertRaises(PluginExecutableIdentityError),
            ):
                executable_module_target_fingerprint(
                    "rsl_demo_plugin",
                    "plugin",
                    loaded.plugin,
                )
        finally:
            if hasattr(loaded.plugin, marker_name):
                delattr(loaded.plugin, marker_name)

    def test_runtime_singleton_alias_and_wrapper_mutation_fail_closed(self) -> None:
        loaded = load_plugin_entry_point_with_coordinates(
            PLUGIN_ENTRY_POINT_NAME
        )
        require_plugin_runtime(loaded.plugin)
        original_runtime = demo_session.runtime
        demo_session.runtime = object()
        try:
            with self.assertRaises(PluginExecutableIdentityError):
                executable_module_target_fingerprint(
                    "rsl_demo_plugin",
                    "plugin",
                    loaded.plugin,
                )
        finally:
            demo_session.runtime = original_runtime

        wrapper = vars(demo_session.DemoRuntimeCapability)["open"]
        original_wrapped = wrapper.__wrapped__
        wrapper.__wrapped__ = lambda *_args, **_kwargs: None
        try:
            with self.assertRaises(PluginExecutableIdentityError):
                executable_module_target_fingerprint(
                    "rsl_demo_plugin",
                    "plugin",
                    loaded.plugin,
                )
        finally:
            wrapper.__wrapped__ = original_wrapped

        forged_globals = dict(original_wrapped.__globals__)
        forged_globals["DemoAssemblyStore"] = object
        forged_wrapped = FunctionType(
            original_wrapped.__code__,
            forged_globals,
            name=original_wrapped.__name__,
            argdefs=original_wrapped.__defaults__,
            closure=original_wrapped.__closure__,
        )
        forged_wrapped.__annotations__ = original_wrapped.__annotations__
        forged_wrapped.__doc__ = original_wrapped.__doc__
        forged_wrapped.__module__ = original_wrapped.__module__
        forged_wrapped.__qualname__ = original_wrapped.__qualname__
        closure_cell = wrapper.__closure__[0]
        original_closure_value = closure_cell.cell_contents
        wrapper.__wrapped__ = forged_wrapped
        closure_cell.cell_contents = forged_wrapped
        try:
            with self.assertRaises(PluginExecutableIdentityError):
                executable_module_target_fingerprint(
                    "rsl_demo_plugin",
                    "plugin",
                    loaded.plugin,
                )
        finally:
            wrapper.__wrapped__ = original_wrapped
            closure_cell.cell_contents = original_closure_value

        original_store = demo_session.DemoAssemblyStore
        demo_session.DemoAssemblyStore = object  # type: ignore[misc]
        try:
            with self.assertRaises(PluginExecutableIdentityError):
                executable_module_target_fingerprint(
                    "rsl_demo_plugin",
                    "plugin",
                    loaded.plugin,
                )
        finally:
            demo_session.DemoAssemblyStore = original_store  # type: ignore[misc]

        original_store_init = original_store.__init__
        original_store.__init__ = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
        try:
            with self.assertRaises(PluginExecutableIdentityError):
                executable_module_target_fingerprint(
                    "rsl_demo_plugin",
                    "plugin",
                    loaded.plugin,
                )
        finally:
            original_store.__init__ = original_store_init  # type: ignore[method-assign]

        original_cache_path = demo_scale_data._history_search_cache_path
        demo_scale_data._history_search_cache_path = (  # type: ignore[assignment]
            lambda archive_path, identity: archive_path / identity
        )
        try:
            with self.assertRaises(PluginExecutableIdentityError):
                executable_module_target_fingerprint(
                    "rsl_demo_plugin",
                    "plugin",
                    loaded.plugin,
                )
        finally:
            demo_scale_data._history_search_cache_path = (  # type: ignore[assignment]
                original_cache_path
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
