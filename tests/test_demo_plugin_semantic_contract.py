from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from importlib.metadata import entry_points
from pathlib import Path

from plugin.assembly_store import DemoAssemblyStore
from generator import (
    ASSEMBLY_ROOT,
    DEMO_NODES,
    AssemblyConfig,
    build_demo_fixture,
)
from generator._scale import _plugin_schema
from plugin import (
    GENERATED_PROJECTION_POLICY,
    PLUGIN_ENTRY_POINT_NAME,
)


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
            "plugin:plugin",
        )
        self.assertIs(
            self.installed_plugin.generated_projection_policy,
            GENERATED_PROJECTION_POLICY,
        )
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
