from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from router_dump_analyzer.plugin_execution_plan import (
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
)
from router_dump_analyzer.revision_store import (
    AssemblyDescriptor,
    RevisionDescriptor,
)

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_PACKAGE_DIGEST = "package-sha256:" + "c" * 64


def _pin(instance_id: str, plugin_id: str) -> PluginExecutionPin:
    return PluginExecutionPin(
        instance_id=instance_id,
        plugin_id=plugin_id,
        plugin_version="1.0",
        core_api_version="2",
        artifact=PluginArtifactIdentity(
            distribution_name=f"{plugin_id}-distribution",
            distribution_version="1.0",
            package_hash=_PACKAGE_DIGEST,
            entry_point_name=instance_id,
            module_target=f"{plugin_id}:plugin",
        ),
        configuration_digest=_DIGEST_A,
        schema_digest=_DIGEST_B,
        roles=(("primary_parser",) if instance_id == "forwarding.0" else ()),
    )


def _plan(node_id: str = "node-a") -> PluginExecutionPlan:
    return PluginExecutionPlan(
        node_id=node_id,
        basis_revision_id="upload-basis-a",
        plugins=(
            _pin("forwarding.0", "vendor.forwarding"),
            _pin("forwarding.1", "vendor.forwarding"),
            _pin("asic.0", "vendor.asic"),
        ),
    )


class RevisionStoreContractTests(unittest.TestCase):
    def test_legacy_descriptor_constructor_remains_valid_without_a_plan(self) -> None:
        descriptor = RevisionDescriptor(
            "node-a",
            "revision-a",
            "Node A",
            10,
            3,
            ("legacy.plugin",),
            {"source": "legacy"},
        )

        self.assertIsNone(descriptor.execution_plan)
        self.assertEqual(descriptor.plugin_ids, ("legacy.plugin",))

    def test_descriptor_binds_an_immutable_execution_plan(self) -> None:
        plan = _plan()
        descriptor = RevisionDescriptor(
            node_id="node-a",
            revision_id="revision-a",
            label="Node A",
            event_count=100_000,
            resource_count=7_500,
            plugin_ids=("vendor.forwarding", "vendor.asic"),
            execution_plan=plan,
        )
        assembly = AssemblyDescriptor(
            assembly_id="fabric",
            revisions=(descriptor,),
        )

        self.assertIsNot(descriptor.execution_plan, plan)
        self.assertEqual(descriptor.execution_plan, plan)
        self.assertIs(assembly.revisions[0], descriptor)
        with self.assertRaises(FrozenInstanceError):
            descriptor.execution_plan = None  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            assembly.revisions = ()  # type: ignore[misc]

    def test_descriptor_detaches_the_plan_from_caller_owned_objects(self) -> None:
        plan = _plan()
        descriptor = RevisionDescriptor(
            node_id="node-a",
            revision_id="revision-a",
            label="Node A",
            event_count=100_000,
            resource_count=7_500,
            plugin_ids=("vendor.forwarding", "vendor.asic"),
            execution_plan=plan,
        )
        bound_plan = descriptor.execution_plan
        assert bound_plan is not None
        original_name = bound_plan.plugins[0].artifact.distribution_name

        object.__setattr__(
            plan.plugins[0].artifact,
            "distribution_name",
            "attacker-mutated-distribution",
        )

        self.assertEqual(
            bound_plan.plugins[0].artifact.distribution_name,
            original_name,
        )

    def test_descriptor_rejects_execution_plan_for_another_node(self) -> None:
        with self.assertRaisesRegex(ValueError, "execution_plan node_id"):
            RevisionDescriptor(
                node_id="node-b",
                revision_id="revision-a",
                label="Node B",
                event_count=10,
                resource_count=3,
                plugin_ids=("vendor.forwarding", "vendor.asic"),
                execution_plan=_plan("node-a"),
            )

    def test_descriptor_rejects_inconsistent_plugin_id_projection(self) -> None:
        with self.assertRaisesRegex(ValueError, "plugin_ids must match"):
            RevisionDescriptor(
                node_id="node-a",
                revision_id="revision-a",
                label="Node A",
                event_count=10,
                resource_count=3,
                plugin_ids=("vendor.asic", "vendor.forwarding"),
                execution_plan=_plan(),
            )

    def test_descriptor_rejects_non_plan_execution_value(self) -> None:
        with self.assertRaisesRegex(TypeError, "PluginExecutionPlan or None"):
            RevisionDescriptor(
                node_id="node-a",
                revision_id="revision-a",
                label="Node A",
                event_count=10,
                resource_count=3,
                execution_plan=object(),  # type: ignore[arg-type]
            )

    def test_assembly_rejects_ambiguous_member_identity(self) -> None:
        first = RevisionDescriptor(
            node_id="node-a",
            revision_id="revision-a",
            label="Node A",
            event_count=100_000,
            resource_count=7_500,
        )
        with self.assertRaisesRegex(ValueError, "node_id"):
            AssemblyDescriptor(
                assembly_id="fabric",
                revisions=(
                    first,
                    RevisionDescriptor(
                        node_id="node-a",
                        revision_id="revision-b",
                        label="Duplicate A",
                        event_count=100_000,
                        resource_count=7_500,
                    ),
                ),
            )

    def test_protocol_does_not_impose_demo_scale_policy(self) -> None:
        descriptor = RevisionDescriptor(
            node_id="small-production-capture",
            revision_id="revision-1",
            label="Small capture",
            event_count=1,
            resource_count=1,
        )
        assembly = AssemblyDescriptor(
            assembly_id="capture",
            revisions=(descriptor,),
            coverage_case_ids=("basic.ipv4",),
        )
        self.assertEqual(assembly.revisions, (descriptor,))


if __name__ == "__main__":
    unittest.main()
