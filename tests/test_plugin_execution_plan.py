from __future__ import annotations

import copy
import unittest
from dataclasses import FrozenInstanceError, replace

from router_dump_analyzer.plugin_execution_plan import (
    PLUGIN_EXECUTION_PLAN_VERSION,
    DecoderIdentity,
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
    RevisionExecutionPlanRef,
    plugin_execution_plan_dict,
    plugin_execution_plan_digest,
    plugin_execution_plan_from_dict,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
PACKAGE_DIGEST = "package-sha256:" + "c" * 64


class _HostileString(str):
    def __len__(self) -> int:
        raise AssertionError("string subclass behavior must not execute")

    def __ne__(self, other: object) -> bool:
        del other
        raise AssertionError("string subclass comparison must not execute")


def _pin(instance_id: str = "forwarding.0") -> PluginExecutionPin:
    return PluginExecutionPin(
        instance_id=instance_id,
        plugin_id="vendor.forwarding",
        plugin_version="2.4.1",
        core_api_version="2",
        artifact=PluginArtifactIdentity(
            distribution_name="vendor-forwarding-plugin",
            distribution_version="2.4.1+build.7",
            package_hash=PACKAGE_DIGEST,
            entry_point_name="forwarding",
            module_target="vendor_plugin:plugin",
        ),
        configuration_digest=DIGEST_A,
        schema_digest=DIGEST_B,
        schema_versions=("resource.v3", "event.v2"),
        capabilities=("dump.parse", "route.resolve"),
        roles=("primary_parser", "forwarding_observer"),
    )


def _plan(*pins: PluginExecutionPin) -> PluginExecutionPlan:
    return PluginExecutionPlan(
        node_id="router-a",
        basis_revision_id="upload-sha256-abc",
        plugins=tuple(pins or (_pin(),)),
        decoder=DecoderIdentity(
            decoder_id="babeltrace",
            decoder_version="2.1.2",
            executable_digest=DIGEST_A,
        ),
    )


class PluginExecutionPlanTests(unittest.TestCase):
    def test_round_trip_is_strict_and_digest_is_stable(self) -> None:
        plan = _plan()
        document = plugin_execution_plan_dict(plan)
        self.assertEqual(document["contract_version"], PLUGIN_EXECUTION_PLAN_VERSION)
        self.assertEqual(plugin_execution_plan_from_dict(document), plan)
        self.assertEqual(plugin_execution_plan_dict(plan), document)

    def test_digest_covers_order_and_every_identity_dimension(self) -> None:
        first = _pin("forwarding.0")
        second = _pin("forwarding.1")
        self.assertNotEqual(_plan(first, second).plan_digest, _plan(second, first).plan_digest)
        mutations = (
            replace(first, configuration_digest=DIGEST_B),
            replace(first, schema_digest=DIGEST_A),
            replace(first, roles=("secondary_parser",)),
            replace(first, capabilities=("dump.parse",)),
        )
        base_digest = _plan(first).plan_digest
        for changed in mutations:
            with self.subTest(changed=changed):
                self.assertNotEqual(_plan(changed).plan_digest, base_digest)

    def test_tampering_and_unknown_fields_fail_closed(self) -> None:
        document = plugin_execution_plan_dict(_plan())
        tampered = copy.deepcopy(document)
        tampered["plugins"][0]["roles"] = ["different"]
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            plugin_execution_plan_from_dict(tampered)
        unknown = copy.deepcopy(document)
        unknown["network_endpoint"] = "https://example.invalid"
        with self.assertRaisesRegex(ValueError, "exactly"):
            plugin_execution_plan_from_dict(unknown)
        missing_digest = copy.deepcopy(document)
        missing_digest["plan_digest"] = ""
        with self.assertRaisesRegex(ValueError, "plan_digest"):
            plugin_execution_plan_from_dict(missing_digest)

    def test_duplicate_instances_mutable_containers_and_bad_hashes_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "instance IDs"):
            _plan(_pin(), _pin())
        with self.assertRaisesRegex(TypeError, "tuple"):
            PluginExecutionPlan(
                node_id="router-a",
                basis_revision_id="basis",
                plugins=[_pin()],  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            PluginArtifactIdentity(
                distribution_name="plugin",
                distribution_version="1",
                package_hash="not-a-hash",
                entry_point_name="plugin",
                module_target="module:plugin",
            )
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            replace(_pin(), configuration_digest=PACKAGE_DIGEST)
        with self.assertRaisesRegex(ValueError, "opaque identifier"):
            replace(_pin(), instance_id="safe\u202eevil")

    def test_values_are_immutable_and_revision_binding_is_separate(self) -> None:
        plan = _plan()
        with self.assertRaises(FrozenInstanceError):
            plan.node_id = "router-b"  # type: ignore[misc]
        reference = RevisionExecutionPlanRef(
            node_id=plan.node_id,
            revision_id="analysis-revision-7",
            plan_digest=plan.plan_digest,
        )
        self.assertEqual(reference.plan_digest, plan.plan_digest)

    def test_identity_scalars_reject_string_subclasses_without_executing_them(
        self,
    ) -> None:
        with self.assertRaisesRegex(TypeError, "exact string"):
            DecoderIdentity(
                decoder_id=_HostileString("decoder"),
                decoder_version="1",
                executable_digest=DIGEST_A,
            )
        with self.assertRaisesRegex(TypeError, "contract_version"):
            PluginExecutionPlan(
                node_id="router-a",
                basis_revision_id="basis",
                plugins=(_pin(),),
                contract_version=_HostileString(PLUGIN_EXECUTION_PLAN_VERSION),
            )
        with self.assertRaisesRegex(TypeError, "plan_digest"):
            PluginExecutionPlan(
                node_id="router-a",
                basis_revision_id="basis",
                plugins=(_pin(),),
                plan_digest=_HostileString(DIGEST_A),
            )

    def test_nested_identities_are_resnapshotted_before_digest_and_projection(
        self,
    ) -> None:
        artifact = _pin().artifact
        object.__setattr__(
            artifact,
            "distribution_name",
            _HostileString("vendor"),
        )
        with self.assertRaisesRegex(TypeError, "distribution_name"):
            replace(_pin(), artifact=artifact)

        pin = _pin()
        object.__setattr__(pin, "plugin_id", _HostileString("vendor.forwarding"))
        with self.assertRaisesRegex(TypeError, "plugin_id"):
            _plan(pin)

        decoder = DecoderIdentity("decoder", "1", DIGEST_A)
        object.__setattr__(decoder, "decoder_id", _HostileString("decoder"))
        with self.assertRaisesRegex(TypeError, "decoder_id"):
            PluginExecutionPlan(
                node_id="router-a",
                basis_revision_id="basis",
                plugins=(_pin(),),
                decoder=decoder,
            )

        plan = _plan()
        object.__setattr__(
            plan.plugins[0],
            "plugin_id",
            _HostileString("vendor.forwarding"),
        )
        with self.assertRaisesRegex(TypeError, "plugin_id"):
            plugin_execution_plan_digest(plan)
        with self.assertRaisesRegex(TypeError, "plugin_id"):
            plugin_execution_plan_dict(plan)


if __name__ == "__main__":
    unittest.main()
