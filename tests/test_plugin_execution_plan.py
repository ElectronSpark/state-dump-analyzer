from __future__ import annotations

import copy
import unittest
from dataclasses import FrozenInstanceError, replace
from unittest.mock import patch

import router_dump_analyzer
from router_dump_analyzer.plugin_composition import (
    DEFAULT_PLUGIN_COMPOSITION_POLICY_DIGEST,
)
from router_dump_analyzer.plugin_execution_plan import (
    PLUGIN_EXECUTION_PLAN_VERSION,
    PLUGIN_EXECUTION_PLAN_VERSION_V1,
    PLUGIN_EXECUTION_PLAN_VERSION_V2,
    DecoderIdentity,
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
    PluginExecutionPlanAuthority,
    RevisionExecutionPlanRef,
    plugin_execution_pin_uses_legacy_identity,
    plugin_execution_plan_dict,
    plugin_execution_plan_digest,
    plugin_execution_plan_from_dict,
    plugin_execution_plan_is_executable,
    primary_parser_execution_pin,
    snapshot_plugin_execution_plan,
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
        registered_execution_identity="sha256:" + "e" * 64,
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
        self.assertEqual(
            document["composition_policy_digest"],
            DEFAULT_PLUGIN_COMPOSITION_POLICY_DIGEST,
        )
        self.assertEqual(document["execution_plan_authority"], "process")
        self.assertEqual(plugin_execution_plan_from_dict(document), plan)
        self.assertEqual(plugin_execution_plan_dict(plan), document)

    def test_retained_v1_round_trip_and_v2_identity_rules(self) -> None:
        legacy_pin = replace(
            _pin(),
            registered_execution_identity="sha256:" + "0" * 64,
        )
        legacy = PluginExecutionPlan(
            node_id="router-a",
            basis_revision_id="upload-sha256-abc",
            plugins=(legacy_pin,),
            contract_version=PLUGIN_EXECUTION_PLAN_VERSION_V1,
        )
        document = plugin_execution_plan_dict(legacy)
        self.assertNotIn("composition_policy_digest", document)
        self.assertNotIn("registered_execution_identity", document["plugins"][0])
        self.assertEqual(
            legacy.plan_digest,
            "sha256:ab2f4836be4ee1430c54d45d5dc36f71"
            "aa75c9534ce89231c5ce24326fdec9ff",
        )
        parsed = plugin_execution_plan_from_dict(document)
        self.assertEqual(parsed, legacy)
        self.assertEqual(
            parsed.plugins[0].registered_execution_identity,
            "sha256:" + "0" * 64,
        )
        self.assertTrue(plugin_execution_pin_uses_legacy_identity(parsed.plugins[0]))
        self.assertFalse(plugin_execution_plan_is_executable(parsed))
        self.assertEqual(
            parsed.composition_policy_digest,
            "sha256:" + "0" * 64,
        )
        v2 = PluginExecutionPlan(
            node_id="router-a",
            basis_revision_id="upload-sha256-abc",
            plugins=(_pin(),),
            contract_version=PLUGIN_EXECUTION_PLAN_VERSION_V2,
        )
        v2_document = plugin_execution_plan_dict(v2)
        self.assertNotIn("execution_plan_authority", v2_document)
        self.assertIs(
            v2.execution_plan_authority,
            PluginExecutionPlanAuthority.LEGACY_UNRECORDED,
        )
        self.assertEqual(plugin_execution_plan_from_dict(v2_document), v2)
        self.assertTrue(plugin_execution_plan_is_executable(v2))
        with self.assertRaisesRegex(ValueError, "v3.*require"):
            replace(legacy, contract_version=PLUGIN_EXECUTION_PLAN_VERSION)
        with self.assertRaisesRegex(ValueError, "v1.*cannot carry"):
            PluginExecutionPlan(
                node_id="router-a",
                basis_revision_id="upload-sha256-abc",
                plugins=(_pin(),),
                contract_version=PLUGIN_EXECUTION_PLAN_VERSION_V1,
            )
        with self.assertRaisesRegex(ValueError, "v1.*composition policy"):
            replace(legacy, composition_policy_digest=DIGEST_A)
        with self.assertRaisesRegex(ValueError, "current.*non-legacy"):
            replace(
                _plan(),
                composition_policy_digest="sha256:" + "0" * 64,
                plan_digest="",
            )

    def test_v3_authority_is_exact_and_matches_artifact_identity_tier(self) -> None:
        manifest_pin = replace(
            _pin(),
            artifact=replace(
                _pin().artifact,
                package_hash="manifest-sha256:" + "d" * 64,
            ),
        )
        manifest_plan = PluginExecutionPlan(
            node_id="router-a",
            basis_revision_id="basis-a",
            plugins=(manifest_pin,),
            execution_plan_authority=(
                PluginExecutionPlanAuthority.TRUSTED_INLINE_MANIFEST
            ),
        )
        self.assertEqual(
            plugin_execution_plan_dict(manifest_plan)["execution_plan_authority"],
            "trusted_inline_manifest",
        )
        with self.assertRaisesRegex(ValueError, "contradicts"):
            replace(
                manifest_plan,
                execution_plan_authority=(
                    PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED
                ),
                plan_digest="",
            )
        with self.assertRaisesRegex(ValueError, "contradicts"):
            replace(
                _plan(),
                execution_plan_authority=(
                    PluginExecutionPlanAuthority.TRUSTED_INLINE_MANIFEST
                ),
                plan_digest="",
            )
        with self.assertRaisesRegex(TypeError, "exact"):
            replace(
                _plan(),
                execution_plan_authority="process",  # type: ignore[arg-type]
                plan_digest="",
            )

    def test_canonical_wire_size_is_bounded_at_construction(self) -> None:
        with patch(
            "router_dump_analyzer.plugin_execution_plan."
            "MAX_PLUGIN_EXECUTION_PLAN_WIRE_BYTES",
            1,
        ), self.assertRaisesRegex(ValueError, "wire-size limit"):
            _plan()

    def test_digest_covers_order_and_every_identity_dimension(self) -> None:
        first = _pin("forwarding.0")
        second = replace(_pin("forwarding.1"), roles=("forwarding_observer",))
        self.assertNotEqual(_plan(first, second).plan_digest, _plan(second, first).plan_digest)
        mutations = (
            replace(first, configuration_digest=DIGEST_B),
            replace(first, schema_digest=DIGEST_A),
            replace(
                first,
                registered_execution_identity="sha256:" + "f" * 64,
            ),
            replace(first, roles=("primary_parser", "secondary_parser")),
            replace(first, capabilities=("dump.parse",)),
        )
        base_digest = _plan(first).plan_digest
        for changed in mutations:
            with self.subTest(changed=changed):
                self.assertNotEqual(_plan(changed).plan_digest, base_digest)
        policy_changed = replace(
            _plan(first),
            composition_policy_digest=DIGEST_A,
            plan_digest="",
        )
        self.assertNotEqual(policy_changed.plan_digest, base_digest)
        authority_changed = replace(
            _plan(first),
            execution_plan_authority=(
                PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED
            ),
            plan_digest="",
        )
        self.assertNotEqual(authority_changed.plan_digest, base_digest)

    def test_snapshot_and_root_exports_preserve_policy_identity(self) -> None:
        plan = replace(
            _plan(),
            composition_policy_digest=DIGEST_A,
            plan_digest="",
        )
        snapshot = snapshot_plugin_execution_plan(plan)
        self.assertIsNot(snapshot, plan)
        self.assertEqual(snapshot, plan)
        self.assertEqual(snapshot.composition_policy_digest, DIGEST_A)
        self.assertIs(
            router_dump_analyzer.snapshot_plugin_execution_plan,
            snapshot_plugin_execution_plan,
        )
        self.assertIs(
            router_dump_analyzer.plugin_execution_plan_is_executable,
            plugin_execution_plan_is_executable,
        )
        self.assertEqual(
            router_dump_analyzer.PLUGIN_EXECUTION_PLAN_VERSION_V1,
            PLUGIN_EXECUTION_PLAN_VERSION_V1,
        )
        self.assertEqual(
            router_dump_analyzer.PLUGIN_EXECUTION_PLAN_VERSION_V2,
            PLUGIN_EXECUTION_PLAN_VERSION_V2,
        )
        self.assertIs(
            router_dump_analyzer.PluginExecutionPlanAuthority,
            PluginExecutionPlanAuthority,
        )

    def test_tampering_and_unknown_fields_fail_closed(self) -> None:
        document = plugin_execution_plan_dict(_plan())
        tampered = copy.deepcopy(document)
        tampered["plugins"][0]["plugin_version"] = "different"
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            plugin_execution_plan_from_dict(tampered)
        unknown = copy.deepcopy(document)
        unknown["network_endpoint"] = "https://example.invalid"
        with self.assertRaisesRegex(ValueError, "exactly"):
            plugin_execution_plan_from_dict(unknown)
        missing_policy = copy.deepcopy(document)
        del missing_policy["composition_policy_digest"]
        with self.assertRaisesRegex(ValueError, "exactly"):
            plugin_execution_plan_from_dict(missing_policy)
        missing_authority = copy.deepcopy(document)
        del missing_authority["execution_plan_authority"]
        with self.assertRaisesRegex(ValueError, "exactly"):
            plugin_execution_plan_from_dict(missing_authority)
        legacy_with_policy = plugin_execution_plan_dict(
            PluginExecutionPlan(
                node_id="router-a",
                basis_revision_id="upload-sha256-abc",
                plugins=(
                    replace(
                        _pin(),
                        registered_execution_identity="sha256:" + "0" * 64,
                    ),
                ),
                contract_version=PLUGIN_EXECUTION_PLAN_VERSION_V1,
            )
        )
        legacy_with_policy["composition_policy_digest"] = DIGEST_A
        with self.assertRaisesRegex(ValueError, "exactly"):
            plugin_execution_plan_from_dict(legacy_with_policy)
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

    def test_primary_parser_role_is_unique_without_forbidding_provider_pins(self) -> None:
        primary = _pin("parser")
        secondary = replace(
            _pin("observer"),
            roles=("forwarding_observer",),
        )
        plan = _plan(primary, secondary)
        self.assertEqual(primary_parser_execution_pin(plan).instance_id, "parser")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            _plan(replace(primary, roles=("observer",)), secondary)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            _plan(primary, replace(secondary, roles=("primary_parser",)))

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
