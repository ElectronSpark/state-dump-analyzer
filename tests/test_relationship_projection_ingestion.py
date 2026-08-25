from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer.capability_router import CapabilityProviderRegistry
from router_dump_analyzer.ingestion import IngestionCoordinator
from router_dump_analyzer.ingestion_pipeline import (
    IngestionPipelineError,
    PluginExecutionProcessError,
    PluginExecutionTimeoutError,
    PluginRegistry,
    _dataset_with_execution_plan,
    _frozen_auxiliary_execution_pins,
    _frozen_auxiliary_process_bootstraps,
    _ingest_plugin_child,
    _plugin_process_bootstrap_digest,
    _run_isolated_child,
    _validated_child_composition_authority,
    _validated_materialization_process_bootstraps,
)
from router_dump_analyzer.plugin_composition import (
    REVISION_CONSISTENCY_ROLE,
    REVISION_RELATIONSHIP_PROJECTION_ROLE,
    PluginCompositionPolicy,
    PluginCompositionRule,
    PluginParticipationSelection,
)
from router_dump_analyzer.plugin_execution_plan import (
    PluginExecutionPlanAuthority,
)
from tests.support.normalized_data import static_data_service
from tests.support.relationship_projection_plugin import (
    RelationshipProjectionAuxiliaryPlugin,
    RelationshipProjectionParsePlugin,
    RelationshipProjectionTombstonePlugin,
)
from tests.test_ingestion import ParseOnlyPlugin


def _two_resource_fixture() -> bytes:
    return (
        "\n".join(
            json.dumps(
                {
                    "captured_at_ns": timestamp,
                    "ifindex": ifindex,
                    "name": name,
                    "oper_status": "up",
                }
            )
            for timestamp, ifindex, name in (
                (100, 7, "xe-0/0/0"),
                (101, 8, "Ethernet1/1"),
            )
        )
        + "\n"
    ).encode("utf-8")


def _semantic_projection(value: object) -> object:
    if type(value) is list:
        return [_semantic_projection(item) for item in value]
    if type(value) is dict:
        plan_bound_fields = {
            "basis_digest",
            "declaration_id",
            "declaration_ids",
            "execution_plan_digest",
            "finding_id",
            "plan_digest",
            "relationship_id",
        }
        return {
            key: _semantic_projection(item)
            for key, item in value.items()
            if key not in plan_bound_fields
        }
    return value


class RelationshipProjectionIngestionTests(unittest.TestCase):
    def _ingest(self, plugin: ParseOnlyPlugin):
        coordinator = IngestionCoordinator()
        registry = PluginRegistry()
        registered = registry.register(
            plugin,
            coordinator=coordinator,
            instance_id="primary",
        )
        providers = CapabilityProviderRegistry.from_primary_registry(registry)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_bytes(_two_resource_fixture())
            result = coordinator.ingest(plugin, path)
        return registered, providers, result

    def test_projection_is_durable_revision_scoped_and_precedes_consistency(self) -> None:
        registered, providers, result = self._ingest(
            RelationshipProjectionParsePlugin()
        )
        dataset_bytes, plan = _dataset_with_execution_plan(
            registered,
            result,
            capability_providers=providers,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )
        dataset = json.loads(dataset_bytes)

        materialization = dataset["relationship_projection_materialization"]
        self.assertEqual(materialization["status"], "complete")
        self.assertEqual(materialization["scope"], "revision")
        self.assertEqual(materialization["plan_digest"], plan.plan_digest)
        self.assertEqual(materialization["declaration_count"], 1)
        self.assertEqual(materialization["resolved_edge_count"], 1)
        self.assertEqual(len(dataset["relationship_declarations"]), 1)
        self.assertEqual(len(dataset["relationship_projection_edges"]), 1)
        edge = dataset["relationship_projection_edges"][0]
        self.assertEqual(edge["relation_type"], "same_logical_interface")
        self.assertEqual(edge["scope"], "revision")
        self.assertNotIn("valid_from_ns", edge)
        self.assertNotIn("valid_to_ns", edge)
        self.assertNotIn("timestamp_ns", edge)
        self.assertEqual(dataset["summary"]["consistency"]["pass"], 1)
        self.assertEqual(
            dataset["findings"][0]["rule_id"],
            "tests.projected-edge-visible-to-consistency",
        )

        service = static_data_service(dataset)
        client_dataset = service.client_dataset()
        self.assertEqual(len(client_dataset["relationship_projection_edges"]), 1)
        # A revision-scoped declaration is not a fabricated temporal interval.
        self.assertEqual(
            tuple(
                relationship
                for relationship in service.relationships_at(100)
                if relationship.get("relation_type")
                == "same_logical_interface"
            ),
            (),
        )

    def test_no_selected_projector_is_explicitly_not_applicable(self) -> None:
        registered, providers, result = self._ingest(ParseOnlyPlugin())
        dataset_bytes, plan = _dataset_with_execution_plan(
            registered,
            result,
            capability_providers=providers,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )
        dataset = json.loads(dataset_bytes)
        materialization = dataset["relationship_projection_materialization"]
        self.assertEqual(materialization["status"], "not_applicable")
        self.assertEqual(materialization["scope"], "revision")
        self.assertEqual(materialization["plan_digest"], plan.plan_digest)
        self.assertIsNone(materialization["basis_digest"])
        self.assertEqual(dataset["relationship_declarations"], [])
        self.assertEqual(dataset["relationship_projection_edges"], [])

    def test_process_and_trusted_inline_materialize_the_same_public_contract(
        self,
    ) -> None:
        coordinator = IngestionCoordinator()
        primary_plugin = RelationshipProjectionParsePlugin()
        primary_registry = PluginRegistry(require_executable_identity=True)
        primary = primary_registry.register(
            primary_plugin,
            coordinator=coordinator,
            instance_id="primary",
        )
        auxiliary_registry = PluginRegistry(require_executable_identity=True)
        auxiliary = auxiliary_registry.register(
            RelationshipProjectionAuxiliaryPlugin(),
            instance_id="projection-auxiliary",
        )
        providers = CapabilityProviderRegistry((primary, auxiliary))
        selection = PluginParticipationSelection(
            instance_id=auxiliary.instance_id,
            registered_execution_identity=auxiliary.registered_execution_identity,
            roles=(
                REVISION_CONSISTENCY_ROLE,
                REVISION_RELATIONSHIP_PROJECTION_ROLE,
            ),
        )
        policy = PluginCompositionPolicy(
            rules=(
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(selection,),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.jsonl"
            path.write_bytes(_two_resource_fixture())
            result = coordinator.ingest(primary_plugin, path)

        datasets: dict[PluginExecutionPlanAuthority, dict[str, object]] = {}
        for authority in (
            PluginExecutionPlanAuthority.PROCESS,
            PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED,
        ):
            dataset_bytes, _plan = _dataset_with_execution_plan(
                primary,
                result,
                capability_providers=providers,
                composition_policy=policy,
                execution_plan_authority=authority,
            )
            datasets[authority] = json.loads(dataset_bytes)

        process = datasets[PluginExecutionPlanAuthority.PROCESS]
        trusted_inline = datasets[
            PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED
        ]

        for field in (
            "relationship_declarations",
            "relationship_projection_edges",
            "relationship_projection_diagnostics",
            "findings",
            "summary",
        ):
            with self.subTest(field=field):
                process_semantics = _semantic_projection(process[field])
                inline_semantics = _semantic_projection(trusted_inline[field])
                if type(process_semantics) is list:
                    self.assertEqual(
                        sorted(
                            json.dumps(item, sort_keys=True, separators=(",", ":"))
                            for item in process_semantics
                        ),
                        sorted(
                            json.dumps(item, sort_keys=True, separators=(",", ":"))
                            for item in inline_semantics  # type: ignore[union-attr]
                        ),
                    )
                else:
                    self.assertEqual(process_semantics, inline_semantics)
        self.assertEqual(
            process["relationship_projection_materialization"]["status"],  # type: ignore[index]
            "complete",
        )
        self.assertEqual(
            trusted_inline["relationship_projection_materialization"][  # type: ignore[index]
                "status"
            ],
            "complete",
        )

    def test_parser_tombstone_prevents_projection_resurrection_before_consistency(
        self,
    ) -> None:
        registered, providers, result = self._ingest(
            RelationshipProjectionTombstonePlugin()
        )
        dataset_bytes, _plan = _dataset_with_execution_plan(
            registered,
            result,
            capability_providers=providers,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )
        dataset = json.loads(dataset_bytes)

        # The declaration remains auditable, but the augmented world honors the
        # parser's explicit absence and consistency therefore sees no live edge.
        self.assertEqual(len(dataset["relationship_declarations"]), 1)
        self.assertEqual(len(dataset["relationship_projection_edges"]), 1)
        self.assertEqual(dataset["findings"], [])
        self.assertEqual(dataset["summary"]["consistency"]["pass"], 0)

    def test_dual_role_auxiliary_uses_one_exact_process_bootstrap(self) -> None:
        primary_registry = PluginRegistry(require_executable_identity=True)
        primary = primary_registry.register(ParseOnlyPlugin(), instance_id="primary")
        auxiliary_registry = PluginRegistry(require_executable_identity=True)
        auxiliary = auxiliary_registry.register(
            RelationshipProjectionAuxiliaryPlugin(),
            instance_id="projection-auxiliary",
        )
        providers = CapabilityProviderRegistry((primary, auxiliary))
        selection = PluginParticipationSelection(
            instance_id=auxiliary.instance_id,
            registered_execution_identity=auxiliary.registered_execution_identity,
            roles=(
                REVISION_CONSISTENCY_ROLE,
                REVISION_RELATIONSHIP_PROJECTION_ROLE,
            ),
        )
        bootstraps = _frozen_auxiliary_process_bootstraps(providers, (selection,))
        bootstrap_digests = tuple(
            _plugin_process_bootstrap_digest(value) for value in bootstraps
        )
        pins = _frozen_auxiliary_execution_pins(providers, (selection,))
        self.assertEqual(len(bootstraps), 1)
        self.assertEqual(
            _validated_materialization_process_bootstraps(
                pins,
                bootstraps,
                bootstrap_digests,
            ),
            bootstraps,
        )

        wrong_capability = replace(
            pins[0],
            capabilities=tuple(
                value
                for value in pins[0].capabilities
                if value != "relationship_projection"
            ),
        )
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "does not declare RELATIONSHIP_PROJECTION",
        ):
            _validated_materialization_process_bootstraps(
                (wrong_capability,),
                bootstraps,
                bootstrap_digests,
            )

        policy = PluginCompositionPolicy(
            rules=(
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(selection,),
                ),
            )
        )
        selected_policy, authorized = _validated_child_composition_authority(
            primary.process_bootstrap,
            pins,
            policy,
        )
        self.assertEqual(selected_policy.policy_digest, policy.policy_digest)
        self.assertEqual(authorized, pins)

        class RecordingConnection:
            def __init__(self) -> None:
                self.messages: list[bytes] = []
                self.closed = False

            def send_bytes(self, payload: bytes) -> None:
                self.messages.append(payload)

            def close(self) -> None:
                self.closed = True

        connection = RecordingConnection()
        with patch(
            "router_dump_analyzer.ingestion_pipeline._registry_from_process_bootstraps"
        ) as loader:
            _ingest_plugin_child(
                connection,
                primary.process_bootstrap,
                primary.process_bootstrap_digest,
                bootstrap_digests,
                "unused-input",
                None,
                {},
                "unused-output",
                pins,
                PluginCompositionPolicy(),
                bootstraps,
            )
        loader.assert_not_called()
        self.assertTrue(connection.closed)
        self.assertEqual(len(connection.messages), 1)
        child_error = json.loads(connection.messages[0])
        self.assertFalse(child_error["ok"])
        self.assertIn("composition policy", child_error["message"])

    def test_spawned_process_materializes_primary_and_auxiliary_projectors(
        self,
    ) -> None:
        primary_plugin = RelationshipProjectionParsePlugin()
        primary_registry = PluginRegistry(require_executable_identity=True)
        primary = primary_registry.register(
            primary_plugin,
            instance_id="primary",
        )
        auxiliary_registry = PluginRegistry(require_executable_identity=True)
        auxiliary = auxiliary_registry.register(
            RelationshipProjectionAuxiliaryPlugin(),
            instance_id="projection-auxiliary",
        )
        providers = CapabilityProviderRegistry((primary, auxiliary))
        selection = PluginParticipationSelection(
            instance_id=auxiliary.instance_id,
            registered_execution_identity=auxiliary.registered_execution_identity,
            roles=(
                REVISION_CONSISTENCY_ROLE,
                REVISION_RELATIONSHIP_PROJECTION_ROLE,
            ),
        )
        policy = PluginCompositionPolicy(
            rules=(
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(selection,),
                ),
            )
        )
        pins = _frozen_auxiliary_execution_pins(providers, (selection,))
        bootstraps = _frozen_auxiliary_process_bootstraps(providers, (selection,))
        bootstrap_digests = tuple(
            _plugin_process_bootstrap_digest(value) for value in bootstraps
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "status.jsonl"
            fixture.write_bytes(_two_resource_fixture())
            staged = root / "dataset.json"
            payload = _run_isolated_child(
                _ingest_plugin_child,
                (
                    primary.process_bootstrap,
                    primary.process_bootstrap_digest,
                    bootstrap_digests,
                    str(fixture),
                    "node-a",
                    {},
                    str(staged),
                    pins,
                    policy,
                    bootstraps,
                ),
                timeout_seconds=30,
                stage="ingest",
                expected_kind="ingest",
                subject="relationship projection composition",
                process_name_prefix="relationship-projection-composition",
                timeout_error=PluginExecutionTimeoutError,
                process_error=PluginExecutionProcessError,
            )
            process_dataset = json.loads(staged.read_bytes())
            inline_result = IngestionCoordinator().ingest(
                primary_plugin,
                fixture,
                node_hint="node-a",
            )
            inline_bytes, _inline_plan = _dataset_with_execution_plan(
                primary,
                inline_result,
                capability_providers=providers,
                composition_policy=policy,
                execution_plan_authority=(
                    PluginExecutionPlanAuthority.TRUSTED_INLINE_ATTESTED
                ),
            )
            inline_dataset = json.loads(inline_bytes)

        self.assertEqual(payload["kind"], "ingest")
        materialization = process_dataset["relationship_projection_materialization"]
        self.assertEqual(materialization["status"], "complete")
        self.assertEqual(
            tuple(provider["instance_id"] for provider in materialization["providers"]),
            ("primary", "projection-auxiliary"),
        )
        contributions = process_dataset["relationship_declarations"][0][
            "contributions"
        ]
        self.assertEqual(
            tuple(item["producer"]["instance_id"] for item in contributions),
            ("primary", "projection-auxiliary"),
        )
        self.assertEqual(
            process_dataset["consistency_materialization"]["status"],
            "complete",
        )
        for field in (
            "relationship_declarations",
            "relationship_projection_edges",
            "relationship_projection_diagnostics",
            "findings",
            "summary",
        ):
            with self.subTest(transport_parity_field=field):
                self.assertEqual(
                    _semantic_projection(process_dataset[field]),
                    _semantic_projection(inline_dataset[field]),
                )


if __name__ == "__main__":
    unittest.main()
