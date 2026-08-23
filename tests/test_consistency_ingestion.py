from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from router_dump_analyzer.capability_router import (
    CapabilityProviderRegistry,
    CapabilityRouteMissingError,
    CapabilityRouteSelector,
    CapabilityRouteStaleError,
    PlanBoundCapabilityRouter,
)
from router_dump_analyzer.consistency_materialization import (
    ConsistencyMaterializationError,
    legacy_consistency_materialization_envelope,
    revision_consistency_selected_pins,
)
from router_dump_analyzer.control_plane import validate_revision_consistency_dataset
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
    _revision_world_basis,
    _run_isolated_child,
    _validated_consistency_process_bootstraps,
)
from router_dump_analyzer.normalized_data import (
    project_consistency_materialization_for_client,
)
from router_dump_analyzer.plugin_api import (
    PluginCapability,
    PropertyPatch,
    RelationshipObservation,
    WorldBasis,
)
from router_dump_analyzer.plugin_composition import (
    REVISION_CONSISTENCY_ROLE,
    PluginCompositionPolicy,
    PluginCompositionRule,
    PluginParticipationSelection,
)
from router_dump_analyzer.plugin_execution_plan import (
    PluginExecutionPlanAuthority,
    plugin_execution_plan_from_dict,
)
from router_dump_analyzer.web import runtime_api
from tests.support.consistency_plugin import (
    ConsistencyAuxiliaryPlugin,
)
from tests.support.consistency_plugin import (
    ConsistencyParsePlugin as _ConsistencyParsePlugin,
)
from tests.test_ingestion import ParseOnlyPlugin
from tests.test_ingestion_pipeline import _fixture_bytes


class _WrongBasisConsistencyPlugin(_ConsistencyParsePlugin):
    manifest = replace(
        _ConsistencyParsePlugin.manifest,
        plugin_id="tests.consistency-ingestion-wrong-basis",
    )

    def check_consistency(self, world: Any):
        finding = next(iter(super().check_consistency(world)))
        incompatible = replace(
            world.basis,
            requested_time_ns=1,
        )
        assert isinstance(incompatible, WorldBasis)
        return (replace(finding, basis=incompatible),)


class _RecordingChildConnection:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    def send_bytes(self, value: bytes) -> None:
        self.sent.append(value)

    def close(self) -> None:
        self.closed = True


class ConsistencyIngestionTests(unittest.TestCase):
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
            path.write_bytes(_fixture_bytes())
            result = coordinator.ingest(plugin, path)
        return registered, providers, result

    def test_plan_bound_findings_are_materialized_before_canonical_bytes(self) -> None:
        registered, providers, result = self._ingest(_ConsistencyParsePlugin())
        dataset_bytes, plan = _dataset_with_execution_plan(
            registered,
            result,
            capability_providers=providers,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )
        dataset = json.loads(dataset_bytes)

        self.assertEqual(dataset["_ingestion"]["mode"], "core-ingestion-v3")
        self.assertEqual(dataset["inventory"]["mode"], "core-ingestion-v3")
        self.assertEqual(
            dataset["_ingestion"]["plugin_execution_plan_digest"],
            plan.plan_digest,
        )
        materialization = dataset["consistency_materialization"]
        self.assertEqual(materialization["status"], "complete")
        self.assertEqual(materialization["plan_digest"], plan.plan_digest)
        self.assertEqual(materialization["finding_count"], 1)
        self.assertEqual(materialization["diagnostic_count"], 0)
        self.assertEqual(materialization["basis"]["kind"], "observed_capture_vector")
        self.assertIsNone(materialization["basis"]["requested_time_ns"])
        self.assertEqual(len(materialization["basis"]["capture_ranges"]), 1)
        self.assertEqual(dataset["summary"]["consistency"]["fail"], 1)
        self.assertEqual(dataset["consistency_diagnostics"], [])
        self.assertEqual(len(dataset["findings"]), 1)
        self.assertEqual(
            dataset["findings"][0]["producer"]["instance_id"],
            "primary",
        )
        indexed_findings, indexed_materialization = (
            validate_revision_consistency_dataset(
                dataset,
                execution_plan=plan,
            )
        )
        self.assertEqual(len(indexed_findings), 1)
        self.assertEqual(indexed_materialization, materialization)
        with (
            patch.object(
                runtime_api,
                "_require_revision",
                return_value=SimpleNamespace(execution_plan=plan),
            ),
            patch.object(runtime_api, "load_dataset", return_value=dataset),
        ):
            public_page = runtime_api.consistency_findings(
                "revision-a",
                limit=1,
                offset=0,
            )
        self.assertEqual(public_page["count"], 1)
        self.assertEqual(public_page["total_count"], 1)
        self.assertIsNone(public_page["next_offset"])
        self.assertNotIn("next_cursor", public_page)
        self.assertEqual(
            set(public_page),
            {
                "revision_id",
                "materialization",
                "items",
                "count",
                "total_count",
                "offset",
                "limit",
                "next_offset",
            },
        )
        self.assertEqual(
            set(public_page["items"][0]["resource_references"][0]),
            {"resource_id"},
        )
        self.assertNotIn("locator", json.dumps(public_page))
        self.assertEqual(
            public_page["materialization"],
            project_consistency_materialization_for_client(materialization),
        )
        self.assertEqual(
            set(public_page["materialization"]),
            set(materialization),
        )

    def test_revision_basis_does_not_hide_mixed_unknown_observation_time(self) -> None:
        _registered, _providers, result = self._ingest(_ConsistencyParsePlugin())

        known_snapshot = result.snapshots[0]
        unknown_snapshot = replace(
            known_snapshot,
            observed_at_min_ns=None,
            observed_at_max_ns=None,
        )
        snapshot_basis = _revision_world_basis(
            replace(
                result,
                snapshots=(known_snapshot, unknown_snapshot),
                relationship_observations=(),
            )
        )
        self.assertEqual(len(snapshot_basis.capture_ranges), 1)
        self.assertIsNone(snapshot_basis.capture_ranges[0].observed_at_min_ns)
        self.assertIsNone(snapshot_basis.capture_ranges[0].observed_at_max_ns)

        known_relationship = RelationshipObservation(
            source=known_snapshot.resource,
            target=known_snapshot.resource,
            relation_type="self",
            observed_at_min_ns=10,
            observed_at_max_ns=10,
            present=True,
            attributes=PropertyPatch(),
            provenance=known_snapshot.provenance,
            quality=known_snapshot.quality,
            evidence=known_snapshot.evidence,
        )
        unknown_relationship = replace(
            known_relationship,
            observed_at_min_ns=None,
            observed_at_max_ns=None,
        )
        relationship_basis = _revision_world_basis(
            replace(
                result,
                snapshots=(),
                relationship_observations=(known_relationship, unknown_relationship),
            )
        )
        self.assertEqual(len(relationship_basis.capture_ranges), 1)
        self.assertIsNone(relationship_basis.capture_ranges[0].observed_at_min_ns)
        self.assertIsNone(relationship_basis.capture_ranges[0].observed_at_max_ns)

    def test_revision_without_selected_provider_is_explicitly_not_applicable(
        self,
    ) -> None:
        registered, providers, result = self._ingest(ParseOnlyPlugin())
        dataset_bytes, plan = _dataset_with_execution_plan(
            registered,
            result,
            capability_providers=providers,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )
        dataset = json.loads(dataset_bytes)

        self.assertEqual(
            dataset["consistency_materialization"]["status"],
            "not_applicable",
        )
        self.assertEqual(
            dataset["consistency_materialization"]["plan_digest"],
            plan.plan_digest,
        )
        self.assertIsNone(dataset["consistency_materialization"]["basis"])
        self.assertEqual(dataset["findings"], [])

    def test_runtime_legacy_envelope_uses_the_shared_contract_shape(self) -> None:
        registered, providers, result = self._ingest(ParseOnlyPlugin())
        dataset_bytes, plan = _dataset_with_execution_plan(
            registered,
            result,
            capability_providers=providers,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )
        dataset = json.loads(dataset_bytes)
        dataset.pop("consistency_materialization")
        dataset["_ingestion"].pop("mode")
        dataset["_ingestion"].pop("consistency_materialization_status")
        dataset.pop("consistency_diagnostics")
        dataset["inventory"]["mode"] = "core-ingestion-v2"
        dataset["findings"] = [{"legacy_rule": "vendor.rule"}]
        with (
            patch.object(
                runtime_api,
                "_require_revision",
                return_value=SimpleNamespace(execution_plan=plan),
            ),
            patch.object(runtime_api, "load_dataset", return_value=dataset),
        ):
            page = runtime_api.consistency_findings(
                "revision-a",
                limit=1_000,
                offset=0,
            )

        self.assertEqual(
            page["materialization"],
            legacy_consistency_materialization_envelope(
                plan_digest=plan.plan_digest,
                finding_count=1,
            ),
        )

    def test_runtime_v3_materialization_corruption_never_downgrades_to_legacy(
        self,
    ) -> None:
        registered, providers, result = self._ingest(ParseOnlyPlugin())
        dataset_bytes, plan = _dataset_with_execution_plan(
            registered,
            result,
            capability_providers=providers,
            execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
        )
        base = json.loads(dataset_bytes)
        corruptions = {
            "missing": (False, None),
            "explicit_null": (True, None),
            "scalar": (True, "invalid"),
            "arbitrary": (True, {"status": "complete"}),
            "bad_count": (
                True,
                {
                    **base["consistency_materialization"],
                    "finding_count": 1,
                },
            ),
            "bad_digest": (
                True,
                {
                    **base["consistency_materialization"],
                    "plan_digest": "sha256:" + "0" * 64,
                },
            ),
        }
        for label, (present, envelope) in corruptions.items():
            dataset = json.loads(dataset_bytes)
            if not present:
                dataset.pop("consistency_materialization")
            else:
                dataset["consistency_materialization"] = envelope
            with (
                self.subTest(label=label),
                patch.object(
                    runtime_api,
                    "_require_revision",
                    return_value=SimpleNamespace(execution_plan=plan),
                ),
                patch.object(runtime_api, "load_dataset", return_value=dataset),
                self.assertRaises(runtime_api._RuntimeHTTPResponse) as raised,
            ):
                runtime_api.consistency_findings(
                    "revision-a",
                    limit=1_000,
                    offset=0,
                )
            self.assertEqual(raised.exception.status_code, 500)

    def test_mismatched_finding_basis_aborts_prepublication_materialization(
        self,
    ) -> None:
        registered, providers, result = self._ingest(_WrongBasisConsistencyPlugin())
        with self.assertRaisesRegex(
            ConsistencyMaterializationError,
            "basis does not match",
        ):
            _dataset_with_execution_plan(
                registered,
                result,
                capability_providers=providers,
                execution_plan_authority=PluginExecutionPlanAuthority.PROCESS,
            )

    def test_process_child_loads_only_the_selected_consistency_auxiliary(
        self,
    ) -> None:
        primary_registry = PluginRegistry(require_executable_identity=True)
        primary = primary_registry.register(
            ParseOnlyPlugin(),
            instance_id="primary",
        )
        auxiliary_registry = PluginRegistry(require_executable_identity=True)
        auxiliary = auxiliary_registry.register(
            ConsistencyAuxiliaryPlugin(),
            instance_id="consistency-auxiliary",
        )
        irrelevant_registry = PluginRegistry(require_executable_identity=True)
        irrelevant = irrelevant_registry.register(
            ConsistencyAuxiliaryPlugin(),
            instance_id="irrelevant-auxiliary",
        )
        providers = CapabilityProviderRegistry((primary, auxiliary, irrelevant))
        selection = PluginParticipationSelection(
            instance_id=auxiliary.instance_id,
            registered_execution_identity=(auxiliary.registered_execution_identity),
            roles=(REVISION_CONSISTENCY_ROLE,),
        )
        irrelevant_selection = PluginParticipationSelection(
            instance_id=irrelevant.instance_id,
            registered_execution_identity=(irrelevant.registered_execution_identity),
            roles=("passive_evidence",),
        )
        policy = PluginCompositionPolicy(
            (
                PluginCompositionRule(
                    primary_instance_id=primary.instance_id,
                    primary_registered_execution_identity=(
                        primary.registered_execution_identity
                    ),
                    auxiliaries=(selection, irrelevant_selection),
                ),
            )
        )
        selections = (selection, irrelevant_selection)
        child_bootstraps = _frozen_auxiliary_process_bootstraps(
            providers,
            selections,
        )
        frozen_pins = _frozen_auxiliary_execution_pins(providers, selections)
        self.assertEqual(len(child_bootstraps), 1)
        self.assertEqual(child_bootstraps[0].instance_id, auxiliary.instance_id)
        self.assertEqual(
            _validated_consistency_process_bootstraps(
                frozen_pins,
                child_bootstraps,
            ),
            child_bootstraps,
        )
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "do not match the frozen plan pins",
        ):
            _validated_consistency_process_bootstraps(frozen_pins, ())
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "does not match its frozen plan pin",
        ):
            _validated_consistency_process_bootstraps(
                frozen_pins,
                (
                    replace(
                        child_bootstraps[0],
                        configuration_digest="sha256:" + ("0" * 64),
                    ),
                ),
            )
        tampered_bootstrap = replace(
            child_bootstraps[0],
            plugin_target=primary.process_bootstrap.plugin_target,
            plugin_target_executable_identity=(
                primary.process_bootstrap.plugin_target_executable_identity
            ),
        )
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "does not match its frozen plan pin",
        ):
            _validated_consistency_process_bootstraps(
                frozen_pins,
                (tampered_bootstrap,),
            )
        invalid_role_pin = replace(
            frozen_pins[1],
            roles=(REVISION_CONSISTENCY_ROLE,),
            capabilities=(),
        )
        with self.assertRaisesRegex(
            IngestionPipelineError,
            "does not declare CONSISTENCY_CHECK",
        ):
            _validated_consistency_process_bootstraps(
                (frozen_pins[0], invalid_role_pin),
                child_bootstraps,
            )

        tampered_primary = replace(
            primary.process_bootstrap,
            plugin_target=child_bootstraps[0].plugin_target,
            plugin_target_executable_identity=(
                child_bootstraps[0].plugin_target_executable_identity
            ),
        )
        primary_connection = _RecordingChildConnection()
        with patch(
            "router_dump_analyzer.ingestion_pipeline._registry_from_process_bootstraps"
        ) as child_loader:
            _ingest_plugin_child(
                primary_connection,
                tampered_primary,
                primary.process_bootstrap_digest,
                "unused",
                None,
                {},
                "unused",
                frozen_pins,
                policy,
                child_bootstraps,
            )
        child_loader.assert_not_called()
        self.assertTrue(primary_connection.closed)
        self.assertFalse(json.loads(primary_connection.sent[0])["ok"])

        connection = _RecordingChildConnection()
        with patch(
            "router_dump_analyzer.ingestion_pipeline._registry_from_process_bootstraps"
        ) as child_loader:
            _ingest_plugin_child(
                connection,
                primary.process_bootstrap,
                primary.process_bootstrap_digest,
                "unused",
                None,
                {},
                "unused",
                frozen_pins,
                policy,
                (*child_bootstraps, irrelevant.process_bootstrap),
            )
        child_loader.assert_not_called()
        self.assertTrue(connection.closed)
        self.assertEqual(len(connection.sent), 1)
        self.assertFalse(json.loads(connection.sent[0])["ok"])

        tampered_connection = _RecordingChildConnection()
        with patch(
            "router_dump_analyzer.ingestion_pipeline._registry_from_process_bootstraps"
        ) as child_loader:
            _ingest_plugin_child(
                tampered_connection,
                primary.process_bootstrap,
                primary.process_bootstrap_digest,
                "unused",
                None,
                {},
                "unused",
                frozen_pins,
                policy,
                (tampered_bootstrap,),
            )
        child_loader.assert_not_called()
        self.assertTrue(tampered_connection.closed)
        self.assertFalse(json.loads(tampered_connection.sent[0])["ok"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "status.jsonl"
            fixture.write_bytes(_fixture_bytes())
            staged = root / "dataset.json"
            payload = _run_isolated_child(
                _ingest_plugin_child,
                (
                    primary.process_bootstrap,
                    primary.process_bootstrap_digest,
                    str(fixture),
                    "node-a",
                    {},
                    str(staged),
                    frozen_pins,
                    policy,
                    child_bootstraps,
                ),
                timeout_seconds=30,
                stage="ingest",
                expected_kind="ingest",
                subject="consistency composition",
                process_name_prefix="consistency-composition",
                timeout_error=PluginExecutionTimeoutError,
                process_error=PluginExecutionProcessError,
            )
            dataset = json.loads(staged.read_bytes())

        self.assertEqual(payload["kind"], "ingest")
        self.assertEqual(
            dataset["consistency_materialization"]["status"],
            "complete",
        )
        self.assertEqual(
            tuple(
                provider["instance_id"]
                for provider in dataset["consistency_materialization"]["providers"]
            ),
            ("consistency-auxiliary",),
        )
        self.assertEqual(
            dataset["findings"][0]["producer"]["instance_id"],
            "consistency-auxiliary",
        )
        plan = plugin_execution_plan_from_dict(payload["execution_plan"])
        consistency_pins = revision_consistency_selected_pins(plan)
        with patch.object(
            PluginRegistry,
            "revalidate_registered_identity",
            side_effect=AssertionError("frozen child indexing invoked live code"),
        ) as live_revalidation:
            selected_registry = (
                CapabilityProviderRegistry._from_frozen_process_execution_plan(
                    (primary, auxiliary),
                    plan,
                    consistency_pins,
                )
            )
        live_revalidation.assert_not_called()

        with self.assertRaises(CapabilityRouteStaleError):
            PlanBoundCapabilityRouter(
                selected_registry,
                plan,
                catalog_revision_id=plan.basis_revision_id,
                member_id=plan.basis_revision_id,
            )
        restricted_router = PlanBoundCapabilityRouter._for_required_pins(
            selected_registry,
            plan,
            catalog_revision_id=plan.basis_revision_id,
            member_id=plan.basis_revision_id,
            required_pins=consistency_pins,
        )
        with self.assertRaises(CapabilityRouteMissingError):
            restricted_router.resolve(
                CapabilityRouteSelector(
                    PluginCapability.CONSISTENCY_CHECK,
                    role="passive_evidence",
                    instance_id=irrelevant.instance_id,
                )
            )


if __name__ == "__main__":
    unittest.main()
