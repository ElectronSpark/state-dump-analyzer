"""Behavioral parity gates for shared primitives and their public adapters."""

from __future__ import annotations

import dataclasses
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from starlette.requests import Request

from router_dump_analyzer import (
    canonical,
    normalized_data,
    revision_queries,
    temporal_core,
)
from router_dump_analyzer.access_control_contract import (
    ACCESS_DENIAL_REASONS_BY_PHASE,
    ACCESS_DENIAL_WIRE_REASONS,
    CONTROL_PLANE_ADMIN_ROLE,
    CONTROL_PLANE_READ_ROLE,
    CONTROL_PLANE_ROLES,
    ControlPlaneAccessPhase,
    ControlPlaneAccessReason,
)
from router_dump_analyzer import operational_logging
from router_dump_analyzer import plugin_composition_deployment as composition
from router_dump_analyzer import private_analysis_deployment as analysis
from router_dump_analyzer.materialization_contract import (
    CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION,
    RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION,
)
from router_dump_analyzer.value_core import require_bounded_integer
from router_dump_analyzer.web import control_plane_api


class SharedDeploymentTests(unittest.TestCase):
    def test_lazy_demo_store_preserves_base_metadata_attribute_contract(self) -> None:
        from rsl_demo_plugin.session import _LazyDemoAssemblyStore

        materialized = SimpleNamespace(manifest={}, coverage={})
        store = _LazyDemoAssemblyStore(Path("not-opened.tgz"))
        with patch.object(store, "_materialized", return_value=materialized):
            manifest, coverage = {"revision": "r1"}, {"complete": False}
            store.manifest = manifest
            store.coverage = coverage
            self.assertIs(store.manifest, manifest)
            self.assertIs(store.coverage, coverage)
            self.assertIs(materialized.manifest, manifest)
            self.assertIs(materialized.coverage, coverage)

    def test_composition_roots_forward_the_complete_authority_bundle(self) -> None:
        policy, providers = object(), object()
        deployment = SimpleNamespace(
            policy=policy,
            capability_providers=providers,
            allow_inline_only=True,
        )
        options = composition._control_plane_composition_options(deployment)
        self.assertEqual(
            set(options),
            {"plugin_composition_policy", "capability_providers", "allow_inline_only"},
        )
        self.assertIs(options["plugin_composition_policy"], policy)
        self.assertIs(options["capability_providers"], providers)
        self.assertIs(options["allow_inline_only"], True)

    def test_contexts_share_normalization_but_not_boundary_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "child" / ".." / "state"
            first = composition.PluginCompositionDeploymentContext(path)
            second = analysis.PrivateAnalysisDeploymentContext(path)
            self.assertEqual(first.state_dir, second.state_dir)
            self.assertTrue(first.state_dir.is_absolute())
            self.assertNotEqual(type(first), type(second))
            for item in (first, second):
                self.assertEqual(
                    [f.name for f in dataclasses.fields(item)], ["state_dir"]
                )
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    item.state_dir = Path(directory)
            with self.assertRaises(TypeError):
                composition._detached_context(second)
            with self.assertRaises(TypeError):
                analysis._detached_context(first)

    def test_target_grammar_has_one_owner_and_preserves_admission(self) -> None:
        self.assertIs(composition._deployment_target, analysis._deployment_target)
        for target in ("package.module:factory", "package:_factory"):
            self.assertEqual(
                composition._deployment_target(target), tuple(target.split(":"))
            )
        for target in (
            "",
            " package:factory",
            "package:",
            ":factory",
            "x:y:z",
            "a-b:c",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                analysis._deployment_target(target)
        for target in (None, 5, Path("package")):
            with self.subTest(target=target), self.assertRaises(TypeError):
                composition._deployment_target(target)


class SharedValueTests(unittest.TestCase):
    def test_exact_integer_contract_does_not_become_wire_coercion(self) -> None:
        for value in (False, True, 1.0, "1", None, -1, 3):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "between 0 and 2"),
            ):
                require_bounded_integer(value, "count", minimum=0, maximum=2)
        for value in range(3):
            self.assertEqual(
                require_bounded_integer(value, "count", minimum=0, maximum=2), value
            )

    def test_cli_json_profile_round_trips_without_changing_hash_profiles(self) -> None:
        from router_dump_analyzer.maintenance_cli import _encode_document as maintenance
        from router_dump_analyzer.pipeline_cli import _encode_document as pipeline

        self.assertIs(maintenance, pipeline)
        self.assertIs(maintenance, canonical.encode_ascii_json_document)
        document = {"z": "中文", "a": [1, True, None]}
        for pretty in (False, True):
            encoded = pipeline(document, pretty=pretty)
            self.assertTrue(encoded.isascii())
            self.assertEqual(json.loads(encoded), document)
            with self.assertRaises(ValueError):
                maintenance({"value": float("nan")}, pretty=pretty)
        self.assertEqual(canonical.canonical_json({"v": "é"}), '{"v":"\\u00e9"}')
        self.assertEqual(canonical.strict_canonical_json({"v": "é"}), '{"v":"é"}')

    def test_temporal_adapters_share_half_open_predicate(self) -> None:
        self.assertIs(normalized_data.overlaps_range, temporal_core.overlaps_range)
        self.assertIs(revision_queries._overlaps_window, temporal_core.overlaps_range)
        self.assertFalse(normalized_data.overlaps_range("0", "10", 10, 20))
        self.assertTrue(revision_queries._overlaps_window(None, None, 10, 20))

    def test_materialization_projection_versions_share_producer_contract(self) -> None:
        from router_dump_analyzer import consistency_materialization as consistency
        from router_dump_analyzer import (
            relationship_projection_materialization as relationships,
        )

        self.assertEqual(
            consistency.CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION,
            CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            normalized_data._CLIENT_CONSISTENCY_MATERIALIZATION_SCHEMA,
            CONSISTENCY_MATERIALIZATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            relationships.RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION,
            RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION,
        )
        self.assertEqual(
            normalized_data._CLIENT_RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA,
            RELATIONSHIP_PROJECTION_MATERIALIZATION_SCHEMA_VERSION,
        )


class SharedAuthorizationTests(unittest.TestCase):
    def test_telemetry_is_derived_from_the_exact_authorization_vocabulary(self) -> None:
        self.assertIs(
            control_plane_api.ControlPlaneAccessPhase, ControlPlaneAccessPhase
        )
        self.assertIs(
            control_plane_api.ControlPlaneAccessReason, ControlPlaneAccessReason
        )
        self.assertIs(
            control_plane_api._ACCESS_DENIAL_REASONS_BY_PHASE,
            ACCESS_DENIAL_REASONS_BY_PHASE,
        )
        self.assertIs(operational_logging._ACCESS_DENIAL_ROLES, CONTROL_PLANE_ROLES)
        self.assertIs(
            operational_logging._ACCESS_DENIAL_PHASE_REASON, ACCESS_DENIAL_WIRE_REASONS
        )
        self.assertEqual(
            set(ACCESS_DENIAL_REASONS_BY_PHASE), set(ControlPlaneAccessPhase)
        )
        self.assertEqual(
            set().union(*ACCESS_DENIAL_REASONS_BY_PHASE.values()),
            set(ControlPlaneAccessReason),
        )
        for phase, reasons in ACCESS_DENIAL_REASONS_BY_PHASE.items():
            self.assertEqual(
                ACCESS_DENIAL_WIRE_REASONS[phase.value],
                {reason.value for reason in reasons},
            )

    @staticmethod
    def _request(project_id: str, roles: frozenset[str]) -> Request:
        identity = control_plane_api.ControlPlaneIdentity(
            tenant_id="tenant",
            principal_id="reader",
            roles=roles,
        )
        return Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "server": ("localhost", 80),
                "path": f"/v1/control-plane/projects/{project_id}/workspaces",
                "query_string": b"",
                "headers": [(b"x-tenant-id", b"tenant")],
                "path_params": {"project_id": project_id},
                "app": SimpleNamespace(
                    state=SimpleNamespace(
                        control_plane_identity_resolver=lambda request: identity,
                    )
                ),
            }
        )

    def test_catalog_ids_cannot_change_roles_and_explicit_admin_remains_required(
        self,
    ) -> None:
        for project_id in ("ordinary", "retention"):
            request = self._request(project_id, frozenset({CONTROL_PLANE_READ_ROLE}))
            self.assertEqual(
                control_plane_api._resolved_identity(request).principal_id, "reader"
            )
            with self.assertRaises(
                control_plane_api._ControlPlaneAccessDenied
            ) as caught:
                control_plane_api._require_control_plane_admin(request)
            self.assertEqual(caught.exception.status_code, 403)
            self.assertEqual(caught.exception.required_role, CONTROL_PLANE_ADMIN_ROLE)
        request = self._request("retention", frozenset({CONTROL_PLANE_ADMIN_ROLE}))
        self.assertEqual(
            control_plane_api._require_control_plane_admin(request).principal_id,
            "reader",
        )


if __name__ == "__main__":
    unittest.main()
