from __future__ import annotations

import unittest
from types import SimpleNamespace

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from router_dump_analyzer.session_store import SqliteSessionStore
from router_dump_analyzer.web.control_plane_api import (
    CONTROL_PLANE_ADMIN_ROLE,
    CONTROL_PLANE_INSTANCE_OPERATOR_ROLE,
    CONTROL_PLANE_READ_ROLE,
    CONTROL_PLANE_WRITE_ROLE,
    ControlPlaneIdentity,
    TrustedHeaderIdentityResolver,
    control_plane_router,
)


class ManagementContextTests(unittest.TestCase):
    """Exercise management bootstrap without workers or a network listener."""

    def setUp(self) -> None:
        self.sessions = SqliteSessionStore(":memory:")
        self.application = FastAPI()
        self.application.include_router(control_plane_router)
        self.application.state.control_plane = SimpleNamespace(
            sessions=self.sessions,
            state_root="PRIVATE-STATE-ROOT",
            configuration={"secret": "PRIVATE-CONFIGURATION-SECRET"},
        )
        self.client = self.enterContext(TestClient(self.application))
        self.addCleanup(self.sessions.close)
        self.headers = {
            "X-Tenant-ID": "tenant-a",
            "X-Principal-ID": "principal-a",
        }

    def _install_identity(
        self,
        roles: frozenset[str],
        *,
        project_ids: frozenset[str] | None = None,
    ) -> None:
        identity = ControlPlaneIdentity(
            tenant_id="tenant-a",
            principal_id="principal-a",
            roles=roles,
            project_ids=project_ids,
        )

        def deployment_identity(_request: Request) -> ControlPlaneIdentity:
            return identity

        self.application.state.control_plane_identity_resolver = deployment_identity

    def test_management_capabilities_require_the_exact_independent_roles(self) -> None:
        cases = (
            (frozenset(), False, False, False),
            (frozenset({CONTROL_PLANE_ADMIN_ROLE}), True, False, False),
            (frozenset({CONTROL_PLANE_WRITE_ROLE}), False, True, False),
            (frozenset({CONTROL_PLANE_INSTANCE_OPERATOR_ROLE}), False, False, True),
            (
                frozenset({CONTROL_PLANE_ADMIN_ROLE, CONTROL_PLANE_WRITE_ROLE}),
                True,
                True,
                False,
            ),
            (
                frozenset(
                    {CONTROL_PLANE_ADMIN_ROLE, CONTROL_PLANE_INSTANCE_OPERATOR_ROLE}
                ),
                True,
                False,
                True,
            ),
            (
                frozenset({CONTROL_PLANE_INSTANCE_OPERATOR_ROLE + ".extra"}),
                False,
                False,
                False,
            ),
        )
        for roles, can_admin, can_write, can_instance_operator in cases:
            with self.subTest(roles=roles):
                self._install_identity(roles | {CONTROL_PLANE_READ_ROLE})
                response = self.client.get(
                    "/v1/control-plane/context", headers=self.headers
                )
                self.assertEqual(response.status_code, 200, response.text)
                payload = response.json()
                self.assertIs(payload["can_admin"], can_admin)
                self.assertIs(payload["can_write"], can_write)
                self.assertIs(payload["can_instance_operator"], can_instance_operator)
                self.assertEqual(payload["identity_mode"], "deployment")

    def test_trusted_header_operator_grant_still_requires_explicit_opt_in(self) -> None:
        for grant_operator in (False, True):
            with self.subTest(grant_operator=grant_operator):
                self.application.state.control_plane_identity_resolver = (
                    TrustedHeaderIdentityResolver(
                        allowed_hosts=("testserver",),
                        grant_instance_operator=grant_operator,
                    )
                )
                response = self.client.get(
                    "/v1/control-plane/context", headers=self.headers
                )
                self.assertEqual(response.status_code, 200, response.text)
                payload = response.json()
                self.assertEqual(payload["identity_mode"], "trusted_headers")
                self.assertIs(payload["can_instance_operator"], grant_operator)
                self.assertIs(payload["can_admin"], True)

    def test_custom_resolver_profile_does_not_claim_the_builtin_adapter(self) -> None:
        class DeploymentResolver(TrustedHeaderIdentityResolver):
            pass

        self.application.state.control_plane_identity_resolver = DeploymentResolver(
            allowed_hosts=("testserver",)
        )
        response = self.client.get("/v1/control-plane/context", headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["identity_mode"], "deployment")

    def test_summary_is_closed_read_only_and_keeps_project_visibility(self) -> None:
        for tenant_id, project_id in (
            ("tenant-a", "project-visible"),
            ("tenant-a", "project-hidden"),
            ("tenant-hidden", "project-other-tenant"),
        ):
            self.sessions.create_project(tenant_id, project_id, project_id=project_id)
        self._install_identity(
            frozenset({CONTROL_PLANE_READ_ROLE}),
            project_ids=frozenset({"project-visible"}),
        )
        response = self.client.get(
            "/v1/control-plane/context",
            headers={
                **self.headers,
                "X-Identity-Mode": "trusted_headers",
                "X-Role": CONTROL_PLANE_INSTANCE_OPERATOR_ROLE,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(
            set(payload),
            {
                "enabled",
                "tenant_id",
                "principal_id",
                "can_admin",
                "can_write",
                "can_instance_operator",
                "identity_mode",
                "configuration",
                "limit",
                "offset",
                "next_offset",
                "projects",
            },
        )
        self.assertIs(payload["enabled"], True)
        self.assertEqual(
            payload["configuration"], {"owner": "deployment", "editable": False}
        )
        self.assertEqual(payload["identity_mode"], "deployment")
        self.assertIs(payload["can_instance_operator"], False)
        self.assertEqual(
            [project["project_id"] for project in payload["projects"]],
            ["project-visible"],
        )
        for private_value in (
            "PRIVATE-STATE-ROOT",
            "PRIVATE-CONFIGURATION-SECRET",
            "tenant-hidden",
            "project-hidden",
            "project-other-tenant",
        ):
            self.assertNotIn(private_value, response.text)

    def test_management_context_does_not_imply_read_access(self) -> None:
        for role in (CONTROL_PLANE_ADMIN_ROLE, CONTROL_PLANE_INSTANCE_OPERATOR_ROLE):
            with self.subTest(role=role):
                self._install_identity(frozenset({role}))
                response = self.client.get(
                    "/v1/control-plane/context", headers=self.headers
                )
                self.assertEqual(response.status_code, 403, response.text)
                self.assertNotIn("configuration", response.json())

    def test_context_keeps_identity_and_configuration_failures_closed(self) -> None:
        self._install_identity(frozenset({CONTROL_PLANE_READ_ROLE}))
        response = self.client.get(
            "/v1/control-plane/context", headers={"X-Tenant-ID": "tenant-wrong"}
        )
        self.assertEqual(response.status_code, 403, response.text)
        self.application.state.control_plane_identity_resolver = None
        response = self.client.get("/v1/control-plane/context", headers=self.headers)
        self.assertEqual(response.status_code, 503, response.text)
        self._install_identity(frozenset({CONTROL_PLANE_READ_ROLE}))
        self.application.state.control_plane = None
        response = self.client.get("/v1/control-plane/context", headers=self.headers)
        self.assertEqual(response.status_code, 503, response.text)
        self.assertNotIn("configuration", response.json())
