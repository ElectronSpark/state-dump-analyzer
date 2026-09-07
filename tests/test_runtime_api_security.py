from __future__ import annotations

import ast
import inspect
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException as StarletteHTTPException

from router_dump_analyzer import revision_queries
from router_dump_analyzer.multi_node_topology import MultiNodeTopologyRequestError
from router_dump_analyzer.temporal_topology import TemporalTopologyRequestError
from router_dump_analyzer.web import runtime_api
from tests.support.generated_demo import (
    configure_generated_demo_for_tests,
    generated_demo_application,
)

configure_generated_demo_for_tests()


PRIVATE_RUNTIME_FAILURE = (
    "sqlite3.OperationalError at C:/srv/private/tenant-a/reviews.sqlite3"
)


class RuntimeApiErrorPolicyTests(unittest.TestCase):
    def test_body_integer_domains_are_structurally_explicit(self) -> None:
        parameters = inspect.signature(runtime_api._body_integer).parameters
        self.assertIs(parameters["minimum"].default, inspect.Parameter.empty)
        self.assertIs(parameters["maximum"].default, inspect.Parameter.empty)

        syntax = ast.parse(inspect.getsource(runtime_api))
        missing_bounds: list[int] = []
        misplaced_time_fields: list[tuple[int, str]] = []
        for node in ast.walk(syntax):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_body_integer"
            ):
                continue
            keyword_names = {item.arg for item in node.keywords}
            if not {"minimum", "maximum"}.issubset(keyword_names):
                missing_bounds.append(node.lineno)
            if (
                len(node.args) > 1
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
                and node.args[1].value.endswith("_ns")
                and node.args[1].value != "cluster_window_ns"
            ):
                misplaced_time_fields.append((node.lineno, node.args[1].value))

        self.assertEqual(missing_bounds, [])
        self.assertEqual(misplaced_time_fields, [])

    def test_adapter_owned_details_use_the_shared_public_text_policy(self) -> None:
        self.assertFalse(hasattr(runtime_api, "HTTPException"))

        safe = runtime_api._RuntimeHTTPResponse(
            status_code=422,
            detail="known request field is invalid",
        )
        self.assertEqual(safe.detail, "known request field is invalid")

        unsafe = runtime_api._RuntimeHTTPResponse(
            status_code=422,
            detail="private\u202e/srv/tenant/runtime.sqlite3",
        )
        self.assertEqual(unsafe.detail, "analysis request was rejected")

    def test_policy_is_exact_exhaustive_and_mro_order_independent(self) -> None:
        expected = {
            "MultiNodeRouteRequestError": 422,
            "MultiNodeTopologyRequestError": 422,
            "RevisionQueryRequestError": 422,
            "SourceRecordRequestError": 422,
            "TemporalTopologyRequestError": 422,
            "TimeoutError": 504,
            "TypeError": 500,
            "ValueError": 500,
        }
        self.assertEqual(
            {
                error_type.__name__: policy.status_code
                for error_type, policy in (
                    runtime_api._RUNTIME_API_ERROR_POLICY_BY_CLASS.items()
                )
            },
            expected,
        )

        production_request_errors: set[type[Exception]] = set()
        pending = list(runtime_api._RUNTIME_API_REQUEST_ERROR_ROOTS)
        while pending:
            error_type = pending.pop()
            if error_type in production_request_errors:
                continue
            production_request_errors.add(error_type)
            pending.extend(
                subclass
                for subclass in error_type.__subclasses__()
                if subclass.__module__.startswith("router_dump_analyzer.")
            )
        self.assertLessEqual(
            production_request_errors,
            set(runtime_api._RUNTIME_API_ERROR_POLICY_BY_CLASS),
        )

        for (
            error_type,
            policy,
        ) in runtime_api._RUNTIME_API_ERROR_POLICY_BY_CLASS.items():
            with self.subTest(error_type=error_type.__name__):
                declared_message = (
                    "invalid caller-owned request field"
                    if policy.expose_message
                    else PRIVATE_RUNTIME_FAILURE
                )
                error = error_type(declared_message)
                self.assertIs(runtime_api._runtime_api_error_policy(error), policy)
                with self.assertRaises(HTTPException) as raised:
                    runtime_api._raise_runtime_api_error(error)
                self.assertEqual(raised.exception.status_code, policy.status_code)
                if policy.expose_message:
                    self.assertEqual(
                        raised.exception.detail,
                        declared_message,
                    )
                else:
                    self.assertNotIn(
                        PRIVATE_RUNTIME_FAILURE,
                        str(raised.exception.detail),
                    )

    def test_message_exposure_is_exact_class_bounded_and_unicode_safe(self) -> None:
        class UndeclaredTemporalError(TemporalTopologyRequestError):
            pass

        unsafe = ("\n", "\u0085", "\u2028", "\u202e", "\U000e0061")
        for character in unsafe:
            error = TemporalTopologyRequestError(f"bad{character}request")
            with self.subTest(codepoint=f"U+{ord(character):04X}"):
                with self.assertRaises(HTTPException) as raised:
                    runtime_api._raise_runtime_api_error(error)
                self.assertEqual(
                    raised.exception.detail,
                    "temporal topology request was rejected",
                )

        for error in (
            TemporalTopologyRequestError("x" * 1_025),
            TemporalTopologyRequestError(PRIVATE_RUNTIME_FAILURE),
            TemporalTopologyRequestError(
                'invalid state at "C:/srv/private/tenant/reviews.sqlite3"'
            ),
            TemporalTopologyRequestError("path=/srv/private/tenant/reviews.sqlite3"),
            TemporalTopologyRequestError(r"path=%APPDATA%\router-dump\reviews.sqlite3"),
            TemporalTopologyRequestError(
                r"path=$env:LOCALAPPDATA\router-dump\reviews.sqlite3"
            ),
            TemporalTopologyRequestError("path=$HOME/.local/state/router-dump"),
            TemporalTopologyRequestError("path=${XDG_STATE_HOME}/router-dump"),
            TemporalTopologyRequestError("path=~/.local/state/router-dump"),
            UndeclaredTemporalError("undeclared public detail"),
        ):
            with self.assertRaises(HTTPException) as raised:
                runtime_api._raise_runtime_api_error(error)
            self.assertEqual(
                raised.exception.detail,
                "temporal topology request was rejected",
            )

        ipv6_detail = "invalid topology prefix 2001:db8::/64"
        with self.assertRaises(HTTPException) as raised_ipv6:
            runtime_api._raise_runtime_api_error(
                TemporalTopologyRequestError(ipv6_detail)
            )
        self.assertEqual(raised_ipv6.exception.detail, ipv6_detail)

        service_http_error = HTTPException(
            status_code=418,
            detail='private "C:/srv/tenant/runtime.sqlite3"\u202e',
        )
        with self.assertRaises(HTTPException) as raised_service_error:
            runtime_api._raise_runtime_api_error(service_http_error)
        self.assertEqual(raised_service_error.exception.status_code, 500)
        self.assertEqual(
            raised_service_error.exception.detail,
            "internal analysis operation failed",
        )

        unknown = RuntimeError("undeclared")
        with self.assertRaises(RuntimeError) as raised_unknown:
            runtime_api._raise_runtime_api_error(unknown)
        self.assertIs(raised_unknown.exception, unknown)

    def test_message_exposure_projects_display_ambiguity_instead_of_hiding_text(
        self,
    ) -> None:
        detail = (
            "emoji \u26a0\ufe0f \u2764\ufe0f \u2139\ufe0f "
            "\U0001f3f3\ufe0f\u200d\U0001f308; Mongolian \u1820\u180b; "
            "CGJ \u034f; PUA \ue000; object \ufffc"
        )
        with self.assertRaises(HTTPException) as raised:
            runtime_api._raise_runtime_api_error(TemporalTopologyRequestError(detail))
        self.assertEqual(
            raised.exception.detail,
            "emoji \u26a0\ufe0f \u2764\ufe0f \u2139\ufe0f "
            "\U0001f3f3\ufe0f\u200d\U0001f308; Mongolian \u1820\\u180b; "
            "CGJ \\u034f; PUA \\ue000; object \\ufffc",
        )
        for sequence in (
            "\u26a0\ufe0f",
            "\u2764\ufe0f",
            "\u2139\ufe0f",
            "\U0001f3f3\ufe0f\u200d\U0001f308",
        ):
            self.assertIn(sequence, raised.exception.detail)
        for character in ("\u180b", "\u034f", "\ue000", "\ufffc"):
            self.assertNotIn(character, raised.exception.detail)


class RuntimeApiLiveBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(generated_demo_application())
        cls.client = cls.client_context.__enter__()
        workspace = cls.client.get("/v1/nodes/node-a/workspace")
        if workspace.status_code != 200:
            raise AssertionError(workspace.text)
        cls.workspace = workspace.json()
        cls.revision_id = cls.workspace["demo"]["revision_id"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def test_internal_value_error_path_and_invisibles_are_redacted_live(self) -> None:
        unsafe_characters = "\u202e\u0085\u2028\U000e0061"
        failure = f"{PRIVATE_RUNTIME_FAILURE}{unsafe_characters}"

        def assert_redacted(response: object) -> None:
            self.assertEqual(response.status_code, 500, response.text)
            self.assertEqual(
                response.json(),
                {"detail": "internal analysis operation failed"},
            )
            self.assertNotIn(PRIVATE_RUNTIME_FAILURE, response.text)
            for character in unsafe_characters:
                self.assertNotIn(character, response.text)

        with patch.object(
            runtime_api,
            "resources_at",
            side_effect=ValueError(failure),
        ):
            assert_redacted(
                self.client.get(f"/v1/revisions/{self.revision_id}/resources/at")
            )
            assert_redacted(
                self.client.post(
                    f"/v1/revisions/{self.revision_id}/resources/query",
                    json={},
                )
            )

        with patch.object(
            runtime_api,
            "query_source_records",
            side_effect=ValueError(failure),
        ):
            assert_redacted(
                self.client.post(
                    f"/v1/revisions/{self.revision_id}/source-records/query",
                    json={},
                )
            )

        def reject(*_args: object, **_kwargs: object) -> None:
            raise ValueError(failure)

        temporal_service = SimpleNamespace(
            query=reject,
            query_changes=reject,
        )
        with patch.object(
            runtime_api,
            "_temporal_topology",
            return_value=temporal_service,
        ):
            for suffix in ("topology/query", "topology/changes/query"):
                assert_redacted(
                    self.client.post(
                        f"/v1/revisions/{self.revision_id}/{suffix}",
                        json={},
                    )
                )

        with patch.object(
            revision_queries,
            "record_lanes_for_window",
            side_effect=ValueError(failure),
        ):
            assert_redacted(
                self.client.post(
                    f"/v1/revisions/{self.revision_id}/timeline/query",
                    json={
                        "start_ns": self.workspace["demo"]["timeline_start_ns"],
                        "end_ns": self.workspace["demo"]["timeline_end_ns"],
                    },
                )
            )

    def test_explicit_request_error_with_invisibles_uses_safe_fallback_live(
        self,
    ) -> None:
        unsafe_characters = "\u202e\u0085\u2028\U000e0061"
        unsafe = f"bad{unsafe_characters}request"

        def reject(_body: object) -> None:
            raise MultiNodeTopologyRequestError(unsafe)

        service = SimpleNamespace(query=reject)
        with patch.object(runtime_api, "_multi_node_topology", return_value=service):
            response = self.client.post("/v1/topologies/query", json={})

        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(
            response.json(),
            {"detail": "topology request was rejected"},
        )
        for character in unsafe_characters:
            self.assertNotIn(character, response.text)

    def test_explicit_request_error_projects_display_ambiguity_live(self) -> None:
        detail = (
            "emoji \u26a0\ufe0f \u2764\ufe0f \u2139\ufe0f "
            "\U0001f3f3\ufe0f\u200d\U0001f308; Mongolian \u1820\u180b; PUA \ue000"
        )

        def reject(_body: object) -> None:
            raise MultiNodeTopologyRequestError(detail)

        service = SimpleNamespace(query=reject)
        with patch.object(runtime_api, "_multi_node_topology", return_value=service):
            response = self.client.post("/v1/topologies/query", json={})

        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(
            response.json(),
            {
                "detail": (
                    "emoji \u26a0\ufe0f \u2764\ufe0f \u2139\ufe0f "
                    "\U0001f3f3\ufe0f\u200d\U0001f308; "
                    "Mongolian \u1820\\u180b; PUA \\ue000"
                )
            },
        )
        for sequence in (
            "\u26a0\ufe0f",
            "\u2764\ufe0f",
            "\u2139\ufe0f",
            "\U0001f3f3\ufe0f\u200d\U0001f308",
        ):
            self.assertIn(sequence, response.json()["detail"])
        for character in ("\u180b", "\ue000"):
            self.assertNotIn(character, response.text)

    def test_service_http_exception_is_not_treated_as_endpoint_validation(
        self,
    ) -> None:
        failure = HTTPException(
            status_code=418,
            detail='private "C:/srv/tenant/runtime.sqlite3"\u202e',
        )

        def reject(_body: object) -> None:
            raise failure

        service = SimpleNamespace(query=reject)
        with patch.object(runtime_api, "_multi_node_topology", return_value=service):
            response = self.client.post("/v1/topologies/query", json={})

        self.assertEqual(response.status_code, 500, response.text)
        self.assertEqual(
            response.json(),
            {"detail": "internal analysis operation failed"},
        )
        self.assertNotIn("/srv/tenant", response.text)
        self.assertNotIn("\u202e", response.text)

    def test_framework_validation_is_bounded_without_flattening_adapter_4xx(
        self,
    ) -> None:
        validation = self.client.get(
            "/v1/nodes/node-a/workspace",
            params={"time_ns": "not-an-integer\u202e/srv/private"},
        )
        self.assertEqual(validation.status_code, 422, validation.text)
        self.assertEqual(
            validation.json(),
            {"detail": "request validation failed"},
        )
        self.assertNotIn("not-an-integer", validation.text)
        self.assertNotIn("/srv/private", validation.text)
        self.assertNotIn("\u202e", validation.text)

        adapter_validation = self.client.post(
            f"/v1/revisions/{self.revision_id}/timeline/query",
            json={"start_ns": "not-an-integer", "end_ns": "0"},
        )
        self.assertEqual(adapter_validation.status_code, 422, adapter_validation.text)
        self.assertEqual(
            adapter_validation.json()["detail"],
            "start_ns must be an integer or decimal integer string",
        )

    def test_route_fence_covers_provider_acquisition_and_dependencies(self) -> None:
        failure_detail = 'private "C:/srv/tenant/runtime.sqlite3"\u202e'
        cases = (
            ("_multi_node_topology", "/v1/topologies/query", {}),
            ("_multi_node_route", "/v1/topologies/routes/trace", {}),
            (
                "_temporal_topology",
                f"/v1/revisions/{self.revision_id}/topology/query",
                {},
            ),
            (
                "load_dataset",
                f"/v1/revisions/{self.revision_id}/resources",
                None,
            ),
            (
                "_require_revision",
                f"/v1/revisions/{self.revision_id}/resources",
                None,
            ),
        )
        for error_type in (HTTPException, StarletteHTTPException):
            for target, path, body in cases:
                with self.subTest(
                    error_type=error_type.__module__,
                    target=target,
                    path=path,
                ):
                    failure = error_type(
                        status_code=418,
                        detail=failure_detail,
                    )
                    with patch.object(runtime_api, target, side_effect=failure):
                        response = (
                            self.client.post(path, json=body)
                            if body is not None
                            else self.client.get(path)
                        )
                    self.assertEqual(response.status_code, 500, response.text)
                    self.assertEqual(
                        response.json(),
                        {"detail": "internal analysis operation failed"},
                    )
                    self.assertNotIn("/srv/tenant", response.text)
                    self.assertNotIn("\u202e", response.text)

    def test_runtime_nanosecond_inputs_match_signed_64_bit_core_bounds(self) -> None:
        oversized = str(10**30)
        timeline = self.client.post(
            f"/v1/revisions/{self.revision_id}/timeline/query",
            json={"start_ns": oversized, "end_ns": oversized},
        )
        self.assertEqual(timeline.status_code, 422, timeline.text)
        self.assertEqual(
            timeline.json()["detail"],
            f"start_ns must be at most {(1 << 63) - 1}",
        )

        workspace = self.client.get(
            "/v1/nodes/node-a/workspace",
            params={"basis_kind": "absolute_time", "time_ns": oversized},
        )
        self.assertEqual(workspace.status_code, 422, workspace.text)

        source_records = self.client.post(
            f"/v1/revisions/{self.revision_id}/source-records/query",
            json={"start_ns": oversized},
        )
        self.assertEqual(source_records.status_code, 422, source_records.text)
        self.assertEqual(
            source_records.json()["detail"],
            f"start_ns must be no greater than {(1 << 63) - 1}",
        )

    def test_browser_visible_runtime_offsets_stay_json_exact(self) -> None:
        resource_response = self.client.get(
            f"/v1/revisions/{self.revision_id}/resources"
        )
        self.assertEqual(resource_response.status_code, 200, resource_response.text)
        resource_id = resource_response.json()["items"][0]["resource_id"]
        safe = runtime_api.MAX_JSON_SAFE_INTEGER
        unsafe = safe + 1

        accepted = (
            self.client.get(
                f"/v1/revisions/{self.revision_id}/resources/at",
                params={"offset": safe},
            ),
            self.client.post(
                f"/v1/revisions/{self.revision_id}/resources/query",
                json={"offset": safe},
            ),
            self.client.post(
                f"/v1/revisions/{self.revision_id}/timeline/clusters/detail",
                json={"resource_id": resource_id, "offset": safe},
            ),
        )
        for response in accepted:
            with self.subTest(endpoint=response.request.url.path):
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()["offset"], safe)

        rejected = (
            self.client.get(
                f"/v1/revisions/{self.revision_id}/resources/at",
                params={"offset": unsafe},
            ),
            self.client.post(
                f"/v1/revisions/{self.revision_id}/resources/query",
                json={"offset": unsafe},
            ),
            self.client.post(
                f"/v1/revisions/{self.revision_id}/timeline/clusters/detail",
                json={"resource_id": resource_id, "offset": unsafe},
            ),
        )
        for response in rejected:
            with self.subTest(endpoint=response.request.url.path):
                self.assertEqual(response.status_code, 422, response.text)
                self.assertNotIn(str(unsafe), response.text)

    def test_every_temporal_topology_and_route_alias_rejects_out_of_range_basis(
        self,
    ) -> None:
        assembly_id = self.workspace["demo"]["assembly_id"]
        oversized = str(10**30)
        undersized = str(-(10**30))
        ordinary_bodies = (
            (f"/v1/revisions/{self.revision_id}/topology/query", {}),
            (f"/v1/revisions/{self.revision_id}/state/query", {}),
            (
                f"/v1/revisions/{self.revision_id}/resources/status/query",
                {},
            ),
            ("/v1/topologies/query", {}),
            ("/v1/topologies/reconstruct", {}),
            (f"/v1/topology-assemblies/{assembly_id}/query", {}),
            (f"/v1/revisions/{self.revision_id}/multi-node/query", {}),
            ("/v1/topologies/nodes/node-a/query", {}),
            ("/v1/topologies/routes/tables/query", {"page": {"limit": 1}}),
            (
                f"/v1/topology-assemblies/{assembly_id}/routes/tables/query",
                {"page": {"limit": 1}},
            ),
            (
                "/v1/topologies/routes/trace",
                {"scenario_id": "recursive-resolution-cycle"},
            ),
            (
                f"/v1/topology-assemblies/{assembly_id}/routes/trace",
                {"scenario_id": "recursive-resolution-cycle"},
            ),
        )
        for label, basis in (
            (
                "absolute",
                {
                    "kind": "absolute_time",
                    "clock_domain": "utc",
                    "time_ns": oversized,
                },
            ),
            (
                "relative",
                {
                    "kind": "relative_to_watermark",
                    "offset_ns": undersized,
                },
            ),
        ):
            for path, extra in ordinary_bodies:
                with self.subTest(label=label, path=path):
                    response = self.client.post(
                        path,
                        json={**extra, "basis": basis},
                    )
                    self.assertEqual(response.status_code, 422, response.text)

        changes = self.client.post(
            f"/v1/revisions/{self.revision_id}/topology/changes/query",
            json={
                "start_basis": {
                    "kind": "absolute_time",
                    "clock_domain": "utc",
                    "time_ns": str(10**30 - 1),
                },
                "end_basis": {
                    "kind": "absolute_time",
                    "clock_domain": "utc",
                    "time_ns": oversized,
                },
            },
        )
        self.assertEqual(changes.status_code, 422, changes.text)

    def test_clock_mapping_cannot_overflow_signed_64_coordinates(self) -> None:
        for boundary in (str((1 << 63) - 1), str(-(1 << 63))):
            with self.subTest(boundary=boundary):
                response = self.client.post(
                    f"/v1/revisions/{self.revision_id}/topology/query",
                    json={
                        "basis": {
                            "kind": "absolute_time",
                            "clock_domain": "utc",
                            "time_ns": boundary,
                        }
                    },
                )
                self.assertEqual(response.status_code, 422, response.text)


if __name__ == "__main__":
    unittest.main()
