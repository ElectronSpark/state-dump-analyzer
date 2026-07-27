from __future__ import annotations

import ast
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from tests.support.generated_demo import (
    configure_generated_demo_for_tests,
    generated_demo_application,
    query_all_route_table_rows,
)

import generator as generated_fixture
from generator import COVERAGE_CASES, DEMO_NODES


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = (
    ROOT / "src",
    ROOT / "demo" / "plugin",
    ROOT / "demo" / "generator",
)
GENERATOR_ROOT = Path(generated_fixture.__file__).resolve().parent


def _assigned_names(statement: ast.Assign | ast.AnnAssign) -> set[str]:
    targets = statement.targets if isinstance(statement, ast.Assign) else [
        statement.target
    ]
    return {
        target.id
        for target in targets
        if isinstance(target, ast.Name)
    }


def _literal_strings(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Constant)
        and isinstance(item.value, str)
    }


def _immediate_literal_strings(node: ast.AST | None) -> set[str]:
    if isinstance(node, ast.Dict):
        values = node.keys
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = node.elts
    else:
        return set()
    return {
        item.value
        for item in values
        if isinstance(item, ast.Constant)
        and isinstance(item.value, str)
    }


def _nongenerator_source_trees() -> list[tuple[Path, ast.Module]]:
    sources: list[tuple[Path, ast.Module]] = []
    for package_root in SOURCE_ROOTS:
        for source_path in package_root.rglob("*.py"):
            resolved = source_path.resolve()
            generator_root = GENERATOR_ROOT.resolve()
            if (
                generator_root == resolved.parent
                or generator_root in resolved.parents
            ):
                continue
            sources.append(
                (
                    source_path,
                    ast.parse(
                        source_path.read_text(encoding="utf-8"),
                        filename=str(source_path),
                    ),
                )
            )
    return sources


class RouteGeometryOwnershipTests(unittest.TestCase):
    def test_generator_is_the_only_routed_node_catalog_owner(self) -> None:
        routed_node_ids = {item.node_id for item in DEMO_NODES}
        duplicate_catalogs: list[str] = []

        for source_path, tree in _nongenerator_source_trees():
            for statement in tree.body:
                if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    continue
                value = statement.value
                names = _assigned_names(statement)
                immediate = (
                    _immediate_literal_strings(value) & routed_node_ids
                )
                recursively_named = set()
                if any(
                    token in name.upper()
                    for name in names
                    for token in ("NODE", "ROUTER", "UNDERLAY", "TOPOLOGY")
                ):
                    recursively_named = _literal_strings(value) & routed_node_ids
                if len(immediate | recursively_named) >= 2:
                    duplicate_catalogs.append(
                        f"{source_path.relative_to(ROOT)}:"
                        f"{statement.lineno}:{','.join(sorted(names))}"
                    )

        self.assertEqual(
            duplicate_catalogs,
            [],
            "routed-node catalogs must be generated fixture inputs only",
        )

    def test_runtime_does_not_construct_named_scenario_geometry(self) -> None:
        routed_node_ids = {item.node_id for item in DEMO_NODES}
        scenario_ids = {item.case_id for item in COVERAGE_CASES}
        source_trees = _nongenerator_source_trees()

        forbidden_advanced_helpers = {
            node.name
            for _source_path, tree in source_trees
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name
            in {"preferred_node_sequence", "forced_node_sequence"}
        }
        self.assertEqual(
            forbidden_advanced_helpers,
            set(),
            "advanced tracing owns packet actions, not route geometry",
        )

        literal_sequences: list[str] = []
        for source_path, tree in source_trees:
            for node in ast.walk(tree):
                if not isinstance(node, (ast.List, ast.Tuple)):
                    continue
                values = _immediate_literal_strings(node)
                if (
                    len(node.elts) >= 2
                    and len(values) == len(node.elts)
                    and values <= routed_node_ids
                ):
                    literal_sequences.append(
                        f"{source_path.relative_to(ROOT)}:{node.lineno}"
                    )
        self.assertEqual(
            literal_sequences,
            [],
            "runtime route geometry must not contain literal node sequences",
        )

        geometry_names = {
            "paths",
            "node_sequence",
            "candidate_paths",
        }
        scenario_geometry_branches: list[str] = []
        for source_path, tree in source_trees:
            for node in ast.walk(tree):
                if not isinstance(node, ast.If):
                    continue
                selector_names = {
                    item.id
                    for item in ast.walk(node.test)
                    if isinstance(item, ast.Name)
                }
                selector_literals = _literal_strings(node.test)
                named_selector = (
                    "scenario_id" in selector_names
                    and (
                        bool(selector_literals & scenario_ids)
                        or any(
                            "SCENARIO" in name.upper()
                            and "ID" in name.upper()
                            for name in selector_names
                        )
                    )
                )
                if not named_selector:
                    continue
                branch = ast.Module(
                    body=[*node.body, *node.orelse],
                    type_ignores=[],
                )
                mutates_geometry = any(
                    isinstance(item, ast.Name)
                    and isinstance(item.ctx, ast.Store)
                    and item.id in geometry_names
                    for item in ast.walk(branch)
                ) or any(
                    isinstance(item, ast.Subscript)
                    and isinstance(item.ctx, ast.Store)
                    and isinstance(item.slice, ast.Constant)
                    and item.slice.value == "node_sequence"
                    for item in ast.walk(branch)
                ) or any(
                    isinstance(item, ast.Call)
                    and isinstance(item.func, ast.Attribute)
                    and isinstance(item.func.value, ast.Name)
                    and item.func.value.id
                    in {"paths", "candidate_paths"}
                    and item.func.attr in {"append", "extend", "insert"}
                    for item in ast.walk(branch)
                )
                if mutates_geometry:
                    scenario_geometry_branches.append(
                        f"{source_path.relative_to(ROOT)}:{node.lineno}"
                    )

        self.assertEqual(
            scenario_geometry_branches,
            [],
            "named scenario branches may select semantics but must not "
            "construct candidate geometry",
        )


class MultiNodeRouteRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configure_generated_demo_for_tests()
        cls.client_context = TestClient(generated_demo_application())
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def assert_candidate_geometry_comes_from_generated_projection(
        self,
        payload: dict,
    ) -> None:
        projection = payload["generated_projection"]
        self.assertIn(
            projection["source"],
            {
                "generated_plugin_projection",
                "generated_plugin_route_inventory",
            },
        )
        candidates = {
            item["candidate_id"]: item
            for item in projection["candidate_paths"]
        }
        self.assertEqual(len(candidates), len(projection["candidate_paths"]))

        rendered_candidate_ids: list[str] = []
        for path in payload["paths"]:
            candidate_id = path["generated_candidate_id"]
            rendered_candidate_ids.append(candidate_id)
            self.assertIn(candidate_id, candidates)
            candidate = candidates[candidate_id]
            self.assertEqual(
                path["generated_candidate_declaration"],
                candidate,
            )
            self.assertEqual(
                path["node_sequence"],
                candidate["node_sequence"],
            )
            self.assertEqual(path["primary"], candidate["primary"])
            self.assertEqual(
                path["alternative_state"],
                candidate["alternative_state"],
            )

        self.assertCountEqual(rendered_candidate_ids, candidates)

    def test_non_shortest_selected_route_row_action_is_executable(self) -> None:
        table = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "filters": {
                    "node_id": "node-c",
                    "vrf_id": "default",
                    "route_type": "mpls_transport",
                    "destination": {
                        "value": "destination:node-a",
                        "match": "exact",
                    },
                    "active": True,
                }
            },
        ).json()
        row = next(
            item
            for item in table["items"]
            if item["attributes"].get("scenario_id")
            == "site-a-site-c-asymmetric"
        )

        response = self.client.post(
            "/v1/topologies/routes/trace", json=row["trace_query"]
        )

        self.assertEqual(response.status_code, 200, response.text)
        trace = response.json()
        self.assertEqual(trace["direction"], "reverse")
        self.assertEqual(trace["focused_path_id"], row["path_id"])
        focused = next(
            item
            for item in trace["paths"]
            if item["path_id"] == row["path_id"]
        )
        self.assertEqual(
            focused["node_sequence"],
            ["node-c", "transit-p-2", "transit-p-1", "node-a"],
        )

    def test_asymmetric_counterpart_request_uses_opposite_context(self) -> None:
        forward = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "site-a-site-c-asymmetric",
                "direction": "forward",
            },
        ).json()

        counterpart = forward["counterpart_request"]
        self.assertEqual(counterpart["route_type"], "mpls_transport")
        self.assertEqual(counterpart["route_family"], "mpls_labeled_unicast")
        self.assertEqual(counterpart["vrf_id"], "default")
        response = self.client.post(
            "/v1/topologies/routes/trace", json=counterpart
        )
        self.assertEqual(response.status_code, 200, response.text)
        reverse = response.json()
        self.assertEqual(reverse["route_type"], counterpart["route_type"])
        self.assertEqual(reverse["route_family"], counterpart["route_family"])
        self.assertEqual(reverse["vrf_id"], counterpart["vrf_id"])
        self.assertTrue(reverse["consistency"]["consistent"])
        self.assertEqual(
            reverse["consistency"]["state"],
            "consistent_with_selected_observations",
        )
        self.assertEqual(reverse["consistency"]["issue_refs"], [])
        self.assertTrue(
            all(
                path["route_type"] == counterpart["route_type"]
                for path in reverse["paths"]
            )
        )

    def test_every_scenario_emits_an_executable_counterpart_request(self) -> None:
        capabilities = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        for scenario in capabilities["scenarios"]:
            with self.subTest(scenario_id=scenario["scenario_id"]):
                initial = self.client.post(
                    "/v1/topologies/routes/trace",
                    json={
                        "scenario_id": scenario["scenario_id"],
                        "direction": "forward",
                    },
                )
                self.assertEqual(initial.status_code, 200, initial.text)
                initial_payload = initial.json()
                self.assert_candidate_geometry_comes_from_generated_projection(
                    initial_payload
                )
                counterpart = initial_payload["counterpart_request"]
                response = self.client.post(
                    "/v1/topologies/routes/trace", json=counterpart
                )
                self.assertEqual(response.status_code, 200, response.text)
                payload = response.json()
                self.assert_candidate_geometry_comes_from_generated_projection(
                    payload
                )
                for field in (
                    "route_type",
                    "route_family",
                    "address_family",
                    "vrf_id",
                ):
                    self.assertEqual(payload[field], counterpart[field])

    def test_every_scenario_has_direction_correct_bidirectional_paths(self) -> None:
        scenarios = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()["scenarios"]
        for scenario in scenarios:
            with self.subTest(scenario_id=scenario["scenario_id"]):
                response = self.client.post(
                    "/v1/topologies/routes/trace",
                    json={
                        "scenario_id": scenario["scenario_id"],
                        "direction": "both",
                    },
                )
                self.assertEqual(response.status_code, 200, response.text)
                for trace in response.json()["traces"].values():
                    start_node_id = trace["trace_start"]["node_id"]
                    for path in trace["paths"]:
                        self.assertEqual(
                            path["node_sequence"][0],
                            start_node_id,
                        )

    def test_router_to_router_ui_defaults_are_router_endpoints(self) -> None:
        capabilities = self.client.get(
            "/v1/topologies/routes/capabilities"
        ).json()
        scenario = next(
            item
            for item in capabilities["scenarios"]
            if item["scenario_id"] == "router-to-router"
        )
        self.assertEqual(scenario["default_source"], "source:node-a")
        self.assertEqual(
            scenario["default_destination"],
            "destination:node-b",
        )
        source = next(
            item
            for item in capabilities["sources"]
            if item["source_id"] == scenario["default_source"]
        )
        destination = next(
            item
            for item in capabilities["destinations"]
            if item["destination_id"] == scenario["default_destination"]
        )
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": scenario["scenario_id"],
                "source_id": source["source_id"],
                "source": source,
                "destination_id": destination["destination_id"],
                "destination": destination,
                "vrf_id": scenario["vrf_id"],
                "route_family": scenario["route_family"],
                "route_type": scenario["route_type"],
            },
        )
        self.assertEqual(response.status_code, 200, response.text)

    def test_fixed_scenario_rejects_an_alternate_supported_route_type(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "evpn-mh-all-active",
                "route_type": "evpn_service",
                "route_family": "l2vpn_evpn",
                "vrf_id": "blue",
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_vrf_scope_is_enforced_on_both_endpoints(self) -> None:
        invalid_requests = [
            {
                "scenario_id": "router-to-router",
                "source_id": "source:node-a",
                "destination_id": "destination:node-b",
                "vrf_id": "red",
                "route_family": "vpnv4_unicast",
                "route_type": "mpls_l3vpn",
            },
            {
                "scenario_id": "router-to-router",
                "source_id": "source:transit-p-1",
                "destination_id": "destination:transit-p-2",
                "vrf_id": "management",
                "route_family": "ipv4_unicast",
                "route_type": "ipv4_unicast",
            },
        ]
        for body in invalid_requests:
            with self.subTest(body=body):
                response = self.client.post(
                    "/v1/topologies/routes/trace", json=body
                )
                self.assertEqual(response.status_code, 422, response.text)

        valid = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "router-to-router",
                "source_id": "source:node-d",
                "destination_id": "destination:node-e",
                "vrf_id": "red",
                "route_family": "vpnv4_unicast",
                "route_type": "mpls_l3vpn",
            },
        )
        self.assertEqual(valid.status_code, 200, valid.text)

    def test_fixed_destination_identity_and_shared_prefix_are_unambiguous(self) -> None:
        default = self.client.post(
            "/v1/topologies/routes/trace",
            json={"scenario_id": "single-active-primary"},
        )
        self.assertEqual(default.status_code, 200, default.text)
        self.assertEqual(
            default.json()["destination"]["destination_id"],
            "destination:blue-service-prefix",
        )
        self.assertEqual(default.json()["destination"]["kind"], "ip_prefix")

        invalid = [
            {
                "scenario_id": "single-active-primary",
                "destination_id": "destination:node-e",
            },
            {
                "scenario_id": "evpn-mh-all-active",
                "destination_id": "destination:node-b",
            },
            {
                "scenario_id": "recursive-static-to-external",
                "destination_id": "destination:node-b",
            },
            {
                "scenario_id": "router-to-router",
                "source_id": "source:node-a",
                "destination": "203.0.113.0/24",
            },
        ]
        for body in invalid:
            with self.subTest(body=body):
                response = self.client.post(
                    "/v1/topologies/routes/trace", json=body
                )
                self.assertEqual(response.status_code, 422, response.text)

        external = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "recursive-static-to-external",
                "destination": "203.0.113.0/24",
            },
        )
        self.assertEqual(external.status_code, 200, external.text)
        self.assertEqual(
            external.json()["destination"]["destination_id"],
            "destination:eta-external-subnet",
        )

    def test_cached_basis_comparison_uses_canonical_semantics(self) -> None:
        relative = self.client.post("/v1/topologies/query", json={}).json()
        time_ns = relative["nodes"][0]["resolved_time"]["query_time_ns"]
        topology = self.client.post(
            "/v1/topologies/query",
            json={
                "basis": {"kind": "absolute_time", "time_ns": time_ns}
            },
        ).json()
        equivalent_basis = {
            "kind": "absolute_time",
            "time_ns": time_ns,
            "clock_domain": "utc",
        }

        table = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "topology_context_id": topology["context_id"],
                "basis": equivalent_basis,
            },
        )
        trace = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "single-active-primary",
                "topology_context_id": topology["context_id"],
                "basis": equivalent_basis,
            },
        )
        self.assertEqual(table.status_code, 200, table.text)
        self.assertEqual(trace.status_code, 200, trace.text)

    def test_route_table_context_aliases_must_agree(self) -> None:
        first = self.client.post("/v1/topologies/query", json={}).json()
        second = self.client.post(
            "/v1/topologies/query",
            json={
                "basis": {
                    "kind": "relative_to_watermark",
                    "offset_ns": "-1",
                }
            },
        ).json()
        self.assertNotEqual(first["context_id"], second["context_id"])

        response = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "topology_context_id": first["context_id"],
                "context_id": second["context_id"],
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_cached_context_rejects_a_different_node_scope(self) -> None:
        topology = self.client.post("/v1/topologies/query", json={}).json()
        node_ids = [item["node_id"] for item in topology["nodes"]]

        matching_table = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "topology_context_id": topology["context_id"],
                "node_ids": node_ids,
            },
        )
        matching_trace = self.client.post(
            "/v1/topologies/routes/trace",
            json={
                "scenario_id": "single-active-primary",
                "topology_context_id": topology["context_id"],
                "node_ids": node_ids,
            },
        )
        self.assertEqual(matching_table.status_code, 200, matching_table.text)
        self.assertEqual(matching_trace.status_code, 200, matching_trace.text)

        for endpoint, extra in (
            ("/v1/topologies/routes/tables/query", {}),
            (
                "/v1/topologies/routes/trace",
                {"scenario_id": "single-active-primary"},
            ),
        ):
            with self.subTest(endpoint=endpoint):
                response = self.client.post(
                    endpoint,
                    json={
                        **extra,
                        "topology_context_id": topology["context_id"],
                        "node_ids": node_ids[:-1],
                    },
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertIn("node selection disagrees", response.text)

    def test_cached_context_rejects_a_different_projection_selection(self) -> None:
        topology = self.client.post(
            "/v1/topologies/query",
            json={"node_ids": ["node-a"]},
        ).json()
        cached = topology["nodes"][0]
        selected = [
            {
                "plugin_id": item["plugin_id"],
                "projection_id": item["projection_id"],
                "status_perspective_id": item["status_perspective_id"],
            }
            for item in cached["selected_plugins"]
        ]
        matching = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "topology_context_id": topology["context_id"],
                "node_queries": [
                    {
                        "node_id": "node-a",
                        "plugin_set_id": cached["plugin_set_id"],
                        "projections": selected,
                    }
                ],
            },
        )
        self.assertEqual(matching.status_code, 200, matching.text)

        differing_selection = [
            {
                **selected[0],
                "projection_id": (
                    f"{selected[0]['projection_id']}.different"
                ),
            }
        ]
        self.assertNotEqual(differing_selection, selected)
        response = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "topology_context_id": topology["context_id"],
                "node_queries": [
                    {
                        "node_id": "node-a",
                        "plugin_set_id": cached["plugin_set_id"],
                        "projections": differing_selection,
                    }
                ],
            },
        )
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("projection selection", response.text)

    def test_route_table_page_integers_are_strict(self) -> None:
        valid = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={"page": {"limit": "1", "offset": "0"}},
        )
        self.assertEqual(valid.status_code, 200, valid.text)
        self.assertEqual(valid.json()["page"]["limit"], 1)
        self.assertEqual(valid.json()["page"]["offset"], 0)

        invalid_pages = (
            {"limit": 1.5},
            {"limit": True},
            {"limit": "1.0"},
            {"limit": None},
            {"offset": 0.5},
            {"offset": False},
            {"offset": " 0"},
            {"offset": None},
        )
        for page in invalid_pages:
            with self.subTest(page=page):
                response = self.client.post(
                    "/v1/topologies/routes/tables/query",
                    json={"page": page},
                )
                self.assertEqual(response.status_code, 422, response.text)

    def test_route_table_cursor_is_bound_to_query_and_context(self) -> None:
        first = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "filters": {"route_type": "ipv4_unicast"},
                "page": {"limit": 1},
            },
        ).json()
        cursor = first["page"]["next_cursor"]
        self.assertTrue(cursor.startswith("rtcursor2-"))

        same_query = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "filters": {"route_type": "ipv4_unicast"},
                "page": {"limit": 1, "cursor": cursor},
            },
        )
        self.assertEqual(same_query.status_code, 200, same_query.text)

        changed_query = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={
                "filters": {"route_type": "mpls_transport"},
                "page": {"limit": 1, "cursor": cursor},
            },
        )
        self.assertEqual(changed_query.status_code, 422)

    def test_explicit_falsy_wrong_object_types_are_rejected(self) -> None:
        cases = [
            ("/v1/topologies/routes/tables/query", {"filters": []}),
            ("/v1/topologies/routes/tables/query", {"page": []}),
            ("/v1/topologies/routes/tables/query", {"basis": []}),
            ("/v1/topologies/routes/trace", {"routing_context": []}),
            (
                "/v1/topologies/routes/trace",
                {"direction": "both", "directional_routing_contexts": []},
            ),
            ("/v1/topologies/routes/trace", {"basis": []}),
        ]
        for endpoint, body in cases:
            with self.subTest(endpoint=endpoint, body=body):
                response = self.client.post(endpoint, json=body)
                self.assertEqual(response.status_code, 422, response.text)

    def test_connected_route_is_local_external_state_not_remote_mesh(self) -> None:
        response = self.client.post(
            "/v1/topologies/routes/tables/query",
            json={"filters": {"route_type": "connected"}},
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["counts"]["total"], 1)
        row = payload["items"][0]
        self.assertEqual(row["node_id"], "node-e")
        self.assertEqual(row["attributes"]["node_sequence"], ["node-e"])
        self.assertIsNone(row["next_hops"][0]["neighbor_node_id"])
        self.assertEqual(
            row["destination"]["destination_id"],
            "destination:eta-external-subnet",
        )
        trace = self.client.post(
            "/v1/topologies/routes/trace", json=row["trace_query"]
        )
        self.assertEqual(trace.status_code, 200, trace.text)
        self.assertIn(row["route_entry_id"], trace.json()["route_table_entry_ids"])

    def test_every_advertised_routing_context_has_route_table_evidence(self) -> None:
        contexts = [
            ("default", "ipv6_unicast", "srv6_policy"),
            ("blue", "ipv4_unicast", "ipv4_unicast"),
            ("blue", "mpls_labeled_unicast", "mpls_transport"),
            ("blue", "l2vpn_evpn", "evpn_ip_prefix"),
            ("red", "vpnv4_unicast", "mpls_l3vpn"),
            ("management", "ipv4_unicast", "ipv4_unicast"),
        ]
        for vrf_id, route_family, route_type in contexts:
            with self.subTest(
                vrf_id=vrf_id,
                route_family=route_family,
                route_type=route_type,
            ):
                table = self.client.post(
                    "/v1/topologies/routes/tables/query",
                    json={
                        "filters": {
                            "vrf_id": vrf_id,
                            "route_family": route_family,
                            "route_type": route_type,
                        }
                    },
                )
                self.assertEqual(table.status_code, 200, table.text)
                payload = table.json()
                self.assertGreater(payload["counts"]["total"], 0)
                trace = self.client.post(
                    "/v1/topologies/routes/trace",
                    json=payload["items"][0]["trace_query"],
                )
                self.assertEqual(trace.status_code, 200, trace.text)

    def test_every_route_table_trace_action_is_executable(self) -> None:
        payload = query_all_route_table_rows(self.client)
        self.assertFalse(payload["page"]["truncated"])
        self.assertEqual(payload["counts"]["total"], len(payload["items"]))

        for row in payload["items"]:
            with self.subTest(route_entry_id=row["route_entry_id"]):
                response = self.client.post(
                    "/v1/topologies/routes/trace", json=row["trace_query"]
                )
                self.assertEqual(response.status_code, 200, response.text)


if __name__ == "__main__":
    unittest.main()
