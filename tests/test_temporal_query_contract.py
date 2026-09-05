"""HTTP request controls exercised against the real small temporal service."""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from router_dump_analyzer.web import runtime_api
from router_dump_analyzer.value_core import MAX_JSON_SAFE_INTEGER
from tests.test_temporal_snapshot_selection import _event, _fixture


def _rewrite_cursor(token, **fields):
    prefix, encoded, _ = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    payload.update(fields)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    checksum = hashlib.sha256(
        raw + b"\0" + payload["revision_id"].encode("utf-8")
    ).hexdigest()[:16]
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return f"{prefix}.{encoded}.{checksum}"


class TemporalQueryContractTests(unittest.TestCase):
    def setUp(self):
        self.dataset, self.data, self.service, identifier = _fixture(
            [
                (10, {"x": "value"}, "observed"),
            ]
        )
        self.projection = self.service.contract["topology_projections"][0]
        self.projection["relationship_types"] = ["owns", "references"]
        self.dataset["relationship_intervals"] = [
            {
                "relationship_id": relation,
                "source": identifier,
                "target": identifier,
                "relation_type": relation,
                "present": True,
                "valid_from_ns": "10",
                "valid_to_ns": None,
            }
            for relation in ("owns", "references", "hidden")
        ]
        for target, value in (
            ("_require_revision", None),
            ("load_dataset", self.dataset),
            ("current_revision_id", "test/revision"),
            ("_temporal_topology", self.service),
        ):
            mocked = patch.object(runtime_api, target, return_value=value)
            mocked.start()
            self.addCleanup(mocked.stop)
        app = FastAPI()
        app.add_api_route(
            "/v1/revisions/{revision_id:path}/state/query",
            runtime_api.temporal_state_query,
            methods=["POST"],
        )
        app.add_api_route(
            "/v1/revisions/{revision_id:path}/topology/changes/query",
            runtime_api.topology_changes_query,
            methods=["POST"],
        )
        self.client = TestClient(app)
        self.addCleanup(self.client.close)

    def query(self, **values):
        return self.client.post(
            "/v1/revisions/test/revision/state/query",
            json={
                "basis": {"kind": "absolute_time", "time_ns": "25"},
                "projection_id": "p",
                "status_perspective_id": "observed",
                **values,
            },
        )

    def test_boolean_relationship_inclusion_controls_the_actual_reader(self):
        reader = Mock(wraps=self.service.relationship_reader)
        self.service.relationship_reader = reader
        response = self.query(include_relationships=False)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["relationships"], [])
        self.assertEqual(len(response.json()["resources"]), 1)
        reader.assert_not_called()
        for values in ({}, {"include_relationships": True}):
            response = self.query(**values)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(len(response.json()["relationships"]), 2)
        self.assertTrue(reader.called)

    def test_non_boolean_inclusion_is_rejected(self):
        for value in (0, 1, "false", None, []):
            with self.subTest(value=value):
                response = self.query(include_relationships=value)
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(
                    response.json()["detail"], "include_relationships must be a boolean"
                )

    def test_requested_relation_types_cannot_broaden_projection(self):
        for requested, expected in (
            (["owns"], {"owns"}),
            (["owns", "hidden"], {"owns"}),
            (["hidden"], set()),
            (["unknown"], set()),
            ([], set()),
        ):
            with self.subTest(requested=requested):
                response = self.query(relation_types=requested)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(
                    {
                        item["relation_type"]
                        for item in response.json()["relationships"]
                    },
                    expected,
                )
        self.assertEqual(self.projection["relationship_types"], ["owns", "references"])

    def test_omitted_projection_types_are_legacy_wildcard_but_explicit_empty_is_not(
        self,
    ):
        self.projection.pop("relationship_types")
        response = self.query(relation_types=["hidden"])
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            [item["relation_type"] for item in response.json()["relationships"]],
            ["hidden"],
        )
        self.projection["relationship_types"] = []
        self.assertEqual(
            self.query(relation_types=["hidden"]).json()["relationships"], []
        )

    def test_malformed_relation_filters_and_unsupported_basis_remain_422(self):
        for value in (None, "owns", [1], [""]):
            self.assertEqual(self.query(relation_types=value).status_code, 422)
        response = self.query(basis={"kind": "reconstructed_time", "time_ns": "25"})
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn(
            "absolute_time or relative_to_watermark", response.json()["detail"]
        )

    def _add_second_resource(self):
        record = dict(
            self.dataset["resources"][0], resource_id="second-resource", label="second"
        )
        self.dataset["resources"].append(record)
        self.service.resource_by_id[record["resource_id"]] = record
        for field in ("state_intervals", "lifecycle_intervals"):
            self.dataset[field].append(
                dict(self.dataset[field][0], resource="second-resource")
            )

    def test_resource_cursor_advances_to_page_two_and_generic_cursor_is_rejected(self):
        self._add_second_resource()
        first = self.query(resource_limit=1, include_relationships=False)
        self.assertEqual(first.status_code, 200, first.text)
        token = first.json()["next_resource_cursor"]
        self.assertIsNotNone(token)
        second = self.query(
            resource_limit=1, include_relationships=False, resource_cursor=token
        )
        self.assertEqual(second.status_code, 200, second.text)
        self.assertNotEqual(
            first.json()["resources"][0]["resource_id"],
            second.json()["resources"][0]["resource_id"],
        )
        self.assertIsNone(second.json()["next_resource_cursor"])
        for fields in (
            {"cursor": token},
            {"cursor": token, "resource_cursor": token},
            {"cursor": ""},
            {"cursor": False},
        ):
            response = self.query(resource_limit=1, **fields)
            self.assertEqual(response.status_code, 422, response.text)
            self.assertIn("use resource_cursor", response.json()["detail"])
        self.assertEqual(self.query(resource_limit=1, cursor=None).status_code, 200)

    def _change_page(self):
        identifier = self.dataset["resources"][0]["resource_id"]
        events = [
            dict(
                _event(uid, time, sequence, {"x": uid}),
                resource_id=identifier,
                affected_resources=[identifier],
            )
            for uid, time, sequence in (("first", 15, 1), ("second", 20, 2))
        ]
        self.dataset["events"] = self.service._events = events
        self.service._event_times = [15, 20]
        body = {
            "start_basis": {"kind": "absolute_time", "time_ns": "11"},
            "end_basis": {"kind": "absolute_time", "time_ns": "30"},
            "projection_id": "p",
            "status_perspective_id": "observed",
            "include_resources": False,
            "change_limit": 1,
        }
        path = "/v1/revisions/test/revision/topology/changes/query"
        first = self.client.post(path, json=body)
        self.assertEqual(first.status_code, 200, first.text)
        return path, body, first

    def test_change_cursor_advances_to_page_two_and_generic_alias_is_rejected(self):
        path, body, first = self._change_page()
        token = first.json()["next_change_cursor"]
        self.assertIsNotNone(token)
        second = self.client.post(path, json={**body, "change_cursor": token})
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(first.json()["changes"][0]["event_uid"], "first")
        self.assertEqual(second.json()["changes"][0]["event_uid"], "second")
        self.assertIsNone(second.json()["next_change_cursor"])
        for fields in ({"cursor": token}, {"cursor": token, "change_cursor": token}):
            rejected = self.client.post(path, json={**body, **fields})
            self.assertEqual(rejected.status_code, 422, rejected.text)
            self.assertIn("change_cursor", rejected.json()["detail"])

    def test_resource_cursor_position_and_offset_require_json_safe_integers(self):
        self._add_second_resource()
        first = self.query(resource_limit=1, include_relationships=False)
        self.assertEqual(first.status_code, 200, first.text)
        token = first.json()["next_resource_cursor"]
        for field in ("position", "offset"):
            for value in (MAX_JSON_SAFE_INTEGER + 1, -1, True):
                with self.subTest(field=field, value=value):
                    response = self.query(
                        resource_limit=1,
                        include_relationships=False,
                        resource_cursor=_rewrite_cursor(token, **{field: value}),
                    )
                    self.assertEqual(response.status_code, 422, response.text)
                    self.assertIn(f"resource_cursor {field}", response.json()["detail"])

    def test_change_cursor_position_requires_json_safe_integer(self):
        path, body, first = self._change_page()
        token = first.json()["next_change_cursor"]
        for value in (MAX_JSON_SAFE_INTEGER + 1, -1, True):
            with self.subTest(value=value):
                response = self.client.post(
                    path,
                    json={**body, "change_cursor": _rewrite_cursor(token, position=value)},
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertIn("change_cursor position", response.json()["detail"])

    def test_change_page_count_addition_cannot_overflow_json_safe_range(self):
        path, body, first = self._change_page()
        token = first.json()["next_change_cursor"]
        for fields in (
            {"position": MAX_JSON_SAFE_INTEGER},
            {"position": MAX_JSON_SAFE_INTEGER - 1, "after": None},
        ):
            with self.subTest(fields=fields):
                response = self.client.post(
                    path,
                    json={**body, "change_cursor": _rewrite_cursor(token, **fields)},
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertIn("change page count", response.json()["detail"])

    def test_maximum_change_count_remains_an_exact_integer_without_overflow(self):
        path, body, first = self._change_page()
        token = first.json()["next_change_cursor"]
        response = self.client.post(
            path,
            json={**body, "change_cursor": _rewrite_cursor(
                token, position=MAX_JSON_SAFE_INTEGER - 1
            )},
        )
        self.assertEqual(response.status_code, 200, response.text)
        counts = response.json()["counts"]["changes"]
        self.assertEqual(counts["returned_count"], 1)
        self.assertEqual(counts["total_count"], MAX_JSON_SAFE_INTEGER)
        self.assertEqual(counts["minimum_total_count"], MAX_JSON_SAFE_INTEGER)
        self.assertIsNone(response.json()["next_change_cursor"])


if __name__ == "__main__":
    unittest.main()
