from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from router_dump_analyzer_demo.app import app
from router_dump_analyzer_demo.data import REVISION_ID


class DashboardQueryApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dataset = {
            "demo": {
                "capture_ns": "1759680006000000000",
            }
        }
        self.load_patch = patch(
            "router_dump_analyzer_demo.app.load_demo_dataset",
            return_value=self.dataset,
        )
        self.query_patch = patch(
            "router_dump_analyzer_demo.app.dashboard_query",
            return_value={
                "revision_id": REVISION_ID,
                "time_ns": "1759680005000000000",
                "population_count": 250,
                "dashboards": [
                    {
                        "dashboard_id": "plugin.health",
                        "statistics": [
                            {
                                "statistic_id": "up",
                                "aggregation": "count",
                                "value": 173,
                                "matching_count": 173,
                                "sample_count": 173,
                            }
                        ],
                        "tables": [
                            {
                                "table_id": "resources",
                                "items": [
                                    {
                                        "resource_id": f"plugin/RESOURCE/{index}",
                                        "exists": True,
                                    }
                                    for index in range(50)
                                ],
                                "total_count": 250,
                                "returned_count": 50,
                                "truncated": True,
                            }
                        ],
                    }
                ],
            },
        )
        self.load_mock = self.load_patch.start()
        self.query_mock = self.query_patch.start()
        self.client_context = TestClient(app)
        self.client = self.client_context.__enter__()

    def tearDown(self) -> None:
        self.client_context.__exit__(None, None, None)
        self.query_patch.stop()
        self.load_patch.stop()

    def test_defaults_to_capture_time_and_all_declared_dashboards(self) -> None:
        response = self.client.post(
            f"/v1/revisions/{REVISION_ID}/dashboards/query",
            json={},
        )

        self.assertEqual(200, response.status_code)
        self.query_mock.assert_called_once_with(
            1759680006000000000,
            dashboard_ids=None,
        )

    def test_selected_ids_are_deduplicated_and_time_keeps_nanosecond_precision(
        self,
    ) -> None:
        response = self.client.post(
            f"/v1/revisions/{REVISION_ID}/dashboards/query",
            json={
                "time_ns": "1759680005000000001",
                "dashboard_ids": [
                    "plugin.health",
                    "plugin.routes",
                    "plugin.health",
                ],
            },
        )

        self.assertEqual(200, response.status_code)
        self.query_mock.assert_called_once_with(
            1759680005000000001,
            dashboard_ids=["plugin.health", "plugin.routes"],
        )

    def test_response_preserves_authoritative_population_and_table_totals(
        self,
    ) -> None:
        response = self.client.post(
            f"/v1/revisions/{REVISION_ID}/dashboards/query",
            json={
                "time_ns": "1759680005000000000",
                "dashboard_ids": ["plugin.health"],
            },
        )

        self.assertEqual(200, response.status_code)
        payload = response.json()
        self.assertEqual(250, payload["population_count"])
        table = payload["dashboards"][0]["tables"][0]
        self.assertEqual(250, table["total_count"])
        self.assertEqual(50, table["returned_count"])
        self.assertEqual(50, len(table["items"]))
        self.assertTrue(table["truncated"])

    def test_empty_dashboard_list_explicitly_selects_none(self) -> None:
        response = self.client.post(
            f"/v1/revisions/{REVISION_ID}/dashboards/query",
            json={"dashboard_ids": []},
        )

        self.assertEqual(200, response.status_code)
        self.query_mock.assert_called_once_with(
            1759680006000000000,
            dashboard_ids=[],
        )

    def test_rejects_non_object_request_body(self) -> None:
        for body in (None, [], "dashboard", 7):
            with self.subTest(body=body):
                response = self.client.post(
                    f"/v1/revisions/{REVISION_ID}/dashboards/query",
                    json=body,
                )
                self.assertEqual(422, response.status_code)

    def test_rejects_invalid_time_shapes(self) -> None:
        for time_ns in (None, True, 1.5, "1.5", "capture"):
            with self.subTest(time_ns=time_ns):
                response = self.client.post(
                    f"/v1/revisions/{REVISION_ID}/dashboards/query",
                    json={"time_ns": time_ns},
                )
                self.assertEqual(422, response.status_code)

    def test_rejects_invalid_dashboard_id_shapes(self) -> None:
        for dashboard_ids in (
            None,
            "plugin.health",
            [""],
            ["plugin.health", 7],
        ):
            with self.subTest(dashboard_ids=dashboard_ids):
                response = self.client.post(
                    f"/v1/revisions/{REVISION_ID}/dashboards/query",
                    json={"dashboard_ids": dashboard_ids},
                )
                self.assertEqual(422, response.status_code)

    def test_unknown_revision_is_not_evaluated(self) -> None:
        response = self.client.post(
            "/v1/revisions/not-a-revision/dashboards/query",
            json={},
        )

        self.assertEqual(404, response.status_code)
        self.query_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
