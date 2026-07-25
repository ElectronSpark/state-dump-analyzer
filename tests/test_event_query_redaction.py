from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from router_dump_analyzer_demo import app as demo_app
from router_dump_analyzer_demo.data import REVISION_ID


class EventQueryRedactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(demo_app.app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client_context.__exit__(None, None, None)

    def setUp(self) -> None:
        self.resource_id = "control/NEIGHBOR/peer-a"
        self.dataset = {
            "kind_descriptors": [
                {
                    "kind": "NEIGHBOR",
                    "properties": [
                        {
                            "name": "peer",
                            "label": "Peer",
                            "value_type": "string",
                            "searchable": True,
                        },
                        {
                            "name": "auth_secret",
                            "label": "Authentication secret",
                            "value_type": "string",
                            "searchable": True,
                            "sensitive": True,
                        },
                    ],
                }
            ],
            "resources": [
                {
                    "resource_id": self.resource_id,
                    "kind": "NEIGHBOR",
                    "layer": "control",
                    "label": "peer-a",
                    "key": {"peer": "192.0.2.10"},
                }
            ],
            "events": [
                {
                    "event_uid": "event-1",
                    "resource_kind": "NEIGHBOR",
                    "outcome": "failure",
                    "subjects": [
                        {
                            "layer": "control",
                            "resource_id": self.resource_id,
                            "auth_secret": "subject-secret",
                        }
                    ],
                    "display_name": "Peer authentication failed",
                    "result": {
                        "peer": "192.0.2.10",
                        "auth_secret": "result-secret",
                    },
                    "attributes": {
                        "plugin_payload": {
                            "auth_secret": "deep-secret",
                            "reason": "key rejected",
                        }
                    },
                },
                {
                    "event_uid": "event-2",
                    "kind": "neighbor_auth_observation",
                    "outcome": "failure",
                    "subjects": [{"layer": "control"}],
                    "display_name": "Unclassified plug-in event",
                    "attributes": {"auth_secret": "unclassified-secret"},
                },
                {
                    "event_uid": "event-3",
                    "outcome": "success",
                    "subjects": [{"layer": "control"}],
                    "display_name": "Neighbor recovered",
                    "effects": [
                        {
                            "resource_id": self.resource_id,
                            "after": {
                                "peer": "192.0.2.10",
                                "auth_secret": "effect-secret",
                            },
                        }
                    ],
                },
            ],
        }

    def _get(self, **params: object):
        with patch.object(
            demo_app,
            "load_demo_dataset",
            return_value=self.dataset,
        ):
            return self.client.get(
                f"/v1/revisions/{REVISION_ID}/events",
                params=params,
            )

    def test_sensitive_plugin_fields_are_not_emitted_at_any_payload_depth(self) -> None:
        response = self._get(layer="control", limit=10)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 3)
        serialized = json.dumps(payload, sort_keys=True)
        self.assertNotIn("auth_secret", serialized)
        for secret in (
            "subject-secret",
            "result-secret",
            "deep-secret",
            "unclassified-secret",
            "effect-secret",
        ):
            self.assertNotIn(secret, serialized)
        # The projection is non-mutating; retained evidence remains available
        # to trusted server-side processing.
        self.assertEqual(
            self.dataset["events"][0]["result"]["auth_secret"],
            "result-secret",
        )

    def test_sensitive_values_cannot_be_used_as_an_event_search_oracle(self) -> None:
        for secret in (
            "result-secret",
            "deep-secret",
            "unclassified-secret",
            "effect-secret",
        ):
            response = self._get(search=secret)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["count"], 0)
            self.assertEqual(response.json()["items"], [])

        visible = self._get(search="192.0.2.10", limit=1)
        self.assertEqual(visible.status_code, 200)
        self.assertEqual(visible.json()["count"], 2)
        self.assertEqual(len(visible.json()["items"]), 1)

    def test_existing_layer_outcome_count_and_limit_semantics_are_preserved(self) -> None:
        response = self._get(
            layer="control",
            outcome="failure",
            search="Unclassified",
            limit=1,
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual([item["event_uid"] for item in payload["items"]], ["event-2"])
        self.assertIsNone(payload["next_cursor"])


if __name__ == "__main__":
    unittest.main()
