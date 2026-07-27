from __future__ import annotations

import copy
import unittest

from tests.support.normalized_data import static_data_service


class NormalizedDataServiceTests(unittest.TestCase):
    def dataset(self) -> dict:
        resource_id = "node-x/INTERFACE/1"
        return {
            "demo": {
                "revision_id": "revision-x",
                "node": "node-x",
                "private_extension": {"token": "opaque"},
            },
            "resources": [
                {
                    "resource_id": resource_id,
                    "kind": "INTERFACE",
                    "layer": "forwarding",
                    "label": "Ethernet1",
                    "state": {"oper_status": "up", "secret": "hidden"},
                }
            ],
            "kind_descriptors": [
                {
                    "kind": "INTERFACE",
                    "condition_field": "oper_status",
                    "properties": [
                        {"name": "oper_status", "searchable": True},
                        {
                            "name": "secret",
                            "searchable": False,
                            "sensitive": True,
                        },
                    ],
                }
            ],
            "lifecycle_intervals": [
                {
                    "resource": resource_id,
                    "valid_from_ns": "10",
                    "valid_to_ns": None,
                }
            ],
            "state_intervals": [
                {
                    "resource": resource_id,
                    "valid_from_ns": "10",
                    "valid_to_ns": None,
                    "status": "up",
                    "status_class": "healthy",
                    "properties": {
                        "oper_status": "up",
                        "secret": "hidden",
                    },
                }
            ],
            "relationships": [],
            "relationship_intervals": [],
            "relationship_mutations": [],
            "relationship_descriptors": [],
            "events": [],
            "source_records": [],
        }

    def test_core_projects_state_and_redacts_declared_sensitive_fields(self) -> None:
        service = static_data_service(self.dataset())

        view = service.resource_state_at("node-x/INTERFACE/1", 10)

        self.assertTrue(view["exists"])
        self.assertEqual(view["status"], "up")
        self.assertNotIn("secret", view["state"])
        self.assertNotIn("secret", view["resource"]["state"])

    def test_client_projection_preserves_opaque_plugin_metadata_without_mutation(
        self,
    ) -> None:
        dataset = self.dataset()
        before = copy.deepcopy(dataset["demo"])
        service = static_data_service(dataset)

        client = service.client_dataset()

        self.assertEqual(dataset["demo"], before)
        self.assertEqual(client["demo"], before)
        self.assertEqual(client["workspace"]["revision_id"], "revision-x")
        self.assertNotIn("secret", client["resources"][0]["state"])


if __name__ == "__main__":
    unittest.main()
