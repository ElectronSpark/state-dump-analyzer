from __future__ import annotations

import copy
import json
import re
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

    def test_client_projection_uses_explicit_metadata_envelope_without_mutation(
        self,
    ) -> None:
        dataset = self.dataset()
        before = copy.deepcopy(dataset["demo"])
        service = static_data_service(dataset)

        client = service.client_dataset()

        self.assertEqual(dataset["demo"], before)
        self.assertEqual(
            client["demo"],
            {"revision_id": "revision-x", "node": "node-x"},
        )
        self.assertNotIn("private_extension", client["demo"])
        self.assertEqual(client["workspace"]["revision_id"], "revision-x")
        self.assertNotIn("secret", client["resources"][0]["state"])

    def test_nested_sensitive_fields_are_removed_from_every_public_projection(
        self,
    ) -> None:
        dataset = self.dataset()
        dataset["kind_descriptors"][0]["properties"].append(
            {
                "name": "nested",
                "searchable": False,
                "client_visible": True,
            }
        )
        resource = dataset["resources"][0]
        resource["state"]["nested"] = {
            "secret": "nested-resource-secret",
            "items": [{"secret": "list-resource-secret", "visible": "yes"}],
        }
        interval = dataset["state_intervals"][0]
        interval["properties"]["nested"] = {
            "secret": "nested-interval-secret",
        }
        dataset["events"] = [
            {
                "event_uid": "nested-secret-event",
                "timestamp_ns": "10",
                "action": "modify",
                "outcome": "success",
                "affected_resources": [resource["resource_id"]],
                "subjects": [
                    {
                        "resource_id": resource["resource_id"],
                        "resource_kind": "INTERFACE",
                    }
                ],
                "effects": [
                    {
                        "resource_id": resource["resource_id"],
                        "after": {
                            "nested": {
                                "secret": "nested-event-secret",
                            }
                        },
                    }
                ],
            }
        ]

        service = static_data_service(dataset)
        serialized = json.dumps(service.client_dataset())
        range_serialized = json.dumps(service.range_summary(10, 10))

        for secret in (
            "nested-resource-secret",
            "list-resource-secret",
            "nested-interval-secret",
            "nested-event-secret",
        ):
            self.assertNotIn(secret, serialized)
            self.assertNotIn(secret, range_serialized)
        self.assertIn('"visible": "yes"', serialized)

    def test_sensitive_condition_cannot_be_promoted_into_public_status(self) -> None:
        dataset = self.dataset()
        descriptor = dataset["kind_descriptors"][0]
        descriptor["condition_field"] = "secret"
        dataset["state_intervals"][0]["status"] = "classified-condition"
        dataset["state_intervals"][0]["properties"]["secret"] = (
            "classified-condition"
        )

        service = static_data_service(dataset)
        view = service.resource_state_at("node-x/INTERFACE/1", 10)
        client = service.client_dataset()

        self.assertEqual(view["status"], "unknown")
        self.assertEqual(client["state_intervals"][0]["status"], "unknown")
        self.assertNotIn("classified-condition", json.dumps(client))

    def test_range_histograms_use_the_redacted_event_projection(self) -> None:
        dataset = self.dataset()
        dataset["kind_descriptors"][0]["properties"].append(
            {"name": "action", "sensitive": True}
        )
        dataset["events"] = [
            {
                "event_uid": "sensitive-action",
                "timestamp_ns": "10",
                "action": "classified-action",
                "outcome": "success",
                "affected_resources": ["node-x/INTERFACE/1"],
                "subjects": [
                    {
                        "resource_id": "node-x/INTERFACE/1",
                        "resource_kind": "INTERFACE",
                    }
                ],
                "effects": [],
            }
        ]

        summary = static_data_service(dataset).range_summary(10, 10)

        self.assertEqual(summary["counts"]["by_action"], {"unknown": 1})
        self.assertNotIn("classified-action", json.dumps(summary))

    def test_invalid_plugin_colors_are_replaced_with_safe_hex_values(self) -> None:
        dataset = self.dataset()
        dataset["kind_descriptors"][0]["properties"].append(
            {
                "name": "color",
                "searchable": False,
                "client_visible": True,
            }
        )
        dataset["resources"][0]["state"]["color"] = "burnt-umber"
        dataset["state_intervals"][0]["properties"]["color"] = "burnt-umber"
        dataset["presentation"] = {
            "layers": [
                {
                    "id": "forwarding",
                    "label": "Forwarding",
                    "color": "red;--node-color:url(javascript:alert(1))",
                }
            ]
        }

        client = static_data_service(dataset).client_dataset()
        color = client["presentation"]["layers"][0]["color"]

        self.assertRegex(color, re.compile(r"^#[0-9A-Fa-f]{6}$"))
        self.assertNotIn("javascript", json.dumps(client))
        self.assertEqual(
            client["resources"][0]["state"]["color"],
            "burnt-umber",
        )

    def test_client_projection_rejects_undeclared_resource_kinds(self) -> None:
        dataset = self.dataset()
        dataset["resources"][0]["kind"] = "UNDECLARED"

        with self.assertRaisesRegex(
            RuntimeError,
            "lacks a resource descriptor for kind 'UNDECLARED'",
        ):
            static_data_service(dataset).client_dataset()


if __name__ == "__main__":
    unittest.main()
