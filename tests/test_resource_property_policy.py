from __future__ import annotations

import unittest

from router_dump_analyzer.normalized_data import (
    redact_resource_for_client,
    redact_resource_view,
    resource_search_text,
    redact_event_for_client,
    resource_id,
)


class ResourcePropertyPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.descriptor = {
            "kind": "NEIGHBOR",
            "display_name_fields": ["peer"],
            "properties": [
                {
                    "name": "peer",
                    "label": "Peer",
                    "value_type": "string",
                    "searchable": True,
                },
                {
                    "name": "oper_state",
                    "label": "State",
                    "value_type": "string",
                    "searchable": True,
                },
                {
                    "name": "diagnostic_blob",
                    "label": "Raw diagnostic",
                    "value_type": "string",
                    "searchable": False,
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
        self.record = {
            "resource_id": "control/NEIGHBOR/peer-a",
            "kind": "NEIGHBOR",
            "layer": "control",
            "label": "peer-a",
            "key": {"peer": "192.0.2.10", "auth_secret": "key-secret"},
            "state": {
                "oper_state": "up",
                "diagnostic_blob": "do-not-index",
                "auth_secret": "state-secret",
            },
            "auth_secret": "record-secret",
        }
        self.view = {
            "resource_id": self.record["resource_id"],
            "kind": "NEIGHBOR",
            "layer": "control",
            "label": "peer-a",
            "status": "up",
            "status_class": "healthy",
            "exists": True,
            "state": dict(self.record["state"]),
            "resource": dict(self.record),
        }

    def test_search_uses_only_plugin_declared_searchable_properties(self) -> None:
        searchable = resource_search_text(
            self.record,
            self.view,
            self.descriptor,
        )

        self.assertIn("192.0.2.10", searchable)
        self.assertIn("up", searchable)
        self.assertNotIn("do-not-index", searchable)
        self.assertNotIn("state-secret", searchable)
        self.assertNotIn("key-secret", searchable)

    def test_sensitive_properties_are_removed_from_every_resource_projection(self) -> None:
        redacted = redact_resource_view(self.view, self.descriptor)

        self.assertNotIn("auth_secret", redacted["state"])
        self.assertNotIn("auth_secret", redacted["resource"])
        self.assertNotIn("auth_secret", redacted["resource"]["key"])
        self.assertNotIn("auth_secret", redacted["resource"]["state"])
        self.assertEqual("do-not-index", redacted["state"]["diagnostic_blob"])

    def test_client_resource_projection_uses_the_shared_redaction_path(self) -> None:
        redacted = redact_resource_for_client(self.record, self.descriptor)

        self.assertEqual(self.record["resource_id"], redacted["resource_id"])
        self.assertEqual("192.0.2.10", redacted["key"]["peer"])
        self.assertEqual("up", redacted["state"]["oper_state"])
        self.assertNotIn("auth_secret", redacted)
        self.assertNotIn("auth_secret", redacted["key"])
        self.assertNotIn("auth_secret", redacted["state"])

    def test_legacy_typed_keys_do_not_collapse_to_display_strings(self) -> None:
        integer_id = resource_id(
            {"layer": "driver", "kind": "OPAQUE", "key": {"id": 1}}
        )
        string_id = resource_id(
            {"layer": "driver", "kind": "OPAQUE", "key": {"id": "1"}}
        )
        nested_id = resource_id(
            {
                "layer": "driver",
                "kind": "OPAQUE",
                "key": {"id": {"type": "opaque_uint", "value": 1}},
            }
        )

        self.assertEqual(3, len({integer_id, string_id, nested_id}))
        self.assertTrue(integer_id.startswith("legacy-resource:"))

    def test_event_effects_and_results_use_the_same_sensitive_field_policy(self) -> None:
        event = {
            "event_uid": "event-1",
            "resource_kind": "NEIGHBOR",
            "result": {"oper_state": "up", "auth_secret": "result-secret"},
            "effects": [
                {
                    "resource_id": self.record["resource_id"],
                    "kind": "NEIGHBOR",
                    "after": {
                        "oper_state": "up",
                        "auth_secret": "effect-secret",
                    },
                }
            ],
        }
        dataset = {
            "kind_descriptors": [self.descriptor],
            "resources": [self.record],
        }

        redacted = redact_event_for_client(event, dataset)

        self.assertNotIn("auth_secret", redacted["result"])
        self.assertNotIn("auth_secret", redacted["effects"][0]["after"])
        self.assertEqual("up", redacted["effects"][0]["after"]["oper_state"])


if __name__ == "__main__":
    unittest.main()
