from __future__ import annotations

import copy
import json
import tempfile
import unittest
from dataclasses import replace

from router_dump_analyzer.ingestion import IngestionCoordinator
from router_dump_analyzer.normalized_data import (
    _project_relationship_attribute_patch,
    descriptor_sensitive_condition,
    redact_sensitive_tree,
)
from router_dump_analyzer.plugin_api import (
    PropertyDescriptor,
    PropertyPatch,
    SnapshotObservation,
)
from tests import test_ingestion as ingestion_fixtures
from tests.support.normalized_data import static_data_service


PRIVATE_VALUE = "private-condition-sentinel"


class PrivateConditionPlugin(ingestion_fixtures.ParseOnlyPlugin):
    """An ordinary parser whose public child cannot override its private parent."""

    def __init__(self, payload, *, sensitive=True):
        self.payload = payload
        self.sensitive = sensitive

    def describe(self):
        schema = super().describe()
        descriptor = replace(
            schema.resource_kinds[0],
            properties=(
                PropertyDescriptor(
                    "credentials", "Credentials", "object",
                    sensitive=self.sensitive, client_visible=self.sensitive,
                ),
                PropertyDescriptor(
                    "credentials.state", "State", "string", searchable=True,
                ),
                PropertyDescriptor("visible", "Visible", "string", searchable=True),
            ),
            condition_field="credentials.state",
            display_name_fields=(),
        )
        return replace(schema, resource_kinds=(descriptor,))

    def parse_status(self, reader, spec):
        for output in super().parse_status(reader, spec):
            if isinstance(output, SnapshotObservation):
                yield replace(
                    output,
                    state=PropertyPatch(
                        set_values={**copy.deepcopy(self.payload), "visible": "public-value"},
                        complete=True,
                    ),
                    condition=PRIVATE_VALUE,
                )


class PropertyVisibilityTests(unittest.TestCase):
    def test_property_paths_reject_empty_segments(self):
        for name in (".", "a..b", ".a", "a."):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "dotted field path"):
                    PropertyDescriptor(name, "Private", "string", sensitive=True)

    def test_condition_policy_uses_recursive_segment_paths(self):
        cases = (
            ("credentials", "credentials.state", True),
            ("credentials.private", "credentials.private.state", True),
            ("credentials", "outer.credentials.state", True),
            ("state", "credentials.state", True),
            ("credentials.private", "outer.credentials.private.state", True),
            ("credentials.state", "credentials.state", True),
            ("credentials", "credentials2.state", False),
            ("credential", "credentials.state", False),
            ("credentials.private", "credentials.privacy.state", False),
            ("credentials.private", "credentials.public.private", False),
        )
        for private_name, condition, hidden in cases:
            for policy in ({"sensitive": True}, {"client_visible": False}):
                with self.subTest(private_name=private_name, condition=condition, policy=policy):
                    properties = [{"name": private_name, **policy}]
                    if condition != private_name:
                        properties.append({"name": condition, "client_visible": True})
                    self.assertEqual(
                        descriptor_sensitive_condition({
                            "condition_field": condition, "properties": properties,
                        }),
                        hidden,
                    )
        self.assertFalse(descriptor_sensitive_condition(None))
        self.assertFalse(descriptor_sensitive_condition({"condition_field": "public"}))

    def test_literal_and_nested_private_paths_have_the_same_policy(self):
        payloads = (
            {"credentials": {"private": {"state": PRIVATE_VALUE}, "public": "keep"}},
            {"credentials.private": {"state": PRIVATE_VALUE}, "public": "keep"},
            {"credentials.private.state": PRIVATE_VALUE, "public": "keep"},
            {"credentials": {"private.state": PRIVATE_VALUE, "public": "keep"}},
            {"wrapper": [{"credentials.private.state": PRIVATE_VALUE, "public": "keep"}]},
            {"credentials": [{"private.state": PRIVATE_VALUE, "public": "keep"}]},
            {"credentials": ({"private.state": PRIVATE_VALUE, "public": "keep"},)},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                before = copy.deepcopy(payload)
                result = redact_sensitive_tree(payload, {"credentials.private"})
                self.assertNotIn(PRIVATE_VALUE, json.dumps(result))
                self.assertIn("keep", json.dumps(result))
                self.assertEqual(payload, before)
        unrelated = {
            "credentials2.private": "keep-1",
            "credentials": {"public": {"private": "keep-2"}},
            "credentials.privacy": "keep-3",
        }
        self.assertEqual(
            redact_sensitive_tree(unrelated, {"credentials.private"}), unrelated,
        )

    def test_ingestion_public_reads_do_not_promote_private_condition(self):
        payloads = (
            {"credentials": {"state": PRIVATE_VALUE}},
            {"credentials.state": PRIVATE_VALUE},
            {"credentials": [{"state": PRIVATE_VALUE}]},
        )
        for sensitive in (True, False):
            for payload in payloads:
                with self.subTest(sensitive=sensitive, payload=payload):
                    with tempfile.TemporaryDirectory() as directory:
                        result = IngestionCoordinator().ingest(
                            PrivateConditionPlugin(payload, sensitive=sensitive),
                            ingestion_fixtures.CoreIngestionTests()._fixture(directory),
                        )
                    dataset = result.dataset
                    self.assertIn(PRIVATE_VALUE, json.dumps(dataset["resources"]))
                    resource_id = dataset["resources"][0]["resource_id"]
                    # Exercise the same normalized event/effect boundary used
                    # by runtime adapters, in addition to real parsed snapshots.
                    dataset["events"] = [{
                        "event_uid": "condition-event", "timestamp_ns": "200",
                        "action": "observe", "outcome": "success",
                        "status": PRIVATE_VALUE, "condition": PRIVATE_VALUE,
                        "condition_class": "healthy",
                        "affected_resources": [resource_id],
                        "properties": copy.deepcopy(payload),
                        "effects": [{
                            "resource_id": resource_id, "resource_kind": "INTERFACE",
                            "status": PRIVATE_VALUE, "condition": PRIVATE_VALUE,
                            "after": copy.deepcopy(payload),
                        }],
                    }]
                    service = static_data_service(dataset)
                    view = service.resource_state_at(resource_id, 200)
                    client = service.client_dataset()
                    summary = service.range_summary(200, 200)
                    self.assertEqual(view["status"], "unknown")
                    self.assertEqual(view["state"], {"visible": "public-value"})
                    self.assertEqual(client["state_intervals"][0]["status"], "unknown")
                    event = client["events"][0]
                    self.assertEqual(event["status"], "unknown")
                    self.assertEqual(event["condition"], "unknown")
                    self.assertEqual(event["condition_class"], "healthy")
                    self.assertEqual(event["effects"][0]["status"], "unknown")
                    for projection in (view, client, summary):
                        self.assertNotIn(PRIVATE_VALUE, json.dumps(projection))
                    self.assertEqual(service.resources_at(200, search=PRIVATE_VALUE)["count"], 0)
                    self.assertEqual(service.resources_at(200, search="public-value")["count"], 1)
                    self.assertEqual(event["action"], "observe")
                    self.assertEqual(event["affected_resources"], [resource_id])

    def test_tagged_relationship_values_apply_paths_to_logical_keys_only(self):
        def scalar(value):
            return {"type": "string", "value": value}

        patch = {"set_values": {
            "credentials.private.state": scalar(PRIVATE_VALUE),
            "wrapper": {"type": "mapping", "entries": {
                "credentials": {"type": "tuple", "items": [{
                    "type": "mapping", "entries": {
                        "private.state": scalar(PRIVATE_VALUE),
                        "public": scalar("keep"),
                    },
                }]},
                "credentials2.private": scalar("keep-too"),
            }},
        }}
        result = _project_relationship_attribute_patch(
            patch, {"credentials.private", "type", "value"},
        )
        self.assertNotIn(PRIVATE_VALUE, json.dumps(result))
        self.assertIn("keep", json.dumps(result))
        self.assertIn("keep-too", json.dumps(result))
        self.assertEqual(result["set_values"]["wrapper"]["type"], "mapping")


if __name__ == "__main__":
    unittest.main()
