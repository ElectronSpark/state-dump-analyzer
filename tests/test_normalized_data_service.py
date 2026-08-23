from __future__ import annotations

import copy
import json
import random
import re
import unittest

from router_dump_analyzer.normalized_data import (
    project_consistency_findings_for_client,
    project_consistency_materialization_for_client,
)
from tests.support.normalized_data import static_data_service

VALID_FINDING_ID = "sha256:" + ("f" * 64)
VALID_ARTIFACT_ID = "00000000-0000-0000-0000-000000000001"


class NormalizedDataServiceTests(unittest.TestCase):
    def test_consistency_materialization_uses_an_exact_client_envelope(self) -> None:
        class UnknownBranchMustNotBeRead(dict):
            def items(self):
                raise AssertionError("unknown materialization branch was traversed")

        digest = "sha256:" + ("a" * 64)
        private_marker = "private-materialization-extension"
        materialization = {
            "schema_version": "router_dump_analyzer.consistency_materialization.v1",
            "status": "complete",
            "plan_digest": digest,
            "basis_digest": digest,
            "provider_count": "private-count-marker",
            "finding_count": 1 << 53,
            "diagnostic_count": 0,
            "emitted_finding_count": 0,
            "emitted_diagnostic_count": 0,
            "duplicate_findings_discarded": 0,
            "duplicate_diagnostics_discarded": 0,
            "world_reads": True,
            "basis": {
                "kind": "observed_capture_vector",
                "requested_time_ns": None,
                "capture_ranges": [
                    {
                        "scope": "node-a",
                        "evidence": [
                            {
                                "artifact_id": VALID_ARTIFACT_ID,
                                "locator": "C:/private/status.dump:7",
                            }
                        ],
                    }
                ],
                "private_extension": UnknownBranchMustNotBeRead(
                    {"marker": private_marker}
                ),
            },
            "providers": [
                {
                    "plugin_id": "plugin-a",
                    "plugin_version": "1",
                    "roles": ["revision-consistency"],
                    "private_extension": private_marker,
                }
            ],
            "private_extension": private_marker,
        }

        projected = project_consistency_materialization_for_client(
            materialization,
        )
        serialized = json.dumps(projected)

        self.assertNotIn("provider_count", projected)
        self.assertNotIn("finding_count", projected)
        self.assertNotIn("world_reads", projected)
        self.assertEqual(projected["diagnostic_count"], 0)
        self.assertEqual(
            projected["basis"]["capture_ranges"][0]["evidence"],
            [{"artifact_id": VALID_ARTIFACT_ID}],
        )
        self.assertNotIn("locator", serialized)
        self.assertNotIn(private_marker, serialized)
        self.assertNotIn("private_extension", serialized)
        malformed = project_consistency_materialization_for_client(
            {
                "schema_version": 1,
                "status": {"marker": private_marker},
                "plan_digest": private_marker,
                "basis_digest": private_marker,
            }
        )
        self.assertEqual(malformed, {})

    def test_consistency_finding_details_use_descriptor_redaction(self) -> None:
        projected = project_consistency_findings_for_client(
            {
                "kind_descriptors": [
                    {
                        "kind": "INTERFACE",
                        "properties": [
                            {"name": "secret", "sensitive": True},
                        ],
                    }
                ],
                "resources": [],
            },
            (
                {
                    "finding_id": VALID_FINDING_ID,
                    "details": {
                        "secret": "must-not-cross-the-client-boundary",
                        "visible": "retained",
                    },
                },
            ),
        )

        self.assertEqual(
            projected,
            [{"finding_id": VALID_FINDING_ID, "details": {"visible": "retained"}}],
        )

    def test_consistency_core_evidence_ignores_property_name_collisions(self) -> None:
        projected = project_consistency_findings_for_client(
            {
                "kind_descriptors": [
                    {
                        "kind": "INTERFACE",
                        "properties": [
                            {"name": name, "sensitive": True}
                            for name in ("artifact_id", "kind", "quality", "scope")
                        ],
                    }
                ],
                "resources": [],
            },
            (
                {
                    "finding_id": VALID_FINDING_ID,
                    "details": {"kind": "hidden-plugin-property"},
                    "evidence": [
                        {
                            "artifact_id": VALID_ARTIFACT_ID,
                            "locator": "private:7",
                        }
                    ],
                    "basis": {
                        "kind": "observed_capture_vector",
                        "provenance": "observed",
                        "quality": "exact",
                        "capture_ranges": [
                            {
                                "scope": "node-a",
                                "evidence": [
                                    {
                                        "artifact_id": VALID_ARTIFACT_ID,
                                        "locator": "private:7",
                                    }
                                ],
                            }
                        ],
                    },
                },
            ),
        )

        finding = projected[0]
        self.assertEqual(finding["details"], {})
        self.assertEqual(finding["evidence"], [{"artifact_id": VALID_ARTIFACT_ID}])
        self.assertEqual(finding["basis"]["kind"], "observed_capture_vector")
        self.assertEqual(finding["basis"]["quality"], "exact")
        self.assertEqual(
            finding["basis"]["capture_ranges"][0]["scope"],
            "node-a",
        )
        self.assertNotIn("locator", json.dumps(finding))

    def test_consistency_resource_references_fail_closed_without_coercion(
        self,
    ) -> None:
        private_marker = "opaque-driver-key-must-not-cross"
        valid_reference = {
            "resource_id": "node-x/forwarding/INTERFACE/abc",
            "typed_resource_key": {
                "namespace": "driver",
                "parts": [{"name": "opaque", "value": private_marker}],
            },
        }
        cases = (
            (
                "list",
                [valid_reference],
                [{"resource_id": valid_reference["resource_id"]}],
            ),
            (
                "tuple",
                (valid_reference,),
                [{"resource_id": valid_reference["resource_id"]}],
            ),
            ("mapping", valid_reference, []),
            ("scalar", private_marker, []),
            (
                "malformed-items",
                [
                    {"resource_id": {"private": private_marker}},
                    {"resource_id": 7},
                    {"resource_id": True},
                    {"resource_id": ""},
                    {"typed_resource_key": {"private": private_marker}},
                    private_marker,
                ],
                [],
            ),
        )

        for name, references, expected in cases:
            with self.subTest(name=name):
                projected = project_consistency_findings_for_client(
                    {"kind_descriptors": []},
                    (
                        {
                            "finding_id": VALID_FINDING_ID,
                            "resource_references": references,
                        },
                    ),
                )
                serialized = json.dumps(projected)
                self.assertEqual(projected[0]["resource_references"], expected)
                self.assertNotIn("typed_resource_key", serialized)
                self.assertNotIn(private_marker, serialized)

    def test_consistency_resources_and_unknown_fields_fail_closed(self) -> None:
        private_marker = "private-typed-resource-atom"
        projected = project_consistency_findings_for_client(
            {"kind_descriptors": []},
            (
                {
                    "finding_id": VALID_FINDING_ID,
                    "resources": [
                        "node-x/forwarding/INTERFACE/abc",
                        {"typed_resource_key": {"value": private_marker}},
                        7,
                        True,
                        "",
                    ],
                    "resource_references": [],
                    "private_extension": {
                        "typed_resource_key": {"value": private_marker}
                    },
                },
            ),
        )

        serialized = json.dumps(projected)
        self.assertEqual(
            projected,
            [
                {
                    "finding_id": VALID_FINDING_ID,
                    "resources": ["node-x/forwarding/INTERFACE/abc"],
                    "resource_references": [],
                }
            ],
        )
        self.assertNotIn(private_marker, serialized)
        self.assertNotIn("private_extension", serialized)

    def test_consistency_known_fields_reject_private_malformed_shapes(self) -> None:
        private_marker = "private-known-field-atom"
        private_value = {"typed_resource_key": {"parts": [{"value": private_marker}]}}
        projected = project_consistency_findings_for_client(
            {"kind_descriptors": []},
            (
                {
                    "finding_id": private_value,
                    "summary": private_value,
                    "details": [private_marker],
                    "resources": [],
                    "resource_references": [],
                    "producer": {
                        "plugin_id": private_value,
                        "roles": [private_value],
                        "unknown": private_value,
                    },
                    "basis": {
                        "kind": private_value,
                        "capture_ranges": [
                            {"scope": private_value, "private": private_value}
                        ],
                        "selector": {"kind": private_value},
                    },
                    "evidence": [
                        {"artifact_id": private_value, "locator": private_value}
                    ],
                },
            ),
        )

        serialized = json.dumps(projected)
        self.assertNotIn(private_marker, serialized)
        self.assertNotIn("finding_id", projected[0])
        self.assertNotIn("summary", projected[0])
        self.assertEqual(projected[0]["details"], {})
        self.assertEqual(projected[0]["producer"], {"roles": []})
        self.assertEqual(projected[0]["evidence"], [])
        self.assertEqual(projected[0]["basis"]["capture_ranges"], [])

    def test_consistency_known_string_slots_enforce_exact_public_domains(self) -> None:
        projected = project_consistency_findings_for_client(
            {"kind_descriptors": [], "resources": []},
            (
                {
                    "finding_id": "sha256:" + ("G" * 64),
                    "execution_plan_digest": "sha256:" + ("z" * 64),
                    "rule_id": "rule.valid",
                    "summary": "summary remains open text",
                    "severity": "severe",
                    "result": "maybe",
                    "provenance": "guessed",
                    "quality": "certain",
                    "evidence": [
                        {
                            "artifact_id": "not-a-uuid",
                            "raw_timestamp_ns": "01",
                            "excerpt_sha256": "F" * 64,
                        }
                    ],
                    "basis": {
                        "kind": "vendor_basis",
                        "requested_time_ns": "+1",
                        "resolved_at_min_ns": str(1 << 63),
                        "provenance": "guessed",
                        "quality": "certain",
                        "capture_ranges": [],
                        "node_resolutions": [
                            {"node_id": "node-a", "quality": "certain"}
                        ],
                        "selector": {
                            "kind": "wall_clock",
                            "time_ns": "01",
                            "clock_policy": "relaxed",
                        },
                        "watermark": {
                            "local_time_ns": "01",
                            "clock_domain": "clock-a",
                            "provenance": "guessed",
                            "quality": "certain",
                            "scope": {},
                            "evidence": [],
                        },
                    },
                    "producer": {
                        "plugin_id": "plugin-a",
                        "plan_digest": "sha256:" + ("Z" * 64),
                        "configuration_digest": "sha256:" + ("x" * 63),
                        "schema_digest": "md5:" + ("a" * 64),
                        "registered_execution_identity": "sha256:invalid",
                        "package_hash": "sha1:" + ("a" * 64),
                        "capability": "status_parse",
                        "roles": ["revision_consistency"],
                    },
                },
            ),
        )

        finding = projected[0]
        self.assertEqual(finding["rule_id"], "rule.valid")
        self.assertEqual(finding["summary"], "summary remains open text")
        for field in (
            "finding_id",
            "execution_plan_digest",
            "severity",
            "result",
            "provenance",
            "quality",
        ):
            self.assertNotIn(field, finding)
        self.assertEqual(finding["evidence"], [])
        self.assertNotIn("kind", finding["basis"])
        self.assertNotIn("requested_time_ns", finding["basis"])
        self.assertEqual(finding["basis"]["node_resolutions"], [])
        self.assertNotIn("kind", finding["basis"]["selector"])
        self.assertNotIn("time_ns", finding["basis"]["selector"])
        self.assertNotIn("local_time_ns", finding["basis"]["watermark"])
        self.assertEqual(
            finding["producer"],
            {"plugin_id": "plugin-a", "roles": ["revision_consistency"]},
        )

    def test_consistency_projection_does_not_traverse_resources(self) -> None:
        class ResourcesMustNotBeRead:
            def __iter__(self):
                raise AssertionError("consistency projection traversed resources")

        projected = project_consistency_findings_for_client(
            {
                "kind_descriptors": [
                    {
                        "kind": "INTERFACE",
                        "properties": [{"name": "secret", "sensitive": True}],
                    }
                ],
                "resources": ResourcesMustNotBeRead(),
            },
            (
                {
                    "finding_id": VALID_FINDING_ID,
                    "details": {"secret": "hidden", "visible": "kept"},
                },
            ),
        )

        self.assertEqual(
            projected,
            [{"finding_id": VALID_FINDING_ID, "details": {"visible": "kept"}}],
        )

    def test_consistency_projection_does_not_traverse_unknown_structural_branches(
        self,
    ) -> None:
        class UnknownBranchMustNotBeRead(dict):
            def items(self):
                raise AssertionError("unknown consistency branch was traversed")

        private = UnknownBranchMustNotBeRead({"marker": "private"})
        projected = project_consistency_findings_for_client(
            {"kind_descriptors": [], "resources": []},
            (
                {
                    "finding_id": VALID_FINDING_ID,
                    "basis": {
                        "kind": "observed_capture_vector",
                        "private_extension": private,
                    },
                    "producer": {
                        "plugin_id": "plugin-a",
                        "private_extension": private,
                    },
                    "resource_references": [
                        {
                            "resource_id": "resource-a",
                            "private_extension": private,
                        }
                    ],
                },
            ),
        )

        self.assertEqual(projected[0]["basis"]["kind"], "observed_capture_vector")
        self.assertEqual(
            projected[0]["producer"], {"plugin_id": "plugin-a", "roles": []}
        )
        self.assertEqual(
            projected[0]["resource_references"],
            [{"resource_id": "resource-a"}],
        )

    def test_client_bootstrap_uses_consistency_reference_projection(self) -> None:
        dataset = self.dataset()
        private_marker = "bootstrap-private-resource-key"
        dataset["findings"] = [
            {
                "finding_id": VALID_FINDING_ID,
                "resource_references": (
                    {
                        "resource_id": "node-x/forwarding/INTERFACE/abc",
                        "typed_resource_key": {
                            "namespace": "driver",
                            "parts": [{"name": "opaque", "value": private_marker}],
                        },
                    },
                ),
            }
        ]
        dataset["consistency_materialization"] = {
            "schema_version": "router_dump_analyzer.consistency_materialization.v1",
            "status": "not_materialized",
            "plan_digest": None,
            "basis_digest": None,
            "provider_count": private_marker,
            "finding_count": 1,
            "diagnostic_count": None,
            "emitted_finding_count": None,
            "emitted_diagnostic_count": None,
            "duplicate_findings_discarded": None,
            "duplicate_diagnostics_discarded": None,
            "world_reads": None,
            "basis": None,
            "providers": None,
            "private_extension": private_marker,
        }

        client = static_data_service(dataset).client_dataset()
        serialized = json.dumps(client)

        self.assertEqual(
            client["findings"][0]["resource_references"],
            [{"resource_id": "node-x/forwarding/INTERFACE/abc"}],
        )
        self.assertNotIn("typed_resource_key", serialized)
        self.assertNotIn(private_marker, serialized)
        self.assertNotIn(
            "provider_count",
            client["consistency_materialization"],
        )
        self.assertEqual(
            client["consistency_materialization"],
            project_consistency_materialization_for_client(
                dataset["consistency_materialization"]
            ),
        )

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

    def test_nested_event_records_use_explicit_client_allowlists(self) -> None:
        dataset = self.dataset()
        resource_id = dataset["resources"][0]["resource_id"]
        dataset["events"] = [
            {
                "event_uid": "nested-event-allowlist",
                "timestamp_ns": "10",
                "action": "modify",
                "outcome": "success",
                "resource": {"secret": "event-core-container-marker"},
                "affected_resources": [
                    {
                        "resource_id": resource_id,
                        "resource_kind": "INTERFACE",
                        "secret": "affected-sensitive-marker",
                        "private_extension": "affected-private-marker",
                    }
                ],
                "subject": {
                    "resource_id": resource_id,
                    "resource_kind": "INTERFACE",
                    "label": {"secret": "subject-core-container-marker"},
                    "private_extension": "subject-private-marker",
                },
                "effects": [
                    {
                        "resource_id": resource_id,
                        "resource_kind": "INTERFACE",
                        "label": {"secret": "effect-core-container-marker"},
                        "after": {
                            "oper_status": "down",
                            "secret": "effect-sensitive-marker",
                        },
                        "private_extension": "effect-private-marker",
                    }
                ],
                "relationship_effects": [
                    {
                        "operation": "add",
                        "relation_type": "depends_on",
                        "source": resource_id,
                        "target": resource_id,
                        "type": {"secret": "relationship-core-container-marker"},
                        "private_extension": "relationship-private-marker",
                    }
                ],
            }
        ]

        service = static_data_service(dataset)
        client_event = service.client_dataset()["events"][0]
        range_event = service.range_summary(10, 10)["events"][0]

        for projected in (client_event, range_event):
            self.assertEqual(
                projected["affected_resources"],
                [
                    {
                        "resource_id": resource_id,
                        "resource_kind": "INTERFACE",
                    }
                ],
            )
            self.assertEqual(
                projected["subject"],
                {
                    "resource_id": resource_id,
                    "resource_kind": "INTERFACE",
                },
            )
            self.assertEqual(
                projected["effects"][0]["after"],
                {"oper_status": "down"},
            )
            self.assertEqual(
                projected["relationship_effects"][0],
                {
                    "operation": "add",
                    "relation_type": "depends_on",
                    "source": resource_id,
                    "target": resource_id,
                },
            )
            serialized = json.dumps(projected)
            for marker in (
                "affected-sensitive-marker",
                "affected-private-marker",
                "event-core-container-marker",
                "subject-private-marker",
                "subject-core-container-marker",
                "effect-sensitive-marker",
                "effect-private-marker",
                "effect-core-container-marker",
                "relationship-private-marker",
                "relationship-core-container-marker",
            ):
                self.assertNotIn(marker, serialized)

    def test_sensitive_condition_cannot_be_promoted_into_public_status(self) -> None:
        dataset = self.dataset()
        descriptor = dataset["kind_descriptors"][0]
        descriptor["condition_field"] = "secret"
        dataset["state_intervals"][0]["status"] = "classified-condition"
        dataset["state_intervals"][0]["properties"]["secret"] = "classified-condition"
        dataset["events"] = [
            {
                "event_uid": "sensitive-condition-event",
                "timestamp_ns": "10",
                "action": "modify",
                "outcome": "success",
                "status": "classified-condition",
                "condition": "classified-condition",
                "condition_class": "healthy",
                "affected_resources": ["node-x/INTERFACE/1"],
                "subjects": [
                    {
                        "resource_id": "node-x/INTERFACE/1",
                        "resource_kind": "INTERFACE",
                    }
                ],
            }
        ]

        service = static_data_service(dataset)
        view = service.resource_state_at("node-x/INTERFACE/1", 10)
        client = service.client_dataset()

        self.assertEqual(view["status"], "unknown")
        self.assertEqual(client["state_intervals"][0]["status"], "unknown")
        self.assertEqual(client["events"][0]["status"], "unknown")
        self.assertEqual(client["events"][0]["condition"], "unknown")
        self.assertEqual(client["events"][0]["condition_class"], "healthy")
        self.assertNotIn("classified-condition", json.dumps(client))

    def test_range_histograms_preserve_core_action_on_property_collision(
        self,
    ) -> None:
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
                "result": {"action": "sensitive-state-action"},
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

        self.assertEqual(
            summary["counts"]["by_action"],
            {"classified-action": 1},
        )
        self.assertNotIn("sensitive-state-action", json.dumps(summary))

    def test_sensitive_property_names_cannot_delete_core_envelope_fields(
        self,
    ) -> None:
        marker = "DECLARED-SENSITIVE-MARKER"
        collisions = (
            "revision_id",
            "label",
            "node_id",
            "capabilities",
            "events",
            "resources",
            "kind_descriptors",
            "demo",
            "action",
            "status_class",
            "key",
            "resource",
            "source",
            "target",
            "operation",
            "valid_from_ns",
        )
        for name in collisions:
            with self.subTest(name=name):
                dataset = self.dataset()
                dataset["demo"]["label"] = "Demo label"
                dataset["kind_descriptors"][0]["label"] = "Interface schema label"
                dataset["nodes"] = [
                    {
                        "node_id": "node-x",
                        "label": "Topology node label",
                        "state": {name: marker},
                    }
                ]
                dataset["kind_descriptors"][0]["properties"].append(
                    {"name": name, "sensitive": True}
                )
                dataset["resources"][0]["state"][name] = marker
                dataset["state_intervals"][0]["properties"][name] = marker
                client = static_data_service(dataset).client_dataset()

                self.assertEqual(
                    client["workspace"]["revision_id"],
                    "revision-x",
                )
                self.assertEqual(client["workspace"]["node_id"], "node-x")
                self.assertIn("label", client["workspace"])
                self.assertIn("capabilities", client["workspace"])
                self.assertIn("events", client)
                self.assertIn("resources", client)
                self.assertIn("kind_descriptors", client)
                self.assertIn("demo", client)
                self.assertEqual(
                    client["demo"]["revision_id"],
                    "revision-x",
                )
                self.assertEqual(client["demo"]["label"], "Demo label")
                self.assertEqual(
                    client["kind_descriptors"][0]["label"],
                    "Interface schema label",
                )
                self.assertEqual(
                    client["nodes"][0]["node_id"],
                    "node-x",
                )
                self.assertEqual(
                    client["nodes"][0]["label"],
                    "Topology node label",
                )
                self.assertEqual(
                    client["lifecycle_intervals"][0]["resource"],
                    "node-x/INTERFACE/1",
                )
                self.assertNotIn(marker, json.dumps(client))

    def test_seeded_adversarial_projection_matrix_preserves_core_envelopes(
        self,
    ) -> None:
        rng = random.Random(0xC0DEC)
        collisions = (
            "action",
            "affected_resources",
            "capabilities",
            "condition",
            "demo",
            "event_uid",
            "events",
            "kind",
            "kind_descriptors",
            "label",
            "layer",
            "node_id",
            "operation",
            "resource",
            "resource_id",
            "resources",
            "revision_id",
            "source",
            "status",
            "status_class",
            "target",
            "timestamp_ns",
            "valid_from_ns",
        )

        def nested_payload(
            *,
            path: tuple[str, str],
            marker: str,
            literal_marker: str,
            collision: str,
            collision_marker: str,
            wrapper: str,
        ) -> dict:
            nested = {
                path[0]: {
                    path[1]: marker,
                    "public": "kept",
                },
                ".".join(path): literal_marker,
                collision: collision_marker,
            }
            distractors = [
                {"public": f"left-{wrapper}"},
                nested,
                [{"public": f"deep-{wrapper}"}, copy.deepcopy(nested)],
            ]
            rng.shuffle(distractors)
            return {wrapper: distractors}

        def client_envelope(client: dict) -> dict:
            resource = client["resources"][0]
            event = client["events"][0]
            lifecycle = client["lifecycle_intervals"][0]
            node = client["nodes"][0]
            return {
                "workspace_revision_id": client["workspace"]["revision_id"],
                "workspace_node_id": client["workspace"]["node_id"],
                "workspace_capabilities": client["workspace"]["capabilities"],
                "demo_revision_id": client["demo"]["revision_id"],
                "demo_label": client["demo"]["label"],
                "resource_id": resource["resource_id"],
                "resource_kind": resource["kind"],
                "resource_layer": resource["layer"],
                "resource_label": resource["label"],
                "event_uid": event["event_uid"],
                "event_timestamp_ns": event["timestamp_ns"],
                "event_action": event["action"],
                "event_outcome": event["outcome"],
                "event_affected_resources": event["affected_resources"],
                "lifecycle_resource": lifecycle["resource"],
                "lifecycle_valid_from_ns": lifecycle["valid_from_ns"],
                "node_id": node["node_id"],
                "node_label": node["label"],
            }

        def state_envelope(view: dict) -> dict:
            return {
                "resource_id": view["resource_id"],
                "kind": view["kind"],
                "layer": view["layer"],
                "label": view["label"],
                "exists": view["exists"],
                "status": view["status"],
                "status_class": view["status_class"],
                "valid_from_ns": view["valid_from_ns"],
            }

        for case in range(32):
            collision = collisions[case % len(collisions)]
            path = (
                f"scope_{rng.randrange(7)}",
                f"private_{rng.randrange(11)}",
            )
            hidden_path = (
                f"scope_{rng.randrange(7)}",
                f"hidden_{rng.randrange(11)}",
            )
            wrapper = f"payload_{rng.randrange(13)}"
            marker = f"SENSITIVE-MARKER-{case:02d}"
            literal_marker = f"LITERAL-DOTTED-MARKER-{case:02d}"
            hidden_marker = f"CLIENT-HIDDEN-MARKER-{case:02d}"
            collision_marker = f"COLLISION-MARKER-{case:02d}"

            baseline = self.dataset()
            baseline["demo"]["label"] = "Adversarial demo"
            baseline["nodes"] = [
                {
                    "node_id": "node-x",
                    "label": "Topology node",
                    "state": {},
                }
            ]
            baseline["events"] = [
                {
                    "event_uid": f"event-{case:02d}",
                    "timestamp_ns": "10",
                    "action": "modify",
                    "outcome": "success",
                    "affected_resources": ["node-x/INTERFACE/1"],
                    "subjects": [
                        {
                            "resource_id": "node-x/INTERFACE/1",
                            "resource_kind": "INTERFACE",
                        }
                    ],
                    "effects": [
                        {
                            "resource_id": "node-x/INTERFACE/1",
                            "resource_kind": "INTERFACE",
                            "after": {},
                        }
                    ],
                    "result": {},
                }
            ]
            adversarial = copy.deepcopy(baseline)
            descriptor = adversarial["kind_descriptors"][0]
            descriptor["properties"].extend(
                (
                    {
                        "name": ".".join(path),
                        "sensitive": True,
                    },
                    {
                        "name": ".".join(hidden_path),
                        "client_visible": False,
                    },
                    {
                        "name": collision,
                        "sensitive": True,
                    },
                    {
                        "name": wrapper,
                        "client_visible": True,
                    },
                )
            )
            payload = nested_payload(
                path=path,
                marker=marker,
                literal_marker=literal_marker,
                collision=collision,
                collision_marker=collision_marker,
                wrapper=wrapper,
            )
            hidden_payload = nested_payload(
                path=hidden_path,
                marker=hidden_marker,
                literal_marker=hidden_marker,
                collision=collision,
                collision_marker=collision_marker,
                wrapper=wrapper,
            )
            payload[wrapper].extend(hidden_payload[wrapper])
            adversarial["resources"][0]["state"].update(copy.deepcopy(payload))
            adversarial["resources"][0]["key"] = copy.deepcopy(payload)
            adversarial["state_intervals"][0]["properties"].update(
                copy.deepcopy(payload)
            )
            adversarial["nodes"][0]["state"] = copy.deepcopy(payload)
            event = adversarial["events"][0]
            event["result"] = copy.deepcopy(payload)
            event["effects"][0]["after"] = copy.deepcopy(payload)

            baseline_service = static_data_service(baseline)
            adversarial_service = static_data_service(adversarial)
            baseline_client = baseline_service.client_dataset()
            adversarial_client = adversarial_service.client_dataset()
            baseline_state = baseline_service.resource_state_at(
                "node-x/INTERFACE/1",
                10,
            )
            adversarial_state = adversarial_service.resource_state_at(
                "node-x/INTERFACE/1",
                10,
            )
            baseline_resources = baseline_service.resources_at(10)
            adversarial_resources = adversarial_service.resources_at(10)
            baseline_range = baseline_service.range_summary(10, 10)
            adversarial_range = adversarial_service.range_summary(10, 10)

            with self.subTest(
                case=case,
                collision=collision,
                path=".".join(path),
            ):
                self.assertEqual(
                    client_envelope(adversarial_client),
                    client_envelope(baseline_client),
                )
                self.assertEqual(
                    state_envelope(adversarial_state),
                    state_envelope(baseline_state),
                )
                self.assertEqual(
                    state_envelope(adversarial_resources["items"][0]),
                    state_envelope(baseline_resources["items"][0]),
                )
                self.assertEqual(
                    adversarial_range["events"][0]["event_uid"],
                    baseline_range["events"][0]["event_uid"],
                )
                self.assertEqual(
                    adversarial_range["events"][0]["action"],
                    baseline_range["events"][0]["action"],
                )
                self.assertEqual(
                    adversarial_range["events"][0]["affected_resources"],
                    baseline_range["events"][0]["affected_resources"],
                )
                for projection in (
                    adversarial_client,
                    adversarial_state,
                    adversarial_resources,
                    adversarial_range,
                ):
                    serialized = json.dumps(projection, sort_keys=True)
                    self.assertNotIn(marker, serialized)
                    self.assertNotIn(literal_marker, serialized)
                    self.assertNotIn(hidden_marker, serialized)
                    self.assertNotIn(collision_marker, serialized)

    def test_dotted_and_metadata_secrets_never_reach_public_views(self) -> None:
        marker = "DECLARED-SENSITIVE-MARKER"
        hidden_marker = "CLIENT-HIDDEN-MARKER"
        dataset = self.dataset()
        descriptor = dataset["kind_descriptors"][0]
        descriptor["key_fields"] = ["cfg.visible"]
        descriptor["properties"].extend(
            (
                {"name": "cfg.token", "sensitive": True},
                {"name": "cfg.private", "client_visible": False},
                {"name": "cfg.visible", "client_visible": True},
                {"name": "token", "sensitive": True},
            )
        )
        resource = dataset["resources"][0]
        resource["key"] = {
            "cfg": {
                "token": marker,
                "private": hidden_marker,
                "visible": "visible-key",
            }
        }
        resource["state"]["cfg"] = {
            "token": marker,
            "private": hidden_marker,
            "visible": "visible-state",
        }
        resource["evidence"] = {
            "artifact_id": "artifact-1",
            "locator": "line:1",
            "token": marker,
        }
        resource["provenance"] = {
            "plugin_run_id": "run-1",
            "token": marker,
        }
        resource["unknown_fields"] = [
            {
                "name": "cfg.token",
                "reason_code": "not-observed",
                "token": marker,
            }
        ]
        resource["incarnation"] = {"token": marker}
        interval = dataset["state_intervals"][0]
        interval["properties"]["cfg"] = {
            "token": marker,
            "private": hidden_marker,
            "visible": "visible-state",
        }
        dataset["events"] = [
            {
                "event_uid": "dotted-secret-event",
                "timestamp_ns": "10",
                "source_sequence": 1,
                "kind": "device_observation",
                "action": "modify",
                "outcome": "success",
                "affected_resources": [resource["resource_id"]],
                "result": {
                    "cfg": {
                        "token": marker,
                        "private": hidden_marker,
                        "visible": "visible-result",
                    }
                },
                "effects": [
                    {
                        "resource_id": resource["resource_id"],
                        "resource_kind": "INTERFACE",
                        "after": {
                            "cfg": {
                                "token": marker,
                                "private": hidden_marker,
                                "visible": "visible-effect",
                            }
                        },
                    }
                ],
            }
        ]

        service = static_data_service(dataset)
        resource_view = service.resource_state_at(
            resource["resource_id"],
            10,
        )
        resources_view = service.resources_at(10)
        projections = (
            service.client_dataset(),
            resource_view,
            resources_view,
            service.range_summary(10, 10),
        )

        for projection in projections:
            self.assertNotIn(marker, json.dumps(projection))
            self.assertNotIn(hidden_marker, json.dumps(projection))
        self.assertEqual(
            resource_view["key"],
            {"cfg": {"visible": "visible-key"}},
        )
        self.assertEqual(
            resource_view["state"]["cfg"],
            {"visible": "visible-state"},
        )
        self.assertEqual(
            resource_view["resource"]["evidence"],
            {
                "artifact_id": "artifact-1",
                "locator": "line:1",
            },
        )
        self.assertNotIn("incarnation", resource_view["resource"])

    def test_affected_resource_kinds_override_generic_event_kind(self) -> None:
        marker = "KIND-B-SENSITIVE-MARKER"
        dataset = self.dataset()
        dataset["kind_descriptors"] = [
            {
                "kind": "A",
                "properties": [
                    {"name": "a_secret", "sensitive": True},
                ],
            },
            {
                "kind": "B",
                "properties": [
                    {"name": "b_secret", "sensitive": True},
                ],
            },
        ]
        dataset["resources"] = [
            {
                "resource_id": "node-x/A/1",
                "kind": "A",
                "layer": "test",
                "state": {},
            },
            {
                "resource_id": "node-x/B/1",
                "kind": "B",
                "layer": "test",
                "state": {},
            },
        ]
        dataset["lifecycle_intervals"] = [
            {
                "resource": "node-x/A/1",
                "valid_from_ns": "0",
                "valid_to_ns": None,
            },
            {
                "resource": "node-x/B/1",
                "valid_from_ns": "0",
                "valid_to_ns": None,
            },
        ]
        dataset["state_intervals"] = []
        dataset["events"] = [
            {
                "event_uid": "mixed-kind-event",
                "timestamp_ns": "10",
                "kind": "A",
                "action": "modify",
                "outcome": "success",
                "affected_resources": ["node-x/B/1"],
                "subjects": [
                    {
                        "resource_id": "node-x/A/1",
                        "resource_kind": "A",
                    }
                ],
                "result": {"b_secret": marker},
            }
        ]

        service = static_data_service(dataset)
        client = service.client_dataset()
        summary = service.range_summary(10, 10)

        self.assertEqual(client["events"][0]["kind"], "A")
        self.assertNotIn(marker, json.dumps(client))
        self.assertNotIn(marker, json.dumps(summary))

    def test_invalid_or_property_colliding_status_class_fails_closed(
        self,
    ) -> None:
        marker = "STATUS-CLASS-SENSITIVE-MARKER"
        dataset = self.dataset()
        dataset["kind_descriptors"][0]["properties"].append(
            {"name": "status_class", "sensitive": True}
        )
        dataset["state_intervals"][0]["status_class"] = marker
        dataset["state_intervals"][0]["properties"]["status_class"] = marker

        service = static_data_service(dataset)
        view = service.resource_state_at("node-x/INTERFACE/1", 10)
        client = service.client_dataset()

        self.assertEqual(view["status_class"], "unknown")
        self.assertNotIn(marker, json.dumps(view))
        self.assertNotIn(marker, json.dumps(client))

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
