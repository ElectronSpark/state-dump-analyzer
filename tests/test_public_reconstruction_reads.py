from __future__ import annotations

import unittest
from types import SimpleNamespace

from router_dump_analyzer.plugin_api import PropertyPatch, StatusPerspectiveRef
from tests.support.normalized_data import static_data_service
from tests.test_reconstruction_boundaries import _dataset
from tests.test_revision_world import _relationship, _resource, _snapshot


def _services(dataset):
    records = dataset["resources"]
    by_id = {record["resource_id"]: record for record in records}
    runtime = SimpleNamespace(
        resources=records,
        resource_by_id=by_id,
        lifecycle_by_resource={
            identifier: [
                item for item in dataset["lifecycle_intervals"]
                if item["resource"] == identifier
            ]
            for identifier in by_id
        },
        state_by_resource={
            identifier: [
                item for item in dataset["state_intervals"]
                if item["resource"] == identifier
            ]
            for identifier in by_id
        },
    )
    for indexed, history in ((False, None), (True, runtime)):
        dataset["_scale_runtime"] = history
        yield indexed, static_data_service(dataset)


class PublicReconstructionReadTests(unittest.TestCase):
    def test_missing_perspective_does_not_publish_nested_other_perspective_state(self):
        resource = _resource("perspective")
        selected = StatusPerspectiveRef("p")
        dataset = _dataset(snapshots=(
            _snapshot(
                resource, 10, PropertyPatch(set_values={"value": "p-only"}),
                locator="p", perspective_ref=selected,
            ),
        ))
        dataset["kind_descriptors"][0]["properties"] = [{"name": "value"}]
        identifier = dataset["resources"][0]["resource_id"]
        for indexed, service in _services(dataset):
            with self.subTest(indexed=indexed):
                present = service.resource_state_at(
                    identifier, 20, perspective_ref=selected
                )
                self.assertTrue(present["exists"])
                self.assertEqual(present["state"], {"value": "p-only"})
                missing = service.resource_state_at(
                    identifier, 20, perspective_ref=StatusPerspectiveRef("q")
                )
                self.assertIsNone(missing["exists"])
                self.assertEqual(missing["state"], {})
                self.assertEqual(missing["status"], "unknown")
                self.assertEqual(missing["quality"], "unknown")
                self.assertEqual(missing["resource"]["state"], {})
                self.assertEqual(missing["resource"]["status"], "unknown")
                self.assertEqual(missing["resource"]["status_class"], "unknown")

    def test_endpoint_only_placeholders_have_unknown_not_absent_lifecycle(self):
        dataset = _dataset(relationships=(
            _relationship(
                _resource("a"), _resource("b"), "link", 10, True,
                PropertyPatch(), locator="link",
            ),
        ))
        self.assertTrue(all(record["placeholder"] for record in dataset["resources"]))
        self.assertEqual(dataset["lifecycle_intervals"], [])
        for indexed, service in _services(dataset):
            with self.subTest(indexed=indexed):
                rows = service.resources_at(20)["items"]
                self.assertEqual(len(rows), 2)
                for row in rows:
                    self.assertIsNone(row["exists"])
                    self.assertEqual(row["state"], {})
                    self.assertEqual(row["status"], "unknown")
                    self.assertEqual(row["status_class"], "unknown")
                    self.assertEqual(row["quality"], "unknown")
                    self.assertEqual(row["unknown_fields"], [
                        {"name": "*", "reason_code": "lifecycle_evidence_missing"}
                    ])

    def test_known_lifecycle_preserves_pre_creation_and_post_deletion_absence(self):
        dataset = _dataset(snapshots=(
            _snapshot(_resource("known"), 10, PropertyPatch(), locator="known"),
        ))
        dataset["lifecycle_intervals"][0]["valid_to_ns"] = "30"
        identifier = dataset["resources"][0]["resource_id"]
        for indexed, service in _services(dataset):
            for timestamp, expected in ((9, False), (10, True), (29, True), (30, False)):
                with self.subTest(indexed=indexed, timestamp=timestamp):
                    view = service.resource_state_at(identifier, timestamp)
                    self.assertIs(view["exists"], expected)
                    if not expected:
                        self.assertEqual(view["status"], "absent")
                        self.assertEqual(view["status_class"], "absent")
                        missing = service.resource_state_at(
                            identifier, timestamp,
                            perspective_ref=StatusPerspectiveRef("missing"),
                        )
                        self.assertFalse(missing["exists"])
                        self.assertEqual(missing["status"], "absent")

    def test_ordinary_normalization_builds_intervals_before_any_query(self):
        dataset = _dataset(snapshots=tuple(
            _snapshot(_resource(name), time, PropertyPatch(), locator=name)
            for name, time in (("a", 10), ("b", 20))
        ))
        self.assertEqual(len(dataset["resources"]), 2)
        self.assertIsInstance(dataset["state_intervals"], list)
        self.assertEqual(len(dataset["state_intervals"]), 2)
        self.assertEqual(len(dataset["lifecycle_intervals"]), 2)

    def test_declared_history_gap_does_not_fall_back_to_a_future_snapshot(self):
        resource = _resource("gap")
        dataset = _dataset(snapshots=(
            _snapshot(
                resource, 10, PropertyPatch(set_values={"value": "past"}),
                locator="past",
            ),
            _snapshot(
                resource, 30, PropertyPatch(set_values={"value": "future"}),
                locator="future",
            ),
        ))
        dataset["kind_descriptors"][0]["properties"] = [{"name": "value"}]
        dataset["state_intervals"][0]["valid_to_ns"] = "20"
        identifier = dataset["resources"][0]["resource_id"]
        for indexed, service in _services(dataset):
            with self.subTest(indexed=indexed):
                self.assertEqual(
                    service.resource_state_at(identifier, 15)["state"], {"value": "past"}
                )
                self.assertEqual(
                    service.resource_state_at(identifier, 30)["state"], {"value": "future"}
                )
                gap = service.resource_state_at(identifier, 25)
                self.assertTrue(gap["exists"])
                self.assertEqual(gap["state"], {})
                self.assertEqual(gap["status"], "unknown")
                self.assertEqual(gap["quality"], "unknown")
                self.assertEqual(gap["resource"]["state"], {})
                self.assertEqual(gap["resource"]["status"], "unknown")
                self.assertEqual(gap["unknown_fields"], [
                    {"name": "*", "reason_code": "state_history_gap"}
                ])


if __name__ == "__main__":
    unittest.main()
