"""Explicit temporal history-index selection and provider wiring regressions."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer.normalized_data import NormalizedDataService
from router_dump_analyzer.temporal_topology import TemporalTopologyService
from tests.support.normalized_data import StaticDataPolicy, StaticDatasetSource
from tests.test_temporal_snapshot_selection import _event, _fixture


class ExplicitIndexSource(StaticDatasetSource):
    def __init__(self, dataset, index):
        super().__init__(dataset)
        self.index = index
        self.index_requests = []
        self.revision_store = SimpleNamespace(default_revision_id="test/revision")

    def indexed_history(self, dataset):
        self.index_requests.append(dataset)
        return self.index


def temporal_fixture():
    dataset, _, template, identifier = _fixture(
        [(10, {"x": "initial"}, "observed"), (40, {"x": "later"}, "observed")],
        indexed=True,
        events=[
            _event("first", 20, 1, {"x": "first"}),
            _event("second", 30, 2, {"x": "second"}),
        ],
    )
    index = dataset.pop("_scale_runtime")
    relationship = {
        "relationship_id": "link",
        "source": identifier,
        "target": identifier,
        "relation_type": "connects",
        "valid_from_ns": "10",
        "valid_to_ns": None,
        "present": True,
    }
    mutation = {
        "mutation_id": "add-link",
        "source": identifier,
        "target": identifier,
        "relation_type": "connects",
        "effective_time_ns": "15",
        "source_sequence": 0,
        "operation": "create",
    }
    dataset["relationship_intervals"] = [relationship]
    dataset["relationship_mutations"] = [mutation]
    index.relationships = [relationship]
    index.relationships_by_endpoint = {identifier: [relationship]}
    index.mutations = [mutation]
    index.mutation_times = [15]
    template.contract["topology_projections"][0]["relationship_types"] = ["connects"]
    return dataset, index, template, identifier


def construct(dataset, data, template, **options):
    return TemporalTopologyService(
        dataset,
        data.resource_state_at,
        data.relationships_at,
        contract=template.contract,
        temporal_metadata=template.temporal_metadata,
        perspective_state_reader=lambda rid, time, ref: data.resource_state_at(
            rid, time, perspective_ref=ref
        ),
        **options,
    )


def snapshot_body(identifier):
    return {
        "basis": {"kind": "absolute_time", "time_ns": "45"},
        "projection_id": "p",
        "status_perspective_id": "observed",
        "resource_ids": [identifier],
        "include": ["resources", "relationships"],
    }


def changes_body(identifier):
    return {
        "start_basis": {"kind": "absolute_time", "time_ns": "10"},
        "end_basis": {"kind": "absolute_time", "time_ns": "50"},
        "projection_id": "p",
        "status_perspective_id": "observed",
        "resource_ids": [identifier],
        "change_limit": 2,
    }


class TemporalIndexTests(unittest.TestCase):
    def test_explicit_index_matches_scan_without_a_private_dataset_key(self):
        dataset, index, template, identifier = temporal_fixture()
        services = []
        for selected in (None, index):
            data = NormalizedDataService(
                ExplicitIndexSource(dataset, selected), StaticDataPolicy()
            )
            services.append(
                construct(dataset, data, template, indexed_history=selected)
            )
        scan, indexed = services
        self.assertIs(indexed.runtime, index)
        self.assertNotIn("_scale_runtime", dataset)
        actual = indexed.query(snapshot_body(identifier))
        self.assertEqual(actual, scan.query(snapshot_body(identifier)))
        self.assertEqual(actual["resources"][0]["state"], {"x": "later"})
        self.assertEqual(actual["relationships"][0]["relationship_id"], "link")
        body = changes_body(identifier)
        first = indexed.query_changes(body)
        self.assertEqual(first, scan.query_changes(body))
        self.assertEqual(
            [item["change_id"] for item in first["changes"]],
            ["add-link", "event:first"],
        )
        cursor = first["next_change_cursor"]
        self.assertIsNotNone(cursor)
        tail_body = dict(body, change_cursor=cursor)
        tail = indexed.query_changes(tail_body)
        self.assertEqual(tail, scan.query_changes(tail_body))
        self.assertEqual(
            [item["change_id"] for item in tail["changes"]], ["event:second"]
        )

    def test_omitted_and_none_ignore_a_conflicting_private_key(self):
        dataset, index, template, identifier = temporal_fixture()
        dataset["_scale_runtime"] = object()
        data = NormalizedDataService(
            ExplicitIndexSource(dataset, None), StaticDataPolicy()
        )
        omitted = construct(dataset, data, template)
        explicit_none = construct(dataset, data, template, indexed_history=None)
        selected = construct(dataset, data, template, indexed_history=index)
        self.assertIsNone(omitted.runtime)
        self.assertIsNone(explicit_none.runtime)
        self.assertIs(selected.runtime, index)
        expected = omitted.query(snapshot_body(identifier))
        self.assertEqual(explicit_none.query(snapshot_body(identifier)), expected)
        self.assertEqual(selected.query(snapshot_body(identifier)), expected)

    def test_demo_provider_preserves_source_selected_index_and_absence(self):
        from rsl_demo_plugin.session import DemoTemporalProvider

        for has_index in (False, True):
            for revision in (None, "test/revision"):
                with self.subTest(has_index=has_index, revision=revision):
                    dataset, index, template, identifier = temporal_fixture()
                    dataset["_scale_runtime"] = object()
                    selected = index if has_index else None
                    source = ExplicitIndexSource(dataset, selected)
                    data = NormalizedDataService(source, StaticDataPolicy())
                    with (
                        patch(
                            "rsl_demo_plugin.session.build_demo_plugin_contract",
                            return_value=template.contract,
                        ),
                        patch(
                            "rsl_demo_plugin.session.build_temporal_metadata",
                            return_value=template.temporal_metadata,
                        ),
                    ):
                        service = DemoTemporalProvider(source).for_revision(
                            revision, data
                        )
                    self.assertEqual(len(source.index_requests), 1)
                    self.assertIs(source.index_requests[0], dataset)
                    self.assertIs(service.runtime, selected)
                    self.assertEqual(
                        service.query(snapshot_body(identifier))["resources"][0][
                            "state"
                        ],
                        {"x": "later"},
                    )

    def test_source_index_failure_is_not_silently_downgraded_to_scan(self):
        from rsl_demo_plugin.session import DemoTemporalProvider

        dataset, _, template, _ = temporal_fixture()

        class FailedIndexSource(ExplicitIndexSource):
            def indexed_history(self, dataset):
                raise RuntimeError("history index unavailable")

        source = FailedIndexSource(dataset, None)
        data = NormalizedDataService(source, StaticDataPolicy())
        with (
            patch(
                "rsl_demo_plugin.session.build_demo_plugin_contract",
                return_value=template.contract,
            ),
            patch(
                "rsl_demo_plugin.session.build_temporal_metadata",
                return_value=template.temporal_metadata,
            ),
            self.assertRaisesRegex(RuntimeError, "history index unavailable"),
        ):
            DemoTemporalProvider(source).for_revision("test/revision", data)


if __name__ == "__main__":
    unittest.main()
