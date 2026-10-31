"""Canonical revision selection across generic, catalog, and concurrent reads."""

from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import patch

from router_dump_analyzer.control_plane import ControlPlane
from router_dump_analyzer.ingestion import (
    IngestedDataPolicy,
    IngestedDatasetSource,
    IngestionError,
)
from router_dump_analyzer.management_analysis import _SelectedStore
from router_dump_analyzer.normalized_data import NormalizedDataService
from router_dump_analyzer.process_control import PROCESS_CONTROL_EXCEPTIONS
from router_dump_analyzer.revision_store import AssemblyDescriptor, RevisionDescriptor


class SyntheticAssembly:
    def __init__(self):
        self.descriptors = {
            key: RevisionDescriptor(f"node-{key}", f"revision-{key}", key, 0, 0)
            for key in ("a", "b")
        }
        self.datasets = {
            item.revision_id: {
                "_ingestion": {
                    "revision_id": item.revision_id,
                    "node_id": item.node_id,
                },
                "resources": [],
            }
            for item in self.descriptors.values()
        }

    @property
    def default_revision_id(self):
        return "revision-a"

    @property
    def assembly(self):
        return AssemblyDescriptor("synthetic", tuple(self.descriptors.values()))

    def revision(self, revision_id):
        return next(
            (
                item
                for item in self.descriptors.values()
                if item.revision_id == revision_id
            ),
            None,
        ) or self._missing(revision_id)

    def _missing(self, key):
        raise KeyError(key)

    def revision_for_node(self, node_id):
        return next(
            (item for item in self.descriptors.values() if item.node_id == node_id),
            None,
        ) or self._missing(node_id)

    def dataset_for_revision(self, revision_id):
        return deepcopy(self.datasets[revision_id])

    def dataset_for_node(self, node_id):
        return self.dataset_for_revision(self.revision_for_node(node_id).revision_id)


class CanonicalRevisionIdentityTests(unittest.TestCase):
    def test_nested_revision_scopes_select_restore_and_fail_without_leaking(self):
        source = IngestedDatasetSource(SyntheticAssembly())
        self.assertEqual(source.revision_id(source.load_dataset()), "revision-a")
        with source.revision_scope("revision-b"):
            self.assertEqual(source.revision_id(source.load_dataset()), "revision-b")
            with source.revision_scope("revision-a"):
                self.assertEqual(
                    source.revision_id(source.load_dataset()), "revision-a"
                )
            self.assertEqual(source.revision_id(source.load_dataset()), "revision-b")
            with self.assertRaises(KeyError), source.revision_scope("unknown"):
                self.fail("unknown scope entered")
            self.assertEqual(source.revision_id(source.load_dataset()), "revision-b")
        self.assertEqual(source.revision_id(source.load_dataset()), "revision-a")

    def test_concurrent_member_queries_do_not_exchange_scopes(self):
        source, barrier = IngestedDatasetSource(SyntheticAssembly()), Barrier(2)

        def query(revision):
            with source.revision_scope(revision):
                barrier.wait(timeout=10)
                return source.revision_id(source.load_dataset())

        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(
                list(executor.map(query, ("revision-a", "revision-b"))),
                ["revision-a", "revision-b"],
            )
        with source.revision_scope("revision-b"):
            context = copy_context()
        self.assertEqual(
            context.run(lambda: source.revision_id(source.load_dataset())), "revision-b"
        )
        self.assertEqual(source.revision_id(source.load_dataset()), "revision-a")

    def test_conflicting_and_invalid_member_references_are_rejected(self):
        source = IngestedDatasetSource(SyntheticAssembly())
        with self.assertRaisesRegex(IngestionError, "disagree"):
            source.load_dataset("revision-a", node_id="node-b")
        with (
            source.revision_scope("revision-b"),
            self.assertRaisesRegex(IngestionError, "disagree"),
        ):
            source.load_dataset(node_id="node-a")
        with self.assertRaises(KeyError):
            source.load_dataset("missing")
        with self.assertRaises(KeyError):
            source.load_dataset(unexpected="ignored-before")
        with self.assertRaises(KeyError):
            source.load_dataset(node_id="missing")

    def test_store_dataset_identity_disagreement_fails_closed(self):
        store = SyntheticAssembly()
        source = IngestedDatasetSource(store)
        store.datasets["revision-b"]["_ingestion"]["revision_id"] = "revision-a"
        with self.assertRaisesRegex(IngestionError, "node does not match"):
            source.load_dataset("revision-b")
        store.datasets["revision-b"] = deepcopy(store.datasets["revision-a"])
        with self.assertRaisesRegex(IngestionError, "selected revision"):
            source.load_dataset("revision-b")

    def test_source_evidence_cache_tracks_revision_scope_including_reused_event_ids(
        self,
    ):
        store = SyntheticAssembly()
        for revision, dataset in store.datasets.items():
            dataset["source_records"] = [
                {"matched_event_uids": ["shared-event"], "message": revision}
            ]
        source = IngestedDatasetSource(store)
        policy = IngestedDataPolicy(store, source=source)
        service = NormalizedDataService(source, policy)
        event = {"event_uid": "shared-event"}
        for revision in ("revision-a", "revision-b", "revision-a"):
            with service.revision_scope(revision):
                self.assertEqual(
                    service.source_record_for_event(event)["message"], revision
                )
        barrier = Barrier(2)

        def query(revision):
            with service.revision_scope(revision):
                barrier.wait(timeout=10)
                return service.source_record_for_event(event)["message"]

        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(
                list(executor.map(query, ("revision-a", "revision-b"))),
                ["revision-a", "revision-b"],
            )
        with self.assertRaisesRegex(ValueError, "same revision store"):
            IngestedDataPolicy(SyntheticAssembly(), source=source)

    def test_scoped_source_failures_preserve_control_flow_without_caching_failure(self):
        class HostileFailure(BaseException):
            pass

        class FailingSource(IngestedDatasetSource):
            failure = None

            def load_dataset(self, *args, **kwargs):
                if self.failure is not None:
                    raise self.failure
                return super().load_dataset(*args, **kwargs)

        for failure_type in (HostileFailure, ValueError, *PROCESS_CONTROL_EXCEPTIONS):
            with self.subTest(failure_type=failure_type.__name__):
                store = SyntheticAssembly()
                store.datasets["revision-b"]["source_records"] = [
                    {"matched_event_uids": ["shared-event"], "message": "revision-b"}
                ]
                source = FailingSource(store)
                policy = IngestedDataPolicy(store, source=source)
                failure = failure_type("private/input/path")
                source.failure = failure
                expected = IngestionError if failure_type is HostileFailure else failure_type
                with source.revision_scope("revision-b"):
                    with self.assertRaises(expected) as caught:
                        policy.source_record_for_event({"event_uid": "shared-event"})
                    if failure_type is HostileFailure:
                        self.assertIs(caught.exception.__cause__, failure)
                        self.assertNotIn("private/input/path", str(caught.exception))
                        self.assertIn("scoped source-record dataset loading", str(caught.exception))
                    else:
                        self.assertIs(caught.exception, failure)
                    self.assertIsNone(policy._source_by_event_uid)
                    self.assertIsNone(policy._source_revision_id)
                    source.failure = None
                    self.assertEqual(
                        policy.source_record_for_event({"event_uid": "shared-event"})[
                            "message"
                        ],
                        "revision-b",
                    )
                self.assertIsNone(source._selected_revision.get())

    def test_catalog_selection_preserves_source_identity_without_mutating_bytes(self):
        dataset = {
            "_ingestion": {"revision_id": "source-1", "node_id": "node-a"},
            "resources": [],
        }
        retained = deepcopy(dataset)
        store = _SelectedStore(
            dataset, {"revision_id": "catalog-1", "node_id": "node-a"}
        )
        source = IngestedDatasetSource(store)
        with source.revision_scope("catalog-1"):
            projected = source.load_dataset()
        self.assertEqual(source.revision_id(projected), "catalog-1")
        self.assertEqual(projected["_ingestion"]["source_revision_id"], "source-1")
        self.assertEqual(dataset, retained)

    def test_revision_descriptors_reject_noncanonical_identity(self):
        for node, revision in (("node", " revision"), ("node", ""), (3, "revision")):
            with (
                self.subTest(node=node, revision=revision),
                self.assertRaises((TypeError, ValueError)),
            ):
                RevisionDescriptor(node, revision, "label", 0, 0)

    def test_public_catalog_dataset_exposes_canonical_id_without_rekeying_retained_basis(
        self,
    ):
        retained = {
            "_ingestion": {"revision_id": "source-1", "node_id": "node-a"},
            "events": [],
        }
        loaded = SimpleNamespace(
            dataset=retained,
            descriptor=SimpleNamespace(
                revision_id="catalog-1",
                node_id="node-a",
                metadata={"source_revision_id": "source-1"},
            ),
        )
        control = object.__new__(ControlPlane)
        with patch.object(control, "_load_revision", return_value=loaded):
            projected = control.load_revision_dataset(None, "catalog-1")
        self.assertEqual(projected["_ingestion"]["revision_id"], "catalog-1")
        self.assertEqual(projected["_ingestion"]["source_revision_id"], "source-1")
        self.assertEqual(retained["_ingestion"]["revision_id"], "source-1")
        projected["events"].append({})
        self.assertEqual(retained["events"], [])


if __name__ == "__main__":
    unittest.main()
