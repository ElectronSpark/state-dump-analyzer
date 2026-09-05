"""Review admission bounds must precede expensive immutable revision reads."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from router_dump_analyzer.annotation_store import (
    MAX_ANNOTATION_SUBJECTS,
    MAX_CORRELATION_SUBJECTS,
    ReviewAnnotationKind,
    ReviewOverlayStore,
    ReviewScope,
    ReviewSubject,
    ReviewSubjectKind,
    ReviewValidationError,
    normalize_review_subjects,
)
from router_dump_analyzer.control_plane import (
    ControlPlane,
    ControlPlaneError,
    ControlPlaneLimits,
    SubjectResolutionError,
)
from router_dump_analyzer.session_store import SqliteSessionStore


class ReviewAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.catalog = SqliteSessionStore(":memory:")
        self.addCleanup(self.catalog.close)
        self.overlay = ReviewOverlayStore(":memory:")
        self.addCleanup(self.overlay.close)
        self.catalog.create_project("tenant", "Project", project_id="project")
        self.catalog.create_workspace(
            "tenant", "project", "Workspace", workspace_id="workspace"
        )
        self.scope = ReviewScope("tenant", "project", "workspace")
        self.plane = object.__new__(ControlPlane)
        self.plane.sessions = self.catalog
        self.plane.annotations = self.overlay
        self.plane.limits = ControlPlaneLimits()
        self.plane.ingestion = SimpleNamespace(dataset_root=Path(self.temporary.name))
        self.plane._coordinated_review_catalog = nullcontext
        self.plane._load_revision = Mock(side_effect=self.loaded)

    @staticmethod
    def loaded(scope, revision_id):
        return SimpleNamespace(
            descriptor=SimpleNamespace(node_id="node"),
            index=SimpleNamespace(resources={"resource"}, events={"event"}),
        )

    def publish(self, revision_id, *, source="source", fixture="fixture", size=8):
        digest = hashlib.sha256(revision_id.encode()).hexdigest()
        if not self.catalog.list_fixtures("tenant", "workspace"):
            self.catalog.attach_fixture(
                "tenant", "workspace", fixture, label="Fixture", content_digest=digest
            )
        path = Path(self.temporary.name) / f"{revision_id}.json"
        path.write_bytes(b" " * size)
        self.catalog.publish_revision(
            "tenant",
            "workspace",
            fixture,
            revision_id,
            node_id="node",
            identity_digest=digest,
            metadata={"source_revision_id": source, "dataset_ref": path.name},
        )
        return ReviewSubject(
            revision_id, ReviewSubjectKind.RESOURCE, subject_id="resource"
        )

    def test_subject_shape_and_duplicates_fail_before_any_load(self):
        subject = ReviewSubject("r", ReviewSubjectKind.RESOURCE, subject_id="resource")
        for selection in (
            (),
            (subject, subject),
            (object(),),
            (subject,) * (MAX_ANNOTATION_SUBJECTS + 1),
        ):
            with (
                self.subTest(size=len(selection)),
                self.assertRaises(ReviewValidationError),
            ):
                self.plane.create_annotation(
                    self.scope,
                    kind=ReviewAnnotationKind.NOTE,
                    subjects=selection,
                    author="reviewer",
                )
        self.plane._load_revision.assert_not_called()

    def test_arbitrary_iterable_is_consumed_only_through_overflow_sentinel(self):
        consumed = []

        def selection():
            for index in range(MAX_ANNOTATION_SUBJECTS + 2):
                consumed.append(index)
                yield ReviewSubject(
                    f"r-{index}", ReviewSubjectKind.RESOURCE, subject_id="resource"
                )
            self.fail("an unbounded input must not be exhausted")

        with self.assertRaises(ReviewValidationError):
            normalize_review_subjects(selection(), maximum=MAX_ANNOTATION_SUBJECTS)
        self.assertEqual(len(consumed), MAX_ANNOTATION_SUBJECTS + 1)

    def test_correlation_specific_limit_and_event_kind_checked_before_load(self):
        subjects = tuple(
            ReviewSubject(f"r-{i}", ReviewSubjectKind.EVENT, subject_id="event")
            for i in range(MAX_CORRELATION_SUBJECTS + 1)
        )
        resource = ReviewSubject("r", ReviewSubjectKind.RESOURCE, subject_id="resource")
        for selection in (subjects, (resource,), (subjects[0],)):
            with (
                self.subTest(size=len(selection)),
                self.assertRaises(ReviewValidationError),
            ):
                self.plane.create_correlation(
                    self.scope, subjects=selection, edges=(), author="reviewer"
                )
        self.plane._load_revision.assert_not_called()

    def test_report_revision_iterable_is_bounded_before_resolution(self):
        consumed = []

        def revision_ids():
            for i in range(self.plane.limits.max_report_revisions + 2):
                consumed.append(i)
                yield f"r-{i}"
            self.fail("report selection exhausted over-limit iterable")

        with self.assertRaisesRegex(ControlPlaneError, "revision limit"):
            self.plane.build_report(self.scope, revision_ids=revision_ids())
        self.assertEqual(len(consumed), self.plane.limits.max_report_revisions + 1)
        self.plane._load_revision.assert_not_called()

    def test_direct_overlay_does_not_exhaust_subject_generators(self):
        for correlation in (False, True):
            maximum = (
                MAX_CORRELATION_SUBJECTS if correlation else MAX_ANNOTATION_SUBJECTS
            )
            consumed = []

            def subjects():
                for index in range(maximum + 2):
                    consumed.append(index)
                    yield ReviewSubject(
                        f"r-{index}", ReviewSubjectKind.EVENT, subject_id="event"
                    )
                self.fail("overlay exhausted over-limit iterable")

            with (
                self.subTest(correlation=correlation),
                self.assertRaises(ReviewValidationError),
            ):
                if correlation:
                    self.overlay.create_correlation(
                        self.scope, subjects=subjects(), edges=(), author="reviewer"
                    )
                else:
                    self.overlay.create_annotation(
                        self.scope,
                        kind=ReviewAnnotationKind.NOTE,
                        subjects=subjects(),
                        author="reviewer",
                    )
            self.assertEqual(len(consumed), maximum + 1)

    def test_revision_and_aggregate_byte_limits_precede_all_loads(self):
        subjects = (self.publish("r0"), self.publish("r1"))
        for limits, message in (
            (ControlPlaneLimits(max_subject_revisions=1), "revision limit"),
            (ControlPlaneLimits(max_subject_dataset_bytes=15), "byte limit"),
        ):
            with self.subTest(message=message):
                self.plane.limits = limits
                with self.assertRaisesRegex(ControlPlaneError, message):
                    self.plane.validate_subjects(self.scope, subjects)
                self.plane._load_revision.assert_not_called()

    def test_selection_order_preserved_and_each_revision_loaded_once(self):
        a, b = self.publish("r0"), self.publish("r1")
        event = ReviewSubject("r0", ReviewSubjectKind.EVENT, subject_id="event")
        subjects = (a, b, event)
        annotation = self.plane.create_annotation(
            self.scope,
            kind=ReviewAnnotationKind.NOTE,
            subjects=subjects,
            author="reviewer",
        )
        self.assertEqual(annotation.subjects, subjects)
        self.assertEqual(
            [call.args[1] for call in self.plane._load_revision.call_args_list],
            ["r0", "r1"],
        )

    def test_individual_file_and_scope_preflight_precede_every_load(self):
        first = self.publish("r0")
        second = self.publish("r1", size=0)
        for size in (0, 17):
            with self.subTest(size=size):
                (Path(self.temporary.name) / "r1.json").write_bytes(b" " * size)
                self.plane.limits = ControlPlaneLimits(max_dataset_bytes=16)
                with self.assertRaisesRegex(ControlPlaneError, "byte limit"):
                    self.plane.validate_subjects(self.scope, (first, second))
                self.plane._load_revision.assert_not_called()

        self.catalog.create_workspace(
            "tenant", "project", "Other workspace", workspace_id="other"
        )
        other = ReviewScope("tenant", "project", "other")
        with self.assertRaises(SubjectResolutionError):
            self.plane.validate_subjects(other, (first,))
        self.plane._load_revision.assert_not_called()

    def test_exact_aggregate_byte_limit_is_inclusive(self):
        subjects = (self.publish("r0"), self.publish("r1"))
        self.plane.limits = ControlPlaneLimits(max_subject_dataset_bytes=16)
        self.assertEqual(self.plane.validate_subjects(self.scope, subjects), subjects)
        self.assertEqual(self.plane._load_revision.call_count, 2)

    def test_catalog_source_match_beyond_first_two_and_false_uniqueness(self):
        for index, source in enumerate(("same", "different", "same", "last")):
            self.publish(f"r{index}", source=source)
        self.assertEqual(
            self.plane.resolve_catalog_revision(
                self.scope, fixture_id="fixture", source_revision_id="last"
            ).revision_id,
            "r3",
        )
        with self.assertRaises(SubjectResolutionError):
            self.plane.resolve_catalog_revision(
                self.scope, fixture_id="fixture", source_revision_id="same"
            )
        matches = self.catalog.list_revisions(
            "tenant",
            "workspace",
            fixture_id="fixture",
            source_revision_id="same",
            limit=1,
            offset=1,
        )
        self.assertEqual([item.revision_id for item in matches], ["r2"])

    def test_subject_limits_validate_exact_integer_configuration(self):
        for field in ("max_subject_revisions", "max_subject_dataset_bytes"):
            for value in (False, 0, -1, 1.5):
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(ValueError),
                ):
                    ControlPlaneLimits(**{field: value})


if __name__ == "__main__":
    unittest.main()
