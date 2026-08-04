from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer.canonical import canonical_json, canonical_json_sha256
from router_dump_analyzer.plugin_execution_plan import (
    DecoderIdentity,
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
    plugin_execution_plan_dict,
)
from router_dump_analyzer.session_store import (
    AnalysisRevisionDescriptor,
    IdempotencyConflict,
    SessionStoreError,
    SqliteSessionStore,
)
from router_dump_analyzer.web.control_plane_api import _json_value


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _qualified_digest(value: str) -> str:
    return f"sha256:{_digest(value)}"


def _pin(
    plugin_id: str = "vendor.forwarding",
    instance_id: str = "forwarding.0",
) -> PluginExecutionPin:
    return PluginExecutionPin(
        instance_id=instance_id,
        plugin_id=plugin_id,
        plugin_version="2.4.1",
        core_api_version="2",
        artifact=PluginArtifactIdentity(
            distribution_name=f"{plugin_id}-distribution",
            distribution_version="2.4.1+build.7",
            package_hash=f"package-{_qualified_digest(plugin_id)}",
            entry_point_name=instance_id,
            module_target=f"{plugin_id}:plugin",
        ),
        configuration_digest=_qualified_digest(f"config:{instance_id}"),
        schema_digest=_qualified_digest(f"schema:{plugin_id}"),
        capabilities=("dump.parse",),
        roles=("primary_parser",),
    )


def _plan(
    node_id: str = "node-a",
    *pins: PluginExecutionPin,
) -> PluginExecutionPlan:
    return PluginExecutionPlan(
        node_id=node_id,
        basis_revision_id="upload-sha256-abc",
        plugins=tuple(pins or (_pin(),)),
        decoder=DecoderIdentity(
            decoder_id="babeltrace",
            decoder_version="2.1.2",
            executable_digest=_qualified_digest("babeltrace"),
        ),
    )


class SessionExecutionPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "sessions.sqlite3"
        self.store = SqliteSessionStore(self.database)
        self.store.create_project(
            "tenant-a", "Project", project_id="project-a"
        )
        self.store.create_workspace(
            "tenant-a",
            "project-a",
            "Workspace",
            workspace_id="workspace-a",
        )
        self.store.attach_fixture(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            label="Fixture",
            content_digest=_digest("fixture-a"),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _publish(
        self,
        revision_id: str,
        *,
        plan: PluginExecutionPlan | None = None,
        plugin_ids: tuple[str, ...] | None = None,
        idempotency_key: str | None = None,
    ) -> AnalysisRevisionDescriptor:
        return self.store.publish_revision(
            "tenant-a",
            "workspace-a",
            "fixture-a",
            revision_id,
            node_id="node-a",
            identity_digest=_digest(revision_id),
            plugin_ids=plugin_ids,
            execution_plan=plan,
            idempotency_key=idempotency_key,
        )

    def test_plan_round_trips_and_exposes_revision_bound_reference(self) -> None:
        plan = _plan()
        published = self._publish("revision-a", plan=plan)

        self.assertEqual(published.plugin_ids, ("vendor.forwarding",))
        self.assertIsNot(published.execution_plan, plan)
        self.assertEqual(published.execution_plan, plan)
        self.assertEqual(published.execution_plan_digest, plan.plan_digest)
        reference = published.execution_plan_ref
        self.assertIsNotNone(reference)
        assert reference is not None
        self.assertEqual(reference.revision_id, "revision-a")
        self.assertEqual(self.store.get_revision("tenant-a", "revision-a"), published)
        self.assertEqual(
            self.store.list_revisions("tenant-a", "workspace-a"),
            (published,),
        )

    def test_published_descriptor_detaches_from_the_callers_plan(self) -> None:
        plan = _plan()
        published = self._publish("revision-a", plan=plan)
        bound_plan = published.execution_plan
        assert bound_plan is not None
        original_name = bound_plan.plugins[0].artifact.distribution_name

        object.__setattr__(
            plan.plugins[0].artifact,
            "distribution_name",
            "attacker-mutated-distribution",
        )

        self.assertEqual(
            bound_plan.plugins[0].artifact.distribution_name,
            original_name,
        )
        durable = self.store.get_revision("tenant-a", "revision-a")
        assert durable.execution_plan is not None
        self.assertEqual(
            durable.execution_plan.plugins[0].artifact.distribution_name,
            original_name,
        )

    def test_publish_uses_one_detached_plan_snapshot(self) -> None:
        plan = _plan()
        original_name = plan.plugins[0].artifact.distribution_name
        calls = 0

        def serialize(value: PluginExecutionPlan) -> dict[str, object]:
            nonlocal calls
            calls += 1
            document = plugin_execution_plan_dict(value)
            if calls == 1:
                object.__setattr__(
                    plan.plugins[0].artifact,
                    "distribution_name",
                    "attacker-mutated-distribution",
                )
            return document

        with patch(
            "router_dump_analyzer.session_store.plugin_execution_plan_dict",
            side_effect=serialize,
        ):
            published = self._publish("revision-a", plan=plan)

        assert published.execution_plan is not None
        self.assertEqual(
            published.execution_plan.plugins[0].artifact.distribution_name,
            original_name,
        )
        durable = self.store.get_revision("tenant-a", "revision-a")
        assert durable.execution_plan is not None
        self.assertEqual(
            durable.execution_plan.plugins[0].artifact.distribution_name,
            original_name,
        )

    def test_descriptor_projections_revalidate_its_bound_plan(self) -> None:
        published = self._publish("revision-a", plan=_plan())
        bound_plan = published.execution_plan
        assert bound_plan is not None
        object.__setattr__(
            bound_plan.plugins[0].artifact,
            "distribution_name",
            "attacker-mutated-distribution",
        )

        with self.assertRaisesRegex(
            ValueError,
            "execution-plan digest does not match",
        ):
            _ = published.execution_plan_digest
        with self.assertRaisesRegex(
            ValueError,
            "execution-plan digest does not match",
        ):
            _ = published.execution_plan_ref
        with self.assertRaisesRegex(
            ValueError,
            "execution-plan digest does not match",
        ):
            _json_value(published)

    def test_duplicate_plugin_instances_derive_distinct_plugin_ids_in_order(self) -> None:
        plan = _plan(
            "node-a",
            _pin("vendor.forwarding", "forwarding.0"),
            _pin("vendor.forwarding", "forwarding.1"),
            _pin("vendor.isis", "isis.0"),
        )
        published = self._publish("revision-a", plan=plan)
        self.assertEqual(
            published.plugin_ids,
            ("vendor.forwarding", "vendor.isis"),
        )
        verified = self._publish(
            "revision-b",
            plan=plan,
            plugin_ids=("vendor.forwarding", "vendor.isis"),
        )
        self.assertEqual(verified.plugin_ids, published.plugin_ids)
        with self.assertRaisesRegex(ValueError, "exactly match"):
            self._publish(
                "revision-c",
                plan=plan,
                plugin_ids=("vendor.isis", "vendor.forwarding"),
            )

    def test_plan_node_must_match_revision_node(self) -> None:
        with self.assertRaisesRegex(ValueError, "node_id must match"):
            self._publish("revision-a", plan=_plan("node-b"))

    def test_plan_participates_in_idempotency_identity_and_replay(self) -> None:
        plan = _plan()
        first = self._publish(
            "revision-a", plan=plan, idempotency_key="publish-a"
        )
        replay = self._publish(
            "revision-a", plan=plan, idempotency_key="publish-a"
        )
        self.assertEqual(replay, first)

        changed = _plan(
            "node-a",
            _pin("vendor.forwarding", "forwarding.changed"),
        )
        with self.assertRaises(IdempotencyConflict):
            self._publish(
                "revision-a", plan=changed, idempotency_key="publish-a"
            )

    def test_planless_publish_replays_manually_constructed_legacy_receipt(
        self,
    ) -> None:
        published = self._publish("revision-legacy")
        legacy_request = {
            "workspace_id": "workspace-a",
            "fixture_id": "fixture-a",
            "revision_id": "revision-legacy",
            "node_id": "node-a",
            "identity_digest": _digest("revision-legacy"),
            "plugin_ids": [],
            "metadata": {},
        }
        legacy_response = {
            "tenant_id": published.tenant_id,
            "workspace_id": published.workspace_id,
            "fixture_id": published.fixture_id,
            "revision_id": published.revision_id,
            "node_id": published.node_id,
            "identity_digest": published.identity_digest,
            "plugin_ids": list(published.plugin_ids),
            "metadata": dict(published.metadata),
            "published_at_ns": published.published_at_ns,
        }
        self.assertNotIn("execution_plan", legacy_request)
        self.assertNotIn("execution_plan", legacy_response)
        self.store._connection.execute(
            """
            INSERT INTO idempotency_keys(
                tenant_id, operation, idempotency_key, request_digest,
                response_json, created_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "tenant-a",
                "publish_revision",
                "legacy-publish",
                canonical_json_sha256(legacy_request),
                canonical_json(legacy_response),
                1,
            ),
        )

        replay = self._publish(
            "revision-legacy",
            idempotency_key="legacy-publish",
        )

        self.assertEqual(replay, published)
        self.assertIsNone(replay.execution_plan)

    def test_idempotency_replay_uses_durable_plan_when_receipt_plan_is_null(
        self,
    ) -> None:
        plan = _plan()
        published = self._publish(
            "revision-a",
            plan=plan,
            idempotency_key="publish-a",
        )
        row = self.store._connection.execute(
            """
            SELECT response_json FROM idempotency_keys
            WHERE tenant_id = 'tenant-a'
              AND operation = 'publish_revision'
              AND idempotency_key = 'publish-a'
            """
        ).fetchone()
        assert row is not None
        response = json.loads(row["response_json"])
        response["execution_plan"] = None
        self.store._connection.execute(
            """
            UPDATE idempotency_keys SET response_json = ?
            WHERE tenant_id = 'tenant-a'
              AND operation = 'publish_revision'
              AND idempotency_key = 'publish-a'
            """,
            (canonical_json(response),),
        )

        replay = self._publish(
            "revision-a",
            plan=plan,
            idempotency_key="publish-a",
        )

        self.assertEqual(replay, published)
        self.assertEqual(replay.execution_plan, plan)

    def test_plan_json_digest_and_plugin_id_tampering_fail_closed(self) -> None:
        plan = _plan()
        self._publish("revision-a", plan=plan)
        cases = (
            (
                "execution_plan_digest = ?",
                (_qualified_digest("tampered"),),
            ),
            (
                "execution_plan_json = ?",
                (json.dumps({"tampered": True}),),
            ),
            (
                "plugin_ids_json = ?",
                ('["other.plugin"]',),
            ),
            (
                "execution_plan_json = NULL, execution_plan_digest = NULL",
                (),
            ),
        )
        for index, (assignment, parameters) in enumerate(cases):
            with self.subTest(case=index):
                self.store.close()
                connection = sqlite3.connect(self.database)
                connection.execute(
                    "DROP TRIGGER analysis_revision_execution_plan_immutable"
                )
                connection.execute(
                    f"UPDATE analysis_revisions SET {assignment} "
                    "WHERE revision_id = 'revision-a'",
                    parameters,
                )
                connection.commit()
                connection.close()
                self.store = SqliteSessionStore(self.database)
                with self.assertRaises(SessionStoreError):
                    self.store.get_revision("tenant-a", "revision-a")
                self.store.close()
                self.database.unlink()
                self.store = SqliteSessionStore(self.database)
                self.store.create_project(
                    "tenant-a", "Project", project_id="project-a"
                )
                self.store.create_workspace(
                    "tenant-a",
                    "project-a",
                    "Workspace",
                    workspace_id="workspace-a",
                )
                self.store.attach_fixture(
                    "tenant-a",
                    "workspace-a",
                    "fixture-a",
                    label="Fixture",
                    content_digest=_digest("fixture-a"),
                )
                self._publish("revision-a", plan=plan)

    def test_plan_columns_cannot_be_coherently_replaced(self) -> None:
        original = _plan()
        published = self._publish("revision-a", plan=original)
        changed_pin = replace(
            original.plugins[0],
            configuration_digest=_qualified_digest("changed-config"),
        )
        changed = replace(
            original,
            plugins=(changed_pin,),
            plan_digest="",
        )

        with self.assertRaises(sqlite3.IntegrityError):
            self.store._connection.execute(
                """
                UPDATE analysis_revisions
                SET execution_plan_json = ?, execution_plan_digest = ?
                WHERE tenant_id = 'tenant-a' AND revision_id = 'revision-a'
                """,
                (
                    canonical_json(plugin_execution_plan_dict(changed)),
                    changed.plan_digest,
                ),
            )

        self.assertEqual(
            self.store.get_revision("tenant-a", "revision-a"),
            published,
        )

    def test_planful_revision_cannot_be_downgraded_to_planless(self) -> None:
        plan = _plan()
        published = self._publish("revision-a", plan=plan)

        with self.assertRaises(sqlite3.IntegrityError):
            self.store._connection.execute(
                """
                UPDATE analysis_revisions
                SET execution_plan_json = NULL,
                    execution_plan_digest = NULL,
                    execution_plan_present = 0
                WHERE tenant_id = 'tenant-a' AND revision_id = 'revision-a'
                """
            )

        self.assertEqual(
            self.store.get_revision("tenant-a", "revision-a"),
            published,
        )

    def test_legacy_descriptor_and_database_rows_remain_planless(self) -> None:
        descriptor = AnalysisRevisionDescriptor(
            tenant_id="tenant-a",
            workspace_id="workspace-a",
            fixture_id="fixture-a",
            revision_id="revision-legacy",
            node_id="node-a",
            identity_digest=_digest("legacy"),
        )
        self.assertIsNone(descriptor.execution_plan)
        self.assertIsNone(descriptor.execution_plan_digest)
        self.assertIsNone(descriptor.execution_plan_ref)

        self.store.close()
        self.database.unlink()
        connection = sqlite3.connect(self.database)
        connection.executescript(
            """
            CREATE TABLE analysis_revisions (
                tenant_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                fixture_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                identity_digest TEXT NOT NULL,
                plugin_ids_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                published_at_ns INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, revision_id)
            ) STRICT;
            INSERT INTO analysis_revisions VALUES (
                'tenant-a', 'revision-legacy', 'workspace-a', 'fixture-a',
                'node-a', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                '[]', '{}', 1
            );
            """
        )
        connection.commit()
        connection.close()

        self.store = SqliteSessionStore(self.database)
        columns = {
            row[1]
            for row in self.store._connection.execute(
                "PRAGMA table_info(analysis_revisions)"
            )
        }
        self.assertIn("execution_plan_json", columns)
        self.assertIn("execution_plan_digest", columns)
        self.assertIn("execution_plan_present", columns)
        marker = self.store._connection.execute(
            """
            SELECT execution_plan_present FROM analysis_revisions
            WHERE revision_id = 'revision-legacy'
            """
        ).fetchone()
        assert marker is not None
        self.assertEqual(marker["execution_plan_present"], 0)
        loaded = self.store.get_revision("tenant-a", "revision-legacy")
        self.assertIsNone(loaded.execution_plan)

    def test_migration_marks_rows_that_already_have_execution_plans(self) -> None:
        plan = _plan()
        plan_json = canonical_json(plugin_execution_plan_dict(plan))
        self.store.close()
        self.database.unlink()
        connection = sqlite3.connect(self.database)
        connection.execute(
            """
            CREATE TABLE analysis_revisions (
                tenant_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                fixture_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                identity_digest TEXT NOT NULL,
                plugin_ids_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                published_at_ns INTEGER NOT NULL,
                execution_plan_json TEXT,
                execution_plan_digest TEXT,
                PRIMARY KEY (tenant_id, revision_id)
            ) STRICT
            """
        )
        connection.execute(
            """
            INSERT INTO analysis_revisions VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                "tenant-a",
                "revision-planful",
                "workspace-a",
                "fixture-a",
                "node-a",
                _digest("revision-planful"),
                canonical_json(["vendor.forwarding"]),
                "{}",
                1,
                plan_json,
                plan.plan_digest,
            ),
        )
        connection.commit()
        connection.close()

        self.store = SqliteSessionStore(self.database)
        marker = self.store._connection.execute(
            """
            SELECT execution_plan_present FROM analysis_revisions
            WHERE revision_id = 'revision-planful'
            """
        ).fetchone()
        assert marker is not None
        self.assertEqual(marker["execution_plan_present"], 1)
        loaded = self.store.get_revision("tenant-a", "revision-planful")
        self.assertEqual(loaded.execution_plan, plan)


if __name__ == "__main__":
    unittest.main()
