from __future__ import annotations

import json
import unittest
from dataclasses import replace
from unittest.mock import patch

import router_dump_analyzer.cancellation as cancellation_helpers
import router_dump_analyzer.private_analysis_revision_evidence as revision_evidence
from router_dump_analyzer import normalized_data
from router_dump_analyzer.plugin_execution_plan import (
    PLUGIN_EXECUTION_PLAN_VERSION_V1,
    PluginArtifactIdentity,
    PluginExecutionPin,
    PluginExecutionPlan,
)
from router_dump_analyzer.private_analysis import (
    EvidenceKind,
    EvidenceTimeBasis,
    PrivateAnalysisClockMode,
    PrivateAnalysisEvidenceClass,
    PrivateAnalysisLimits,
    PrivateAnalysisQueryArguments,
    PrivateAnalysisRequest,
    PrivateAnalysisRunnerSelection,
    PrivateAnalysisTaskKind,
    PrivateAnalysisTransport,
    default_private_analysis_tool_catalog,
)
from router_dump_analyzer.private_analysis_binding import (
    PrivateAnalysisEvidenceBindingError,
    bind_private_analysis_revision,
)
from router_dump_analyzer.private_analysis_revision_evidence import (
    PrivateAnalysisRevisionEvidenceCancelled,
    PrivateAnalysisRevisionEvidenceError,
    TrustedPrivateAnalysisRevision,
    build_private_analysis_revision_evidence_corpus,
    private_analysis_revision_cutoff_ns,
)
from router_dump_analyzer.session_store import (
    AnalysisRevisionDescriptor,
    FixtureDescriptor,
    WorkspaceDescriptor,
)


def _pin(suffix: str) -> PluginExecutionPin:
    return PluginExecutionPin(
        instance_id=f"parser-{suffix}",
        plugin_id=f"vendor.platform-{suffix}",
        plugin_version=f"{suffix}.0.0",
        core_api_version="1",
        artifact=PluginArtifactIdentity(
            distribution_name=f"vendor-platform-{suffix}",
            distribution_version=f"{suffix}.0.0",
            package_hash="sha256:" + suffix * 64,
            entry_point_name=f"parser-{suffix}",
            module_target=f"vendor_{suffix}:plugin",
        ),
        configuration_digest="sha256:" + "c" * 64,
        schema_digest="sha256:" + "d" * 64,
        registered_execution_identity="sha256:" + suffix * 64,
        schema_versions=(f"vendor.schema.{suffix}",),
        capabilities=("source_record_parser",),
        roles=("primary_parser",),
    )


def _catalog(
    suffix: str,
) -> tuple[WorkspaceDescriptor, FixtureDescriptor, AnalysisRevisionDescriptor]:
    workspace = WorkspaceDescriptor(
        tenant_id="tenant-a",
        project_id="project-a",
        workspace_id="workspace-a",
        label="Workspace A",
    )
    fixture = FixtureDescriptor(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        fixture_id=f"fixture-{suffix}",
        label=f"Fixture {suffix}",
        content_digest=("1" if suffix == "a" else "2") * 64,
    )
    plan = PluginExecutionPlan(
        node_id=f"node-{suffix}",
        basis_revision_id=f"basis-{suffix}",
        plugins=(_pin(suffix),),
    )
    revision = AnalysisRevisionDescriptor(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        fixture_id=fixture.fixture_id,
        revision_id=f"revision-{suffix}",
        node_id=f"node-{suffix}",
        identity_digest=("3" if suffix == "a" else "4") * 64,
        plugin_ids=(f"vendor.platform-{suffix}",),
        execution_plan=plan,
    )
    return workspace, fixture, revision


def _dataset(
    suffix: str,
    *,
    start_ns: int,
    end_ns: int,
) -> dict[str, object]:
    resource_a = f"node-{suffix}/INTERFACE/a"
    resource_b = f"node-{suffix}/INTERFACE/b"
    resource_c = f"node-{suffix}/INTERFACE/c"
    return {
        "_ingestion": {
            "timeline_start_ns": str(start_ns),
            "timeline_end_ns": str(end_ns),
            "timeline_time_basis": "absolute_unix_ns",
        },
        "kind_descriptors": [
            {
                "kind": "INTERFACE",
                "condition_field": "oper_status",
                "key_fields": ["name"],
                "properties": [
                    {"name": "oper_status", "client_visible": True},
                    {"name": "secret", "sensitive": True},
                ],
            }
        ],
        "resources": [
            {
                "resource_id": resource_a,
                "kind": "INTERFACE",
                "layer": "forwarding",
                "label": f"Ethernet-{suffix}-a",
                "key": {"name": "a", "secret": "private-key"},
                "state": {"oper_status": "up", "secret": "private-state"},
            },
            {
                "resource_id": resource_b,
                "kind": "INTERFACE",
                "layer": "forwarding",
                "label": f"Ethernet-{suffix}-b",
                "key": {"name": "b"},
                "state": {"oper_status": "up"},
            },
            {
                "resource_id": resource_c,
                "kind": "INTERFACE",
                "layer": "forwarding",
                "label": f"Ethernet-{suffix}-c",
                "key": {"name": "c"},
                "state": {"oper_status": "up"},
            },
        ],
        "lifecycle_intervals": [
            {
                "resource": resource_a,
                "valid_from_ns": str(start_ns),
                "valid_to_ns": None,
            },
            {
                "resource": resource_b,
                "valid_from_ns": str(start_ns),
                "valid_to_ns": None,
            },
            {
                "resource": resource_c,
                "valid_from_ns": str(start_ns),
                "valid_to_ns": str(start_ns + 50),
            },
        ],
        "state_intervals": [
            {
                "resource": resource_a,
                "valid_from_ns": str(start_ns),
                "valid_to_ns": str(start_ns + 50),
                "status": "initial",
                "status_class": "healthy",
                "properties": {
                    "oper_status": "initial",
                    "secret": "past-secret",
                },
                "provenance": "observed",
            },
            {
                "resource": resource_a,
                "valid_from_ns": str(start_ns + 50),
                "valid_to_ns": None,
                "status": "current",
                "status_class": "healthy",
                "properties": {
                    "oper_status": "current",
                    "secret": "future-secret",
                },
                "provenance": "reconstructed",
            },
        ],
        "relationship_intervals": [
            {
                "source": resource_a,
                "target": resource_b,
                "relation_type": "adjacent_to",
                "present": True,
                "valid_from_ns": str(start_ns),
                "valid_to_ns": str(start_ns + 50),
                "attributes": {"raw": "not-client-safe"},
                "provenance": "correlated",
                "quality": "exact",
            },
            {
                "source": resource_a,
                "target": resource_b,
                "relation_type": "future_relation",
                "present": True,
                "valid_from_ns": str(start_ns + 50),
                "valid_to_ns": None,
                "attributes": {"raw": "not-client-safe"},
                "provenance": "correlated",
                "quality": "exact",
            },
        ],
        "events": [
            {
                "event_uid": f"event-{suffix}-before",
                "timestamp_ns": str(start_ns + 10),
                "event_type": f"vendor_{suffix}_before",
                "action": "modify",
                "outcome": "success",
                "resource_id": resource_a,
                "attributes": {
                    "oper_status": "up",
                    "secret": "event-secret",
                },
                "provenance": "event_derived",
            },
            {
                "event_uid": f"event-{suffix}-after",
                "timestamp_ns": str(end_ns),
                "event_type": f"vendor_{suffix}_after",
                "action": "modify",
                "outcome": "success",
                "resource_id": resource_a,
                "provenance": "event_derived",
            },
        ],
        "source_records": [
            {
                "source_record_uid": f"source-{suffix}-before",
                "timestamp_ns": str(start_ns + 9),
                "source_type": "ctf",
                "source_name": "trace",
                "record_name": "before",
                "message": "safe source record",
                "layer": "forwarding",
                "attributes": {"raw": "not-client-safe"},
                "copy_text": "must not be projected",
            },
            {
                "source_record_uid": f"source-{suffix}-after",
                "timestamp_ns": str(end_ns),
                "source_type": "ctf",
                "source_name": "trace",
                "record_name": "after",
                "message": "future source record",
                "layer": "forwarding",
            },
        ],
    }


def _request(
    trusted: tuple[TrustedPrivateAnalysisRevision, ...],
    *,
    mode: PrivateAnalysisClockMode,
    selected_time_ns: int | None,
) -> PrivateAnalysisRequest:
    bindings = tuple(
        bind_private_analysis_revision(item.workspace, item.fixture, item.revision)[1]
        for item in trusted
    )
    bindings = tuple(
        sorted(bindings, key=lambda item: (item.node_id, item.revision_id))
    )
    scope = bind_private_analysis_revision(
        trusted[0].workspace,
        trusted[0].fixture,
        trusted[0].revision,
    )[0]
    return PrivateAnalysisRequest(
        scope=scope,
        revisions=bindings,
        runner=PrivateAnalysisRunnerSelection(
            runner_id="deployment.local-private-model",
            runner_version="1.0.0",
            transport=PrivateAnalysisTransport.IN_PROCESS,
            configuration_digest="sha256:" + "a" * 64,
        ),
        workspace_policy_digest="b" * 64,
        instruction_profile_digest="sha256:" + "c" * 64,
        tool_catalog_digest=default_private_analysis_tool_catalog().catalog_digest,
        task_kind=PrivateAnalysisTaskKind.CROSS_NODE_CORROBORATION,
        query="Correlate these exact revision snapshots.",
        clock_mode=mode,
        selected_time_ns=selected_time_ns,
        limits=PrivateAnalysisLimits(),
    )


def _trusted(suffix: str, start: int, end: int) -> TrustedPrivateAnalysisRevision:
    workspace, fixture, revision = _catalog(suffix)
    return TrustedPrivateAnalysisRevision(
        workspace,
        fixture,
        revision,
        _dataset(suffix, start_ns=start, end_ns=end),
    )


class PrivateAnalysisRevisionEvidenceTests(unittest.TestCase):
    def test_default_relative_timeline_preserves_declared_coordinates(self) -> None:
        workspace, fixture, revision = _catalog("a")
        dataset = _dataset("a", start_ns=-100, end_ns=-1)
        ingestion = dataset["_ingestion"]
        assert isinstance(ingestion, dict)
        ingestion.pop("timeline_time_basis")
        trusted = TrustedPrivateAnalysisRevision(
            workspace,
            fixture,
            revision,
            dataset,
        )
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )

        corpus = build_private_analysis_revision_evidence_corpus(request, (trusted,))
        event = next(
            entry
            for entry in corpus.entries
            if entry.reference.kind is EvidenceKind.EVENT
            and entry.payload.get("event_uid") == "event-a-before"
        )
        self.assertIs(
            event.reference.time_range.basis,
            EvidenceTimeBasis.REVISION_START_RELATIVE_NS,
        )
        self.assertEqual(event.reference.time_range.start_ns, -90)
        metadata = next(
            entry.payload
            for entry in corpus.entries
            if entry.reference.kind is EvidenceKind.REVISION_METADATA
        )
        self.assertEqual(metadata["timeline_time_basis"], "revision_start_relative_ns")
        self.assertEqual(metadata["selected_evidence_coordinate_ns"], "-1")

        absolute_request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
            selected_time_ns=0,
        )
        with self.assertRaisesRegex(
            PrivateAnalysisRevisionEvidenceError,
            "requires a revision timeline proven as absolute",
        ):
            build_private_analysis_revision_evidence_corpus(
                absolute_request,
                (trusted,),
            )

    def test_declared_relative_timeline_start_is_a_bound_not_an_origin(self) -> None:
        trusted = _trusted("a", 100, 200)
        dataset = trusted.dataset
        assert isinstance(dataset, dict)
        ingestion = dataset["_ingestion"]
        assert isinstance(ingestion, dict)
        ingestion["timeline_time_basis"] = "revision_start_relative_ns"
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )

        corpus = build_private_analysis_revision_evidence_corpus(request, (trusted,))
        event = next(
            entry
            for entry in corpus.entries
            if entry.reference.kind is EvidenceKind.EVENT
            and entry.payload.get("event_uid") == "event-a-before"
        )
        metadata = next(
            entry.payload
            for entry in corpus.entries
            if entry.reference.kind is EvidenceKind.REVISION_METADATA
        )

        self.assertIs(
            event.reference.time_range.basis,
            EvidenceTimeBasis.REVISION_START_RELATIVE_NS,
        )
        self.assertEqual(event.reference.time_range.start_ns, 110)
        self.assertEqual(metadata["selected_evidence_coordinate_ns"], "200")

    def test_declared_source_clock_is_preserved(self) -> None:
        workspace, fixture, revision = _catalog("a")
        dataset = _dataset("a", start_ns=-100, end_ns=-1)
        ingestion = dataset["_ingestion"]
        assert isinstance(ingestion, dict)
        ingestion["timeline_time_basis"] = "source_clock_ns"
        ingestion["timeline_clock_domain"] = "node-a-monotonic"
        trusted = TrustedPrivateAnalysisRevision(
            workspace,
            fixture,
            revision,
            dataset,
        )
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )

        corpus = build_private_analysis_revision_evidence_corpus(request, (trusted,))
        event = next(
            entry
            for entry in corpus.entries
            if entry.reference.kind is EvidenceKind.EVENT
            and entry.payload.get("event_uid") == "event-a-before"
        )
        self.assertIs(
            event.reference.time_range.basis,
            EvidenceTimeBasis.SOURCE_CLOCK_NS,
        )
        self.assertEqual(event.reference.time_range.start_ns, -90)
        self.assertEqual(
            event.reference.time_range.clock_domain,
            "node-a-monotonic",
        )

    def test_distinct_source_clock_domains_are_not_conflated_across_revisions(
        self,
    ) -> None:
        trusted: list[TrustedPrivateAnalysisRevision] = []
        for suffix in ("a", "b"):
            workspace, fixture, revision = _catalog(suffix)
            dataset = _dataset(suffix, start_ns=-100, end_ns=-1)
            ingestion = dataset["_ingestion"]
            assert isinstance(ingestion, dict)
            ingestion["timeline_time_basis"] = "source_clock_ns"
            ingestion["timeline_clock_domain"] = f"node-{suffix}-monotonic"
            trusted.append(
                TrustedPrivateAnalysisRevision(
                    workspace,
                    fixture,
                    revision,
                    dataset,
                )
            )

        trusted_tuple = tuple(trusted)
        request = _request(
            trusted_tuple,
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        corpus = build_private_analysis_revision_evidence_corpus(
            request,
            trusted_tuple,
        )

        observed = {
            (
                entry.reference.revision.node_id,
                entry.reference.time_range.basis,
                entry.reference.time_range.clock_domain,
            )
            for entry in corpus.entries
            if entry.reference.kind is EvidenceKind.EVENT
        }
        self.assertEqual(
            observed,
            {
                (
                    "node-a",
                    EvidenceTimeBasis.SOURCE_CLOCK_NS,
                    "node-a-monotonic",
                ),
                (
                    "node-b",
                    EvidenceTimeBasis.SOURCE_CLOCK_NS,
                    "node-b-monotonic",
                ),
            },
        )
        for suffix in ("a", "b"):
            domain = f"node-{suffix}-monotonic"
            page = corpus.query_references(
                request,
                PrivateAnalysisQueryArguments(
                    evidence_kinds=(EvidenceKind.EVENT,),
                    time_basis=EvidenceTimeBasis.SOURCE_CLOCK_NS,
                    time_start_ns=-90,
                    time_end_ns=-90,
                    time_clock_domain=domain,
                ),
            )
            self.assertEqual(
                {reference.revision.node_id for reference in page.references},
                {f"node-{suffix}"},
            )

    def test_empty_source_clock_revision_rejects_invalid_clock_domains(self) -> None:
        workspace, fixture, revision = _catalog("a")
        dataset: dict[str, object] = {
            "_ingestion": {
                "timeline_start_ns": "-100",
                "timeline_end_ns": "-1",
                "timeline_time_basis": "source_clock_ns",
                "timeline_clock_domain": "node-a-monotonic",
            }
        }
        trusted = TrustedPrivateAnalysisRevision(
            workspace,
            fixture,
            revision,
            dataset,
        )
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        ingestion = dataset["_ingestion"]
        assert isinstance(ingestion, dict)

        for invalid_domain in (
            "node a monotonic",
            "x" * 257,
            "node-a/monotonic",
        ):
            with (
                self.subTest(clock_domain=invalid_domain),
                self.assertRaisesRegex(
                    PrivateAnalysisRevisionEvidenceError,
                    "bounded path-safe token",
                ),
            ):
                ingestion["timeline_clock_domain"] = invalid_domain
                build_private_analysis_revision_evidence_corpus(
                    request,
                    (trusted,),
                )

    def test_clock_domain_validation_preserves_process_control(self) -> None:
        workspace, fixture, revision = _catalog("a")
        dataset: dict[str, object] = {
            "_ingestion": {
                "timeline_start_ns": "-100",
                "timeline_end_ns": "-1",
                "timeline_time_basis": "source_clock_ns",
                "timeline_clock_domain": "node-a-monotonic",
            }
        }
        trusted = TrustedPrivateAnalysisRevision(
            workspace,
            fixture,
            revision,
            dataset,
        )
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )

        with (
            patch.object(
                revision_evidence,
                "validate_evidence_token",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            build_private_analysis_revision_evidence_corpus(request, (trusted,))

    def test_cutoff_rejects_negative_absolute_timeline_bound(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )

        with self.assertRaisesRegex(
            PrivateAnalysisRevisionEvidenceError,
            "timeline bounds are invalid",
        ):
            private_analysis_revision_cutoff_ns(
                request,
                request.revisions[0],
                timeline_start_ns=-1,
                timeline_end_ns=200,
                timeline_basis=EvidenceTimeBasis.ABSOLUTE_UNIX_NS,
            )

    def test_cutoff_rejects_sub_int64_relative_timeline_start(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )

        with self.assertRaisesRegex(
            PrivateAnalysisRevisionEvidenceError,
            "timeline bounds are invalid",
        ):
            private_analysis_revision_cutoff_ns(
                request,
                request.revisions[0],
                timeline_start_ns=-(1 << 63) - 1,
                timeline_end_ns=-1,
                timeline_basis=EvidenceTimeBasis.REVISION_START_RELATIVE_NS,
            )

    def test_uncertain_observation_overlapping_cutoff_is_retained(self) -> None:
        trusted = _trusted("a", 100, 300)
        assert isinstance(trusted.dataset, dict)
        events = trusted.dataset["events"]
        assert isinstance(events, list)
        events[0]["timestamp_ns"] = "200"
        events[0]["timestamp_uncertainty_ns"] = "100"
        events[1]["timestamp_ns"] = "260"
        events[1]["timestamp_uncertainty_ns"] = "50"
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
            selected_time_ns=150,
        )

        corpus = build_private_analysis_revision_evidence_corpus(request, (trusted,))
        event_entries = tuple(
            entry
            for entry in corpus.entries
            if entry.reference.kind is EvidenceKind.EVENT
        )
        self.assertEqual(len(event_entries), 1)
        self.assertEqual(event_entries[0].payload["event_uid"], "event-a-before")
        self.assertEqual(event_entries[0].reference.time_range.start_ns, 200)
        self.assertEqual(event_entries[0].reference.time_range.uncertainty_ns, 100)

    def test_latest_projection_retains_unknown_time_observations_explicitly(
        self,
    ) -> None:
        trusted = _trusted("a", 100, 200)
        assert isinstance(trusted.dataset, dict)
        source_records = trusted.dataset["source_records"]
        events = trusted.dataset["events"]
        assert isinstance(source_records, list)
        assert isinstance(events, list)
        source_records.append(
            {
                "source_record_uid": "source-a-unknown",
                "timestamp_ns": None,
                "source_type": "ctf",
                "source_name": "trace",
                "record_name": "unknown-time",
                "message": "retained without an invented time",
                "layer": "forwarding",
            }
        )
        events.append(
            {
                "event_uid": "event-a-unknown",
                "timestamp_ns": None,
                "event_type": "vendor_a_unknown_time",
                "action": "observe",
                "outcome": "unknown",
                "resource_id": "node-a/INTERFACE/a",
                "provenance": "event_derived",
            }
        )
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )

        corpus = build_private_analysis_revision_evidence_corpus(request, (trusted,))
        unknown_entries = [
            entry
            for entry in corpus.entries
            if entry.reference.time_range.basis is EvidenceTimeBasis.UNKNOWN
        ]
        self.assertEqual(
            {entry.reference.kind for entry in unknown_entries},
            {EvidenceKind.SOURCE_RECORD, EvidenceKind.EVENT},
        )
        self.assertEqual(
            {entry.payload.get("timestamp_ns") for entry in unknown_entries},
            {None},
        )

    def test_historical_projection_rejects_unknown_time_observations(self) -> None:
        for field, item, subject in (
            (
                "source_records",
                {
                    "source_record_uid": "source-a-unknown",
                    "timestamp_ns": None,
                    "source_type": "ctf",
                    "source_name": "trace",
                    "record_name": "unknown-time",
                    "message": "unknown",
                    "layer": "forwarding",
                },
                "source record",
            ),
            (
                "events",
                {
                    "event_uid": "event-a-unknown",
                    "timestamp_ns": None,
                    "event_type": "vendor_a_unknown_time",
                    "action": "observe",
                    "outcome": "unknown",
                    "resource_id": "node-a/INTERFACE/a",
                    "provenance": "event_derived",
                },
                "event",
            ),
        ):
            with self.subTest(field=field):
                trusted = _trusted("a", 100, 200)
                assert isinstance(trusted.dataset, dict)
                values = trusted.dataset[field]
                assert isinstance(values, list)
                values.append(item)
                request = _request(
                    (trusted,),
                    mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
                    selected_time_ns=150,
                )
                with self.assertRaisesRegex(
                    PrivateAnalysisRevisionEvidenceError,
                    rf"historical private analysis cannot place {subject}",
                ):
                    build_private_analysis_revision_evidence_corpus(
                        request,
                        (trusted,),
                    )

    def test_historical_projection_rejects_active_unknown_start_intervals(
        self,
    ) -> None:
        cases = (
            ("lifecycle_intervals", 0, "resource lifecycle interval"),
            ("state_intervals", 1, "resource state interval"),
            ("relationship_intervals", 1, "relationship interval"),
        )
        for field, ordinal, subject in cases:
            with self.subTest(field=field):
                trusted = _trusted("a", 100, 200)
                assert isinstance(trusted.dataset, dict)
                intervals = trusted.dataset[field]
                assert isinstance(intervals, list)
                intervals[ordinal]["valid_from_ns"] = None
                request = _request(
                    (trusted,),
                    mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
                    selected_time_ns=150,
                )

                with self.assertRaisesRegex(
                    PrivateAnalysisRevisionEvidenceError,
                    rf"historical private analysis cannot place {subject}",
                ):
                    build_private_analysis_revision_evidence_corpus(
                        request,
                        (trusted,),
                    )

    def test_latest_projection_retains_unknown_interval_time_without_invention(
        self,
    ) -> None:
        trusted = _trusted("a", 100, 200)
        assert isinstance(trusted.dataset, dict)
        states = trusted.dataset["state_intervals"]
        relationships = trusted.dataset["relationship_intervals"]
        assert isinstance(states, list)
        assert isinstance(relationships, list)
        states[1]["valid_from_ns"] = None
        relationships[1]["valid_from_ns"] = None
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )

        corpus = build_private_analysis_revision_evidence_corpus(request, (trusted,))
        temporal_entries = [
            entry
            for entry in corpus.entries
            if entry.reference.kind
            in {
                EvidenceKind.RESOURCE_STATE_INTERVAL,
                EvidenceKind.RELATIONSHIP_INTERVAL,
            }
        ]
        self.assertEqual(len(temporal_entries), 2)
        self.assertTrue(
            all(
                entry.reference.time_range.basis is EvidenceTimeBasis.UNKNOWN
                for entry in temporal_entries
            )
        )
        self.assertEqual(
            {entry.payload.get("valid_from_ns") for entry in temporal_entries},
            {None},
        )

    def test_resource_identity_never_copies_latest_summary_state(self) -> None:
        trusted = _trusted("a", 100, 200)
        assert isinstance(trusted.dataset, dict)
        resources = trusted.dataset["resources"]
        assert isinstance(resources, list)
        resources[0]["state"] = {
            "oper_status": "future-only-summary",
            "secret": "future-only-secret",
        }
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
            selected_time_ns=125,
        )

        corpus = build_private_analysis_revision_evidence_corpus(request, (trusted,))
        identities = [
            entry.payload
            for entry in corpus.entries
            if entry.reference.kind is EvidenceKind.RESOURCE_IDENTITY
        ]
        self.assertTrue(identities)
        self.assertTrue(all("state" not in payload for payload in identities))
        self.assertNotIn("future-only-summary", repr(identities))
        self.assertNotIn("future-only-secret", repr(identities))

    def test_unknown_time_observation_rejects_uncertainty(self) -> None:
        trusted = _trusted("a", 100, 200)
        assert isinstance(trusted.dataset, dict)
        events = trusted.dataset["events"]
        assert isinstance(events, list)
        events.append(
            {
                "event_uid": "event-a-unknown",
                "timestamp_ns": None,
                "timestamp_uncertainty_ns": "1",
                "event_type": "vendor_a_unknown_time",
                "action": "observe",
                "outcome": "unknown",
                "resource_id": "node-a/INTERFACE/a",
            }
        )
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        with self.assertRaisesRegex(
            PrivateAnalysisRevisionEvidenceError,
            "unknown timestamp cannot carry uncertainty",
        ):
            build_private_analysis_revision_evidence_corpus(request, (trusted,))

    def test_client_event_redaction_policy_is_compiled_once_per_revision(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        with patch.object(
            revision_evidence,
            "event_redaction_policy",
            wraps=revision_evidence.event_redaction_policy,
        ) as compile_policy:
            build_private_analysis_revision_evidence_corpus(request, (trusted,))
        self.assertEqual(compile_policy.call_count, 1)

    def test_mixed_revision_relative_clocks_and_exact_primary_plugins(self) -> None:
        revision_a = _trusted("a", 100, 200)
        revision_b = _trusted("b", 400, 500)
        for trusted in (revision_a, revision_b):
            dataset = trusted.dataset
            assert isinstance(dataset, dict)
            ingestion = dataset["_ingestion"]
            assert isinstance(ingestion, dict)
            ingestion["timeline_time_basis"] = "revision_start_relative_ns"
        request = _request(
            (revision_a, revision_b),
            mode=PrivateAnalysisClockMode.REVISION_END_RELATIVE_NS,
            selected_time_ns=-50,
        )

        corpus = build_private_analysis_revision_evidence_corpus(
            request,
            (revision_b, revision_a),
        )
        metadata = [
            entry.payload
            for entry in corpus.entries
            if entry.reference.kind is EvidenceKind.REVISION_METADATA
        ]
        self.assertEqual(
            {(item["node_id"], item["selected_cutoff_ns"]) for item in metadata},
            {("node-a", "150"), ("node-b", "450")},
        )
        self.assertEqual(
            {
                (item["node_id"], item["selected_evidence_coordinate_ns"])
                for item in metadata
            },
            {("node-a", "150"), ("node-b", "450")},
        )
        for coordinate, expected_node in ((110, "node-a"), (410, "node-b")):
            page = corpus.query_references(
                request,
                PrivateAnalysisQueryArguments(
                    evidence_kinds=(EvidenceKind.EVENT,),
                    time_basis=EvidenceTimeBasis.REVISION_START_RELATIVE_NS,
                    time_start_ns=coordinate,
                    time_end_ns=coordinate,
                ),
            )
            self.assertEqual(
                {reference.revision.node_id for reference in page.references},
                {expected_node},
            )
        event_producers = {
            (
                entry.reference.revision.node_id,
                entry.reference.producer.producer_id,
                entry.reference.producer.plugin_instance_id,
                entry.reference.producer.plugin_role,
                entry.reference.producer.plugin_capability,
            )
            for entry in corpus.entries
            if entry.reference.kind is EvidenceKind.EVENT
        }
        self.assertEqual(
            event_producers,
            {
                ("node-a", "vendor.platform-a", "parser-a", "primary_parser", None),
                ("node-b", "vendor.platform-b", "parser-b", "primary_parser", None),
            },
        )

    def test_past_cutoff_excludes_future_records_and_uses_half_open_intervals(
        self,
    ) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
            selected_time_ns=150,
        )

        corpus = build_private_analysis_revision_evidence_corpus(request, (trusted,))
        payloads_by_kind = {
            kind: [
                entry.payload
                for entry in corpus.entries
                if entry.reference.kind is kind
            ]
            for kind in EvidenceKind
        }
        self.assertEqual(
            [item["event_uid"] for item in payloads_by_kind[EvidenceKind.EVENT]],
            ["event-a-before"],
        )
        self.assertEqual(
            [
                item["source_record_uid"]
                for item in payloads_by_kind[EvidenceKind.SOURCE_RECORD]
            ],
            ["source-a-before"],
        )
        states = payloads_by_kind[EvidenceKind.RESOURCE_STATE_INTERVAL]
        self.assertEqual(len(states), 1)
        self.assertEqual(states[0]["status"], "current")
        self.assertIsNone(states[0]["valid_to_ns"])
        # Resource C and the old relationship end exactly at the selected
        # instant; the replacement relation starts there.  Half-open semantics
        # therefore retain A/B plus only the replacement at t=150.
        self.assertEqual(
            len(payloads_by_kind[EvidenceKind.RESOURCE_IDENTITY]),
            2,
        )
        self.assertEqual(
            [
                item["relation_type"]
                for item in payloads_by_kind[EvidenceKind.RELATIONSHIP_INTERVAL]
            ],
            ["future_relation"],
        )
        serialized = json.dumps(payloads_by_kind, default=str)
        self.assertNotIn("copy_text", serialized)
        self.assertNotIn("not-client-safe", serialized)
        self.assertNotIn("private-state", serialized)
        self.assertNotIn("future-secret", serialized)

    def test_full_fidelity_projection_keeps_plugin_owned_private_fields(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
            selected_time_ns=150,
        )

        corpus = build_private_analysis_revision_evidence_corpus(
            request,
            (trusted,),
            plugin_evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        )
        plugin_entries = tuple(
            entry
            for entry in corpus.entries
            if entry.reference.kind
            not in {EvidenceKind.REVISION_METADATA, EvidenceKind.PLUGIN_SCHEMA}
        )

        self.assertTrue(plugin_entries)
        self.assertTrue(
            all(
                entry.reference.evidence_class
                is PrivateAnalysisEvidenceClass.PROPRIETARY
                for entry in plugin_entries
            )
        )
        serialized = json.dumps(
            [entry.payload for entry in plugin_entries],
            default=str,
        )
        self.assertIn("must not be projected", serialized)
        self.assertIn("event-secret", serialized)
        # Timeless identity must not copy the final snapshot's summary state
        # into a historical reconstruction, even in full-fidelity mode.
        self.assertNotIn("private-state", serialized)
        self.assertIn("future-secret", serialized)
        self.assertIn("not-client-safe", serialized)
        self.assertTrue(
            all(
                entry.reference.evidence_class
                is PrivateAnalysisEvidenceClass.CLIENT_SAFE
                for entry in corpus.entries
                if entry.reference.kind
                in {EvidenceKind.REVISION_METADATA, EvidenceKind.PLUGIN_SCHEMA}
            )
        )

        with self.assertRaisesRegex(ValueError, "client_safe or proprietary"):
            build_private_analysis_revision_evidence_corpus(
                request,
                (trusted,),
                plugin_evidence_class=(PrivateAnalysisEvidenceClass.NEVER_ASSISTANT),
            )

    def test_full_fidelity_payload_stringifies_exact_large_integers(self) -> None:
        timestamp_ns = 1_759_680_000_000_000_000
        trusted = _trusted("a", timestamp_ns - 100, timestamp_ns + 100)
        dataset = trusted.dataset
        assert isinstance(dataset, dict)
        source_records = dataset["source_records"]
        assert isinstance(source_records, list)
        source = source_records[0]
        assert isinstance(source, dict)
        source["timestamp_ns"] = timestamp_ns
        attributes = source["attributes"]
        assert isinstance(attributes, dict)
        attributes["opaque_id"] = -timestamp_ns
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
            selected_time_ns=timestamp_ns,
        )

        corpus = build_private_analysis_revision_evidence_corpus(
            request,
            (trusted,),
            plugin_evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
        )
        entry = next(
            item
            for item in corpus.entries
            if item.reference.kind is EvidenceKind.SOURCE_RECORD
        )
        self.assertEqual(entry.payload["timestamp_ns"], str(timestamp_ns))
        projected_attributes = entry.payload["attributes"]
        assert isinstance(projected_attributes, dict)
        self.assertEqual(
            projected_attributes["opaque_id"],
            str(-timestamp_ns),
        )

    def test_full_fidelity_payload_rejects_cycles_before_projection(self) -> None:
        trusted = _trusted("a", 100, 200)
        dataset = trusted.dataset
        assert isinstance(dataset, dict)
        source_records = dataset["source_records"]
        assert isinstance(source_records, list)
        source = source_records[0]
        assert isinstance(source, dict)
        attributes = source["attributes"]
        assert isinstance(attributes, dict)
        attributes["cycle"] = attributes

        with self.assertRaisesRegex(ValueError, "must not contain reference cycles"):
            build_private_analysis_revision_evidence_corpus(
                _request(
                    (trusted,),
                    mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
                    selected_time_ns=150,
                ),
                (trusted,),
                plugin_evidence_class=PrivateAnalysisEvidenceClass.PROPRIETARY,
            )

    def test_selected_time_outside_any_revision_fails_instead_of_clamping(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.ABSOLUTE_UNIX_NS,
            selected_time_ns=99,
        )
        with self.assertRaisesRegex(
            PrivateAnalysisRevisionEvidenceError,
            "outside the revision timeline",
        ):
            build_private_analysis_revision_evidence_corpus(request, (trusted,))

    def test_corpus_is_deterministic_and_isolated_from_dataset_mutation(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.REVISION_END_RELATIVE_NS,
            selected_time_ns=-50,
        )
        first = build_private_analysis_revision_evidence_corpus(request, (trusted,))
        second = build_private_analysis_revision_evidence_corpus(request, (trusted,))
        self.assertEqual(first.reference_digests, second.reference_digests)
        self.assertEqual(
            first.reference_digests, tuple(sorted(first.reference_digests))
        )

        event_entry = next(
            entry
            for entry in first.entries
            if entry.reference.kind is EvidenceKind.EVENT
        )
        dataset = trusted.dataset
        assert isinstance(dataset["events"], list)
        dataset["events"][0]["event_uid"] = "mutated-event"
        dataset["events"][0]["attributes"]["oper_status"] = "mutated"
        self.assertEqual(event_entry.payload["event_uid"], "event-a-before")
        attributes = event_entry.payload["attributes"]
        assert isinstance(attributes, dict)
        self.assertEqual(attributes["oper_status"], "up")

    def test_plugin_schema_evidence_binds_registered_execution_identity(self) -> None:
        workspace, fixture, revision = _catalog("a")
        baseline = TrustedPrivateAnalysisRevision(
            workspace,
            fixture,
            revision,
            _dataset("a", start_ns=100, end_ns=200),
        )
        baseline_request = _request(
            (baseline,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        baseline_corpus = build_private_analysis_revision_evidence_corpus(
            baseline_request,
            (baseline,),
        )

        plan = revision.execution_plan
        assert plan is not None
        changed_pin = replace(
            plan.plugins[0],
            registered_execution_identity="sha256:" + "f" * 64,
        )
        changed_plan = replace(plan, plugins=(changed_pin,), plan_digest="")
        changed_revision = replace(revision, execution_plan=changed_plan)
        changed = TrustedPrivateAnalysisRevision(
            workspace,
            fixture,
            changed_revision,
            _dataset("a", start_ns=100, end_ns=200),
        )
        changed_request = _request(
            (changed,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        changed_corpus = build_private_analysis_revision_evidence_corpus(
            changed_request,
            (changed,),
        )

        baseline_schema = next(
            entry
            for entry in baseline_corpus.entries
            if entry.reference.kind is EvidenceKind.PLUGIN_SCHEMA
        )
        changed_schema = next(
            entry
            for entry in changed_corpus.entries
            if entry.reference.kind is EvidenceKind.PLUGIN_SCHEMA
        )
        self.assertEqual(
            baseline_schema.payload["registered_execution_identity"],
            plan.plugins[0].registered_execution_identity,
        )
        self.assertEqual(
            changed_schema.payload["registered_execution_identity"],
            changed_pin.registered_execution_identity,
        )
        self.assertNotEqual(
            baseline_schema.reference.content_digest,
            changed_schema.reference.content_digest,
        )
        self.assertNotEqual(
            baseline_schema.reference.reference_digest,
            changed_schema.reference.reference_digest,
        )
        self.assertNotEqual(
            baseline_corpus.query_references(
                baseline_request,
                PrivateAnalysisQueryArguments(),
            ).snapshot_digest,
            changed_corpus.query_references(
                changed_request,
                PrivateAnalysisQueryArguments(),
            ).snapshot_digest,
        )

    def test_retained_v1_plan_cannot_produce_private_analysis_evidence(self) -> None:
        workspace, fixture, revision = _catalog("a")
        plan = revision.execution_plan
        assert plan is not None
        legacy_identity = "sha256:" + "0" * 64
        legacy_plan = PluginExecutionPlan(
            node_id=plan.node_id,
            basis_revision_id=plan.basis_revision_id,
            plugins=(
                replace(
                    plan.plugins[0],
                    registered_execution_identity=legacy_identity,
                ),
            ),
            decoder=plan.decoder,
            contract_version=PLUGIN_EXECUTION_PLAN_VERSION_V1,
        )
        legacy_revision = replace(revision, execution_plan=legacy_plan)
        with self.assertRaisesRegex(
            PrivateAnalysisEvidenceBindingError,
            "retained v1.*cannot produce",
        ):
            TrustedPrivateAnalysisRevision(
                workspace,
                fixture,
                legacy_revision,
                _dataset("a", start_ns=100, end_ns=200),
            )

    def test_request_requires_exact_revision_set(self) -> None:
        revision_a = _trusted("a", 100, 200)
        revision_b = _trusted("b", 400, 500)
        request = _request(
            (revision_a, revision_b),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        with self.assertRaisesRegex(ValueError, "exactly match"):
            build_private_analysis_revision_evidence_corpus(
                request,
                (revision_a,),
            )

    def test_large_projection_honors_cooperative_cancellation(self) -> None:
        trusted = _trusted("a", 100, 10_000)
        dataset = trusted.dataset
        assert isinstance(dataset, dict)
        template = dataset["events"][0]
        assert isinstance(template, dict)
        dataset["events"] = [
            {
                **template,
                "event_uid": f"event-a-{ordinal:05d}",
                "event_id": f"event-a-{ordinal:05d}",
                "timestamp_ns": str(100 + ordinal),
            }
            for ordinal in range(5_000)
        ]
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        probes = 0

        def cancelled() -> bool:
            nonlocal probes
            probes += 1
            return probes >= 8

        with self.assertRaises(PrivateAnalysisRevisionEvidenceCancelled):
            build_private_analysis_revision_evidence_corpus(
                request,
                (trusted,),
                cancellation_probe=cancelled,
            )
        self.assertGreaterEqual(probes, 8)
        self.assertLess(probes, 32)

    def test_large_active_resource_ordering_cancels_after_bounded_sort_chunk(
        self,
    ) -> None:
        trusted = _trusted("a", 100, 10_000)
        dataset = trusted.dataset
        assert isinstance(dataset, dict)
        resource_ids = [
            f"node-a/INTERFACE/resource-{ordinal:05d}"
            for ordinal in range(8_193)
        ]
        dataset["resources"] = [
            {
                "resource_id": identifier,
                "kind": "INTERFACE",
                "layer": "forwarding",
                "label": identifier,
                "key": {"name": identifier},
                "state": {"oper_status": "up"},
            }
            for identifier in resource_ids
        ]
        dataset["lifecycle_intervals"] = [
            {
                "resource": identifier,
                "valid_from_ns": "100",
                "valid_to_ns": None,
            }
            for identifier in resource_ids
        ]
        dataset["source_records"] = []
        dataset["events"] = []
        dataset["state_intervals"] = []
        dataset["relationship_intervals"] = []
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        original_sorted = sorted
        sort_calls = 0
        cancelled = False

        def observed_sorted(values):  # type: ignore[no-untyped-def]
            nonlocal cancelled, sort_calls
            result = original_sorted(values)
            sort_calls += 1
            cancelled = True
            return result

        with (
            patch.object(
                cancellation_helpers,
                "sorted",
                new=observed_sorted,
                create=True,
            ),
            self.assertRaises(PrivateAnalysisRevisionEvidenceCancelled),
        ):
            build_private_analysis_revision_evidence_corpus(
                request,
                (trusted,),
                cancellation_probe=lambda: cancelled,
            )

        self.assertEqual(sort_calls, 1)

    def test_expensive_record_normalization_and_hash_are_checkpointed(self) -> None:
        def selected_revision() -> tuple[
            TrustedPrivateAnalysisRevision,
            PrivateAnalysisRequest,
        ]:
            trusted = _trusted("a", 100, 200)
            dataset = trusted.dataset
            assert isinstance(dataset, dict)
            source_records = dataset["source_records"]
            assert isinstance(source_records, list)
            record = source_records[0]
            assert isinstance(record, dict)
            dataset["source_records"] = [
                {
                    **record,
                    "message": "x" * 60_000,
                }
            ]
            dataset["events"] = []
            dataset["resources"] = []
            dataset["lifecycle_intervals"] = []
            dataset["state_intervals"] = []
            dataset["relationship_intervals"] = []
            return trusted, _request(
                (trusted,),
                mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
                selected_time_ns=None,
            )

        with self.subTest(phase="normalization"):
            trusted, request = selected_revision()
            cancelled = False
            source_hashes = 0
            original_projection = revision_evidence.project_source_record_for_log
            original_digest = revision_evidence.evidence_payload_digest

            def observed_projection(record):  # type: ignore[no-untyped-def]
                nonlocal cancelled
                result = original_projection(record)
                cancelled = True
                return result

            def observed_digest(schema, payload):  # type: ignore[no-untyped-def]
                nonlocal source_hashes
                if schema == revision_evidence._SOURCE_RECORD_SCHEMA:
                    source_hashes += 1
                return original_digest(schema, payload)

            with (
                patch.object(
                    revision_evidence,
                    "project_source_record_for_log",
                    new=observed_projection,
                ),
                patch.object(
                    revision_evidence,
                    "evidence_payload_digest",
                    new=observed_digest,
                ),
                self.assertRaises(PrivateAnalysisRevisionEvidenceCancelled),
            ):
                build_private_analysis_revision_evidence_corpus(
                    request,
                    (trusted,),
                    cancellation_probe=lambda: cancelled,
                )
            self.assertEqual(source_hashes, 0)

        with self.subTest(phase="hash"):
            trusted, request = selected_revision()
            cancelled = False
            source_hashes = 0
            original_digest = revision_evidence.evidence_payload_digest

            def observed_digest(schema, payload):  # type: ignore[no-untyped-def]
                nonlocal cancelled, source_hashes
                result = original_digest(schema, payload)
                if schema == revision_evidence._PROPRIETARY_SOURCE_RECORD_SCHEMA:
                    source_hashes += 1
                    cancelled = True
                return result

            with (
                patch.object(
                    revision_evidence,
                    "evidence_payload_digest",
                    new=observed_digest,
                ),
                self.assertRaises(PrivateAnalysisRevisionEvidenceCancelled),
            ):
                build_private_analysis_revision_evidence_corpus(
                    request,
                    (trusted,),
                    plugin_evidence_class=(
                        PrivateAnalysisEvidenceClass.PROPRIETARY
                    ),
                    cancellation_probe=lambda: cancelled,
                )
            self.assertEqual(source_hashes, 1)

    def test_client_policy_resource_scan_cancels_before_reading_all_rows(
        self,
    ) -> None:
        trusted = _trusted("a", 100, 200)
        dataset = trusted.dataset
        assert isinstance(dataset, dict)
        resources = dataset["resources"]
        assert isinstance(resources, list)
        template = resources[0]
        assert isinstance(template, dict)
        dataset["resources"] = [
            {
                **template,
                "resource_id": f"node-a/INTERFACE/resource-{ordinal:05d}",
            }
            for ordinal in range(8_192)
        ]
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        scanned = 0
        identify = normalized_data.resource_id

        def counted_resource_id(record: object) -> str:
            nonlocal scanned
            scanned += 1
            assert isinstance(record, dict)
            return identify(record)

        def cancelled() -> bool:
            return scanned >= 256

        with (
            patch.object(
                normalized_data,
                "resource_id",
                side_effect=counted_resource_id,
            ),
            self.assertRaises(PrivateAnalysisRevisionEvidenceCancelled),
        ):
            build_private_analysis_revision_evidence_corpus(
                request,
                (trusted,),
                cancellation_probe=cancelled,
            )

        self.assertGreaterEqual(scanned, 256)
        self.assertLess(scanned, len(dataset["resources"]))

    def test_client_policy_probe_failures_keep_private_static_mapping(self) -> None:
        trusted = _trusted("a", 100, 200)
        dataset = trusted.dataset
        assert isinstance(dataset, dict)
        resources = dataset["resources"]
        assert isinstance(resources, list)
        template = resources[0]
        assert isinstance(template, dict)
        dataset["resources"] = [
            {
                **template,
                "resource_id": f"node-a/INTERFACE/resource-{ordinal:05d}",
            }
            for ordinal in range(1_024)
        ]
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        scanned = 0
        identify = normalized_data.resource_id

        def counted_resource_id(record: object) -> str:
            nonlocal scanned
            scanned += 1
            assert isinstance(record, dict)
            return identify(record)

        def failed_probe() -> bool:
            if scanned >= 256:
                raise RuntimeError("C:\\private\\operator\\secret")
            return False

        with (
            patch.object(
                normalized_data,
                "resource_id",
                side_effect=counted_resource_id,
            ),
            self.assertRaisesRegex(
                PrivateAnalysisRevisionEvidenceError,
                "private-analysis cancellation state is unavailable",
            ) as raised,
        ):
            build_private_analysis_revision_evidence_corpus(
                request,
                (trusted,),
                cancellation_probe=failed_probe,
            )

        self.assertNotIn("operator", str(raised.exception))
        self.assertLess(scanned, len(dataset["resources"]))

    def test_sequence_validation_cancels_before_a_late_invalid_element(self) -> None:
        values: list[object] = [{} for _ in range(512)]
        values.append(object())
        probes = 0

        def cancelled() -> bool:
            nonlocal probes
            probes += 1
            return probes == 2

        with self.assertRaises(PrivateAnalysisRevisionEvidenceCancelled):
            revision_evidence._dataset_sequence(
                {"events": values},
                "events",
                cancellation_probe=cancelled,
            )
        self.assertEqual(probes, 2)

    def test_cancellation_probe_failure_is_bounded_and_fail_closed(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )

        def failed_probe() -> bool:
            raise RuntimeError("C:\\private\\operator\\secret")

        with self.assertRaisesRegex(
            PrivateAnalysisRevisionEvidenceError,
            "cancellation state is unavailable",
        ) as raised:
            build_private_analysis_revision_evidence_corpus(
                request,
                (trusted,),
                cancellation_probe=failed_probe,
            )
        self.assertNotIn("operator", str(raised.exception))

    def test_corpus_ceiling_fails_before_constructing_entry_n_plus_one(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        with (
            patch.object(
                revision_evidence,
                "_entry",
                wraps=revision_evidence._entry,
            ) as construct,
            patch.object(
                revision_evidence,
                "event_redaction_policy",
                wraps=revision_evidence.event_redaction_policy,
            ) as compile_policy,
            self.assertRaisesRegex(
                PrivateAnalysisRevisionEvidenceError,
                "configured corpus entry limit",
            ),
        ):
            build_private_analysis_revision_evidence_corpus(
                request,
                (trusted,),
                maximum_entries=1,
            )
        self.assertEqual(construct.call_count, 0)
        self.assertEqual(compile_policy.call_count, 0)

    def test_filled_event_capacity_stops_before_resource_preprocessing(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        # metadata + one pin + two source records + two events exhaust six
        # slots; resource and descriptor indexing must not begin afterward.
        with (
            patch.object(
                revision_evidence,
                "_descriptors",
                wraps=revision_evidence._descriptors,
            ) as descriptors,
            patch.object(
                revision_evidence,
                "resource_id",
                wraps=revision_evidence.resource_id,
            ) as identify,
            self.assertRaisesRegex(
                PrivateAnalysisRevisionEvidenceError,
                "configured corpus entry limit",
            ),
        ):
            build_private_analysis_revision_evidence_corpus(
                request,
                (trusted,),
                maximum_entries=6,
            )
        self.assertEqual(descriptors.call_count, 0)
        self.assertEqual(identify.call_count, 0)

    def test_corpus_payload_ceiling_fails_during_projection(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        with self.assertRaisesRegex(
            PrivateAnalysisRevisionEvidenceError,
            "configured corpus payload byte limit",
        ):
            build_private_analysis_revision_evidence_corpus(
                request,
                (trusted,),
                maximum_payload_bytes=1,
            )

    def test_reference_binding_detects_stale_revision_identity(self) -> None:
        trusted = _trusted("a", 100, 200)
        request = _request(
            (trusted,),
            mode=PrivateAnalysisClockMode.LATEST_PER_REVISION,
            selected_time_ns=None,
        )
        stale = replace(
            trusted,
            revision=replace(trusted.revision, identity_digest="9" * 64),
        )
        with self.assertRaisesRegex(ValueError, "exactly match"):
            build_private_analysis_revision_evidence_corpus(request, (stale,))


if __name__ == "__main__":
    unittest.main()
