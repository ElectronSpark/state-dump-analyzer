from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "demo"))

from router_dump_analyzer.web import runtime_api
from router_dump_analyzer.normalized_data import NormalizedDataService
from router_dump_analyzer.revision_store import AssemblyDescriptor, RevisionDescriptor
from router_dump_analyzer.runtime import CoreRuntimeSession
from router_dump_analyzer.web.runtime_context import activate_runtime_session
from rsl_demo_plugin.data import REVISION_ID
from rsl_demo_plugin.scale_data import ScaleRuntime
from router_dump_analyzer.source_record_core import record_lanes_for_window
from tests.support.generated_demo import (
    configure_generated_demo_for_tests,
    generated_demo_client,
    generated_demo_runtime_session,
)
from tests.support.normalized_data import StaticDataPolicy, StaticDatasetSource


APP_JS = ROOT / "frontend" / "assets" / "app.js"
STYLES_CSS = ROOT / "frontend" / "assets" / "styles.css"


def javascript_function(source: str, name: str) -> str:
    """Return one top-level function body for focused source-contract checks."""

    start = source.index(f"function {name}(")
    match = re.search(r"\nfunction [A-Za-z0-9_$]+\(", source[start + 1 :])
    return source[start :] if match is None else source[start : start + 1 + match.start()]


def scale_runtime_dataset() -> tuple[dict[str, object], str, str, str, str]:
    root = "data/ETG/root"
    old_path = "data/ETE/root/old"
    new_path = "data/ETE/root/new"
    future_path = "data/ETE/root/future"
    resources = [
        {
            "resource_id": identifier,
            "kind": "ETG" if identifier == root else "ETE",
            "layer": "data",
            "label": identifier.rsplit("/", 1)[-1],
        }
        for identifier in (root, old_path, new_path, future_path)
    ]
    relationships = [
        {
            "relationship_id": "owns-old",
            "source": root,
            "target": old_path,
            "relation_type": "owns",
            "valid_from_ns": "100",
            "valid_to_ns": "200",
            "quality": "exact",
        },
        {
            "relationship_id": "owns-new",
            "source": root,
            "target": new_path,
            "relation_type": "owns",
            "valid_from_ns": "200",
            "valid_to_ns": None,
            "quality": "exact",
        },
        {
            "relationship_id": "owns-future",
            "source": root,
            "target": future_path,
            "relation_type": "owns",
            "valid_from_ns": "300",
            "valid_to_ns": "400",
            "quality": "exact",
        },
    ]
    relationships_by_endpoint = {item["resource_id"]: [] for item in resources}
    for relationship in relationships:
        relationships_by_endpoint[relationship["source"]].append(relationship)
        relationships_by_endpoint[relationship["target"]].append(relationship)
    lifecycle_by_resource = {
        item["resource_id"]: [
            {
                "resource": item["resource_id"],
                "valid_from_ns": "0",
                "valid_to_ns": None,
                "start_event_uid": None,
                "end_event_uid": None,
            }
        ]
        for item in resources
    }
    state_by_resource = {item["resource_id"]: [] for item in resources}
    runtime = ScaleRuntime(
        resources=resources,
        resource_by_id={item["resource_id"]: item for item in resources},
        resources_by_kind={
            "ETG": [resources[0]],
            "ETE": resources[1:],
        },
        resource_counts={"ETG": 1, "ETE": 3},
        events=[],
        event_by_uid={},
        event_times=[],
        events_by_resource={item["resource_id"]: [] for item in resources},
        lifecycle_by_resource=lifecycle_by_resource,
        state_by_resource=state_by_resource,
        relationships=relationships,
        relationships_by_endpoint=relationships_by_endpoint,
        mutations=[],
        mutation_times=[],
        mutations_by_endpoint={item["resource_id"]: [] for item in resources},
        initial_resource_ids=[root],
    )
    dataset: dict[str, object] = {
        "_scale_runtime": runtime,
        "demo": {
            "timeline_start_ns": "0",
            "timeline_end_ns": "500",
            "capture_ns": "500",
        },
        "resources": resources,
        "events": [],
        "source_records": [],
        "source_record_descriptors": [],
        "relationship_descriptors": [
            {
                "relation_type": "owns",
                "label": "Owns",
                "directed": True,
            }
        ],
        "relationship_mutations": [],
    }
    return dataset, root, old_path, new_path, future_path


class NodeWorkspaceRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configure_generated_demo_for_tests()
        cls.script = APP_JS.read_text(encoding="utf-8")
        cls.styles = STYLES_CSS.read_text(encoding="utf-8")

    def test_record_lane_budget_is_shared_before_broad_lane_can_starve_exact_lane(self) -> None:
        records = [
            {
                "source_record_uid": f"record-{index}",
                "timestamp_ns": str(index),
                "source_type": "ctf",
                "source_name": "trace.ctf2",
                "record_name": "special" if index == 9 else "ordinary",
                "message": f"record {index}",
                "matched_event_uid": None,
            }
            for index in range(10)
        ]
        lanes = record_lanes_for_window(
            records,
            [
                {"lane_id": "broad", "label": "Broad", "pattern": ".+"},
                {"lane_id": "exact", "label": "Exact", "pattern": "special"},
            ],
            start_ns=0,
            end_ns=20,
            known_source_types={"ctf"},
            max_marks=3,
        )

        self.assertEqual([lane["record_count"] for lane in lanes], [10, 1])
        self.assertEqual([len(lane["marks"]) for lane in lanes], [2, 1])
        self.assertEqual(
            lanes[1]["marks"][0]["source_record_uid"],
            "record-9",
        )
        self.assertEqual(sum(len(lane["marks"]) for lane in lanes), 3)
        self.assertTrue(lanes[0]["truncated"])
        self.assertFalse(lanes[1]["truncated"])

    def test_scale_timeline_expands_historical_relationship_endpoints_in_window(self) -> None:
        dataset, root, old_path, new_path, future_path = scale_runtime_dataset()
        with (
            generated_demo_runtime_session(),
            patch.object(runtime_api, "load_dataset", return_value=dataset),
            patch.object(runtime_api, "_require_revision", return_value=None),
        ):
            payload = runtime_api.timeline_query(
                REVISION_ID,
                {
                    "start_ns": "50",
                    "end_ns": "250",
                    "resource_ids": [root],
                    "relationship_history_roots": [root],
                },
            )

        self.assertEqual(payload["requested_resource_ids"], [root])
        self.assertEqual(payload["relationship_history_roots"], [root])
        self.assertEqual(
            set(payload["relationship_history_expanded_resource_ids"]),
            {old_path, new_path},
        )
        self.assertEqual(
            {lane["resource_id"] for lane in payload["lanes"]},
            {root, old_path, new_path},
        )
        self.assertNotIn(future_path, {lane["resource_id"] for lane in payload["lanes"]})
        self.assertEqual(
            {item["relationship_id"] for item in payload["relationship_intervals"]},
            {"owns-old", "owns-new"},
        )

    def test_timeline_request_generation_ignores_stale_success_and_failure(self) -> None:
        function = javascript_function(self.script, "requestTimeline")
        self.assertIn("const requestId = ++state.timelineRequestId;", function)
        self.assertGreaterEqual(
            function.count("if (requestId !== state.timelineRequestId) return false;"),
            2,
        )
        self.assertLess(
            function.index("if (requestId !== state.timelineRequestId) return false;"),
            function.index("state.timelinePayload = payload;"),
        )
        catch_index = function.index("} catch (error) {")
        self.assertIn(
            "if (requestId !== state.timelineRequestId) return false;",
            function[catch_index:],
        )

    def test_hidden_selected_resource_is_not_reintroduced_as_relationship_root(self) -> None:
        function = javascript_function(self.script, "requestTimeline")

        self.assertIn(
            "const selectedRelationshipRoot = canonicalResourceId(state.selectedResourceId)",
            function,
        )
        self.assertIn(
            "!resourceHiddenFromTimeline(selectedRelationshipRoot)",
            function,
        )
        self.assertIn(
            "relationship_history_roots: relationshipHistoryRoots",
            function,
        )

    def test_event_clustering_and_density_resolution_follow_zoom_to_timestamp_resolution(self) -> None:
        clustering = javascript_function(self.script, "buildClientGlyphs")
        density = javascript_function(self.script, "eventDensityLane")
        windowing = javascript_function(self.script, "densityRenderWindow")

        self.assertIn("13 / Math.max(1, state.trackWidth) * 100", clustering)
        self.assertNotIn("Math.max(7", clustering)
        self.assertIn("const requestedBins = 180 * state.zoom", density)
        self.assertIn("Number.isFinite(requestedBins) ? Math.round(requestedBins)", density)
        self.assertIn("maximumUsefulBins", density)
        self.assertIn("captureSlots", density)
        self.assertNotRegex(density, r"Math\.min\(\s*\d[\d_]*\s*,\s*requestedBins")
        self.assertIn("const bins = new Map();", density)
        self.assertIn("densityRenderWindow(binCount, trackWidth)", density)
        self.assertIn("if (index < renderWindow.start || index >= renderWindow.end) continue;", density)
        self.assertIn("visibleStart", windowing)
        self.assertIn("overscan", windowing)
        self.assertIn("data-density-window-start", density)

    def test_interval_highlighting_is_half_open_while_moment_selection_is_inclusive(self) -> None:
        intersects = javascript_function(self.script, "intersectsRange")
        moment = javascript_function(self.script, "inSelectedRange")
        self.assertIn("toNs(start) < bounds[1]", intersects)
        self.assertNotIn("toNs(start) <= bounds[1]", intersects)
        self.assertIn("toNs(end) > bounds[0]", intersects)
        self.assertNotIn("toNs(end) >= bounds[0]", intersects)
        self.assertIn("candidate >= bounds[0] && candidate <= bounds[1]", moment)
        self.assertIn(".timeline-frame.has-range .partial-range", self.styles)
        self.assertIn(".cluster-event.in-range", self.styles)

    def test_dashboard_layout_storage_is_scoped_by_revision_and_schema(self) -> None:
        storage_key = javascript_function(self.script, "dashboardLayoutStorageKey")
        initialization = javascript_function(self.script, "initializeDashboardLayout")
        self.assertIn("workspaceMetadata().revision_id", storage_key)
        self.assertIn("dashboardDescriptors()", storage_key)
        self.assertIn("item.dashboard_id", storage_key)
        self.assertIn("encodeURIComponent(revision)", storage_key)
        self.assertIn("hash.toString(16)", storage_key)
        self.assertIn("localStorage.getItem(dashboardLayoutStorageKey())", initialization)
        self.assertNotIn('localStorage.getItem(DASHBOARD_LAYOUT_STORAGE_KEY_PREFIX)', initialization)

    def test_generic_resource_tables_honor_plugin_key_and_state_fields(self) -> None:
        columns = javascript_function(self.script, "presentationColumns")
        field_value = javascript_function(self.script, "resourceTableFieldValue")
        field_label = javascript_function(self.script, "resourceTableFieldLabel")
        render = javascript_function(self.script, "renderResourceTables")

        explicit_index = columns.index("Array.isArray(table?.columns)")
        descriptor_index = columns.index("table?.descriptor")
        self.assertLess(explicit_index, descriptor_index)
        self.assertIn("descriptor.key_fields", columns)
        self.assertIn("descriptor.default_table_fields", columns)
        self.assertIn('normalizeResourceTableColumn(field, "key")', columns)
        self.assertIn('normalizeResourceTableColumn(field, "state")', columns)

        self.assertIn("resourceRecord.key || item.key", field_value)
        self.assertIn('column.source === "key"', field_value)
        self.assertIn('column.source === "state"', field_value)
        self.assertGreaterEqual(field_value.count("dashboardFieldValue("), 5)
        self.assertIn('source === "key"', field_label)
        self.assertIn('source === "state"', field_label)
        self.assertIn("formatResourceTableCell(item, column)", render)

    def test_resource_bundle_details_are_plugin_descriptor_driven(self) -> None:
        detail_columns = javascript_function(self.script, "resourceBundleDetailColumns")
        applicability = javascript_function(self.script, "resourceBundleColumnApplies")
        facts = javascript_function(self.script, "resourceBundleDetailFacts")
        hover = javascript_function(self.script, "resourceBundleHoverHtml")
        render = javascript_function(self.script, "renderResourceBundleTable")

        self.assertIn("resourceKindDescriptor(kind)", detail_columns)
        self.assertIn("descriptor.columns", detail_columns)
        self.assertIn("kindDescriptor.key_fields", detail_columns)
        self.assertIn("kindDescriptor.default_table_fields", detail_columns)
        self.assertIn(".slice(0, 12)", detail_columns)
        self.assertIn("column.resource_kinds", applicability)
        self.assertIn("column.depths", applicability)
        self.assertIn("column.relation_types", applicability)
        self.assertIn("node.relation_label", facts)
        self.assertIn("relationship.source", facts)
        self.assertIn("relationship.target", facts)
        self.assertIn("relationship.quality", facts)
        self.assertIn("resourceBundleDetailFacts", hover)
        self.assertIn("data-bundle-details", render)
        self.assertIn("bindCorrelationHover", render)
        self.assertNotRegex(
            "\n".join((detail_columns, applicability, facts, hover, render)),
            r'kind\s*===?\s*["\'](?:NEIGHBOR|ETG|ETE)["\']',
        )

    def test_resource_presentation_tags_are_plugin_kind_metadata(self) -> None:
        tags = javascript_function(self.script, "presentationTags")
        bundle_render = javascript_function(self.script, "renderResourceBundleTable")

        self.assertIn("resourceKindDescriptor(kind)?.presentation_tags", tags)
        self.assertIn("descriptorTags", tags)
        self.assertIn("recordTags", tags)
        self.assertIn('tags.has("compact") || tags.has("connector")', bundle_render)
        self.assertIn('compact ? " resource-connector"', bundle_render)

    def test_keyboard_space_activation_prevents_page_scrolling(self) -> None:
        patterns = [
            r'if \(event\.key !== "Enter" && event\.key !== " "\) return;\s*event\.preventDefault\(\);\s*choose\(\);',
            r'if \(event\.target !== row \|\| \(event\.key !== "Enter" && event\.key !== " "\)\) return;\s*event\.preventDefault\(\);\s*closeCorrelationHover\(\);\s*selectResource\(row\.dataset\.resourceId\);',
        ]
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertRegex(self.script, pattern)

    def test_topology_member_deep_link_bootstraps_its_exact_revision(self) -> None:
        with generated_demo_client() as client:
            session = client.app.state.runtime_session
            descriptor = session.revision_store.revision_for_node("node-b")
            response = client.get("/v1/nodes/node-b/workspace")
            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            expected = session.data_service.client_dataset(node_id="node-b")
            default = client.get("/v1/nodes/node-a/workspace")
            self.assertEqual(default.status_code, 200, default.text)
            resource_ids = {item["resource_id"] for item in payload["resources"]}
            requested_ids = sorted(resource_ids)[:3]
            timeline = client.post(
                f"/v1/revisions/{descriptor.revision_id}/timeline/query",
                json={
                    "start_ns": payload["workspace"]["timeline_start_ns"],
                    "end_ns": payload["workspace"]["timeline_end_ns"],
                    "resource_ids": requested_ids,
                },
            )
            self.assertEqual(timeline.status_code, 200, timeline.text)

        self.assertEqual(
            payload["workspace"]["workspace_kind"],
            "node",
        )
        self.assertEqual(payload["workspace"]["history_mode"], "server-windowed")
        self.assertEqual(payload["workspace"]["revision_id"], descriptor.revision_id)
        self.assertEqual(payload["workspace"]["node_id"], "node-b")
        self.assertEqual(payload["workspace"]["resource_count"], descriptor.resource_count)
        self.assertEqual(payload["workspace"]["event_count"], descriptor.event_count)
        self.assertEqual(payload["node_snapshot"]["revision_id"], descriptor.revision_id)
        self.assertEqual(payload["node_snapshot"]["source"], "plugin-revision-store")
        self.assertTrue(payload["resources"])
        self.assertEqual(payload["resources"], expected["resources"])
        self.assertEqual(
            payload["kind_descriptors"], expected["kind_descriptors"]
        )
        self.assertEqual(
            payload["schema"], expected["schema"]
        )
        self.assertTrue(
            resource_ids.isdisjoint(
                item["resource_id"] for item in default.json()["resources"]
            )
        )
        # A bounded bootstrap does not manufacture all-time history; use the
        # selected revision's actual timeline route for interval evidence.
        for field in ("events", "state_intervals", "lifecycle_intervals", "relationship_intervals"):
            self.assertEqual(payload[field], [])
        self.assertEqual(
            payload["history_transport"]["events"]["total_count"],
            descriptor.event_count,
        )
        timeline_payload = timeline.json()
        self.assertTrue(
            all(
                item["source"] in resource_ids and item["target"] in resource_ids
                for item in timeline_payload["relationship_intervals"]
            )
        )
        self.assertEqual(
            {lane["resource_id"] for lane in timeline_payload["lanes"]},
            set(requested_ids),
        )

    def test_topology_member_navigation_requests_the_node_workspace_route(self) -> None:
        bootstrap = javascript_function(self.script, "bootstrapDatasetPath")
        self.assertIn('return "/v1/workspace"', bootstrap)
        self.assertIn('/v1/nodes/${encodeURIComponent(navigationContext.nodeId)}/workspace', bootstrap)
        initialize = self.script[self.script.index("async function initialize()") :]
        self.assertIn(
            "state.dataset = await analysisRuntimeApi(bootstrapDatasetPath());",
            initialize,
        )

    def test_node_workspace_http_preserves_plugin_vocabulary_and_disclosure(self) -> None:
        kind = "vendor.opaque_kind-v7"
        perspective = "vendor.observation-x9"
        projection = "vendor.projection-y8"
        relation = "vendor.raw_relation-z6"
        descriptor = RevisionDescriptor(
            node_id="opaque-node", revision_id="opaque/revision", label="Literal node",
            event_count=0, resource_count=1,
        )
        dataset = {
            "workspace": {"revision_id": descriptor.revision_id},
            "resources": [{
                "resource_id": "opaque-id", "kind": kind, "layer": perspective,
                "label": "Literal resource", "exists": None, "status": "not-ready!",
                "state": {"mode": "not-ready!", "secret": "private-sentinel"},
            }],
            "kind_descriptors": [{
                "kind": kind, "label": "Literal kind", "condition_field": "mode",
                "properties": [
                    {"name": "mode", "type": "string", "client_visible": True},
                    {"name": "secret", "type": "string", "sensitive": True},
                ],
            }],
            "relationship_descriptors": [{
                "relation_type": relation, "label": "Literal relation", "directed": False,
            }],
            "topology_capabilities": {
                "projections": [{
                    "projection_id": projection, "label": "Literal projection",
                    "supported_status_perspective_ids": [perspective],
                }],
                "status_perspectives": [{
                    "status_perspective_id": perspective, "label": "Literal perspective",
                }],
                "defaults": {"projection_id": projection, "status_perspective_id": perspective},
            },
            "lifecycle_intervals": [], "state_intervals": [],
            "relationship_intervals": [], "events": [],
            "_private_cache": {"secret": "cache-sentinel"},
        }
        selections = []

        class SelectedNodeSource(StaticDatasetSource):
            def load_dataset(self, revision_id=None, **selection):
                selections.append(selection)
                return super().load_dataset(revision_id, **selection)

        source = SelectedNodeSource(dataset)
        store = SimpleNamespace(
            assembly=AssemblyDescriptor("opaque-assembly", (descriptor,)),
            revision_for_node=lambda node_id: {descriptor.node_id: descriptor}[node_id],
        )
        session = CoreRuntimeSession(
            plugin_session=SimpleNamespace(revision_store=store),
            data_service=NormalizedDataService(source, StaticDataPolicy()),
        )
        application = FastAPI()
        application.include_router(runtime_api.api_router)

        @application.middleware("http")
        async def bind_session(request, call_next):
            with activate_runtime_session(session):
                return await call_next(request)

        selectors = {
            "plugin_set_id": "vendor.set", "plugin_id": "vendor.plugin",
            "projection_id": projection, "status_perspective_id": perspective,
        }
        with TestClient(application) as client:
            response = client.get("/v1/nodes/opaque-node/workspace", params=selectors)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn({"node_id": descriptor.node_id}, selections)
            unknown = client.get("/v1/nodes/unknown-node/workspace")
            self.assertEqual(unknown.status_code, 404, unknown.text)
        payload = response.json()
        self.assertEqual(payload["workspace"]["revision_id"], descriptor.revision_id)
        self.assertEqual(payload["workspace"]["history_mode"], "embedded-history")
        self.assertEqual(payload["node_snapshot"]["plugin_selection"], selectors)
        self.assertEqual(payload["resources"][0]["kind"], kind)
        self.assertEqual(payload["resources"][0]["layer"], perspective)
        self.assertEqual(payload["resources"][0]["status"], "not-ready!")
        self.assertIsNone(payload["resources"][0]["exists"])
        self.assertEqual(payload["resources"][0]["state"], {"mode": "not-ready!"})
        for field in ("kind_descriptors", "relationship_descriptors", "topology_capabilities"):
            self.assertEqual(payload[field], dataset[field])
        for field in ("lifecycle_intervals", "state_intervals", "relationship_intervals"):
            self.assertEqual(payload[field], [])
        self.assertNotIn("timeline", payload)
        self.assertNotIn("private-sentinel", response.text)
        self.assertNotIn("cache-sentinel", response.text)

    def test_node_history_workspace_uses_runtime_identity_and_counts(self) -> None:
        detection = javascript_function(self.script, "isTopologyNodeSnapshot")
        identity = javascript_function(self.script, "renderWorkspaceIdentity")
        summary = javascript_function(self.script, "fillSummary")

        self.assertIn('workspace.history_mode === "point-in-time"', detection)
        self.assertIn('workspace.capabilities?.historical_state === false', detection)
        self.assertNotIn("dataset?.demo", detection)
        self.assertIn("if (!isNodeWorkspace()) return;", identity)
        self.assertIn("Node analysis workspace.", identity)
        self.assertIn("eventCount.toLocaleString()", identity)
        self.assertIn("runtime capabilities", identity)
        self.assertIn('Inspect member resources', identity)
        self.assertIn("workspace.matched_event_count", summary)
        self.assertIn("workspace.resource_count", summary)
        self.assertIn("isNodeWorkspace()", summary)
        self.assertNotIn("point-in-time resources", summary)

    def test_node_snapshot_empty_features_explain_plugin_coverage(self) -> None:
        unavailable = javascript_function(self.script, "nodeSnapshotUnavailableMarkup")
        incident = javascript_function(self.script, "renderIncidentSummary")
        findings = javascript_function(self.script, "renderFindings")
        inventory = javascript_function(self.script, "renderInventory")
        dashboards = javascript_function(self.script, "renderPluginDashboards")
        event_log = javascript_function(self.script, "rebuildEventLogRows")

        self.assertIn("NOT SUPPLIED BY THE MEMBER PLUG-IN", unavailable)
        self.assertIn("Event history is unavailable", incident)
        self.assertIn("This is not a zero-finding result", findings)
        self.assertIn("Archive inventory is not part of this snapshot", inventory)
        self.assertIn("Resource dashboards were not supplied", dashboards)
        self.assertIn("History streams not supplied by member plug-ins", event_log)
        self.assertIn("No normalized or retained source records match these filters", event_log)

    def test_event_details_are_hydrated_on_demand_with_per_resource_effects(self) -> None:
        normalize = javascript_function(self.script, "normalizeMark")
        request = javascript_function(self.script, "requestEventDetail")
        hydrate = javascript_function(self.script, "hydrateEventDetail")
        inspector = javascript_function(self.script, "renderEventInspector")
        hover = javascript_function(self.script, "eventHoverHtml")

        self.assertIn("resourceEffectFor(event, lane.resourceId)", normalize)
        self.assertIn("resource_effect", normalize)
        self.assertIn('revisionPath(`events/${encodeURIComponent(uid)}`)', request)
        self.assertIn("state.eventDetailRequests.has(uid)", request)
        self.assertIn("state.eventDetailByUid.has(uid)", request)
        self.assertIn("resourceEffectFor(normalized, lane.resourceId)", hydrate)
        self.assertIn("resourceEffectFor(event, canonicalId)", inspector)
        self.assertIn("eventEffectMarkup(event, canonicalId)", inspector)
        self.assertIn("resourceEffectCondition(mark.effect, lane.resourceId)", hover)
        self.assertNotRegex(
            "\n".join((normalize, request, hydrate, inspector, hover)),
            r'kind\s*===?\s*["\'](?:ETG|ETE|DTE|NEIGHBOR)["\']',
        )

    def test_timeline_reset_rebuilds_log_and_range_overlap_is_half_open(self) -> None:
        reset = javascript_function(self.script, "resetTimelineView")
        highlight = javascript_function(self.script, "applyRangeHighlight")
        local_summary = javascript_function(self.script, "localRangeSummary")

        self.assertIn("clearRangeSelection({ refreshEventLog: false })", reset)
        self.assertIn("renderEventTable({ resetScroll: true })", reset)
        self.assertNotIn("state.rangeStartNs = null", reset)
        self.assertIn("intersectsRange(element.dataset.rangeStartNs, element.dataset.rangeEndNs)", highlight)
        self.assertIn("item.startNs < end && item.endNs > start", local_summary)
        self.assertNotIn("item.startNs <= end", local_summary)
        self.assertNotIn("item.endNs >= start", local_summary)

    def test_resource_views_preserve_returned_time_while_new_moment_is_pending(self) -> None:
        cursor = javascript_function(self.script, "setCursor")
        request = javascript_function(self.script, "requestResources")
        summary = javascript_function(self.script, "resourceTimeSummary")
        settle = javascript_function(self.script, "settleResourceRequest")
        refresh = javascript_function(self.script, "refreshResourceTimePresentation")
        table = javascript_function(self.script, "renderResourceTables")
        bundle = javascript_function(self.script, "renderResourceBundleTable")
        statistic = javascript_function(self.script, "renderDashboardStatistic")

        self.assertIn("markResourcesPending(state.cursorNs)", cursor)
        self.assertNotIn("renderResourceTables()", cursor)
        self.assertNotIn("renderPluginDashboards()", cursor)
        self.assertIn("const requestedTimeNs = state.cursorNs;", request)
        self.assertIn("time_ns: requestedTimeNs.toString()", request)
        self.assertGreaterEqual(request.count("if (requestId !== state.resourceRequestId) return;"), 2)
        self.assertNotIn("renderPluginDashboards()", request)
        self.assertNotIn("renderResourceTables();\n  if", request)
        self.assertIn("state.resourceReturnedTimeNs", settle)
        self.assertIn("state.resourcePending = false", settle)
        self.assertIn("refreshResourceTimePresentation()", settle)
        self.assertIn('querySelector("[data-resource-time-summary]")', refresh)
        self.assertIn('wrap.setAttribute("aria-busy", String(state.resourcePending))', refresh)
        self.assertIn("showing ${formatOffset(shown)}", summary)
        self.assertIn("updating to ${formatOffset(requested)}", summary)
        self.assertIn("resourceTimeSummary()", table)
        self.assertIn("resourceTimeSummary()", bundle)
        self.assertIn("resourceTimeSummary()", statistic)

    def test_zero_result_resource_search_preserves_the_selected_kind(self) -> None:
        render = javascript_function(self.script, "renderResourceTables")

        self.assertIn("const resourceSearchActive = Boolean", render)
        self.assertIn("!activeView && !state.selectedResourceKind", render)
        self.assertIn("&& !resourceSearchActive", render)
        self.assertIn("&& !kinds.includes(state.selectedResourceKind)", render)
        self.assertLess(
            render.index("&& !resourceSearchActive"),
            render.index("state.selectedResourceKind = kinds[0];"),
        )

    def test_full_correlation_query_does_not_keep_selected_root_filter(self) -> None:
        request = javascript_function(self.script, "requestGraph")
        self.assertIn("const resourceIds = state.graphShowFull", request)
        self.assertRegex(request, r"state\.graphShowFull\s*\? \[\]")
        self.assertIn("resource_ids: resourceIds", request)

    def test_route_resolution_ignores_stale_responses_and_attributes_request_basis(self) -> None:
        route = javascript_function(self.script, "resolveRoute")
        self.assertIn("const requestId = ++state.routeRequestId;", route)
        self.assertIn("const requestContext", route)
        self.assertIn("timeNs: state.cursorNs", route)
        self.assertIn("time_ns: requestContext.timeNs.toString()", route)
        self.assertGreaterEqual(
            route.count("if (requestId !== state.routeRequestId) return;"),
            2,
        )
        self.assertIn('result.setAttribute("aria-busy", "true")', route)
        self.assertGreaterEqual(route.count('result.setAttribute("aria-busy", "false")'), 2)
        self.assertIn("returnedTimeCopy", route)

    def test_invalid_zoom_is_normalized_without_an_upper_scale_cap(self) -> None:
        apply_zoom = javascript_function(self.script, "applyTimelineZoom")
        controls = javascript_function(self.script, "bindControls")

        self.assertRegex(
            apply_zoom,
            r"!Number\.isFinite\(zoom\)\s*\|\|\s*zoom < 1",
        )
        self.assertIn("control.value = timelineZoomControlValue(normalized)", apply_zoom)
        self.assertIn('control.setAttribute("aria-invalid", "true")', apply_zoom)
        self.assertIn("state.zoom = viewport.zoom", apply_zoom)
        self.assertNotIn("MAX_ZOOM", apply_zoom)
        self.assertNotRegex(apply_zoom, r"zoom\s*=\s*Math\.min\(")
        self.assertIn("applyTimelineZoom(event.target.value", controls)
        self.assertIn('zoomTimelineBy("out")', controls)
        self.assertIn('zoomTimelineBy("in")', controls)

    def test_incident_arrows_only_follow_explicit_plugin_causal_links(self) -> None:
        path = javascript_function(self.script, "incidentCausalPath")
        render = javascript_function(self.script, "renderIncidentSummary")

        self.assertIn("state.dataset?.causal_links", path)
        self.assertIn("state.dataset?.causal_link_descriptors", path)
        self.assertIn("state.dataset?.schema?.causal_link_types", path)
        self.assertIn("source_event_uid", path)
        self.assertIn("target_event_uid", path)
        self.assertIn("explicitPath && link", render)
        self.assertIn("Highlighted failures (unordered)", render)
        self.assertNotIn('index ? \'<div class="chain-arrow"', render)


if __name__ == "__main__":
    unittest.main()
