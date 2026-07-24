from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "frontend" / "assets" / "app.js"
INDEX_HTML = ROOT / "frontend" / "pages" / "node.html"


def javascript_function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    match = re.search(r"\n(?:async )?function [A-Za-z0-9_$]+\(", source[start + 1 :])
    return source if match is None else source[start : start + 1 + match.start()]


class ScaleHistoryFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = APP_JS.read_text(encoding="utf-8")
        cls.index = INDEX_HTML.read_text(encoding="utf-8")

    def test_server_history_mode_is_scale_only_and_snapshot_safe(self) -> None:
        detection = javascript_function(self.script, "usesServerWindowedHistory")

        self.assertIn("isScaleMode()", detection)
        self.assertIn("!isTopologyNodeSnapshot()", detection)
        self.assertIn('history_transport?.mode === "server-windowed"', detection)

    def test_density_uses_bounded_generation_safe_server_pages_and_local_cache(self) -> None:
        render = javascript_function(self.script, "eventDensityLane")
        schedule = javascript_function(self.script, "scheduleDensityPageRequest")
        local = javascript_function(self.script, "localDensityHistogram")
        height = javascript_function(self.script, "densityBinHeight")

        self.assertIn("usesServerWindowedHistory()", render)
        self.assertIn("densityServerQuery(binCount, renderWindow)", render)
        self.assertIn("cachedDensityPage(query)", render)
        self.assertIn("scheduleDensityPageRequest(query)", render)
        self.assertIn("localDensityHistogram(binCount)", render)
        self.assertNotIn("state.eventByUid.values()", render)
        self.assertIn('revisionPath("events/density/query")', schedule)
        self.assertIn("const requestId = ++state.densityRequestId", schedule)
        self.assertGreaterEqual(schedule.count("requestId !== state.densityRequestId"), 2)
        self.assertIn("start_ns: query.startNs.toString()", schedule)
        self.assertIn("bin_count: query.pageBinCount", schedule)
        self.assertIn("state.densityLocalCache?.key === key", local)
        self.assertIn("state.eventByUid.values()", local)
        self.assertIn("Math.log2", height)
        self.assertNotIn("maximum", render)

    def test_density_pages_keep_server_relative_indices_and_bound_hover_models(self) -> None:
        normalize = javascript_function(self.script, "normalizeDensityPage")
        render = javascript_function(self.script, "eventDensityLane")

        self.assertIn("query.globalStart + pageIndex", normalize)
        self.assertIn("Number(raw.index || 0)", normalize)
        self.assertNotIn("startNs - state.viewStartNs", normalize)
        self.assertIn('startsWith("density:")', render)
        self.assertIn("state.hoverModels.delete(key)", render)

    def test_server_log_query_sends_explicit_plugin_source_types_and_range(self) -> None:
        body = javascript_function(self.script, "serverEventLogRequestBody")
        selected_types = javascript_function(self.script, "selectedEventLogSourceTypes")
        grouping = javascript_function(self.script, "sourceDescriptorStreamGroup")
        initialize_groups = javascript_function(self.script, "initializeSourceRecordGroups")

        self.assertIn("source_types: selectedEventLogSourceTypes()", body)
        self.assertIn("include_normalized: state.eventLogInclude.normalized", body)
        self.assertIn("layers: layer ? [layer] : []", body)
        self.assertIn("start_ns: bounds[0].toString()", body)
        self.assertIn("end_ns: bounds[1].toString()", body)
        self.assertIn("state.sourceRecordTypes.values()", selected_types)
        self.assertIn("descriptor?.stream_group", grouping)
        self.assertIn("source-type:", grouping)
        self.assertNotIn('"ctf"', grouping.lower())
        self.assertIn("state.includedSourceRecordGroups.has(group)", selected_types)
        self.assertIn("source_record_group_descriptors", initialize_groups)
        self.assertIn("descriptor.default_included === true", initialize_groups)
        self.assertIn('id="event-source-group-controls"', self.index)
        self.assertNotIn('id="event-include-ctf"', self.index)
        self.assertNotIn('id="event-include-external"', self.index)

    def test_server_log_has_exact_sparse_virtual_rows_and_bounded_pages(self) -> None:
        prepare = javascript_function(self.script, "prepareServerEventLogQuery")
        request = javascript_function(self.script, "requestServerEventLogPage")
        apply_payload = javascript_function(self.script, "applyServerEventLogPayload")
        layout = javascript_function(self.script, "serverEventLogLayout")
        row_at = javascript_function(self.script, "serverEventLogRowAt")
        render_window = javascript_function(self.script, "renderEventTableWindow")

        self.assertIn("state.eventLogServerQueryId += 1", prepare)
        self.assertIn("state.eventLogServerItems = new Map()", prepare)
        self.assertIn('revisionPath("event-log/query")', request)
        self.assertIn("queryId !== state.eventLogServerQueryId", request)
        self.assertIn("state.eventLogServerRequests.has(safeOffset)", request)
        self.assertIn("payload?.total_count", apply_payload)
        self.assertIn("payload?.inside_count", apply_payload)
        self.assertIn("payload?.outside_count", apply_payload)
        self.assertIn("registerServerEventLogItem", apply_payload)
        self.assertIn("EVENT_LOG_PAGE_CACHE_LIMIT", self.script)
        self.assertIn("outsideGroupIndex", layout)
        self.assertIn('groupKind: "selected-period"', row_at)
        self.assertIn('groupKind: "other-events"', row_at)
        self.assertIn('kind: "loading"', row_at)
        self.assertIn("ensureServerEventLogPages(start, end)", render_window)

    def test_server_log_eviction_prunes_page_owned_global_entries(self) -> None:
        register = javascript_function(self.script, "registerServerEventLogItem")
        remember = javascript_function(self.script, "rememberServerEventLogPage")
        prune = javascript_function(self.script, "pruneServerEventLogOwnedCaches")
        prepare = javascript_function(self.script, "prepareServerEventLogQuery")

        self.assertIn("state.eventLogOwnedEvents.set", register)
        self.assertIn("state.eventLogOwnedSources.set", register)
        self.assertIn("state.eventLogServerItems.delete(index)", remember)
        self.assertIn("pruneServerEventLogOwnedCaches()", remember)
        self.assertIn("loadedEvents.has(uid)", prune)
        self.assertIn("timelineEvents.has(uid)", prune)
        self.assertIn("state.eventByUid.delete(uid)", prune)
        self.assertIn("state.sourceRecordByUid.delete(uid)", prune)
        self.assertIn("pruneServerEventLogOwnedCaches()", prepare)

    def test_server_locate_adjusts_group_headers_then_loads_and_focuses_page(self) -> None:
        locate = javascript_function(self.script, "locateServerEventLogEntry")
        virtual_index = javascript_function(
            self.script, "serverEventLogVirtualRowForDataIndex"
        )
        jump = javascript_function(self.script, "jumpToLogEntry")

        self.assertIn('kind: source ? "source" : "event"', locate)
        self.assertIn("located_display_index", locate)
        self.assertIn("Math.floor(safeDataIndex / EVENT_LOG_PAGE_SIZE)", locate)
        self.assertIn("await requestServerEventLogPage(pageOffset)", locate)
        self.assertIn("serverEventLogVirtualRowForDataIndex(safeDataIndex)", locate)
        self.assertIn("focusServerEventLogTarget(entryId, virtualIndex)", locate)
        self.assertIn("layout.outsideGroupIndex + 1", virtual_index)
        self.assertIn("usesServerWindowedHistory()", jump)
        self.assertIn("locateServerEventLogEntry(entryId)", jump)

    def test_filters_are_debounced_and_failure_preview_precedes_first_render(self) -> None:
        preview = javascript_function(self.script, "requestFailureIncidentPreview")
        controls = javascript_function(self.script, "bindControls")
        initialize = self.script[self.script.index("async function initialize()") :]

        self.assertIn('revisionPath("events?outcome=failure&limit=3")', preview)
        self.assertIn("state.eventByUid.set", preview)
        self.assertIn("EVENT_LOG_FILTER_DELAY_MS", controls)
        self.assertIn("state.eventLogFilterTimer", controls)
        self.assertLess(
            initialize.index("await requestFailureIncidentPreview()"),
            initialize.index("renderIncidentSummary()"),
        )


if __name__ == "__main__":
    unittest.main()
