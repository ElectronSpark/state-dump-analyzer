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

    def test_server_history_mode_is_transport_declared_and_snapshot_safe(self) -> None:
        detection = javascript_function(self.script, "usesServerWindowedHistory")

        self.assertNotIn("isScaleMode()", detection)
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
        self.assertIn("bin_count: query.binCount", schedule)
        self.assertIn("bin_start_index: query.globalStart", schedule)
        self.assertIn("bin_end_index: query.globalEnd", schedule)
        self.assertIn("state.densityLocalCache?.key === key", local)
        self.assertIn("state.eventByUid.values()", local)
        self.assertIn("timelineDensityBinIndex", local)
        self.assertIn("timelineDensityBinIndex", javascript_function(self.script, "densityRenderWindow"))
        self.assertIn("timelineDensityBinBounds", render)
        self.assertIn("Math.log2", height)
        self.assertIn("const requestedBins = 180 * state.zoom", render)
        self.assertIn("captureSlots", render)
        self.assertIn("Number.MAX_SAFE_INTEGER", render)
        self.assertNotRegex(render, r"Math\.min\(\s*\d[\d_]*\s*,\s*requestedBins")

    def test_density_pages_keep_server_global_indices_and_bound_hover_models(self) -> None:
        normalize = javascript_function(self.script, "normalizeDensityPage")
        render = javascript_function(self.script, "eventDensityLane")

        self.assertIn("Number(raw.index || 0)", normalize)
        self.assertNotIn("query.globalStart +", normalize)
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

    def test_event_log_selection_uses_query_scoped_ranges_and_common_gestures(self) -> None:
        normalize = javascript_function(
            self.script,
            "normalizeEventLogSelectionRanges",
        )
        gesture = javascript_function(
            self.script,
            "applyEventLogSelectionGesture",
        )
        bind = javascript_function(self.script, "bindVisibleEventLogRows")
        query_binding = javascript_function(
            self.script,
            "bindEventLogSelectionToQuery",
        )
        render_table = javascript_function(self.script, "renderEventTable")

        self.assertIn("start > prior[1] + 1", normalize)
        self.assertIn("eventLogSelectionIncludes(target, ranges)", gesture)
        self.assertIn("removeEventLogSelectionRange", gesture)
        self.assertIn("toggle: additive && !extend", bind)
        self.assertIn("event.shiftKey", bind)
        self.assertIn('event.key === "ArrowDown"', bind)
        self.assertIn("revealEventLogEntry(row)", bind)
        self.assertIn("state.eventLogSelectionRanges = []", query_binding)
        self.assertLess(
            query_binding.index("finishEventLogDrag(null, false)"),
            query_binding.index("state.eventLogSelectionRanges = []"),
        )
        self.assertIn("stream order changed", query_binding)
        self.assertIn("renderEventLogSelectionToolbar()", render_table)

    def test_event_log_drag_is_host_captured_and_touch_scroll_safe(self) -> None:
        down = javascript_function(self.script, "eventLogPointerDown")
        move = javascript_function(self.script, "eventLogPointerMove")
        finish = javascript_function(self.script, "finishEventLogDrag")
        controls = javascript_function(self.script, "bindControls")

        self.assertIn('event.pointerType === "touch"', down)
        self.assertNotIn("setPointerCapture", down)
        self.assertIn("setPointerCapture", move)
        self.assertLess(move.index("Math.hypot"), move.index("setPointerCapture"))
        self.assertIn("visibleEventLogRowAtPoint", move)
        self.assertIn("releasePointerCapture", finish)
        self.assertIn("cancelAnimationFrame", finish)
        self.assertIn("baseFocus", down)
        self.assertIn("focus: drag.baseFocus", finish)
        self.assertIn("eventLogPointerDown", controls)
        self.assertIn("lostpointercapture", controls)

    def test_event_log_hover_registry_survives_timeline_rerenders(self) -> None:
        register = javascript_function(
            self.script,
            "registerVisibleEventLogHoverModels",
        )
        show = javascript_function(self.script, "showHover")
        render_timeline = javascript_function(self.script, "renderTimeline")
        source_row = javascript_function(self.script, "renderSourceRecordRow")
        source_hover = javascript_function(self.script, "sourceRecordHoverHtml")
        hover_model = javascript_function(self.script, "eventLogHoverModel")
        bind_timeline = javascript_function(self.script, "bindTimelineInteractions")

        self.assertIn("state.eventLogHoverModels.clear()", register)
        self.assertIn("eventLogHoverModel(entry)", register)
        self.assertIn("bindHoverTarget(row)", register)
        self.assertIn("state.eventLogHoverModels.get(key)", show)
        self.assertIn("if (!pin && state.hoverPinned) return", show)
        self.assertIn("state.hoverModels.clear()", render_timeline)
        self.assertNotIn('title="${escapeHtml(record.message', source_row)
        self.assertIn("matchedEventUids.length > 0", source_hover)
        self.assertIn("resource: record", hover_model)
        self.assertNotIn("\n    resource,\n", hover_model)
        self.assertIn('const timeline = byId("timeline-content")', bind_timeline)
        self.assertNotIn('document.querySelectorAll("[data-hover-key]")', bind_timeline)

    def test_selected_log_actions_use_server_projection_and_marker_lane(self) -> None:
        request = javascript_function(self.script, "resolveEventLogSelection")
        action = javascript_function(
            self.script,
            "applyEventLogTimelineAction",
        )
        markers = javascript_function(self.script, "reviewMarkerLaneHtml")
        timeline = javascript_function(self.script, "requestTimeline")
        copy_label = javascript_function(self.script, "eventLogCopyActionLabel")
        timeline_pointer = javascript_function(self.script, "timelinePointerDown")
        timeline_bindings = javascript_function(
            self.script,
            "bindTimelineInteractions",
        )

        self.assertIn('revisionPath("event-log/selection")', request)
        self.assertIn("MAX_EVENT_LOG_SELECTION_ITEMS", request)
        self.assertNotIn("forEach(rememberTimelineEntryProjection)", request)
        self.assertIn("selection_ranges", self.script)
        self.assertNotIn('"ctf"', request.lower())
        self.assertIn("state.hiddenTimelineEntryIds", action)
        self.assertIn("state.markedTimelineEntryIds", action)
        self.assertIn("state.timelineEntryProjections", markers)
        self.assertIn("annotation-cluster", markers)
        self.assertIn("underlying-hidden", markers)
        self.assertIn("selected_event_uid: state.selectedEventUid", timeline)
        self.assertIn("state.eventLogSelectionCache", copy_label)
        self.assertIn("eventLogSelectionSignature()", copy_label)
        self.assertIn(".review-marker", timeline_pointer)
        self.assertIn(".review-marker[data-hover-key]", timeline_bindings)
        for identifier in (
            "event-selection-toolbar",
            "event-selection-reveal",
            "event-selection-copy",
            "event-selection-hide",
            "event-selection-show",
            "event-selection-mark",
            "event-selection-unmark",
        ):
            self.assertIn(f'id="{identifier}"', self.index)
        self.assertIn("Ctrl/Command-click to toggle", self.index)


if __name__ == "__main__":
    unittest.main()
