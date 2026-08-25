from __future__ import annotations

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "frontend" / "assets" / "app.js"
NODE_HTML = ROOT / "frontend" / "pages" / "node.html"
STYLES_CSS = ROOT / "frontend" / "assets" / "styles.css"


def javascript_function(source: str, name: str) -> str:
    """Return one top-level JavaScript function for focused contract checks."""

    marker = re.search(rf"(?:async\s+)?function {re.escape(name)}\(", source)
    if marker is None:
        raise AssertionError(f"production JavaScript must define {name}()")
    start = marker.start()
    match = re.search(r"\n(?:async\s+)?function [A-Za-z0-9_$]+\(", source[start + 1 :])
    return source[start:] if match is None else source[start : start + 1 + match.start()]


def function_call_depths(source: str, call: str) -> list[tuple[int, str]]:
    """Return brace depth and source line for simple focused wiring checks."""

    depth = 0
    matches: list[tuple[int, str]] = []
    for line in source.splitlines():
        if call in line:
            matches.append((depth, line.strip()))
        depth += line.count("{") - line.count("}")
    return matches


class _TimelineElementParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.by_id: dict[str, dict[str, str | None]] = {}
        self.timeline_actions: list[dict[str, str | None]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = dict(attrs)
        values["_tag"] = tag
        if identifier := values.get("id"):
            self.by_id[identifier] = values
        if "data-timeline-action" in values:
            self.timeline_actions.append(values)


class TimelineInteractionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = APP_JS.read_text(encoding="utf-8")
        cls.page = NODE_HTML.read_text(encoding="utf-8")
        cls.styles = STYLES_CSS.read_text(encoding="utf-8")
        cls.elements = _TimelineElementParser()
        cls.elements.feed(cls.page)

    def test_toolbar_and_context_menu_are_static_accessible_controls(self) -> None:
        required_buttons = (
            "timeline-zoom-out",
            "timeline-zoom-in",
            "timeline-zoom-selection",
            "timeline-fit",
            "timeline-center",
            "timeline-actions",
        )
        for identifier in required_buttons:
            with self.subTest(identifier=identifier):
                self.assertIn(identifier, self.elements.by_id)
                attrs = self.elements.by_id[identifier]
                self.assertEqual(attrs["_tag"], "button")
                self.assertEqual(attrs.get("type"), "button")

        self.assertIn("timeline-actions", self.elements.by_id)
        actions_button = self.elements.by_id["timeline-actions"]
        self.assertEqual(actions_button.get("aria-haspopup"), "menu")
        self.assertEqual(actions_button.get("aria-controls"), "timeline-context-menu")
        self.assertEqual(actions_button.get("aria-expanded"), "false")

        self.assertIn("timeline-context-menu", self.elements.by_id)
        menu = self.elements.by_id["timeline-context-menu"]
        self.assertEqual(menu.get("role"), "menu")
        self.assertIn("hidden", menu)
        self.assertGreater(len(self.elements.timeline_actions), 0)
        for action in self.elements.timeline_actions:
            self.assertEqual(action["_tag"], "button")
            self.assertEqual(action.get("type"), "button")
            self.assertEqual(action.get("role"), "menuitem")
            self.assertTrue(action.get("data-timeline-action"))

    def test_context_menu_is_delegated_from_the_stable_timeline_surface(self) -> None:
        controls = javascript_function(self.script, "bindControls")
        binding = re.search(
            r'timelineContent\.addEventListener\(\s*"contextmenu"\s*,\s*'
            r"([A-Za-z0-9_$]+)\s*\)",
            controls,
        )
        self.assertIsNotNone(binding)
        handler = javascript_function(self.script, binding.group(1))
        self.assertIn("event.preventDefault()", handler)
        self.assertIn("event.target.closest", handler)
        self.assertNotIn("querySelectorAll", handler)

    def test_escape_closes_the_context_menu_before_clearing_timeline_state(self) -> None:
        escape = javascript_function(self.script, "handleEscapeKey")
        self.assertIn("event.defaultPrevented", escape)
        self.assertIn("closeTimelineContextMenu(", escape)
        close_call = escape.index("closeTimelineContextMenu(")
        clear_call = escape.index("clearTimelineSelection(")
        self.assertLess(close_call, clear_call)
        between = escape[close_call:clear_call]
        self.assertIn("event.preventDefault()", between)
        self.assertRegex(between, r"\breturn\b")

    def test_context_menu_has_pointer_and_complete_keyboard_entry(self) -> None:
        controls = javascript_function(self.script, "bindControls")
        key_binding = re.search(
            r'timelineContent\.addEventListener\(\s*"keydown"\s*,\s*'
            r"([A-Za-z0-9_$]+)\s*\)",
            controls,
        )
        self.assertIsNotNone(key_binding)
        surface_keys = javascript_function(self.script, key_binding.group(1))
        self.assertIn('event.key === "ContextMenu"', surface_keys)
        self.assertIn('event.key === "F10"', surface_keys)
        self.assertIn("event.shiftKey", surface_keys)
        self.assertIn("event.preventDefault()", surface_keys)

        menu_binding = re.search(
            r'byId\("timeline-context-menu"\)\.addEventListener\('
            r'\s*"keydown"\s*,\s*([A-Za-z0-9_$]+)\s*\)',
            controls,
        )
        self.assertIsNotNone(menu_binding)
        menu_keys = javascript_function(self.script, menu_binding.group(1))
        for key in ("ArrowDown", "ArrowUp", "Home", "End", "Enter", " ", "Escape"):
            with self.subTest(key=key):
                self.assertIn(f'"{key}"', menu_keys)
        self.assertIn("event.preventDefault()", menu_keys)
        self.assertIn("closeTimelineContextMenu", menu_keys)

    def test_wheel_zoom_is_frame_coalesced_and_preserves_the_pointer_anchor(self) -> None:
        controls = javascript_function(self.script, "bindControls")
        wheel_binding = re.search(
            r'byId\("timeline-scroll"\)\.addEventListener\('
            r'\s*"wheel"\s*,\s*([A-Za-z0-9_$]+)',
            controls,
        )
        self.assertIsNotNone(wheel_binding)
        wheel = javascript_function(self.script, wheel_binding.group(1))
        self.assertIn("event.clientX", wheel)
        self.assertIn("event.preventDefault()", wheel)
        self.assertIn("scheduleTimelineZoom", wheel)
        self.assertNotIn("renderTimeline()", wheel)

        schedule = javascript_function(self.script, "scheduleTimelineZoom")
        self.assertIn("requestAnimationFrame", schedule)
        self.assertIn("anchorClientX", schedule)
        self.assertIn("applyTimelineZoom", schedule)

        apply_zoom = javascript_function(self.script, "applyTimelineZoom")
        self.assertIn("anchorClientX", apply_zoom)
        self.assertIn("scroll.scrollLeft", apply_zoom)
        self.assertIn("pointNsFromClientX", wheel)

    def test_horizontal_trackpad_pan_is_logical_and_frame_coalesced(self) -> None:
        wheel = javascript_function(self.script, "timelineWheel")
        self.assertIn("event.deltaX", wheel)
        self.assertIn("event.deltaY", wheel)
        self.assertIn("event.shiftKey", wheel)
        self.assertIn("event.deltaMode", wheel)
        self.assertIn("event.preventDefault()", wheel)
        self.assertIn("scheduleTimelinePan", wheel)
        self.assertNotIn("renderTimeline()", wheel)

        schedule = javascript_function(self.script, "scheduleTimelinePan")
        self.assertIn("requestAnimationFrame", schedule)
        self.assertIn("state.timelinePanDeltaPx += deltaPx", schedule)
        self.assertIn("beginTimelineWheelBurst", schedule)
        self.assertIn("scheduleTimelineWheelBurstFinish", schedule)
        self.assertIn("panTimelineViewportByPixels", schedule)
        self.assertIn("recordHistory: false", schedule)
        self.assertIn("fromWheel: true", schedule)

        pan = javascript_function(self.script, "panTimelineViewportByPixels")
        self.assertIn("timelineWindowBounds()", pan)
        self.assertIn("timelineTimeAtRatio", pan)
        self.assertIn("state.viewStartNs", pan)
        self.assertIn("state.viewEndNs", pan)
        self.assertIn("state.timelineWindowStartNs", pan)
        self.assertIn("state.timelineWindowEndNs", pan)
        self.assertIn("rememberTimelineView", pan)
        self.assertIn("scheduleTimelineWindowRefresh", pan)
        self.assertNotIn("scrollLeft", pan)

    def test_wheel_burst_records_one_view_and_direct_commands_cancel_pending_frames(self) -> None:
        schedule = javascript_function(self.script, "scheduleTimelineZoom")
        remember_calls = function_call_depths(schedule, "rememberTimelineView(")
        for depth, line in remember_calls:
            with self.subTest(line=line):
                self.assertTrue(
                    depth > 1 or re.search(r"\bif\s*\(", line),
                    "each wheel event must not append an unconditional history entry",
                )

        delayed_history = javascript_function(self.script, "scheduleTimelineViewHistory")
        self.assertIn("rememberTimelineView", delayed_history)

        cancel = javascript_function(self.script, "cancelScheduledTimelineZoom")
        self.assertIn("cancelAnimationFrame", cancel)
        for pending_field in (
            "timelineWheelFrameId",
            "timelineWheelTargetZoom",
            "timelineWheelAnchorNs",
            "timelineWheelAnchorClientX",
            "timelinePanFrameId",
            "timelinePanDeltaPx",
        ):
            with self.subTest(pending_field=pending_field):
                self.assertIn(pending_field, cancel)

        for command in (
            "applyTimelineZoom",
            "restoreTimelineView",
            "resetTimelineView",
        ):
            with self.subTest(command=command):
                body = javascript_function(self.script, command)
                self.assertIn(
                    "cancelScheduledTimelineZoom",
                    body,
                    f"{command} must not be overwritten by an older queued wheel frame",
                )

        restore = javascript_function(self.script, "restoreTimelineView")
        relative = restore.index("index - state.timelineViewHistoryIndex")
        cancel_call = restore.index("cancelScheduledTimelineZoom")
        resolved = restore.index("state.timelineViewHistoryIndex + relativeOffset")
        bounds_check = restore.index("index < 0")
        self.assertLess(relative, cancel_call)
        self.assertLess(cancel_call, resolved)
        self.assertLess(resolved, bounds_check)

    def test_wheel_burst_settles_pending_frames_before_committing_its_final_view(self) -> None:
        finish = javascript_function(self.script, "finishTimelineWheelBurst")
        final_history = finish.index("rememberTimelineView(")
        before_history = finish[:final_history]

        # In a background tab a timeout may run while requestAnimationFrame is
        # suspended. The finish path must therefore settle both kinds of queued
        # work before recording the final history entry; otherwise a late frame
        # changes the viewport without history or a server-window refresh.
        direct_settlement = (
            "timelineWheelFrameId" in before_history
            and "timelinePanFrameId" in before_history
        )
        delegated_settlement = False
        for call in re.findall(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", before_history):
            if call in {"if", "for", "while", "switch", "catch"}:
                continue
            try:
                helper = javascript_function(self.script, call)
            except AssertionError:
                continue
            if "timelineWheelFrameId" in helper and "timelinePanFrameId" in helper:
                delegated_settlement = True
                break
        self.assertTrue(
            direct_settlement or delegated_settlement,
            "wheel-burst completion must settle queued zoom and pan frames before history",
        )
        self.assertIn("scheduleTimelineWindowRefresh", finish)

    def test_zoom_to_range_preserves_selection_and_global_time_domain(self) -> None:
        zoom_range = javascript_function(self.script, "zoomToSelectedRange")
        self.assertIn("rangeBounds()", zoom_range)
        self.assertIn("applyTimelineZoom", zoom_range)
        self.assertIn("windowOverride: viewport", zoom_range)
        self.assertNotIn("scroll.scrollLeft", zoom_range)
        self.assertNotIn("clearRangeSelection", zoom_range)
        self.assertNotIn("state.rangeStartNs =", zoom_range)
        self.assertNotIn("state.rangeEndNs =", zoom_range)
        self.assertNotIn("state.viewStartNs =", zoom_range)
        self.assertNotIn("state.viewEndNs =", zoom_range)
        controls = javascript_function(self.script, "bindControls")
        self.assertIn('byId("timeline-zoom-selection")', controls)
        self.assertIn("zoomToSelectedRange", controls)

    def test_deep_zoom_ruler_and_hover_labels_follow_visible_time_precision(self) -> None:
        precision = javascript_function(self.script, "visibleTimelineOffsetPrecision")
        ruler = javascript_function(self.script, "renderRuler")
        hover = javascript_function(self.script, "showTimelineHoverAt")
        context = javascript_function(self.script, "syncTimelineContextMenu")

        self.assertIn("timelineWindowBounds()", precision)
        self.assertIn("offsetPrecisionForSpan", precision)
        self.assertIn("visibleTimelineOffsetPrecision()", ruler)
        self.assertIn("formatOffset(timestamp, precision)", ruler)
        self.assertIn("visibleTimelineOffsetPrecision()", hover)
        self.assertIn("visibleTimelineOffsetPrecision()", context)

    def test_exact_time_and_virtual_window_helpers_drive_application_zoom(self) -> None:
        ratio = javascript_function(self.script, "ratioBetween")
        inverse = javascript_function(self.script, "nsAtRatio")
        self.assertIn("timelineRatioForTime", ratio)
        self.assertNotIn("1_000_000n", ratio)
        self.assertIn("timelineTimeAtRatio", inverse)
        self.assertNotIn("1_000_000n", inverse)

        apply_zoom = javascript_function(self.script, "applyTimelineZoom")
        fit = javascript_function(self.script, "fitTimelineCapture")
        zoom_range = javascript_function(self.script, "zoomToSelectedRange")
        self.assertIn("timelineWindowForZoom", apply_zoom)
        self.assertIn("applyTimelineZoom(1", fit)
        self.assertIn("timelineWindowForRange", zoom_range)

    def test_deep_zoom_queries_and_renders_only_the_exact_virtual_window(self) -> None:
        request = javascript_function(self.script, "requestTimeline")
        self.assertIn("timelineWindowBounds()", request)
        self.assertIn("start_ns: windowStartNs.toString()", request)
        self.assertIn("end_ns: windowEndNs.toString()", request)
        self.assertIn("viewport_pixels: timelinePhysicalTrackWidth()", request)

        refresh = javascript_function(self.script, "scheduleTimelineWindowRefresh")
        self.assertIn("setTimeout", refresh)
        self.assertIn("requestTimeline", refresh)

        event_glyphs = javascript_function(self.script, "buildClientGlyphs")
        self.assertIn("timelinePointVisible", event_glyphs)
        timeline_render = javascript_function(self.script, "renderTimeline")
        self.assertIn("timelineIntervalVisible", timeline_render)
        source_glyphs = javascript_function(self.script, "buildSourceGlyphs")
        self.assertIn("timelinePointVisible", source_glyphs)
        marker_lane = javascript_function(self.script, "reviewMarkerLaneHtml")
        self.assertIn("timelinePointVisible", marker_lane)

        range_band = javascript_function(self.script, "timelineRangeBandHtml")
        range_update = javascript_function(self.script, "updateRangeBands")
        self.assertIn("timelineIntervalPercentGeometry", range_band)
        self.assertIn("timelineIntervalPercentGeometry", range_update)
        self.assertRegex(
            self.styles,
            r"\.timeline-frame\s+\.lane-track\s*\{[^}]*min-width:\s*0[^}]*overflow:\s*hidden",
        )

    def test_range_boundaries_remain_positive_at_both_capture_edges(self) -> None:
        boundary = javascript_function(self.script, "setTimelineRangeBoundary")
        self.assertNotIn(
            'boundary === "start" && state.rangeEndNs + minimum',
            boundary,
        )
        self.assertRegex(
            boundary,
            r"if\s*\(state\.rangeEndNs \+ minimum <= state\.viewEndNs\)\s*"
            r"state\.rangeEndNs \+= minimum",
        )
        self.assertRegex(
            boundary,
            r"else if\s*\(state\.rangeStartNs - minimum >= state\.viewStartNs\)\s*"
            r"state\.rangeStartNs -= minimum",
        )
        self.assertIn("[state.rangeStartNs, state.rangeEndNs] = rangeBounds()", boundary)

    def test_context_menu_focus_and_generic_hover_targets_are_accessible(self) -> None:
        target = javascript_function(self.script, "timelineInteractionTarget")
        self.assertIn('"[data-hover-key]"', target)
        self.assertIn("hoverKey", target)

        sync = javascript_function(self.script, "syncTimelineContextMenu")
        self.assertNotIn('new Set(["inspect", "reveal-log"])', sync)
        self.assertIn('action === "inspect"', sync)
        self.assertIn('action === "reveal-log"', sync)

        open_menu = javascript_function(self.script, "openTimelineContextMenu")
        self.assertIn("const firstItem = timelineContextMenuItems()[0]", open_menu)
        self.assertIn("firstItem?.focus", open_menu)
        self.assertIn("menu.scrollTop = 0", open_menu)
        self.assertIn("firstItem?.scrollIntoView", open_menu)

        activate = javascript_function(self.script, "activateTimelineContextAction")
        self.assertIn("restoreTimelineContextActionFocus", activate)
        self.assertIn('action !== "reveal-log"', activate)
        restore = javascript_function(self.script, "restoreTimelineContextActionFocus")
        self.assertIn("returnFocus?.isConnected", restore)
        self.assertIn("originWasTimeline", restore)
        self.assertIn('byId("timeline-scroll")', restore)

        menu_keys = javascript_function(self.script, "timelineContextMenuKeyDown")
        self.assertIn('scrollIntoView({ block: "nearest", inline: "nearest" })', menu_keys)
        self.assertRegex(
            menu_keys,
            r'event\.key === "Tab"\)\s*\{(?s:.*?)event\.preventDefault\(\)(?s:.*?)timelineContextTabDestination',
        )
        self.assertRegex(
            self.styles,
            r"\.timeline-context-group button:focus-visible\s*\{[^}]*outline:\s*2px",
        )

    def test_toolbar_uses_roving_focus_and_arrow_navigation(self) -> None:
        self.assertIn("timeline-viewport-controls", self.elements.by_id)
        toolbar = self.elements.by_id["timeline-viewport-controls"]
        self.assertEqual(toolbar.get("role"), "toolbar")

        controls = javascript_function(self.script, "bindControls")
        toolbar_assignment = re.search(
            r'const\s+([A-Za-z0-9_$]+)\s*=\s*byId\("timeline-viewport-controls"\)',
            controls,
        )
        self.assertIsNotNone(toolbar_assignment)
        toolbar_variable = re.escape(toolbar_assignment.group(1))
        binding = re.search(
            rf'{toolbar_variable}\.addEventListener\('
            r'\s*"keydown"\s*,\s*([A-Za-z0-9_$]+)\s*\)',
            controls,
        )
        self.assertIsNotNone(binding)
        handler = javascript_function(self.script, binding.group(1))
        for key in ("ArrowLeft", "ArrowRight", "Home", "End"):
            with self.subTest(key=key):
                self.assertIn(f'"{key}"', handler)
        self.assertIn("event.preventDefault()", handler)
        self.assertIn("focus(", handler)
        self.assertIn("event.target.matches", handler)
        self.assertIn("getBoundingClientRect", handler)
        self.assertNotIn("nextItem.offsetLeft", handler)
        toolbar_items = javascript_function(self.script, "timelineToolbarItems")
        self.assertIn('querySelectorAll("button")', toolbar_items)
        self.assertNotIn('querySelectorAll("button, input")', toolbar_items)
        availability = javascript_function(
            self.script,
            "updateTimelineCommandAvailability",
        )
        self.assertIn("const priorFocus = document.activeElement", availability)
        self.assertIn("priorFocus.disabled", availability)
        self.assertIn("?.focus({ preventScroll: true })", availability)
        self.assertRegex(self.script, r'(?:\.tabIndex\s*=|setAttribute\(\s*"tabindex")')

    def test_keyboard_viewport_commands_move_focus_off_replaced_glyphs(self) -> None:
        keyboard = javascript_function(self.script, "timelineViewportKeyDown")
        self.assertIn("const retainStableFocus", keyboard)
        self.assertIn('byId("timeline-content")?.contains(event.target)', keyboard)
        self.assertIn('byId("timeline-scroll")?.focus({ preventScroll: true })', keyboard)
        self.assertGreaterEqual(keyboard.count("retainStableFocus();"), 9)

        escape = javascript_function(self.script, "handleEscapeKey")
        self.assertIn('byId("timeline-content")?.contains(document.activeElement)', escape)
        self.assertLess(
            escape.index('byId("timeline-scroll")?.focus'),
            escape.index("clearTimelineSelection()"),
        )

    def test_brush_auto_pan_uses_the_logical_viewport_and_finalizes_history(self) -> None:
        auto_pan = javascript_function(self.script, "runBrushAutoScroll")
        self.assertIn("panTimelineViewportByPixels", auto_pan)
        self.assertIn("recordHistory: false", auto_pan)
        self.assertIn("brush.viewportChanged = true", auto_pan)
        self.assertNotIn("scrollLeft +=", auto_pan)

        finish_navigation = javascript_function(
            self.script,
            "finishBrushViewportNavigation",
        )
        self.assertIn("brush.priorViewport", finish_navigation)
        self.assertIn("rememberTimelineView", finish_navigation)
        self.assertIn("scheduleTimelineWindowRefresh", finish_navigation)

        finish_pointer = javascript_function(self.script, "finishTimelinePointer")
        self.assertGreaterEqual(
            finish_pointer.count("finishBrushViewportNavigation(brush, true)"),
            2,
            "cancel and no-op handle completion must both roll back auto-pan",
        )
        self.assertIn("finishBrushViewportNavigation(brush, false)", finish_pointer)

        wheel = javascript_function(self.script, "timelineWheel")
        brush_guard = re.search(
            r"if\s*\(state\.brush\)\s*\{(?P<body>.*?)\}",
            wheel,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(brush_guard)
        self.assertIn("event.preventDefault()", brush_guard.group("body"))
        self.assertIn("return", brush_guard.group("body"))

    def test_density_and_point_clusters_keep_inclusive_endpoint_semantics(self) -> None:
        density = javascript_function(self.script, "eventDensityLane")
        render = javascript_function(self.script, "renderTimeline")
        highlight = javascript_function(self.script, "applyRangeHighlight")
        marker_lane = javascript_function(self.script, "reviewMarkerLaneHtml")
        windowing = javascript_function(self.script, "densityRenderWindow")

        self.assertIn('data-range-semantics="inclusive"', density)
        self.assertIn('element.dataset.rangeSemantics === "inclusive"', highlight)
        self.assertIn("inclusiveIntervalIntersectsRange", highlight)
        self.assertIn('data-range-semantics="inclusive"', marker_lane)
        self.assertEqual(windowing.count("timelineDensityBinIndex({"), 2)
        self.assertIn("timeNs: windowStartNs", windowing)
        self.assertIn("timeNs: windowEndNs", windowing)
        self.assertRegex(windowing, r"timelineDensityBinIndex\(\{[\s\S]*?\}\) \+ 1")
        self.assertIn("timelinePointIntervalVisible(startNs, endNs)", density)
        self.assertIn("timelinePointIntervalVisible(glyph.startNs, glyph.endNs)", render)
        self.assertIn("timelineIntervalVisible(interval.startNs, interval.endNs)", render)

    def test_deep_zoom_glyph_names_and_rerenders_preserve_keyboard_focus(self) -> None:
        source_lanes = javascript_function(self.script, "sourceRecordLanesHtml")
        review_lanes = javascript_function(self.script, "reviewMarkerLaneHtml")
        render = javascript_function(self.script, "renderTimeline")
        capture = javascript_function(self.script, "timelineFocusDescriptor")
        restore = javascript_function(self.script, "restoreTimelineFocusDescriptor")

        self.assertIn("visibleTimelineOffsetPrecision()", source_lanes)
        self.assertIn("visibleTimelineOffsetPrecision()", review_lanes)
        self.assertGreaterEqual(render.count("visibleTimelineOffsetPrecision()"), 2)
        self.assertIn("timelineFocusDescriptor()", render)
        self.assertIn("restoreTimelineFocusDescriptor(focusDescriptor)", render)
        self.assertIn("element.dataset[property]", capture)
        self.assertIn('byId("timeline-scroll")', restore)

    def test_context_action_captures_timeline_origin_before_replacing_glyphs(self) -> None:
        opening = javascript_function(self.script, "openTimelineContextMenu")
        action = javascript_function(self.script, "activateTimelineContextAction")
        restore = javascript_function(self.script, "restoreTimelineContextActionFocus")

        self.assertIn("timelineContextOriginWasTimeline", opening)
        self.assertLess(
            action.index("const originWasTimeline"),
            action.index("closeTimelineContextMenu()"),
        )
        self.assertIn("originWasTimeline", restore)
        self.assertIn('byId("timeline-scroll")', restore)

    def test_stale_server_clusters_preserve_visible_preview_until_refresh(self) -> None:
        glyphs = javascript_function(self.script, "buildClientGlyphs")
        render = javascript_function(self.script, "renderTimeline")
        hover = javascript_function(self.script, "clusterHoverHtml")

        self.assertIn("containedClusters", glyphs)
        self.assertIn("stalePreviewMarks", glyphs)
        self.assertIn("stalePlaceholders", glyphs)
        self.assertIn("staleWindow: true", glyphs)
        self.assertIn('glyph.staleWindow ? " stale-window"', render)
        self.assertIn("cluster.staleWindow", hover)
        self.assertIn("exact window refreshes", hover)
        self.assertIn(".event-mark.cluster.stale-window", self.styles)

    def test_window_mutations_invalidate_old_server_queries(self) -> None:
        invalidate = javascript_function(
            self.script,
            "invalidatePendingTimelineWindowRequest",
        )
        self.assertIn("state.timelineRequestId += 1", invalidate)
        self.assertIn('abortLatestRequests("timelineAbortController")', invalidate)
        for function_name in (
            "restoreTimelineView",
            "applyTimelineZoom",
            "panTimelineViewportByPixels",
            "resetTimelineView",
        ):
            with self.subTest(function_name=function_name):
                body = javascript_function(self.script, function_name)
                self.assertIn("invalidatePendingTimelineWindowRequest", body)

    def test_cross_view_reveal_centers_the_logical_window_before_querying(self) -> None:
        reveal = javascript_function(self.script, "moveTimelineWindowToReveal")
        refresh = javascript_function(self.script, "refreshTimelineForNavigation")
        event_jump = javascript_function(self.script, "jumpToTimelineEvent")
        source_jump = javascript_function(self.script, "jumpSourceRecordToTimeline")

        self.assertIn("timelineWindowBounds()", reveal)
        self.assertIn("applyTimelineZoom(state.zoom", reveal)
        self.assertIn("anchorNs: targetNs", reveal)
        self.assertIn("requestTimeline", refresh)
        self.assertLess(
            event_jump.index("moveTimelineWindowToReveal"),
            event_jump.index("refreshTimelineForNavigation"),
        )
        self.assertLess(
            event_jump.index("state.selectedEventUid = eventUid"),
            event_jump.index("refreshTimelineForNavigation"),
        )
        self.assertLess(
            source_jump.index("moveTimelineWindowToReveal"),
            source_jump.index("ensureSourceRecordLane"),
        )
        self.assertNotIn('inline: "center"', event_jump)
        self.assertNotIn('inline: "center"', source_jump)

    def test_narrow_timeline_keeps_a_usable_temporal_surface(self) -> None:
        lane_width = javascript_function(self.script, "timelineLaneWidth")
        track_width = javascript_function(self.script, "timelinePhysicalTrackWidth")
        brush_point = javascript_function(self.script, "brushNsFromClientX")
        apply_zoom = javascript_function(self.script, "applyTimelineZoom")

        self.assertIn('matchMedia?.("(max-width: 760px)")', lane_width)
        self.assertIn("MIN_TIMELINE_TRACK_WIDTH", track_width)
        self.assertIn("timelineLaneWidth()", track_width)
        self.assertIn("scroll.scrollLeft", brush_point)
        self.assertIn("scroll.scrollLeft", apply_zoom)
        self.assertIn("retainedScrollLeft", apply_zoom)

    def test_context_actions_do_not_scale_with_the_million_event_stream(self) -> None:
        handler_match = re.search(
            r'timelineContent\.addEventListener\(\s*"contextmenu"\s*,\s*'
            r"([A-Za-z0-9_$]+)\s*\)",
            javascript_function(self.script, "bindControls"),
        )
        self.assertIsNotNone(handler_match)
        handler = javascript_function(self.script, handler_match.group(1))
        for unbounded_shape in (
            "state.eventByUid.values(",
            "state.sourceRecordByUid.values(",
            "state.eventLogServerItems.values(",
            "querySelectorAll",
        ):
            self.assertNotIn(unbounded_shape, handler)

        request = javascript_function(self.script, "requestTimeline")
        self.assertIn("max_glyphs: 3000", request)
        self.assertIn("max_record_marks: 5000", request)


if __name__ == "__main__":
    unittest.main()
