from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "frontend" / "assets" / "app.js"
APP_CSS = ROOT / "frontend" / "assets" / "styles.css"
TOPOLOGY_JS = ROOT / "frontend" / "assets" / "topology.js"
TOPOLOGY_CSS = ROOT / "frontend" / "assets" / "topology.css"
TOPOLOGY_HTML = ROOT / "frontend" / "pages" / "topology.html"


def javascript_function(source: str, name: str) -> str:
    """Return one top-level JavaScript function for focused contract checks."""

    start = source.index(f"function {name}(")
    match = re.search(r"\nfunction [A-Za-z0-9_$]+\(", source[start + 1 :])
    return source[start:] if match is None else source[start : start + 1 + match.start()]


class SingleNodeAuditRegressionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = APP_JS.read_text(encoding="utf-8")
        cls.styles = APP_CSS.read_text(encoding="utf-8")

    def test_resource_query_and_both_table_shapes_are_pageable(self) -> None:
        request = javascript_function(self.script, "requestResources")
        page = javascript_function(self.script, "resourcePageDetails")
        markup = javascript_function(self.script, "resourcePaginationMarkup")
        binding = javascript_function(self.script, "bindResourcePagination")
        bundle = javascript_function(self.script, "renderResourceBundleTable")
        generic = javascript_function(self.script, "renderResourceTables")
        cursor = javascript_function(self.script, "setCursor")

        self.assertRegex(self.script, r"\bresourceOffset:\s*0\b")
        self.assertIn("offset: state.resourceOffset", request)
        self.assertIn("payload.next_offset", page)
        self.assertIn("payload.matched_count", page)
        self.assertIn("previousOffset", page)
        self.assertIn("nextOffset", page)
        self.assertIn('aria-label="Resource table pages"', markup)
        self.assertIn('data-resource-page-offset="${page.previousOffset', markup)
        self.assertIn('data-resource-page-offset="${page.nextOffset', markup)
        self.assertIn("state.resourceOffset = Math.max", binding)
        self.assertIn("requestResources()", binding)
        self.assertIn("resourcePaginationMarkup(payload)", bundle)
        self.assertIn("bindResourcePagination(container)", bundle)
        self.assertIn("resourcePaginationMarkup(state.resourceQuery)", generic)
        self.assertIn("bindResourcePagination(container)", generic)
        self.assertIn("state.resourceOffset = 0", cursor)

    def test_resource_bundle_tree_guides_continue_across_nested_and_detail_rows(self) -> None:
        rows = javascript_function(self.script, "resourceBundleRows")
        row_guides = javascript_function(self.script, "resourceBundleRowGuides")
        detail_guides = javascript_function(self.script, "resourceBundleDetailGuides")
        render = javascript_function(self.script, "renderResourceBundleTable")

        self.assertIn("hasVisibleChildren", rows)
        self.assertIn("hasNextSibling", rows)
        self.assertIn("continuationDepths", rows)
        self.assertIn("[...continuationDepths, depth]", rows)
        self.assertIn('resourceBundleGuide(depth, "through")', row_guides)
        self.assertIn('row.hasNextSibling ? "incoming continues" : "incoming"', row_guides)
        self.assertIn("row.depth + 1", row_guides)
        self.assertIn("if (row.hasNextSibling", detail_guides)
        self.assertIn("if (row.hasVisibleChildren)", detail_guides)
        self.assertIn("${resourceBundleRowGuides(row)}", render)
        self.assertIn("${resourceBundleDetailGuides(row)}", render)

        self.assertIn(".resource-bundle-guides", self.styles)
        self.assertIn(".resource-bundle-guide-through", self.styles)
        self.assertIn(".resource-bundle-guide-incoming.continues", self.styles)
        self.assertIn(".resource-bundle-guide-child", self.styles)
        self.assertNotIn("top: -20px", self.styles)

    def test_temporal_correlation_inspection_can_be_pinned_and_cleared(self) -> None:
        validate = javascript_function(self.script, "validGraphInspection")
        inspect = javascript_function(self.script, "setGraphInspection")
        pin = javascript_function(self.script, "pinGraphInspection")
        clear = javascript_function(self.script, "clearPinnedGraphInspection")
        bind_blank = javascript_function(self.script, "bindGraphStageInspectionClear")
        render = javascript_function(self.script, "renderGraph")
        bind_controls = javascript_function(self.script, "bindControls")
        escape = javascript_function(self.script, "handleEscapeKey")
        schedule_close = javascript_function(self.script, "scheduleCorrelationHoverClose")
        hover_card = javascript_function(self.script, "showCorrelationHover")

        self.assertIn("graphPinnedInspection: null", self.script)
        self.assertIn('inspection.kind === "resource"', validate)
        self.assertIn('inspection.kind === "edge"', validate)
        self.assertIn("state.graphPinnedInspection", inspect)
        self.assertIn('classList.toggle("is-pinned"', inspect)
        self.assertIn('setAttribute("aria-pressed"', inspect)
        self.assertIn('classList.contains("graph-edge-label")', inspect)
        self.assertIn("state.graphPinnedInspection = nextInspection", pin)
        self.assertIn("showCorrelationHover(anchor, html, { pinned: true })", pin)
        self.assertIn("state.graphPinnedInspection = null", clear)
        self.assertIn('classList.remove("is-inspecting", "has-pinned-inspection")', clear)
        self.assertIn("if (clearPinnedGraphInspection())", escape)

        self.assertIn('event.target.closest(".graph-node, [data-graph-edge-id]")', bind_blank)
        self.assertIn("clearPinnedGraphInspection()", bind_blank)
        self.assertIn("bindGraphStageInspectionClear()", bind_controls)
        self.assertIn("pinGraphInspection(", render)
        self.assertIn("state.graphPinnedInspection", render)
        self.assertIn("click to keep it highlighted", render)
        self.assertIn('role="group" aria-label="Correlation relationships"', render)
        self.assertIn('tabindex="0" role="button" aria-label="${escapeHtml(edgeActionLabel)}"', render)
        self.assertIn('event.key !== "Enter" && event.key !== " "', render)
        self.assertIn('dataset.pinned === "true"', schedule_close)
        self.assertIn("rect.right + gap + width", hover_card)
        self.assertIn("rect.left - width - gap", hover_card)

        self.assertIn(".graph-stage.has-pinned-inspection .graph-node.is-pinned", self.styles)
        self.assertIn(".graph-stage.has-pinned-inspection .graph-edge.is-pinned", self.styles)

    def test_point_clusters_use_member_timestamps_not_cluster_span(self) -> None:
        exact = javascript_function(self.script, "pointClusterRangeState")
        highlight = javascript_function(self.script, "applyRangeHighlight")
        source_lanes = javascript_function(self.script, "sourceRecordLanesHtml")
        source_hover = javascript_function(self.script, "sourceClusterHoverHtml")
        timeline = javascript_function(self.script, "renderTimeline")

        self.assertIn("item.timeNs >= bounds[0] && item.timeNs <= bounds[1]", exact)
        self.assertIn("count === points.length", exact)
        self.assertIn('" partial-range"', exact)
        self.assertIn("state.hoverModels.get(element.dataset.hoverKey)", highlight)
        self.assertIn("pointClusterRangeState(model?.cluster?.items || [], bounds)", highlight)
        self.assertIn('element.classList.toggle("partial-range"', highlight)
        self.assertIn(":not(.event-mark.cluster):not(.source-record-mark.cluster)", highlight)
        self.assertIn('element.setAttribute("aria-label"', highlight)
        self.assertIn("pointClusterRangeState(glyph.items, bounds)", source_lanes)
        self.assertIn("pointClusterRangeState(clusterItems, bounds)", timeline)
        self.assertIn("inSelectedRange(mark.timeNs)", source_hover)
        self.assertIn("in selected range", source_hover)

    def test_bounded_timeline_expansion_is_disclosed_in_the_lane_surface(self) -> None:
        normalize = javascript_function(self.script, "normalizeTimeline")
        notice = javascript_function(self.script, "timelineExpansionNoticeHtml")
        render = javascript_function(self.script, "renderTimeline")

        self.assertIn(
            "state.timelineExpansion = payload?.relationship_history_expansion || null",
            normalize,
        )
        self.assertIn("if (!expansion?.truncated) return", notice)
        self.assertIn("expansion.dropped_base_ids", notice)
        self.assertIn("expansion.dropped_root_ids", notice)
        self.assertIn("Relationship expansion is bounded", notice)
        self.assertIn("Refine the focused resource or lane search", notice)
        self.assertIn("const expansionNotice = timelineExpansionNoticeHtml(trackWidth)", render)
        self.assertIn("content.innerHTML = expansionNotice + densityLane", render)

    def test_temporal_relationship_intervals_share_one_tree_child_lane(self) -> None:
        groups = javascript_function(self.script, "relationshipGroupsForResource")

        self.assertIn(
            "const key = `${edge.source}|${edge.type}|${edge.target}`",
            groups,
        )
        self.assertNotIn("${edge.id}", groups)
        self.assertIn("groups.get(key).spans.push(edge)", groups)

    def test_resource_timeline_close_is_canonical_accessible_and_table_synchronized(self) -> None:
        hidden = javascript_function(self.script, "resourceHiddenFromTimeline")
        selected = javascript_function(self.script, "laneSelectedByMode")
        groups = javascript_function(self.script, "relationshipGroupsForResource")
        combined = javascript_function(self.script, "combinedAssociationLane")
        render = javascript_function(self.script, "renderTimeline")
        bindings = javascript_function(self.script, "bindTimelineInteractions")
        visibility = javascript_function(self.script, "setExplicitLaneVisibility")
        jump_event = javascript_function(self.script, "jumpToTimelineEvent")
        jump_resource = javascript_function(self.script, "jumpToTimelineResource")
        reset = javascript_function(self.script, "resetTimelineView")
        picker = javascript_function(self.script, "renderLanePicker")
        bundle = javascript_function(self.script, "renderResourceBundleTable")
        generic = javascript_function(self.script, "renderResourceTables")

        self.assertIn("hiddenTimelineResourceIds: new Set()", self.script)
        self.assertIn("resourceId = canonicalResourceId(resourceId)", hidden)
        self.assertIn("state.hiddenTimelineResourceIds.has(resourceId)", hidden)
        self.assertIn("resourceId = canonicalResourceId(resourceId)", selected)
        self.assertIn("resourceHiddenFromTimeline(resourceId)", selected)
        self.assertIn('class="resource-lane-label-shell"', render)
        self.assertIn('class="lane-close"', render)
        self.assertIn('data-lane-close-resource-id="${escapeHtml(lane.resourceId)}"', render)
        self.assertIn("Hide ${lane.label} from Resource timeline", render)
        self.assertLess(
            render.index('class="lane-close"'),
            render.index('class="lane-label" type="button" data-resource-id='),
        )
        self.assertIn("resourceHiddenFromTimeline(otherId)", groups)
        self.assertIn("resourceHiddenFromTimeline(state.selectedResourceId)", combined)
        self.assertIn("!resourceHiddenFromTimeline(edge.otherId)", combined)
        self.assertIn("resourceHiddenFromTimeline(state.selectedResourceId)", render)
        self.assertIn('state.correlationTimelineView === "combined"', render)
        self.assertIn(": []", render)
        self.assertIn('const combinedMode = state.correlationTimelineView === "combined"', picker)
        self.assertIn("combinedMode ? `${combinedLaneCount} combined`", picker)

        self.assertIn('const timeline = byId("timeline-content")', bindings)
        self.assertIn('timeline.querySelectorAll("[data-lane-close-resource-id]")', bindings)
        self.assertIn("event.preventDefault()", bindings)
        self.assertIn("event.stopPropagation()", bindings)
        self.assertIn("closeHover()", bindings)
        self.assertIn(
            "setExplicitLaneVisibility(button.dataset.laneCloseResourceId, false)",
            bindings,
        )
        self.assertNotIn("explicitLaneIds.delete", bindings)

        self.assertIn("state.hiddenTimelineResourceIds.add(resourceId)", visibility)
        self.assertIn("state.hiddenTimelineResourceIds.delete(resourceId)", visibility)
        self.assertIn("state.explicitLaneIds.delete(resourceId)", visibility)
        self.assertIn("state.explicitLaneIds.add(resourceId)", visibility)
        self.assertIn("renderTimeline()", visibility)
        self.assertIn("renderResourceTables()", visibility)
        self.assertIn("void refreshScaleTimeline()", visibility)
        self.assertLess(
            visibility.index("renderTimeline()"),
            visibility.index("void refreshScaleTimeline()"),
        )

        self.assertIn("state.hiddenTimelineResourceIds.delete(resourceId)", jump_event)
        self.assertIn("state.hiddenTimelineResourceIds.delete(resourceId)", jump_resource)
        self.assertIn("state.hiddenTimelineResourceIds.clear()", reset)
        self.assertIn("laneSelectedByMode(resourceId)", bundle)
        self.assertIn("laneSelectedByMode(item.resource_id)", generic)
        self.assertNotIn('resourceId.includes("ETG")', selected)
        self.assertNotIn('resourceId.includes("DTE")', selected)

        self.assertIn(".resource-lane-label-shell", self.styles)
        self.assertIn("grid-template-columns: 28px minmax(0, 1fr)", self.styles)
        self.assertIn(".lane-close:focus-visible", self.styles)
        self.assertIn("outline: 2px solid var(--cyan)", self.styles)

    def test_large_correlation_canvas_is_bounded_while_index_is_pageable(self) -> None:
        bounded = javascript_function(self.script, "boundedCorrelationGraph")
        request = javascript_function(self.script, "requestGraph")
        index = javascript_function(self.script, "renderCorrelationList")
        render = javascript_function(self.script, "renderGraph")

        self.assertRegex(self.script, r"const MAX_CORRELATION_RENDER_NODES = \d+;")
        self.assertRegex(self.script, r"const CORRELATION_LIST_PAGE_SIZE = \d+;")
        self.assertIn("totalNodes <= MAX_CORRELATION_RENDER_NODES", bounded)
        self.assertIn("if (state.selectedResourceId)", bounded)
        self.assertIn("display_truncated: true", bounded)
        self.assertIn("display_total_nodes: totalNodes", bounded)
        self.assertIn("display_total_edges: totalEdges", bounded)
        self.assertIn(
            "state.correlationListLimit = CORRELATION_LIST_PAGE_SIZE",
            request,
        )
        self.assertIn(".slice(0, state.correlationListLimit)", index)
        self.assertIn("data-correlation-show-more", index)
        self.assertIn(
            "state.correlationListLimit += CORRELATION_LIST_PAGE_SIZE",
            index,
        )
        self.assertIn("const scoped = scopedGraph(fullGraph)", render)
        self.assertIn("const graph = boundedCorrelationGraph(scoped)", render)
        self.assertIn("renderCorrelationList(scoped)", render)
        self.assertIn("the index below remains pageable across the full response", render)

    def test_opening_dashboard_marks_request_pending_before_rendering(self) -> None:
        toggle = javascript_function(self.script, "toggleDashboardOpen")
        initialize = javascript_function(self.script, "initialize")

        self.assertIn("requestDashboards()", toggle)
        self.assertIn("renderPluginDashboards()", toggle)
        self.assertLess(
            toggle.index("requestDashboards()"),
            toggle.index("renderPluginDashboards()"),
        )
        self.assertIn("markDashboardsPending(state.cursorNs)", initialize)
        self.assertLess(
            initialize.index("markDashboardsPending(state.cursorNs)"),
            initialize.index("renderPluginDashboards()"),
        )

    def test_zoom_rejects_unrepresentable_derived_dimensions_without_capping(self) -> None:
        zoom = javascript_function(self.script, "applyTimelineZoom")

        self.assertIn("const derivedTrackWidth = Math.round(900 * zoom)", zoom)
        self.assertIn("const derivedDensityBins = Math.round(180 * zoom)", zoom)
        self.assertIn("!Number.isFinite(derivedTrackWidth)", zoom)
        self.assertIn("!Number.isFinite(derivedDensityBins)", zoom)
        self.assertIn('control.setAttribute("aria-invalid", "true")', zoom)
        self.assertIn("remain representable by this browser", zoom)
        self.assertNotRegex(zoom, r"Math\.min\(")

    def test_server_health_and_failure_semantics_remain_visible(self) -> None:
        normalize_graph = javascript_function(self.script, "normalizedGraph")
        render_graph = javascript_function(self.script, "renderGraph")
        request_preview = javascript_function(
            self.script,
            "requestFailureIncidentPreview",
        )
        render_incident = javascript_function(self.script, "renderIncidentSummary")

        self.assertIn("status_class: statusClass", normalize_graph)
        self.assertIn("node.status_class", normalize_graph)
        self.assertIn("node.status", normalize_graph)
        self.assertIn('statusClass === "error"', render_graph)
        self.assertIn("state.failureIncidentPreview = events", request_preview)
        self.assertIn("state.failureIncidentPreview.slice(0, 3)", render_incident)
        self.assertIn("formatOffset(eventTime(event))", render_incident)
        self.assertIn('title="${escapeHtml(uid)}"', render_incident)

    def test_node_route_panel_never_infers_local_or_forwards_inactive_branches(
        self,
    ) -> None:
        branches = javascript_function(self.script, "routePayloadBranches")
        forwarding = javascript_function(
            self.script,
            "routePayloadForwardingPresentation",
        )
        render = javascript_function(self.script, "renderRoutePayload")

        self.assertIn("item.active === true ? true", branches)
        self.assertIn("item.active === false ? false", branches)
        self.assertIn("branches.filter((item) => item.active === true)", forwarding)
        self.assertIn("branches.filter((item) => item.active === null)", forwarding)
        self.assertNotIn('"local"', forwarding + render)
        self.assertIn('"Not returned"', forwarding)
        self.assertIn("No forwarding branches returned", render)
        self.assertIn("does not infer local delivery", render)
        self.assertIn("inactive / not forwarding", render)
        self.assertIn("payload.result", render)

    def test_range_summary_discloses_bounded_endpoint_comparison(self) -> None:
        render = javascript_function(self.script, "renderRangeSummary")
        flags = javascript_function(self.script, "rangeTruncationFlags")

        self.assertIn("endpoint_diff_evaluated_count", render)
        self.assertIn("affected_resource_count", render)
        self.assertIn("rangeTruncationFlags(summary)", render)
        self.assertIn("Endpoint comparison is bounded", render)
        self.assertIn("evaluated subset", render)
        self.assertIn("detail sets truncated", render)
        self.assertIn("endpoint_diff: true", flags)
        self.assertIn(".range-facts .bounded-fact", self.styles)
        self.assertIn(".range-scope-note", self.styles)

    def test_latest_temporal_requests_abort_superseded_fetches(self) -> None:
        helper = javascript_function(self.script, "beginLatestRequest")
        schedule = javascript_function(self.script, "scheduleTemporalRefresh")

        self.assertIn("state[controllerKey]?.abort()", helper)
        self.assertIn("new AbortController()", helper)
        for name, controller in (
            ("requestTimeline", "timelineAbortController"),
            ("requestRangeSummary", "rangeAbortController"),
            ("requestResources", "resourceAbortController"),
            ("requestDashboards", "dashboardAbortController"),
            ("requestGraph", "graphAbortController"),
            ("requestTopology", "topologyAbortController"),
            ("resolveRoute", "routeAbortController"),
        ):
            body = javascript_function(self.script, name)
            self.assertIn(controller, body)
            self.assertIn("controller.signal", body)
            self.assertIn("requestWasAborted", body)
        for controller in (
            "graphAbortController",
            "resourceAbortController",
            "dashboardAbortController",
        ):
            self.assertIn(controller, schedule)
        topology = javascript_function(self.script, "requestTopology")
        self.assertLess(
            topology.index("request = topologyRequestBody()"),
            topology.index('abortLatestRequests("topologyAbortController")'),
        )
        topology_schedule = javascript_function(
            self.script,
            "scheduleTopologyRefreshFromCursor",
        )
        self.assertNotIn(
            'abortLatestRequests("topologyAbortController")',
            topology_schedule,
        )

    def test_range_boundary_drag_target_does_not_cover_event_lanes(self) -> None:
        handles = javascript_function(self.script, "updateRangeHandles")

        self.assertNotIn("handle.style.height", handles)
        self.assertIn("height: 30px", self.styles)


class TopologyAuditRegressionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = TOPOLOGY_JS.read_text(encoding="utf-8")
        cls.styles = TOPOLOGY_CSS.read_text(encoding="utf-8")
        cls.page = TOPOLOGY_HTML.read_text(encoding="utf-8")

    def test_health_uses_explicit_normalized_vocabulary(self) -> None:
        declared = javascript_function(self.script, "declaredHealthPresentation")
        node = javascript_function(self.script, "nodeHealth")
        link = javascript_function(self.script, "linkHealth")

        self.assertIn("const NORMALIZED_HEALTH_PRESENTATION = new Map", self.script)
        self.assertIn("value?.condition_class", declared)
        self.assertIn("value?.status_class", declared)
        self.assertIn("value?.health_class", declared)
        self.assertIn('["healthy", "good"]', self.script)
        self.assertIn('["usable", "good"]', self.script)
        self.assertIn('["degraded", "warning"]', self.script)
        self.assertIn('["unusable", "error"]', self.script)
        self.assertIn('["error", "error"]', self.script)
        for raw_status in ('"up"', '"down"', '"programmed"'):
            self.assertNotIn(raw_status, self.script[: self.script.index("const state =")])
        self.assertIn("node?.resource_previews || node?.resources", node)
        self.assertIn("declaredHealthPresentation(resource)", node)
        self.assertIn('|| "warning"', node)
        self.assertIn("[node, coverage].map(declaredHealthPresentation)", node)
        self.assertIn('return "warning"', node)
        self.assertNotIn(".test(", node)
        self.assertIn(
            "declaredHealthPresentation(link, { includeStatus: true })",
            link,
        )
        self.assertIn("includeStatus ? value?.status : null", declared)
        self.assertNotIn("link?.resolution", link)

    def test_dirty_device_selection_filters_stale_results_and_refreshes_map(self) -> None:
        selected = javascript_function(self.script, "selectedResultNodes")
        index = javascript_function(self.script, "renderCapabilityNodeIndex")
        bindings = javascript_function(self.script, "bindControls")

        self.assertIn("if (!state.queryControlsDirty) return nodes", selected)
        self.assertIn(
            "nodes.filter((node) => state.selectedNodeKeys.has(node.key))",
            selected,
        )
        selection_change = index[index.index('querySelectorAll("[data-node-toggle]")') :]
        self.assertIn("markTopologyQueryDirty()", selection_change)
        self.assertIn("renderMetrics()", selection_change)
        self.assertIn("renderMap()", selection_change)
        self.assertIn("syncUrl()", selection_change)
        select_all = bindings[bindings.index('byId("mn-select-all")') :]
        self.assertIn("renderMetrics()", select_all)
        self.assertIn("renderMap()", select_all)
        self.assertIn("syncUrl()", select_all)

    def test_route_table_seed_is_pending_until_trace_returns_correlation(self) -> None:
        keys = javascript_function(self.script, "focusedRouteEntryKeys")
        row = javascript_function(self.script, "routeTableRowMarkup")
        clear = javascript_function(self.script, "clearFocusedRouteEntry")
        controls = javascript_function(self.script, "bindControls")

        self.assertIn("const trace = state.routeTrace", keys)
        self.assertIn("const path = selectedRoutePath()", keys)
        self.assertIn("const pathValues = collect(", keys)
        self.assertIn("if (trace && !values.length)", keys)
        self.assertIn("if (state.focusedRouteEntryRef)", keys)
        self.assertIn(
            "state.focusedRouteEntryId === entry.route_entry_id && !matched",
            row,
        )
        self.assertIn("used by focused trace", row)
        self.assertIn("loaded into trace", row)
        self.assertIn("renderRouteTables()", clear)
        self.assertIn("renderRouteSeed()", clear)
        endpoint_inputs = controls[controls.index('["mn-route-source", "mn-route-destination"]') :]
        self.assertIn(
            "if (state.focusedRouteEntryId) clearFocusedRouteEntry()",
            endpoint_inputs,
        )

    def test_route_table_seeds_trace_with_plugin_canonical_endpoints(self) -> None:
        seed = javascript_function(self.script, "useRouteTableEntry")
        endpoint = javascript_function(self.script, "routeEndpointSeedValue")

        self.assertIn("routeEndpointSeedValue(explicitFlowSource", seed)
        self.assertIn("routeEndpointSeedValue(explicitFlowDestination", seed)
        self.assertIn("query?.flow?.source ?? query?.source", seed)
        self.assertIn("raw.resource_id", endpoint)
        self.assertIn("raw.node_id", endpoint)
        self.assertLess(endpoint.index("raw.endpoint_id"), endpoint.index("raw.value"))
        self.assertLess(
            seed.index("entry.destination?.destination_id"),
            seed.index("entry.destination?.value"),
        )
        self.assertIn('setRouteEndpointInput("destination", destination)', seed)
        self.assertIn('setRouteEndpointInput("source", source)', seed)
        self.assertNotIn('if (source) setRouteEndpointInput("source", source)', seed)
        self.assertIn("setRouteStartInput(start)", seed)
        self.assertIn("routeStartSeedValue(startDescriptor, entry.node_id)", seed)
        self.assertNotIn("`start:${entry.node_id}`", seed)

    def test_route_result_reflows_without_clipping_evidence(self) -> None:
        self.assertIn(".mn-route-workbench > *", self.styles)
        self.assertIn(".mn-route-workbench .mn-route-summary", self.styles)
        self.assertIn(
            "grid-template-columns: repeat(2, minmax(0, 1fr))",
            self.styles,
        )
        result_rule = self.styles[
            self.styles.rindex(".mn-route-result {") :
            self.styles.index(".mn-route-empty {", self.styles.rindex(".mn-route-result {"))
        ]
        self.assertIn("min-width: 0", result_rule)
        self.assertIn("overflow-x: auto", result_rule)
        self.assertNotIn("overflow: hidden", result_rule)

    def test_route_table_disables_rows_without_a_plugin_trace_query(self) -> None:
        normalize = javascript_function(self.script, "normalizeRouteTableEntry")
        row = javascript_function(self.script, "routeTableRowMarkup")
        seed = javascript_function(self.script, "useRouteTableEntry")

        self.assertIn("const declaredTraceable = explicitRouteBoolean(raw?.traceable)", normalize)
        self.assertIn("declaredTraceable !== false", normalize)
        self.assertIn("Object.keys(traceQuery).length > 0", normalize)
        self.assertIn("traceable,", normalize)
        self.assertIn("trace_query: traceQuery", normalize)
        self.assertIn("entry.traceable === true", row)
        self.assertIn('data-route-entry-trace="', row)
        self.assertIn('disabled aria-label="', row)
        self.assertIn(">No trace</button>", row)
        self.assertIn(
            "The node plug-in did not provide a usable trace query for this row.",
            row,
        )
        self.assertIn("entry.traceable !== true", seed)
        self.assertIn(".mn-route-table-trace:disabled", self.styles)
        self.assertIn(".mn-route-table-trace:not(:disabled):hover", self.styles)

    def test_route_form_separates_observation_start_from_traffic_endpoints(
        self,
    ) -> None:
        request = javascript_function(self.script, "buildRouteTraceRequest")
        start_state = javascript_function(self.script, "syncRouteStartControlState")

        self.assertIn('id="mn-route-start"', self.page)
        self.assertIn("Start trace at", self.page)
        self.assertIn("Traffic source", self.page)
        self.assertIn("Traffic destination", self.page)
        self.assertNotIn(
            "Ingress router, interface, address, or plug-in-owned endpoint",
            self.page,
        )
        self.assertIn('const usesForwardStart = direction !== "reverse"', request)
        self.assertIn("usesForwardStart ? selectedRouteStart() : null", request)
        self.assertIn("flow:", request)
        self.assertIn("if (usesForwardStart)", request)
        self.assertIn("request.ingress = forwardStart", request)
        self.assertIn("request.trace_starts = { forward: forwardStart }", request)
        self.assertIn('input.disabled = !state.routeCapabilities || !used', start_state)
        self.assertIn("Not used for return-only tracing", start_state)
        self.assertIn(".mn-route-field-start.is-unused", self.styles)

    def test_route_start_identity_and_defaults_remain_plugin_owned(self) -> None:
        match = javascript_function(self.script, "routeStartMatch")
        seed = javascript_function(self.script, "routeStartSeedValue")
        controls = javascript_function(self.script, "renderRouteControls")
        normalize = javascript_function(self.script, "normalizeRouteCapabilities")

        self.assertIn("item.start_id === value", match)
        self.assertIn("matches.length === 1", match)
        self.assertIn("item.node_id === value", match)
        self.assertNotIn(
            "item.start_id === value || item.node_id === value",
            match,
        )
        self.assertIn("advertisedRouteStart(raw, fallbackNodeId)", seed)
        self.assertNotIn('`start:${', seed)
        self.assertIn("routeStartSelectorValue(", normalize)
        self.assertLess(
            controls.index("|| state.routeCapabilities.default_start"),
            controls.index("|| sourceStart?.start_id"),
        )

    def test_executable_capability_ids_are_declared_or_unavailable(self) -> None:
        plugin_id = javascript_function(self.script, "pluginId")
        projection_id = javascript_function(self.script, "projectionId")
        perspective_id = javascript_function(self.script, "perspectiveId")
        normalize_plugin = javascript_function(self.script, "normalizePlugin")
        normalize_node = javascript_function(self.script, "normalizeNode")
        normalize_capabilities = javascript_function(
            self.script, "normalizeCapabilities"
        )
        plan = javascript_function(self.script, "nodePlan")
        request = javascript_function(self.script, "buildQueryRequest")
        route = javascript_function(self.script, "normalizeRouteCapabilities")
        steering = javascript_function(
            self.script, "steeringProfilesForScenario"
        )

        for helper in (plugin_id, projection_id, perspective_id):
            self.assertIn("firstDeclaredString(", helper)
        for fabricated in (
            "unspecified-provider",
            "resource-association",
            "observed-status",
            "boundary-observer",
            "revision-dump-provider",
        ):
            self.assertNotIn(
                fabricated,
                normalize_plugin + normalize_node + normalize_capabilities,
            )
        self.assertIn("executable", plan)
        self.assertIn("unavailable_reason", plan)
        self.assertIn("if (!plan.executable) throw new Error", request)
        self.assertNotIn("...plan", request)

        for fabricated in (
            "legacy_source_attachment",
            "Default forwarding trace",
            '["best_effort", "strict"]',
            '?? "default"',
            '`start:${',
        ):
            self.assertNotIn(fabricated, route)
        self.assertIn("scenarios,", route)
        self.assertIn("policies,", route)
        self.assertIn('default_scenario_id: defaultScenario?.scenario_id || ""', route)
        self.assertIn('default_vrf: defaultVrf?.vrf || ""', route)
        self.assertNotIn('|| "observed"', steering)

    def test_connectivity_domains_come_only_from_declared_segments(self) -> None:
        normalize = javascript_function(self.script, "normalizeQuery")
        domain = javascript_function(self.script, "normalizeConnectivityDomain")
        visible = javascript_function(self.script, "topologyConnectivityDomains")

        domain_source = normalize[
            normalize.index("const domainSource")
            : normalize.index("const segmentAttachments")
        ]
        self.assertIn("raw?.connectivity_domains", domain_source)
        self.assertIn("raw?.network_segments", domain_source)
        self.assertNotIn("raw?.subnets", domain_source)
        self.assertNotIn("raw?.broadcast_domains", domain_source)
        self.assertNotIn("raw?.vpn_segments", domain_source)
        self.assertNotIn('`network-${index + 1}`', domain)
        self.assertNotIn('?? "transit"', domain)
        self.assertNotIn('?? "subnet"', domain)
        self.assertIn("state.query?.connectivity_domains", visible)
        self.assertNotIn("addDomainMembership", visible)
        self.assertNotIn("connectivityDomainKey", visible)
        self.assertNotIn('source: "link-projection"', visible)
        self.assertIn("member.link_ids", visible)
        self.assertIn("They never create a domain or a membership", visible)

    def test_route_domain_tokens_preserve_domain_and_attachment_identity(self) -> None:
        route_tokens = javascript_function(self.script, "routeTokensFor")
        segment = javascript_function(self.script, "normalizeRouteSegment")
        domain = javascript_function(self.script, "connectivityDomainMarkup")
        attachment = javascript_function(self.script, "attachmentEdgeAttributes")
        edges = javascript_function(self.script, "renderConnectivityEdges")
        compact = edges[
            edges.index("for (const decision of orderedCompactDecisions)") :
        ]

        self.assertIn("raw?.network_segment_id", route_tokens)
        self.assertIn("raw?.network_segment_attachment_ids", route_tokens)
        self.assertIn("raw?.connectivity_attachment_ids", route_tokens)
        self.assertIn("`network-segment:${networkSegmentId}`", route_tokens)
        self.assertIn("`network-attachment:${attachmentId}`", route_tokens)
        self.assertIn("network_segment_id: networkSegmentId", segment)
        self.assertIn(
            "network_segment_attachment_ids: firstArray(",
            segment,
        )
        self.assertIn(
            "`network-attachment:${attachmentId}`",
            segment,
        )
        self.assertIn(
            "`network-attachment:${member.member_id}`",
            domain,
        )
        self.assertIn(
            "`network-attachment:${member.member_id}`",
            attachment,
        )
        self.assertIn(
            "`network-attachment:${attachmentId}`",
            compact,
        )

    def test_compact_domain_attachment_merge_is_defined_and_lossless(self) -> None:
        merge = javascript_function(self.script, "mergeAttachment")
        participant = javascript_function(
            self.script,
            "mergedParticipantAttachment",
        )
        renderer = javascript_function(self.script, "renderConnectivityEdges")
        compact = renderer[
            renderer.rindex("for (const decision of orderedCompactDecisions)") :
            renderer.rindex("for (const link of directLinks)")
        ]

        self.assertIn("uniqueStrings(", merge)
        self.assertIn("left.interface_names", merge)
        self.assertIn("right.interface_names", merge)
        self.assertIn("left.physical_interfaces", merge)
        self.assertIn("right.physical_interfaces", merge)
        self.assertIn("left.addresses", merge)
        self.assertIn("right.addresses", merge)
        self.assertIn("mergeAttachment(combined, member.attachment || {})", participant)
        self.assertIn("for (const [memberIndex, member] of [...left.members]", compact)
        self.assertIn("for (const [memberIndex, member] of [...right.members]", compact)
        self.assertIn("attachmentEdgeAttributes(member.links?.[0]", compact)
        self.assertIn("groupOrdinal: memberIndex", compact)
        self.assertNotIn("const leftMember = left.members[0]", compact)
        self.assertNotIn("const rightMember = right.members[0]", compact)

    def test_topology_asset_has_no_mojibake_sequences(self) -> None:
        for corrupted in ("â†’", "Â·", "â€¦", "Ã", "\ufffd"):
            self.assertNotIn(corrupted, self.script)

    def test_route_endpoint_normalization_preserves_plugin_selector_ids(self) -> None:
        normalize = javascript_function(self.script, "normalizeRouteEndpoint")
        match = javascript_function(self.script, "routeEndpointMatch")

        self.assertIn("endpoint?.[idField]", normalize)
        self.assertLess(
            normalize.index("endpoint?.[idField]"),
            normalize.index("endpoint?.endpoint_id"),
        )
        self.assertIn("[idField]: selectorId", normalize)
        self.assertIn("endpoint_id: canonicalEndpointId", normalize)
        self.assertIn("item[idField] === value || item.endpoint_id === value", match)

    def test_transit_start_rendering_and_endpoint_summary_keep_roles_distinct(
        self,
    ) -> None:
        focused_node = javascript_function(self.script, "mapNodeMarkup")
        overview_node = javascript_function(self.script, "allPathNodeMarkup")
        render = javascript_function(self.script, "renderRouteTrace")
        comparison = javascript_function(self.script, "bidirectionalSummary")
        request = javascript_function(self.script, "buildRouteTraceRequest")

        for node_markup in (focused_node, overview_node):
            self.assertIn('"TRACE START"', node_markup)
            self.assertNotIn('"SOURCE"', node_markup)
        self.assertIn("`Return flow ${flowDestinationLabel}", render)
        self.assertIn("sameCanonicalRouteEndpoint", request)
        self.assertNotIn(
            "sourceCapability.node_id === destinationCapability.node_id",
            request,
        )
        self.assertIn('"partial_active_reachability"', comparison)
        self.assertLess(
            comparison.index("if (incompleteComparison)"),
            comparison.index("const oneWay ="),
        )

    def test_route_table_request_uses_one_node_scope_selector(self) -> None:
        query = javascript_function(self.script, "queryRouteTables")

        self.assertIn("const nodeQueries = firstArray(query.request.node_queries)", query)
        self.assertIn("if (nodeQueries.length) body.node_queries = nodeQueries", query)
        self.assertIn("else body.node_ids = query.nodes.map", query)
        body_literal = query[query.index("const body = {") : query.index("const failures")]
        self.assertNotIn("node_queries:", body_literal)
        self.assertNotIn("node_ids:", body_literal)

    def test_topology_edges_use_stable_visible_curves_for_single_and_parallel_links(self) -> None:
        lane = javascript_function(self.script, "nextEdgeLane")
        sign = javascript_function(self.script, "stableEdgeBendSign")
        bend = javascript_function(self.script, "baseEdgeBend")
        geometry = javascript_function(self.script, "curvedEdgeGeometry")
        topology = javascript_function(self.script, "renderConnectivityEdges")
        focused_route = javascript_function(self.script, "renderEdges")
        all_routes = javascript_function(self.script, "renderAllPathEdges")
        attachments = javascript_function(self.script, "renderAttachmentComponents")
        boundary_tag = javascript_function(self.script, "routeBoundaryTagMarkup")
        viewport = javascript_function(self.script, "setupGraphViewport")
        transform = javascript_function(self.script, "applyGraphTransform")

        for declaration in (
            "const MAP_EDGE_BASE_BEND_MIN = ",
            "const MAP_EDGE_BASE_BEND_MAX = ",
            "const MAP_EDGE_BASE_BEND_RATIO = ",
            "const MAP_EDGE_MAX_BEND_RATIO = ",
        ):
            self.assertIn(declaration, self.script)
        self.assertIn("if (total === 1) return 1", lane)
        self.assertIn("ordinal % 2 === 0 ? band : -band", lane)
        self.assertIn("stableLayoutHash(pairKey)", sign)
        self.assertNotIn("Math.random", sign + lane + bend + geometry)
        self.assertIn("length * MAP_EDGE_MAX_BEND_RATIO", bend)
        self.assertIn("const orientation = sourceToken <= targetToken ? 1 : -1", geometry)
        self.assertIn("stableEdgeBendSign(pairKey)", geometry)
        self.assertIn("baseEdgeBend(length)", geometry)
        self.assertIn("normalizedLane === 0", geometry)
        self.assertIn("nodeBoundaryPoint(sourceCenter, control, sourceBox)", geometry)
        self.assertIn("nodeBoundaryPoint(targetCenter, control, targetBox)", geometry)
        self.assertIn("Q ${control.x} ${control.y}", geometry)

        for renderer in (topology, focused_route, all_routes):
            self.assertIn("curvedEdgeGeometry(", renderer)
            self.assertIn('d="${geometry.d}"', renderer)
        self.assertGreaterEqual(topology.count('d="${geometry.d}"'), 6)
        self.assertGreaterEqual(focused_route.count('d="${geometry.d}"'), 3)
        self.assertGreaterEqual(all_routes.count('d="${geometry.d}"'), 2)
        self.assertIn("pairTotals.get(edge.pairKey) > 1", all_routes)
        self.assertIn("edge.cycleClosing", all_routes)
        self.assertIn("targetPosition.x <= sourcePosition.x", all_routes)
        self.assertIn(": 0", all_routes)
        self.assertIn("quadraticEdgePoint(geometry, pathPosition)", attachments)
        self.assertIn("quadraticEdgePoint(geometry, 0.5)", topology)
        self.assertIn("quadraticEdgePoint(geometry, 0.5)", boundary_tag)
        self.assertIn("requestAnimationFrame(redraw)", viewport)
        self.assertIn("graphWorldLayers(stage).forEach", transform)
        self.assertIn('layer.style.transform = transform', transform)

    def test_all_path_layout_orders_rows_by_stable_candidate_lanes(self) -> None:
        normalize = javascript_function(self.script, "normalizeRouteTrace")
        layout = javascript_function(self.script, "mapAllPathsLayout")
        render = javascript_function(self.script, "renderAllPathsRouteMap")

        self.assertIn(
            "left.rank - right.rank || compareLayoutIds(left.path_id, right.path_id)",
            normalize,
        )
        self.assertIn("const nodePathRanks = new Map()", layout)
        self.assertIn("pathRank(left) - pathRank(right)", layout)
        self.assertIn("compareLayoutIds(left.key, right.key)", layout)
        self.assertIn("ROUTE_OVERVIEW_LAYOUT_VERSION", render)

    def test_vpn_suggestion_uses_declared_presentation_role_only(self) -> None:
        normalize = javascript_function(self.script, "normalizeProfile")
        role_lookup = javascript_function(self.script, "profileForPresentationRole")
        render = javascript_function(self.script, "renderLinkStatusMap")
        vpn_section = render[render.index("const suggestedProfile") :]

        self.assertIn("raw?.presentation_roles", normalize)
        self.assertIn("raw?.presentation?.roles", normalize)
        self.assertIn("raw?.empty_action_label", normalize)
        self.assertIn("profile?.presentation_roles", role_lookup)
        self.assertIn("String(candidate) === String(role)", role_lookup)
        self.assertIn('profileForPresentationRole("vpn")', vpn_section)
        self.assertNotIn("projection_role", vpn_section)
        self.assertIn("VPN identity must come from a device plug-in", vpn_section)

    def test_topology_assembly_id_must_be_declared_by_capabilities(self) -> None:
        assembly = javascript_function(self.script, "topologyAssemblyId")

        self.assertIn("state.capabilities?.assembly_id", assembly)
        self.assertIn('throw new Error("Topology capabilities did not declare assembly_id.")', assembly)
        self.assertNotIn("demo.fabric.multi-node", assembly)

    def test_route_family_labels_match_the_normalized_filter_semantics(self) -> None:
        self.assertNotIn("Address family", self.page)
        self.assertGreaterEqual(self.page.count("Route family"), 2)
        self.assertIn('id="mn-route-family"', self.page)
        self.assertIn('id="mn-route-table-family-filter"', self.page)
        self.assertIn("All route families", self.page)

    def test_route_cycles_preserve_path_scoped_node_occurrences(self) -> None:
        normalize = javascript_function(self.script, "normalizeRoutePath")
        sequence = javascript_function(self.script, "routeNodeSequence")
        all_nodes = javascript_function(self.script, "allPathGraphNodes")
        memberships = javascript_function(self.script, "routePathMemberships")
        focused_edges = javascript_function(self.script, "renderEdges")
        all_edges = javascript_function(self.script, "renderAllPathEdges")

        self.assertIn("normalizedRouteOccurrences(raw, pathId, segments, nodes)", normalize)
        self.assertIn("node_occurrences: nodeOccurrences", normalize)
        self.assertIn("raw.cycle.first_occurrence_id", normalize)
        self.assertIn("raw.cycle.closing_occurrence_id", normalize)
        self.assertIn("raw.cycle.closing_step", normalize)
        self.assertIn("route_occurrence_id: occurrenceId", sequence)
        self.assertIn("route_base_key: baseKey", sequence)
        self.assertNotIn("const seen = new Set()", sequence)
        self.assertNotIn("seen.has(node.key)", all_nodes)
        self.assertIn("route_graph_shared: true", all_nodes)
        self.assertIn("sameRouteRef(ref, node)", memberships)
        for renderer in (focused_edges, all_edges):
            self.assertIn("findRouteOccurrence(", renderer)
            self.assertIn("routeSegmentIsCycleClosing(", renderer)
            self.assertIn("loop-closing segment", renderer)
            self.assertIn("mn-route-cycle", renderer)

    def test_policy_blocking_uses_generic_class_and_plugin_declared_copy(self) -> None:
        normalize = javascript_function(self.script, "normalizeRoutePath")
        decision = javascript_function(self.script, "normalizeRoutePolicyDecision")
        presentation = javascript_function(self.script, "routePolicyPresentation")
        blocked_segment = javascript_function(
            self.script,
            "routeSegmentIsPolicyBlocked",
        )
        diagnostics = javascript_function(self.script, "routeDiagnosticItems")
        direction = javascript_function(self.script, "traceDirectionState")
        badges = javascript_function(self.script, "routePathBadges")
        summary = javascript_function(self.script, "pathStatusSummary")

        self.assertIn("normalizeRoutePolicyDecision", normalize)
        self.assertIn("policy_decisions: policyDecisions", normalize)
        self.assertIn("item.core_verdict", decision)
        self.assertIn("item.scope_refs", decision)
        self.assertIn("item.policy_category", decision)
        self.assertIn("item.label", decision)
        self.assertIn("item.text", decision)
        self.assertIn("decision?.label", presentation)
        self.assertIn("decision?.detail", presentation)
        self.assertIn("decision?.policy_category", presentation)
        self.assertIn("segment?.policy_decision_refs", blocked_segment)
        self.assertIn("path?.cycle?.repeated_state", diagnostics)
        self.assertIn('code: "cycle"', direction)
        self.assertIn('code: "policy_blocked"', direction)
        self.assertIn("routePolicyPresentation(path).label", badges)
        self.assertIn("routePolicyPresentation(path).label", summary)
        self.assertNotRegex(
            self.script + self.page + self.styles,
            r"(?i)split[-_ ]horizon",
        )
        self.assertGreaterEqual(self.script.count('"Looped paths"'), 1)
        self.assertGreaterEqual(self.script.count('"Policy-blocked paths"'), 1)
        self.assertIn("- cycleCount - policyBlockedCount - unusableCount", self.script)
        self.assertIn(
            "&& !routeValueIsCycle(path) && !routeValueIsPolicyBlocked(path)",
            self.script,
        )
        self.assertIn('class="is-cycle"', self.page)
        self.assertIn('class="is-policy-blocked"', self.page)
        self.assertIn(".mn-route-edge.is-cycle", self.styles)
        self.assertIn(".mn-route-edge.is-policy-blocked", self.styles)
        self.assertIn(".mn-route-badge.is-cycle", self.styles)
        self.assertIn(".mn-route-badge.is-policy-blocked", self.styles)

    def test_all_path_overview_hides_unpinned_detail_even_if_dom_is_retained(self) -> None:
        chrome = javascript_function(self.script, "updateRouteViewChrome")
        render = javascript_function(self.script, "renderRouteTrace")
        invalidate = javascript_function(self.script, "invalidateRouteTraceResult")
        controls = javascript_function(self.script, "bindControls")

        self.assertIn(
            "const hideDetail = Boolean(trace && paths.length && allPaths && !pinned)",
            chrome,
        )
        self.assertIn("result.hidden = hideDetail", chrome)
        unselected = render[render.index("if (!selected)") :]
        self.assertIn("renderUnselectedRoutePathTabs(trace)", unselected)
        self.assertIn("content.hidden = true", unselected)
        self.assertLess(
            unselected.index("content.hidden = true"),
            unselected.index("return;"),
        )
        self.assertIn('state.selectedRoutePathId = ""', invalidate)
        self.assertIn('state.requestedRoutePathId = ""', invalidate)
        scenario_change = controls[controls.index('byId("mn-route-scenario")') :]
        self.assertLess(
            scenario_change.index("invalidateRouteTraceResult()"),
            scenario_change.index("syncUrl()"),
        )

    def test_packet_evolution_steering_is_server_advertised_and_request_scoped(
        self,
    ) -> None:
        normalize = javascript_function(self.script, "normalizeRouteCapabilities")
        controls = javascript_function(self.script, "renderRouteControls")
        request = javascript_function(self.script, "buildRouteTraceRequest")
        allowed = javascript_function(
            self.script, "steeringProfilesForScenario"
        )
        options = javascript_function(
            self.script, "renderRouteSteeringProfiles"
        )

        self.assertIn('id="mn-route-steering"', self.page)
        self.assertIn("No steering override", self.page)
        self.assertIn("server-advertised counterfactual rules", self.page)
        self.assertIn("firstArray(raw?.steering_profiles)", normalize)
        self.assertIn("profile_id: profileId", normalize)
        self.assertIn("steering_profiles: steeringProfiles", normalize)
        self.assertIn("default_steering_profile:", normalize)
        self.assertIn('const steeringSelect = byId("mn-route-steering")', controls)
        self.assertIn("renderRouteSteeringProfiles(scenario", controls)
        self.assertIn("firstArray(scenario?.steering_profiles)", allowed)
        self.assertIn("advertised.filter", allowed)
        self.assertIn("allowed.has(profile.profile_id)", allowed)
        self.assertIn("select.disabled = !profiles.length", options)
        self.assertIn('\'<option value="">No steering override</option>\'', options)
        self.assertNotIn('profiles[0]?.profile_id || ""', options)
        self.assertIn(
            'const steeringProfileId = byId("mn-route-steering").value',
            request,
        )
        self.assertIn(
            "if (steeringProfileId) request.steering_profile_id = steeringProfileId",
            request,
        )
        self.assertNotIn(
            "steering_profile_id:",
            request[request.index("const request = {") : request.index("if (usesForwardStart)")],
        )

    def test_packet_trace_normalization_preserves_backend_metadata_and_exact_refs(
        self,
    ) -> None:
        layer = javascript_function(self.script, "normalizePacketLayer")
        packet_state = javascript_function(self.script, "normalizePacketState")
        packet_ref = javascript_function(self.script, "packetTransitionRef")
        evaluation = javascript_function(
            self.script,
            "normalizePacketTransitionEvaluation",
        )
        trace = javascript_function(self.script, "normalizePacketTrace")
        path = javascript_function(self.script, "normalizeRoutePath")

        self.assertIn(
            "JSON.stringify([String(pathId), String(stepId), String(transitionId)])",
            packet_ref,
        )
        for backend_field in (
            "layer_id: layerId",
            "contract_id: contractId",
            "label:",
            "fields: normalizePacketFields(layer.fields)",
            "size_bytes: normalizedPacketNumber(layer.size_bytes)",
            "complete:",
        ):
            self.assertIn(backend_field, layer)
        self.assertIn("firstArray(packet.layers)", packet_state)
        self.assertIn("size: normalizePacketSize(packet.size)", packet_state)
        self.assertIn(
            "packet_ref: packetTransitionRef(pathId, stepId, transitionId)",
            evaluation,
        )
        self.assertIn(
            "evaluation.segment_id ?? transitionRaw.segment_id",
            evaluation,
        )
        self.assertIn(
            "candidate.segment_id === sourceStepId",
            evaluation,
        )
        self.assertIn("const stepId = String(step?.step_id || sourceStepId)", evaluation)
        self.assertIn("source_step_id: sourceStepId", evaluation)
        self.assertIn(
            "segment_id: segment?.segment_id || explicitSegmentId || null",
            evaluation,
        )
        for backend_field in (
            "action_contract_id:",
            "action_label:",
            "disposition:",
            "origin:",
            "actor_id:",
            "forced_rule_id:",
            "added_layer_ids:",
            "removed_layer_ids:",
            "changed_layer_ids:",
            "moved_layer_ids:",
            "complete:",
            "outcome:",
            "size_bytes:",
            "limit_bytes:",
            "excess_bytes:",
            "basis_contract_id:",
            "continuity_valid:",
        ):
            self.assertIn(backend_field, evaluation)
        self.assertIn("firstArray(raw.transitions)", trace)
        self.assertIn("step.packet_refs = [...new Set(", trace)
        self.assertIn("segment.packet_refs = [...new Set(", trace)
        self.assertIn("initial_state: normalizePacketState(raw.initial_state", trace)
        self.assertIn("continuity_complete:", trace)
        self.assertIn("counterfactual:", trace)
        self.assertIn(
            "contribution.resource_references.flatMap("
            "packetResourceReferenceTokens)",
            evaluation,
        )
        self.assertIn(
            "contribution.topology_references.flatMap("
            "packetTopologyReferenceTokens)",
            evaluation,
        )
        self.assertIn(
            "normalizePacketTrace(raw?.packet_trace, pathId, steps, segments)",
            path,
        )
        self.assertIn("packet_trace: packetTrace", path)

    def test_packet_rail_is_legacy_safe_and_correlates_preview_pin_step_and_graph(
        self,
    ) -> None:
        render = javascript_function(self.script, "renderRoutePacketEvolution")
        route_render = javascript_function(self.script, "renderRouteTrace")
        preview = javascript_function(self.script, "showRoutePacketPreview")
        detail = javascript_function(self.script, "renderRoutePacketDetail")
        select = javascript_function(self.script, "selectRoutePacketTransition")
        rail_bindings = javascript_function(self.script, "bindRoutePacketElements")
        graph_bindings = javascript_function(
            self.script,
            "bindRoutePacketGraphElements",
        )
        step = javascript_function(self.script, "routeStepMarkup")
        node = javascript_function(self.script, "mapNodeMarkup")
        edges = javascript_function(self.script, "renderEdges")

        for element_id in (
            "mn-route-packet-evolution",
            "mn-route-packet-rail",
            "mn-route-packet-detail",
            "mn-route-packet-preview",
        ):
            self.assertIn(f'id="{element_id}"', self.page)
        self.assertIn("const transitions = packetTransitionsForPath(path)", render)
        self.assertIn("section.hidden = !transitions.length", render)
        no_transitions = render[render.index("if (!transitions.length)") :]
        self.assertIn('rail.innerHTML = ""', no_transitions)
        self.assertIn('status.textContent = ""', no_transitions)
        self.assertIn("renderRoutePacketEvolution(null)", route_render)
        self.assertIn("renderRoutePacketEvolution(selected)", route_render)

        self.assertIn("packetTransitionPreviewMarkup(evaluation)", preview)
        self.assertIn("state.routePacketPreviewRef = packetRef", preview)
        self.assertIn("packetTransitionDetailMarkup(evaluation)", detail)
        self.assertIn("state.routePacketPinnedRef === packetRef", select)
        self.assertIn("renderRoutePacketDetail()", select)
        self.assertIn('element.addEventListener("pointerenter"', rail_bindings)
        self.assertIn(
            'element.addEventListener("click", () => selectRoutePacketTransition',
            rail_bindings,
        )

        self.assertIn('data-route-packet-refs="${packetRefsAttribute(step.packet_refs)}"', step)
        self.assertIn("packetRefsForRouteNode(", node)
        self.assertIn("data-route-packet-refs=", node)
        self.assertIn("packetRefsAttribute(segment.packet_refs)", edges)
        self.assertIn("data-route-packet-refs=", edges)
        self.assertIn('state.routeGraphMode !== "focused"', graph_bindings)
        self.assertIn("if (refs.length !== 1) return", graph_bindings)
        self.assertIn("showRoutePacketPreview(packetRef, element", graph_bindings)
        self.assertIn("selectRoutePacketTransition(packetRef, element)", graph_bindings)
        self.assertIn(".mn-route-packet-preview", self.styles)
        self.assertIn(".mn-route-packet-detail", self.styles)
        self.assertIn(".is-packet-focus", self.styles)

    def test_packet_rendering_is_protocol_neutral_uses_server_mtu_and_clears_first(
        self,
    ) -> None:
        normalize = javascript_function(
            self.script,
            "normalizePacketTransitionEvaluation",
        )
        state_markup = javascript_function(self.script, "packetStateMarkup")
        preview_markup = javascript_function(
            self.script,
            "packetTransitionPreviewMarkup",
        )
        detail_markup = javascript_function(
            self.script,
            "packetTransitionDetailMarkup",
        )
        contribution_markup = javascript_function(
            self.script,
            "packetContributionsMarkup",
        )
        diff_count = javascript_function(self.script, "packetDiffCount")
        diff_markup = javascript_function(self.script, "packetDiffMarkup")
        mtu = javascript_function(self.script, "packetMtuLabel")
        direction = javascript_function(self.script, "selectRouteDirection")
        path = javascript_function(self.script, "selectRoutePath")
        graph_mode = javascript_function(self.script, "setRouteGraphMode")
        invalidate = javascript_function(self.script, "invalidateRouteTraceResult")
        run = javascript_function(self.script, "runRouteTrace")
        controls = javascript_function(self.script, "bindControls")

        protocol_neutral_surface = (
            normalize + state_markup + preview_markup + detail_markup
        ).lower()
        for protocol_name in (
            "ethernet",
            "evpn",
            "ipv4",
            "ipv6",
            "mpls",
            "srv6",
            "vlan",
            "vxlan",
        ):
            self.assertNotIn(protocol_name, protocol_neutral_surface)
        self.assertNotIn(".test(", protocol_neutral_surface)
        self.assertIn('if (outcome === "fits")', mtu)
        self.assertIn('if (outcome === "exceeds")', mtu)
        self.assertIn("mtu.size_bytes", mtu)
        self.assertIn("mtu.limit_bytes", mtu)
        self.assertIn("mtu.excess_bytes", mtu)
        self.assertNotRegex(
            mtu,
            r"(?:size_bytes\s*-\s*limit_bytes|limit_bytes\s*-\s*size_bytes)",
        )
        self.assertNotIn("Math.", mtu)
        self.assertIn("mtuConstraint?.resource", detail_markup)
        self.assertIn("packetResourceReferenceText(", detail_markup)
        self.assertIn(
            "contribution.resource_references.map(",
            contribution_markup,
        )
        self.assertIn(
            "contribution.topology_references.map(",
            contribution_markup,
        )
        self.assertIn("contribution.evidence.map(", contribution_markup)
        self.assertIn("diff.complete === true", diff_count)
        self.assertIn("partial diff", diff_count)
        self.assertIn("diff completeness unknown", diff_count)
        self.assertIn("Structural diff is partial", diff_markup)
        self.assertIn(
            "Structural diff completeness was not declared",
            diff_markup,
        )
        self.assertIn(".mn-route-packet-reference-list", self.styles)
        self.assertIn(".mn-route-packet-evidence-list", self.styles)

        for lifecycle in (direction, path, graph_mode, invalidate, run):
            self.assertIn("clearRoutePacketSelection(", lifecycle)
        self.assertLess(
            direction.index("clearRoutePacketSelection("),
            direction.index("state.activeRouteDirection = direction"),
        )
        self.assertLess(
            run.index("clearRoutePacketSelection("),
            run.index("state.routePending = true"),
        )
        escape = controls[controls.index('document.addEventListener("keydown"') :]
        self.assertIn(
            "if (state.routePacketPinnedRef || state.routePacketPreviewRef)",
            escape,
        )
        self.assertIn(
            "clearRoutePacketSelection({ restoreFocus: true })",
            escape,
        )
        self.assertLess(
            escape.index(
                "if (state.routePacketPinnedRef || state.routePacketPreviewRef)"
            ),
            escape.index("if (state.topologyInspectorKey)"),
        )


if __name__ == "__main__":
    unittest.main()
