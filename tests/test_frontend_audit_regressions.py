from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "frontend" / "assets" / "app.js"
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


class TopologyAuditRegressionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = TOPOLOGY_JS.read_text(encoding="utf-8")
        cls.styles = TOPOLOGY_CSS.read_text(encoding="utf-8")
        cls.page = TOPOLOGY_HTML.read_text(encoding="utf-8")

    def test_health_uses_exact_normalized_status_classes_and_unknown_is_not_green(self) -> None:
        node = javascript_function(self.script, "nodeHealth")
        link = javascript_function(self.script, "linkHealth")

        for declaration in (
            "const HEALTH_ERROR_VALUES = new Set",
            "const HEALTH_WARNING_VALUES = new Set",
            "const HEALTH_GOOD_VALUES = new Set",
        ):
            self.assertIn(declaration, self.script)
        self.assertIn("node?.resource_previews || node?.resources", node)
        self.assertIn("HEALTH_ERROR_VALUES.has(value)", node)
        self.assertIn("HEALTH_WARNING_VALUES.has(value)", node)
        self.assertIn("HEALTH_GOOD_VALUES.has(value)", node)
        self.assertIn('return "warning"', node)
        self.assertNotIn(".test(", node)
        self.assertIn("HEALTH_ERROR_VALUES.has(value)", link)
        self.assertIn("HEALTH_WARNING_VALUES.has(value)", link)
        self.assertIn("HEALTH_GOOD_VALUES.has(value)", link)
        self.assertIn('return "warning"', link)
        self.assertNotIn(".test(", link)

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

    def test_route_table_seeds_trace_with_routable_value_before_opaque_id(self) -> None:
        seed = javascript_function(self.script, "useRouteTableEntry")

        self.assertIn("query.destination?.value || entry.destination?.value", seed)
        self.assertIn(
            "query.destination_id || entry.destination?.destination_id || entry.prefix",
            seed,
        )
        self.assertIn('setRouteEndpointInput("destination", destination)', seed)
        self.assertLess(
            seed.index("query.destination?.value || entry.destination?.value"),
            seed.index("query.destination_id || entry.destination?.destination_id"),
        )

    def test_route_table_request_uses_one_node_scope_selector(self) -> None:
        query = javascript_function(self.script, "queryRouteTables")

        self.assertIn("const nodeQueries = firstArray(query.request.node_queries)", query)
        self.assertIn("if (nodeQueries.length) body.node_queries = nodeQueries", query)
        self.assertIn("else body.node_ids = query.nodes.map", query)
        body_literal = query[query.index("const body = {") : query.index("const failures")]
        self.assertNotIn("node_queries:", body_literal)
        self.assertNotIn("node_ids:", body_literal)

    def test_vpn_suggestion_uses_declared_projection_role_only(self) -> None:
        render = javascript_function(self.script, "renderLinkStatusMap")
        vpn_section = render[render.index("const evpnProfile") :]

        self.assertIn('profile.projection_role === "evpn"', vpn_section)
        self.assertNotIn(".test(", vpn_section)
        self.assertNotIn(".includes(", vpn_section)
        self.assertIn("VPN identity must come from a device plug-in", vpn_section)

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

    def test_policy_blocked_and_split_horizon_are_not_generic_drops(self) -> None:
        normalize = javascript_function(self.script, "normalizeRoutePath")
        decision = javascript_function(self.script, "normalizeRoutePolicyDecision")
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
        self.assertIn("segment?.policy_decision_refs", blocked_segment)
        self.assertIn("path?.cycle?.repeated_state", diagnostics)
        self.assertIn('code: "cycle"', direction)
        self.assertIn('code: "policy_blocked"', direction)
        self.assertIn("Split horizon blocked", badges)
        self.assertIn("Blocked by split horizon", summary)
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


if __name__ == "__main__":
    unittest.main()
