from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "demo" / "frontend" / "assets" / "app.js"
APP_CSS = ROOT / "demo" / "frontend" / "assets" / "styles.css"
TOPOLOGY_JS = ROOT / "demo" / "frontend" / "assets" / "topology.js"
TOPOLOGY_CSS = ROOT / "demo" / "frontend" / "assets" / "topology.css"
TOPOLOGY_HTML = ROOT / "demo" / "frontend" / "pages" / "topology.html"


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

        self.assertIn("routeEndpointSeedValue(explicitFlowSource", seed)
        self.assertIn("routeEndpointSeedValue(explicitFlowDestination", seed)
        self.assertIn('setRouteEndpointInput("destination", destination)', seed)
        self.assertIn("setRouteStartInput(start)", seed)
        self.assertIn("routeStartSeedValue(startDescriptor, entry.node_id)", seed)
        self.assertNotIn("`start:${entry.node_id}`", seed)

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
        self.assertIn("nodeBoundaryPoint(sourceCenter, control, sourceBox)", geometry)
        self.assertIn("nodeBoundaryPoint(targetCenter, control, targetBox)", geometry)
        self.assertIn("Q ${control.x} ${control.y}", geometry)

        for renderer in (topology, focused_route, all_routes):
            self.assertIn("curvedEdgeGeometry(", renderer)
            self.assertIn('d="${geometry.d}"', renderer)
        self.assertGreaterEqual(topology.count('d="${geometry.d}"'), 6)
        self.assertGreaterEqual(focused_route.count('d="${geometry.d}"'), 3)
        self.assertGreaterEqual(all_routes.count('d="${geometry.d}"'), 2)
        self.assertIn("quadraticEdgePoint(geometry, pathPosition)", attachments)
        self.assertIn("quadraticEdgePoint(geometry, 0.5)", topology)
        self.assertIn("quadraticEdgePoint(geometry, 0.5)", boundary_tag)
        self.assertIn("requestAnimationFrame(redraw)", viewport)
        self.assertIn("graphWorldLayers(stage).forEach", transform)
        self.assertIn('layer.style.transform = transform', transform)

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
        self.assertIn("select.disabled = profiles.length <= 1", options)
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
