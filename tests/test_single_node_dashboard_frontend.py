from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "frontend" / "assets" / "app.js"
VIEW_MODELS_JS = ROOT / "frontend" / "assets" / "view_models.js"


def javascript_function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    match = re.search(r"\nfunction [A-Za-z0-9_$]+\(", source[start + 1 :])
    return source[start:] if match is None else source[start : start + 1 + match.start()]


class SingleNodeDashboardFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = APP_JS.read_text(encoding="utf-8")
        cls.view_models = VIEW_MODELS_JS.read_text(encoding="utf-8")

    def test_node_snapshot_range_summary_never_uses_global_revision(self) -> None:
        request = javascript_function(self.script, "requestRangeSummary")

        self.assertIn("if (isTopologyNodeSnapshot())", request)
        self.assertIn("state.rangeSummary = localRangeSummary()", request)
        self.assertLess(
            request.index("if (isTopologyNodeSnapshot())"),
            request.index('api(revisionPath("range/summary")'),
        )

    def test_node_snapshot_route_requires_explicit_node_scoped_plugin_payload(self) -> None:
        local = javascript_function(self.script, "localNodeRouteResponse")
        resolve = javascript_function(self.script, "resolveRoute")

        self.assertIn('capability.scope !== "node"', local)
        self.assertIn("capability.plugin_defined !== true", local)
        self.assertIn("capability.node_id", local)
        self.assertIn("request.route_id", local)
        self.assertIn("request.basis_kind", local)
        self.assertIn("request.time_ns", local)
        self.assertIn("if (isTopologyNodeSnapshot())", resolve)
        self.assertIn("Route resolution was not supplied", resolve)
        self.assertIn("global revision resolver", resolve)
        self.assertLess(
            resolve.index("if (isTopologyNodeSnapshot())"),
            resolve.index('api(revisionPath("routes/resolve")'),
        )

    def test_dashboard_request_is_separate_temporal_authoritative_query(self) -> None:
        request = javascript_function(self.script, "requestDashboards")
        ids = javascript_function(self.script, "dashboardQueryIds")
        cursor = javascript_function(self.script, "setCursor")
        schedule = javascript_function(self.script, "scheduleTemporalRefresh")

        self.assertIn("state.dashboardRequestId", request)
        self.assertGreaterEqual(
            request.count("if (requestId !== state.dashboardRequestId) return;"),
            2,
        )
        self.assertIn('revisionPath("dashboards/query")', request)
        self.assertIn("time_ns: requestedTimeNs.toString()", request)
        self.assertIn("dashboard_ids: dashboardIds", request)
        self.assertLess(
            request.index("if (isTopologyNodeSnapshot())"),
            request.index('analysisRuntimeApi(revisionPath("dashboards/query")'),
        )
        self.assertIn("state.openDashboardIds.has", ids)
        self.assertIn("dashboardNeedsPointInTimeQuery", ids)
        self.assertIn("markDashboardsPending(state.cursorNs)", cursor)
        self.assertNotIn("renderPluginDashboards()", cursor)
        self.assertIn("requestDashboards()", schedule)
        self.assertLess(
            request.index("markDashboardsPending(requestedTimeNs)"),
            request.index("if (isTopologyNodeSnapshot())"),
        )
        self.assertNotIn(
            "renderPluginDashboards()",
            request[
                request.index("markDashboardsPending(requestedTimeNs)")
                : request.index("if (isTopologyNodeSnapshot())")
            ],
        )

    def test_resource_requests_do_not_invalidate_dashboard_bodies(self) -> None:
        request = javascript_function(self.script, "requestResources")
        refresh = javascript_function(self.script, "refreshDashboardTimePresentation")
        select_resource = javascript_function(self.script, "selectResource")

        self.assertNotIn("renderPluginDashboards()", request)
        self.assertIn('modules.setAttribute("aria-busy", String(state.dashboardPending))', refresh)
        self.assertIn('byId("dashboard-time-status")', refresh)
        self.assertIn("refreshDashboardSelectionPresentation()", select_resource)
        self.assertNotIn("renderPluginDashboards()", select_resource)

    def test_dashboard_rendering_does_not_use_bounded_resource_query_population(self) -> None:
        rows = javascript_function(self.script, "dashboardResourceRows")
        statistic = javascript_function(self.script, "dashboardStatisticResult")
        table = javascript_function(self.script, "renderDashboardTable")
        render = javascript_function(self.script, "renderPluginDashboards")

        self.assertIn("if (!isTopologyNodeSnapshot()) return []", rows)
        self.assertIn("state.dataset?.resources", rows)
        self.assertNotIn("fallbackResourceItems", rows)
        self.assertNotIn("state.resourceQuery", rows)
        self.assertIn("dashboardFieldValue,", self.script)
        self.assertIn("dashboardFilterMatches,", self.script)
        self.assertIn("dashboardRowIncluded,", self.script)
        self.assertIn("dashboardStatisticEvaluation,", self.script)
        self.assertIn('from "./view_models.js"', self.script)
        self.assertIn("dashboardResultFor(dashboardId)", statistic)
        self.assertIn('source: "authoritative_query"', statistic)
        self.assertIn('source: "plugin_precomputed"', statistic)
        self.assertIn("dashboardStatisticEvaluation(rows, descriptor)", statistic)
        self.assertIn("dashboardResultFor(dashboardId)", table)
        self.assertIn("result.total_count", table)
        self.assertIn("result.truncated", table)
        self.assertIn("descriptor.filters", table)
        self.assertIn("dashboardFilterMatches(item, filter)", table)
        self.assertIn("state.dashboardPending", render)
        self.assertNotIn("state.resourcePending", render)

    def test_dashboard_existence_and_descriptor_errors_are_not_optimistic_or_hidden(self) -> None:
        rows = javascript_function(self.script, "dashboardResourceRows")
        render = javascript_function(self.script, "renderPluginDashboards")

        self.assertIn("dashboardRowIncluded(item, resourceKinds, includeAbsent)", rows)
        self.assertIn("item.exists === true ? true : item.exists === false ? false : null", rows)
        self.assertIn("state.dashboardQueryError", render)
        self.assertIn('class="empty-state dashboard-query-error" role="alert"', render)
        self.assertIn("Dashboard descriptor unavailable", render)

    def test_precomputed_statistics_are_not_mislabelled_point_in_time(self) -> None:
        render = javascript_function(self.script, "renderDashboardStatistic")

        self.assertIn("Plug-in-precomputed archive metric", render)
        self.assertIn("not point-in-time", render)
        self.assertIn("dashboardTimeSummary()", render)

    def test_dashboard_open_close_requeries_only_open_modules(self) -> None:
        toggle = javascript_function(self.script, "toggleDashboardOpen")
        reset = javascript_function(self.script, "resetDashboardLayout")

        self.assertIn("requestDashboards()", toggle)
        self.assertIn("requestDashboards()", reset)


if __name__ == "__main__":
    unittest.main()
