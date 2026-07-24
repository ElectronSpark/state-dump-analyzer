from __future__ import annotations

import re
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from router_dump_analyzer import demo_app
from router_dump_analyzer.demo_data import REVISION_ID


ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "frontend" / "assets" / "app.js"
STYLES_CSS = ROOT / "frontend" / "assets" / "styles.css"


def javascript_function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    match = re.search(r"\nfunction [A-Za-z0-9_$]+\(", source[start + 1 :])
    return source[start:] if match is None else source[start : start + 1 + match.start()]


class TimelineClusterDetailTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resource_id = "opaque-resource-1"
        self.dataset = {
            "demo": {"timeline_start_ns": "0", "timeline_end_ns": "100"},
            "kind_descriptors": [],
            "resources": [
                {
                    "resource_id": self.resource_id,
                    "kind": "PLUGIN_KIND",
                    "layer": "plugin-layer",
                    "key": {},
                    "state": {},
                }
            ],
            "events": [
                {
                    "event_uid": f"event-{index}",
                    "timestamp_ns": str(index * 10),
                    "event_type": "plugin.event",
                    "outcome": "success",
                    "state_changed": True,
                    "affected_resources": [self.resource_id],
                    "effects": [
                        {
                            "resource_id": self.resource_id,
                            "kind": "PLUGIN_KIND",
                            "effect_type": "modified",
                            "state_changed": True,
                        }
                    ],
                }
                for index in range(6)
            ],
        }

    def test_cluster_detail_pages_exact_events_without_losing_total(self) -> None:
        with patch.object(demo_app, "load_demo_dataset", return_value=self.dataset), patch.object(
            demo_app, "scale_runtime", return_value=None
        ):
            first = demo_app.timeline_cluster_detail(
                REVISION_ID,
                {
                    "resource_id": self.resource_id,
                    "start_ns": "0",
                    "end_ns": "50",
                    "offset": 0,
                    "limit": 2,
                },
            )
            second = demo_app.timeline_cluster_detail(
                REVISION_ID,
                {
                    "resource_id": self.resource_id,
                    "start_ns": "0",
                    "end_ns": "50",
                    "offset": first["next_offset"],
                    "limit": 4,
                },
            )

        self.assertEqual(6, first["total_count"])
        self.assertEqual(["event-0", "event-1"], [item["event_uid"] for item in first["items"]])
        self.assertEqual(2, first["next_offset"])
        self.assertEqual(["event-2", "event-3", "event-4", "event-5"], [item["event_uid"] for item in second["items"]])
        self.assertIsNone(second["next_offset"])

    def test_cluster_detail_requires_a_canonical_string_resource_id(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            demo_app.timeline_cluster_detail(
                REVISION_ID,
                {"resource_id": {"typed": "object"}},
            )

        self.assertEqual(422, raised.exception.status_code)


class TimelineClusterDetailFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = APP_JS.read_text(encoding="utf-8")
        cls.styles = STYLES_CSS.read_text(encoding="utf-8")

    def test_normalized_server_cluster_retains_paging_metadata(self) -> None:
        normalize = javascript_function(self.script, "normalizeCluster")

        self.assertIn('typeof raw?.detail_truncated === "boolean"', normalize)
        self.assertIn("detailTruncated: Boolean(raw?.detail_truncated)", normalize)
        self.assertIn("detailHydrated: false", normalize)
        self.assertIn("detailNextOffset: null", normalize)
        self.assertIn("detailRequestId: 0", normalize)

    def test_detail_request_is_revision_scoped_bounded_and_stale_safe(self) -> None:
        available = javascript_function(self.script, "clusterDetailRequestAvailable")
        request = javascript_function(self.script, "requestClusterDetail")

        self.assertIn("!isTopologyNodeSnapshot()", available)
        self.assertIn('revisionPath("timeline/clusters/detail")', request)
        self.assertIn("resource_id: lane.resourceId", request)
        self.assertIn("start_ns: cluster.startNs.toString()", request)
        self.assertIn("end_ns: cluster.endNs.toString()", request)
        self.assertIn("limit: CLUSTER_DETAIL_PAGE_SIZE", request)
        self.assertIn("requestId !== cluster.detailRequestId", request)
        self.assertIn("new Set([...cluster.eventUids", request)
        self.assertIn("payload.next_offset", request)
        self.assertIn("Boolean(payload.truncated)", request)

    def test_hover_replaces_preview_with_scrollable_exact_pages(self) -> None:
        markup = javascript_function(self.script, "clusterHoverHtml")
        show = javascript_function(self.script, "showHover")

        self.assertIn("cluster.detailHydrated ? cluster.detailItems : preview", markup)
        self.assertNotIn("slice(0, 40)", markup)
        self.assertIn("data-cluster-detail-offset", markup)
        self.assertIn("Load more events", markup)
        self.assertIn("requestClusterDetail(key, model.cluster, model.lane, 0)", show)
        self.assertRegex(self.styles, r"\.cluster-window\s*\{[^}]*overflow-y:\s*auto")

    def test_specific_hydrated_event_keeps_ctrl_click_log_jump(self) -> None:
        bindings = javascript_function(self.script, "bindHoverCardActions")

        self.assertIn('card.querySelectorAll("[data-cluster-event-uid]")', bindings)
        self.assertIn("event.ctrlKey || event.metaKey", bindings)
        self.assertIn("jumpToNormalizedLog(button.dataset.clusterEventUid", bindings)
        self.assertIn("selectEvent(button.dataset.clusterEventUid", bindings)


if __name__ == "__main__":
    unittest.main()
