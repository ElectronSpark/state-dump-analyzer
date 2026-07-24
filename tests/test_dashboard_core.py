from __future__ import annotations

import unittest

from router_dump_analyzer.dashboard_core import evaluate_dashboards


class DashboardCoreTests(unittest.TestCase):
    def test_widgets_use_the_full_temporal_population_not_a_visible_page(self) -> None:
        rows = [
            {
                "resource_id": f"opaque-{index}",
                "kind": "PLUGIN_KIND",
                "label": f"row-{index}",
                "exists": index != 4,
                "state": {
                    "condition": "usable" if index % 2 == 0 else "blocked",
                    "metric": index,
                },
            }
            for index in range(5)
        ]
        descriptors = [
            {
                "dashboard_id": "plugin-dashboard",
                "statistics": [
                    {
                        "statistic_id": "usable",
                        "aggregation": "count",
                        "resource_kinds": ["PLUGIN_KIND"],
                        "filters": [
                            {
                                "field": "state.condition",
                                "operator": "eq",
                                "value": "usable",
                            }
                        ],
                    },
                    {
                        "statistic_id": "average",
                        "aggregation": "average",
                        "resource_kinds": ["PLUGIN_KIND"],
                        "field": "state.metric",
                    },
                ],
                "tables": [
                    {
                        "table_id": "bounded-table",
                        "resource_kinds": ["PLUGIN_KIND"],
                        "columns": [{"field": "label", "label": "Resource"}],
                        "max_rows": 2,
                        "sort_field": "state.metric",
                        "sort_direction": "descending",
                    }
                ],
            }
        ]

        result = evaluate_dashboards(descriptors, rows)[0]

        self.assertEqual(2, result["statistics"][0]["value"])
        self.assertEqual(1.5, result["statistics"][1]["value"])
        table = result["tables"][0]
        self.assertEqual(4, table["total_count"])
        self.assertEqual(2, table["returned_count"])
        self.assertTrue(table["truncated"])
        self.assertEqual(
            ["opaque-3", "opaque-2"],
            [item["resource_id"] for item in table["items"]],
        )

    def test_filters_and_distinct_counts_preserve_value_types(self) -> None:
        rows = [
            {
                "resource_id": f"opaque-{index}",
                "kind": "PLUGIN_KIND",
                "exists": True,
                "state": {"value": value},
            }
            for index, value in enumerate((1, "1", True, 1.0))
        ]
        result = evaluate_dashboards(
            [
                {
                    "dashboard_id": "typed-values",
                    "statistics": [
                        {
                            "statistic_id": "integer-only",
                            "aggregation": "count",
                            "filters": [
                                {
                                    "field": "state.value",
                                    "operator": "eq",
                                    "value": 1,
                                }
                            ],
                        },
                        {
                            "statistic_id": "integer-membership",
                            "aggregation": "count",
                            "filters": [
                                {
                                    "field": "state.value",
                                    "operator": "in",
                                    "value": [1],
                                }
                            ],
                        },
                        {
                            "statistic_id": "typed-distinct",
                            "aggregation": "count_distinct",
                            "field": "state.value",
                        },
                    ],
                    "tables": [],
                }
            ],
            rows,
        )[0]

        self.assertEqual(1, result["statistics"][0]["value"])
        self.assertEqual(1, result["statistics"][1]["value"])
        self.assertEqual(4, result["statistics"][2]["value"])

    def test_unknown_existence_is_not_present_unless_absent_rows_are_requested(
        self,
    ) -> None:
        rows = [
            {
                "resource_id": f"opaque-{exists}",
                "kind": "PLUGIN_KIND",
                "exists": exists,
            }
            for exists in (True, False, None)
        ]
        result = evaluate_dashboards(
            [
                {
                    "dashboard_id": "presence",
                    "statistics": [
                        {
                            "statistic_id": "present-only",
                            "aggregation": "count",
                        },
                        {
                            "statistic_id": "all-existence-states",
                            "aggregation": "count",
                            "include_absent": True,
                        },
                    ],
                    "tables": [],
                }
            ],
            rows,
        )[0]

        self.assertEqual(1, result["statistics"][0]["value"])
        self.assertEqual(3, result["statistics"][1]["value"])

    def test_integer_aggregates_do_not_round_through_binary_float(self) -> None:
        lower = 9_007_199_254_740_993
        upper = 9_007_199_254_740_997
        rows = [
            {
                "resource_id": f"opaque-{index}",
                "kind": "PLUGIN_KIND",
                "exists": True,
                "state": {"counter": value},
            }
            for index, value in enumerate((lower, upper))
        ]
        result = evaluate_dashboards(
            [
                {
                    "dashboard_id": "precise-counters",
                    "statistics": [
                        {
                            "statistic_id": aggregation,
                            "aggregation": aggregation,
                            "field": "state.counter",
                        }
                        for aggregation in (
                            "sum",
                            "average",
                            "minimum",
                            "maximum",
                        )
                    ],
                    "tables": [],
                }
            ],
            rows,
        )[0]
        values = {
            item["statistic_id"]: item["value"]
            for item in result["statistics"]
        }

        self.assertEqual(lower + upper, values["sum"])
        self.assertIsInstance(values["sum"], int)
        self.assertEqual((lower + upper) // 2, values["average"])
        self.assertIsInstance(values["average"], int)
        self.assertEqual(lower, values["minimum"])
        self.assertEqual(upper, values["maximum"])

    def test_tables_project_only_the_envelope_and_declared_columns(self) -> None:
        row = {
            "resource_id": "opaque-resource",
            "kind": "PLUGIN_KIND",
            "layer": "plugin-layer",
            "label": "Visible resource",
            "exists": True,
            "status": "ready",
            "status_class": "healthy",
            "valid_from_ns": "100",
            "valid_to_ns": None,
            "source_event_uid": "event-1",
            "quality": "exact",
            "state": {
                "declared": "visible",
                "private_detail": "must-not-leak",
            },
            "key": {
                "declared_id": 7,
                "private_key_part": "must-not-leak",
            },
            "resource": {
                "raw_payload": "must-not-leak",
                "state": {"other": "must-not-leak"},
            },
            "internal_cache": {"must": "not-leak"},
        }
        table = evaluate_dashboards(
            [
                {
                    "dashboard_id": "projected-table",
                    "statistics": [],
                    "tables": [
                        {
                            "table_id": "resources",
                            "columns": [
                                {"field": "label", "label": "Resource"},
                                {
                                    "field": "state.declared",
                                    "label": "Declared state",
                                },
                                {
                                    "field": "key.declared_id",
                                    "label": "Declared key",
                                },
                            ],
                        }
                    ],
                }
            ],
            [row],
        )[0]["tables"][0]

        self.assertEqual(
            {
                "resource_id": "opaque-resource",
                "kind": "PLUGIN_KIND",
                "layer": "plugin-layer",
                "label": "Visible resource",
                "exists": True,
                "status": "ready",
                "status_class": "healthy",
                "valid_from_ns": "100",
                "valid_to_ns": None,
                "source_event_uid": "event-1",
                "quality": "exact",
                "state": {"declared": "visible"},
                "key": {"declared_id": 7},
            },
            table["items"][0],
        )
        self.assertNotIn("resource", table["items"][0])
        self.assertNotIn("internal_cache", table["items"][0])

    def test_undeclared_precomputed_statistics_are_not_recomputed_by_guessing(self) -> None:
        result = evaluate_dashboards(
            [
                {
                    "dashboard_id": "plugin-dashboard",
                    "statistics": [
                        {
                            "statistic_id": "plugin-owned",
                            "aggregation": "precomputed",
                            "scale_metric": "opaque.path",
                        }
                    ],
                    "tables": [],
                }
            ],
            [],
        )[0]

        self.assertEqual([], result["statistics"])


if __name__ == "__main__":
    unittest.main()
