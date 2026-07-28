from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any, cast

from router_dump_analyzer.dashboard_core import (
    DashboardDescriptorValidationError,
    dashboard_filter_matches,
    evaluate_dashboards,
)
from tests.support.normalized_data import static_data_service

_PARITY_FIXTURE_PATH = (
    Path(__file__).with_name("fixtures") / "dashboard-evaluator-parity.json"
)


def _dashboard_parity_fixture() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(_PARITY_FIXTURE_PATH.read_text(encoding="utf-8")),
    )


def _parity_recipe_amount(
    recipe: dict[str, Any],
    bounds: dict[str, Any],
) -> int:
    return int(bounds[str(recipe["bound"])]) + int(recipe.get("offset", 0))


def _build_parity_value(
    recipe: dict[str, Any],
    bounds: dict[str, Any],
) -> Any:
    kind = str(recipe["kind"])
    if kind == "literal":
        return recipe.get("value")
    if kind == "signed_zero":
        return -0.0 if recipe.get("negative") is True else 0.0
    if kind == "nonfinite":
        return {
            "nan": float("nan"),
            "positive_infinity": float("inf"),
            "negative_infinity": float("-inf"),
        }[str(recipe["value"])]
    if kind == "bigint_bits":
        bits = _parity_recipe_amount(recipe, bounds)
        return 1 << (bits - 1)
    if kind == "nested_sequence":
        value: Any = None
        for _ in range(_parity_recipe_amount(recipe, bounds)):
            value = [value]
        return value
    if kind == "sequence_items":
        return list(range(_parity_recipe_amount(recipe, bounds)))
    if kind == "mapping_items":
        return {
            f"key-{index}": index
            for index in range(_parity_recipe_amount(recipe, bounds))
        }
    if kind == "comparison_unit_tree":
        target_units = _parity_recipe_amount(recipe, bounds)
        group_count = int(bounds["max_container_items"])
        leaf_count = target_units - 1 - group_count
        if leaf_count < 0 or leaf_count > group_count * 3:
            raise AssertionError("comparison_unit_tree recipe is not representable")
        groups: list[list[int]] = []
        for _ in range(group_count):
            group_size = min(3, leaf_count)
            groups.append([0] * group_size)
            leaf_count -= group_size
        if leaf_count:
            raise AssertionError("comparison_unit_tree recipe left unused units")
        return groups
    if kind == "repeated_string":
        return "x" * _parity_recipe_amount(recipe, bounds)
    if kind == "unsupported":
        return object()
    if kind == "cycle_sequence":
        cycle: list[Any] = []
        cycle.append(cycle)
        return cycle
    raise AssertionError(f"unknown dashboard parity recipe: {kind}")


class DashboardCoreTests(unittest.TestCase):
    def test_field_presence_distinguishes_explicit_null_from_missing(self) -> None:
        rows = [
            {
                "resource_id": "explicit-null",
                "kind": "PLUGIN_KIND",
                "exists": True,
                "status": None,
                "state": {
                    "status": "must-not-shadow-envelope-null",
                    "optional": None,
                },
            },
            {
                "resource_id": "missing",
                "kind": "PLUGIN_KIND",
                "exists": True,
                "status": "ready",
                "state": {},
            },
        ]
        result = evaluate_dashboards(
            [
                {
                    "dashboard_id": "presence-aware",
                    "statistics": [
                        {
                            "statistic_id": "root-null-wins",
                            "aggregation": "count",
                            "filters": [
                                {
                                    "field": "status",
                                    "operator": "eq",
                                    "value": None,
                                }
                            ],
                        },
                        {
                            "statistic_id": "null-equality",
                            "aggregation": "count",
                            "filters": [
                                {
                                    "field": "state.optional",
                                    "operator": "eq",
                                    "value": None,
                                }
                            ],
                        },
                        {
                            "statistic_id": "missing-not-unequal",
                            "aggregation": "count",
                            "filters": [
                                {
                                    "field": "state.optional",
                                    "operator": "not_eq",
                                    "value": "anything",
                                }
                            ],
                        },
                        {
                            "statistic_id": "present-even-when-null",
                            "aggregation": "count",
                            "filters": [
                                {
                                    "field": "state.optional",
                                    "operator": "exists",
                                    "value": True,
                                }
                            ],
                        },
                        {
                            "statistic_id": "exists-defaults-to-present",
                            "aggregation": "count",
                            "filters": [
                                {
                                    "field": "state.optional",
                                    "operator": "exists",
                                }
                            ],
                        },
                        {
                            "statistic_id": "actually-missing",
                            "aggregation": "count",
                            "filters": [
                                {
                                    "field": "state.optional",
                                    "operator": "exists",
                                    "value": False,
                                }
                            ],
                        },
                        {
                            "statistic_id": "null-is-distinct",
                            "aggregation": "count_distinct",
                            "field": "state.optional",
                        },
                    ],
                    "tables": [
                        {
                            "table_id": "presence-projection",
                            "columns": [
                                {
                                    "field": "state.optional",
                                    "label": "Optional",
                                },
                                {
                                    "field": "state.absent",
                                    "label": "Absent",
                                },
                            ],
                        }
                    ],
                }
            ],
            rows,
        )[0]

        statistics = {item["statistic_id"]: item for item in result["statistics"]}
        self.assertEqual(1, statistics["root-null-wins"]["value"])
        self.assertEqual(1, statistics["null-equality"]["value"])
        self.assertEqual(1, statistics["missing-not-unequal"]["value"])
        self.assertEqual(1, statistics["present-even-when-null"]["value"])
        self.assertEqual(1, statistics["exists-defaults-to-present"]["value"])
        self.assertEqual(1, statistics["actually-missing"]["value"])
        self.assertEqual(1, statistics["null-is-distinct"]["value"])
        self.assertEqual(1, statistics["null-is-distinct"]["sample_count"])
        explicit, missing = result["tables"][0]["items"]
        self.assertEqual({"optional": None}, explicit["state"])
        self.assertNotIn("state", missing)

    def test_empty_numeric_sum_remains_zero_with_zero_samples(self) -> None:
        result = evaluate_dashboards(
            [
                {
                    "dashboard_id": "empty-sum",
                    "statistics": [
                        {
                            "statistic_id": "sum",
                            "aggregation": "sum",
                            "field": "state.metric",
                        }
                    ],
                    "tables": [],
                }
            ],
            [
                {
                    "resource_id": "not-numeric",
                    "kind": "PLUGIN_KIND",
                    "exists": True,
                    "state": {"metric": "unknown"},
                }
            ],
        )[0]["statistics"][0]

        self.assertEqual(0, result["value"])
        self.assertEqual(0, result["sample_count"])
        self.assertEqual(1, result["matching_count"])

    def test_unknown_aggregation_is_rejected_before_evaluation(self) -> None:
        with self.assertRaises(DashboardDescriptorValidationError) as raised:
            evaluate_dashboards(
                [
                    {
                        "dashboard_id": "invalid-aggregation",
                        "statistics": [
                            {
                                "statistic_id": "plausible-null",
                                "aggregation": "median",
                                "field": "state.metric",
                            }
                        ],
                        "tables": [],
                    }
                ],
                [],
            )

        self.assertEqual(
            "dashboards[0].statistics[0].aggregation",
            raised.exception.path,
        )
        self.assertEqual(
            "invalid-aggregation",
            raised.exception.dashboard_id,
        )

    def test_raw_table_max_rows_requires_a_bounded_exact_integer(self) -> None:
        for value in ("abc", True, 1.5, 0, 501, None):
            with self.subTest(value=value):
                with self.assertRaises(DashboardDescriptorValidationError) as raised:
                    evaluate_dashboards(
                        [
                            {
                                "dashboard_id": "invalid-table",
                                "statistics": [],
                                "tables": [
                                    {
                                        "table_id": "resources",
                                        "columns": [
                                            {
                                                "field": "label",
                                                "label": "Resource",
                                            }
                                        ],
                                        "max_rows": value,
                                    }
                                ],
                            }
                        ],
                        [],
                    )
                self.assertEqual(
                    "dashboards[0].tables[0].max_rows",
                    raised.exception.path,
                )

    def test_normalized_query_reports_invalid_descriptors_structurally(self) -> None:
        result = static_data_service(
            {
                "demo": {
                    "capture_ns": "0",
                    "revision_id": "test/revision",
                },
                "dashboard_descriptors": [
                    {
                        "dashboard_id": "invalid-table",
                        "statistics": [],
                        "tables": [
                            {
                                "table_id": "resources",
                                "columns": [
                                    {
                                        "field": "label",
                                        "label": "Resource",
                                    }
                                ],
                                "max_rows": "abc",
                            }
                        ],
                    }
                ],
            }
        ).dashboard_query(0)

        self.assertEqual([], result["dashboards"])
        self.assertEqual(0, result["population_count"])
        self.assertEqual(
            [
                {
                    "code": "invalid_dashboard_descriptor",
                    "dashboard_id": "invalid-table",
                    "path": "dashboards[0].tables[0].max_rows",
                    "message": (
                        "dashboard table max_rows must be an integer between 1 and 500"
                    ),
                }
            ],
            result["descriptor_errors"],
        )

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

    def test_mixed_finite_and_nonfinite_mapping_keys_do_not_crash(self) -> None:
        value = {1.5: "finite", float("nan"): "nonfinite"}
        result = evaluate_dashboards(
            [
                {
                    "dashboard_id": "mapping-values",
                    "statistics": [
                        {
                            "statistic_id": "distinct",
                            "aggregation": "count_distinct",
                            "field": "state.value",
                        }
                    ],
                    "tables": [],
                }
            ],
            [
                {
                    "resource_id": "opaque",
                    "kind": "PLUGIN_KIND",
                    "exists": True,
                    "state": {"value": value},
                }
            ],
        )[0]

        self.assertEqual(1, result["statistics"][0]["value"])
        self.assertEqual(1, result["statistics"][0]["sample_count"])

    def test_mapping_equality_preserves_duplicate_canonical_entries(self) -> None:
        first_nan = float("nan")
        second_nan = float("nan")
        single = {first_nan: "value"}
        repeated = {first_nan: "value", second_nan: "value"}
        result = evaluate_dashboards(
            [
                {
                    "dashboard_id": "mapping-multiplicity",
                    "statistics": [
                        {
                            "statistic_id": "single-only",
                            "aggregation": "count",
                            "filters": [
                                {
                                    "field": "state.value",
                                    "operator": "eq",
                                    "value": single,
                                }
                            ],
                        },
                        {
                            "statistic_id": "distinct",
                            "aggregation": "count_distinct",
                            "field": "state.value",
                        },
                    ],
                    "tables": [],
                }
            ],
            [
                {
                    "resource_id": "single",
                    "kind": "PLUGIN_KIND",
                    "exists": True,
                    "state": {"value": single},
                },
                {
                    "resource_id": "repeated",
                    "kind": "PLUGIN_KIND",
                    "exists": True,
                    "state": {"value": repeated},
                },
            ],
        )[0]

        self.assertEqual(1, result["statistics"][0]["value"])
        self.assertEqual(2, result["statistics"][1]["value"])

    def test_cyclic_dashboard_values_are_excluded_fail_closed(self) -> None:
        cyclic: list[object] = []
        cyclic.append(cyclic)
        result = evaluate_dashboards(
            [
                {
                    "dashboard_id": "cyclic-values",
                    "statistics": [
                        {
                            "statistic_id": "matching",
                            "aggregation": "count",
                            "filters": [
                                {
                                    "field": "state.value",
                                    "operator": "not_eq",
                                    "value": "anything",
                                }
                            ],
                        },
                        {
                            "statistic_id": "distinct",
                            "aggregation": "count_distinct",
                            "field": "state.value",
                        },
                    ],
                    "tables": [],
                }
            ],
            [
                {
                    "resource_id": "opaque",
                    "kind": "PLUGIN_KIND",
                    "exists": True,
                    "state": {"value": cyclic},
                }
            ],
        )[0]

        self.assertEqual(0, result["statistics"][0]["value"])
        self.assertEqual(0, result["statistics"][1]["value"])
        self.assertEqual(0, result["statistics"][1]["sample_count"])

    def test_shared_dashboard_evaluator_parity_fixture(self) -> None:
        fixture = _dashboard_parity_fixture()
        self.assertEqual(1, fixture["schema_version"])
        bounds = fixture["bounds"]
        values = {
            str(item["id"]): _build_parity_value(item["recipe"], bounds)
            for item in fixture["values"]
        }

        descriptor = [
            {
                "dashboard_id": "parity",
                "statistics": [
                    {
                        "statistic_id": "distinct",
                        "aggregation": "count_distinct",
                        "field": "state.value",
                    }
                ],
                "tables": [],
            }
        ]
        for item in fixture["values"]:
            with self.subTest(kind="comparable", case=item["id"]):
                statistic = evaluate_dashboards(
                    descriptor,
                    [
                        {
                            "resource_id": "fixture",
                            "kind": "FIXTURE",
                            "exists": True,
                            "state": {"value": values[str(item["id"])]},
                        }
                    ],
                )[0]["statistics"][0]
                self.assertEqual(
                    1 if item["comparable"] else 0,
                    statistic["sample_count"],
                )
                self.assertEqual(
                    1 if item["comparable"] else 0,
                    statistic["value"],
                )

        for case in fixture["equality_cases"]:
            with self.subTest(kind="equality", case=case["id"]):
                actual = values[str(case["left"])]
                expected = values[str(case["right"])]
                self.assertIs(
                    bool(case["equal"]),
                    dashboard_filter_matches(
                        {"state": {"value": actual}},
                        {
                            "field": "state.value",
                            "operator": "eq",
                            "value": expected,
                        },
                    ),
                )

        for case in fixture["filter_cases"]:
            with self.subTest(kind="filter", case=case["id"]):
                state = (
                    {"value": values[str(case["actual"])]}
                    if "actual" in case
                    else {}
                )
                expected = (
                    [values[str(item)] for item in case["candidates"]]
                    if "candidates" in case
                    else values[str(case["expected"])]
                )
                self.assertIs(
                    bool(case["matches"]),
                    dashboard_filter_matches(
                        {"state": state},
                        {
                            "field": "state.value",
                            "operator": case["operator"],
                            "value": expected,
                        },
                    ),
                )

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
        values = {item["statistic_id"]: item["value"] for item in result["statistics"]}

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

    def test_undeclared_precomputed_statistics_are_not_recomputed_by_guessing(
        self,
    ) -> None:
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
