from __future__ import annotations

import unittest
from dataclasses import fields

from router_dump_analyzer.plugin_api import (
    ConditionClass,
    SnapshotObservation,
    StateMutation,
)


class ConditionContractTests(unittest.TestCase):
    def test_plugins_supply_normalized_condition_classes(self) -> None:
        self.assertEqual(
            {"healthy", "degraded", "error", "absent", "unknown"},
            {item.value for item in ConditionClass},
        )
        self.assertIn("condition", {item.name for item in fields(SnapshotObservation)})
        self.assertIn(
            "condition_class", {item.name for item in fields(SnapshotObservation)}
        )
        self.assertIn("condition", {item.name for item in fields(StateMutation)})
        self.assertIn(
            "condition_class", {item.name for item in fields(StateMutation)}
        )


if __name__ == "__main__":
    unittest.main()
