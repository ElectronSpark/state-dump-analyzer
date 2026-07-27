from __future__ import annotations

import unittest

from router_dump_analyzer.normalized_data import overlaps_range
from router_dump_analyzer.web.runtime_api import _overlaps_window


class TemporalBoundaryTests(unittest.TestCase):
    def test_state_intervals_use_half_open_intersection(self) -> None:
        self.assertFalse(overlaps_range(0, 10, 10, 20))
        self.assertFalse(overlaps_range(20, 30, 10, 20))
        self.assertTrue(overlaps_range(0, 11, 10, 20))
        self.assertTrue(overlaps_range(19, 30, 10, 20))
        self.assertTrue(overlaps_range(None, None, 10, 20))
        self.assertFalse(_overlaps_window(0, 10, 10, 20))
        self.assertFalse(_overlaps_window(20, 30, 10, 20))


if __name__ == "__main__":
    unittest.main()
