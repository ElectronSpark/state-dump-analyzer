from __future__ import annotations

import unittest

from router_dump_analyzer.value_core import parse_decimal_integer


class DecimalIntegerTests(unittest.TestCase):
    def test_accepts_integer_and_decimal_string_forms(self) -> None:
        self.assertEqual(42, parse_decimal_integer(42, "value"))
        self.assertEqual(42, parse_decimal_integer("42", "value"))
        self.assertEqual(-42, parse_decimal_integer("-42", "value"))

    def test_rejects_python_specific_or_ambiguous_forms(self) -> None:
        for value in (
            True,
            1.5,
            "",
            "-",
            "+1",
            " 1",
            "0x10",
            "１２",
            "١٢",
            "-１２",
            None,
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError,
                    "value must be an integer or decimal integer string",
                ):
                    parse_decimal_integer(value, "value")


if __name__ == "__main__":
    unittest.main()
