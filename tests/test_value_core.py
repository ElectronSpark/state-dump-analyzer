from __future__ import annotations

import unittest

from router_dump_analyzer.value_core import (
    CanonicalIntegerError,
    CanonicalIntegerErrorReason,
    parse_canonical_decimal_integer,
    parse_decimal_integer,
)


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
            "01",
            "-0",
            "-01",
            " 1",
            "0x10",
            "１２",
            "١٢",
            "-１２",
            None,
        ):
            with self.subTest(value=value), self.assertRaisesRegex(
                ValueError,
                "value must be an integer or decimal integer string",
            ):
                parse_decimal_integer(value, "value")

    def test_canonical_parser_applies_domain_bounds_without_widening_grammar(
        self,
    ) -> None:
        self.assertEqual(
            255,
            parse_canonical_decimal_integer(
                "255",
                "value",
                minimum=0,
                maximum=255,
                max_bits=8,
            ),
        )
        for value in ("01", "-0", True, 1.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_canonical_decimal_integer(value, "value")
        with self.assertRaisesRegex(ValueError, "at least 0"):
            parse_canonical_decimal_integer(-1, "value", minimum=0)
        with self.assertRaisesRegex(ValueError, "no greater than 255"):
            parse_canonical_decimal_integer(256, "value", maximum=255)

    def test_canonical_parser_exposes_closed_failure_reasons(self) -> None:
        cases = (
            (
                "01",
                {},
                CanonicalIntegerErrorReason.GRAMMAR,
            ),
            (
                -1,
                {"minimum": 0},
                CanonicalIntegerErrorReason.BELOW_MINIMUM,
            ),
            (
                256,
                {"maximum": 255},
                CanonicalIntegerErrorReason.ABOVE_MAXIMUM,
            ),
            (
                256,
                {"max_bits": 8},
                CanonicalIntegerErrorReason.BIT_LIMIT,
            ),
        )
        for value, options, expected_reason in cases:
            with self.subTest(value=value, reason=expected_reason):
                with self.assertRaises(CanonicalIntegerError) as raised:
                    parse_canonical_decimal_integer(value, "value", **options)
                self.assertEqual(raised.exception.field, "value")
                self.assertIs(raised.exception.reason, expected_reason)


if __name__ == "__main__":
    unittest.main()
