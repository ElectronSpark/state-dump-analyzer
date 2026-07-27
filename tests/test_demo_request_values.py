from __future__ import annotations

import unittest

from fastapi import HTTPException

from router_dump_analyzer.web.runtime_api import _body_integer


class DemoBodyIntegerTests(unittest.TestCase):
    def test_accepts_shared_decimal_forms_and_missing_field_default(self) -> None:
        self.assertEqual(7, _body_integer({}, "limit", 7))
        self.assertEqual(8, _body_integer({"limit": 8}, "limit", 7))
        self.assertEqual(9, _body_integer({"limit": "9"}, "limit", 7))
        self.assertEqual(-9, _body_integer({"limit": "-9"}, "limit", 7))

    def test_rejects_ambiguous_values_with_the_existing_http_contract(self) -> None:
        for value in (None, True, 1.5, "", "-", "+1", " 1", "0x10"):
            with self.subTest(value=value):
                with self.assertRaises(HTTPException) as caught:
                    _body_integer({"limit": value}, "limit", 7)
                self.assertEqual(422, caught.exception.status_code)
                self.assertEqual(
                    "limit must be an integer or decimal integer string",
                    caught.exception.detail,
                )

    def test_applies_endpoint_specific_bounds_after_shared_parsing(self) -> None:
        with self.assertRaises(HTTPException) as below:
            _body_integer({"limit": "0"}, "limit", 7, minimum=1)
        self.assertEqual(422, below.exception.status_code)
        self.assertEqual("limit must be at least 1", below.exception.detail)

        with self.assertRaises(HTTPException) as above:
            _body_integer({"limit": "11"}, "limit", 7, maximum=10)
        self.assertEqual(422, above.exception.status_code)
        self.assertEqual("limit must be at most 10", above.exception.detail)


if __name__ == "__main__":
    unittest.main()
