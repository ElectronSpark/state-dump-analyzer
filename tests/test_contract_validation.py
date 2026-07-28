from __future__ import annotations

import unittest
from collections import UserDict
from enum import StrEnum
from types import MappingProxyType

from router_dump_analyzer.contract_validation import (
    bounded_mapping,
    bounded_string,
    coerce_enum,
    strict_boolean,
    strict_integer,
    typed_tuple,
    validate_bounded_json_value,
    validity_bounds,
)


class _Mode(StrEnum):
    ONE = "one"
    TWO = "two"


class _IntegerSubclass(int):
    pass


class ContractValidationTests(unittest.TestCase):
    def test_strict_scalars_do_not_coerce_adjacent_types(self) -> None:
        self.assertEqual(bounded_string("name", "field"), "name")
        self.assertEqual(strict_integer(7, "count", minimum=0), 7)
        self.assertTrue(strict_boolean(True, "enabled"))
        with self.assertRaises(ValueError):
            bounded_string(7, "field")
        with self.assertRaises(ValueError):
            strict_integer(True, "count")
        with self.assertRaises(ValueError):
            strict_boolean(1, "enabled")

    def test_bounded_mapping_rejects_coercion_and_unbounded_iteration(
        self,
    ) -> None:
        self.assertEqual(
            bounded_mapping({"role": "external"}, "semantics"),
            {"role": "external"},
        )
        self.assertEqual(
            bounded_mapping(None, "semantics", allow_none=True),
            {},
        )
        for invalid in (
            [("role", "external")],
            {1: "external"},
            {"": "external"},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                bounded_mapping(invalid, "semantics")
        with self.assertRaisesRegex(ValueError, "at most 1"):
            bounded_mapping(
                {"one": 1, "two": 2},
                "semantics",
                maximum_items=1,
            )

    def test_bounded_json_value_is_strict_recursive_and_cycle_safe(
        self,
    ) -> None:
        validate_bounded_json_value(
            {
                "null": None,
                "bool": True,
                "integer": 7,
                "float": 1.25,
                "string": "value",
                "array": [1, {"nested": "value"}],
                "tuple_encoded_as_array": ("one", "two"),
            },
            "semantics",
        )

        cyclic: list[object] = []
        cyclic.append(cyclic)
        invalid_values = (
            b"not-json",
            object(),
            float("nan"),
            float("inf"),
            {1: "non-string-key"},
            {"nested": UserDict({"value": 1})},
            {"nested": MappingProxyType({"value": 1})},
            cyclic,
        )
        for invalid in invalid_values:
            with self.subTest(
                invalid=type(invalid).__name__
            ), self.assertRaises(ValueError):
                validate_bounded_json_value(invalid, "semantics")

        with self.assertRaisesRegex(ValueError, "at most 2"):
            validate_bounded_json_value(
                [1, 2, 3],
                "semantics",
                maximum_container_items=2,
            )
        with self.assertRaisesRegex(ValueError, "value units"):
            validate_bounded_json_value(
                [[1], [2]],
                "semantics",
                maximum_units=3,
            )

    def test_integer_subclass_compatibility_is_explicit(self) -> None:
        value = _IntegerSubclass(7)
        with self.assertRaises(ValueError):
            strict_integer(value, "count")
        self.assertIs(
            strict_integer(value, "count", exact=False),
            value,
        )

    def test_enum_tuple_and_bounds_share_fail_closed_semantics(self) -> None:
        self.assertIs(coerce_enum(_Mode, "one", "mode"), _Mode.ONE)
        self.assertEqual(
            typed_tuple(
                ("a", "b"),
                "names",
                str,
                minimum=1,
                unique_key=lambda item: item,
            ),
            ("a", "b"),
        )
        self.assertEqual(validity_bounds(10, 20, "window"), (10, 20))
        self.assertEqual(
            validity_bounds(None, None, "window"),
            (None, None),
        )
        with self.assertRaises(ValueError):
            coerce_enum(_Mode, "three", "mode")
        with self.assertRaises(ValueError):
            typed_tuple(("a", "a"), "names", str, unique_key=lambda item: item)
        with self.assertRaises(ValueError):
            validity_bounds(20, 10, "window")
        with self.assertRaises(ValueError):
            validity_bounds(10, None, "window")

    def test_partial_validity_bounds_preserve_one_sided_contract_windows(
        self,
    ) -> None:
        self.assertEqual(
            validity_bounds(
                10,
                None,
                "window",
                allow_partial=True,
            ),
            (10, None),
        )
        self.assertEqual(
            validity_bounds(
                None,
                20,
                "window",
                allow_partial=True,
            ),
            (None, 20),
        )
        with self.assertRaisesRegex(ValueError, "custom lower"):
            validity_bounds(
                True,
                None,
                "window",
                allow_partial=True,
                minimum_type_message="custom lower",
            )

    def test_custom_messages_do_not_weaken_strict_checks(self) -> None:
        with self.assertRaisesRegex(ValueError, "bounded count"):
            strict_integer(
                True,
                "count",
                minimum=0,
                message="bounded count",
            )
        with self.assertRaisesRegex(ValueError, "declared values"):
            typed_tuple(
                [1],
                "values",
                int,
                tuple_message="declared values",
            )
        with self.assertRaisesRegex(ValueError, "supported mode"):
            coerce_enum(
                _Mode,
                "three",
                "mode",
                message="supported mode",
            )

    def test_invalid_combinator_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "string bounds"):
            bounded_string("value", "field", minimum=2, maximum=1)
        with self.assertRaisesRegex(ValueError, "integer bounds"):
            strict_integer(1, "field", minimum=2, maximum=1)
        with self.assertRaisesRegex(ValueError, "tuple bounds"):
            typed_tuple((), "field", str, minimum=2, maximum=1)
        with self.assertRaisesRegex(ValueError, "mapping bounds"):
            bounded_mapping({}, "field", maximum_items=-1)
        with self.assertRaisesRegex(ValueError, "JSON value bounds"):
            validate_bounded_json_value(
                {},
                "field",
                maximum_depth=-1,
            )


if __name__ == "__main__":
    unittest.main()
