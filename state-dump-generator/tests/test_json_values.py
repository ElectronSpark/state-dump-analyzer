from __future__ import annotations

import unittest
from dataclasses import dataclass
from pathlib import Path

from state_dump_generator import __main__, archive, server


@dataclass
class Record:
    value: object


class DictionaryRecord:
    def to_dict(self) -> dict:
        return {"record": Record((1, True, None))}


class JsonProjectionTests(unittest.TestCase):
    def test_all_boundaries_share_nested_record_projection(self) -> None:
        for project in (
            __main__._plain_value,
            archive._plain_value,
            server._plain_value,
        ):
            with self.subTest(project=project):
                self.assertEqual(
                    project(DictionaryRecord()), {"record": {"value": [1, True, None]}}
                )
                self.assertEqual(
                    project({1: Record("value")}), {"1": {"value": "value"}}
                )

    def test_set_and_path_policies_remain_boundary_specific(self) -> None:
        with self.assertRaisesRegex(TypeError, "cannot serialize set"):
            __main__._plain_value(Record({2, 1}))
        self.assertEqual(archive._plain_value(Record({2, 1})), {"value": [1, 2]})
        self.assertEqual(
            server._plain_value(Record(frozenset({2, 1}))), {"value": [1, 2]}
        )
        path = Path("example")
        self.assertEqual(archive._plain_value({"path": path}), {"path": str(path)})
        with self.assertRaisesRegex(TypeError, "cannot serialize"):
            __main__._plain_value(path)
        with self.assertRaisesRegex(server.ScenarioRequestError, "as scenario JSON"):
            server._plain_value(path)

    def test_error_types_and_nonfinite_set_sorting_are_preserved(self) -> None:
        with self.assertRaisesRegex(
            archive.ArchiveProjectionError, "non-serializable object"
        ):
            archive._plain_value(object())
        with self.assertRaisesRegex(
            server.ScenarioRequestError, "cannot serialize object as scenario JSON"
        ):
            server._plain_value(object())
        with self.assertRaises(ValueError):
            archive._plain_value({float("inf")})
        self.assertEqual(server._plain_value({float("inf")}), [float("inf")])


if __name__ == "__main__":
    unittest.main()
