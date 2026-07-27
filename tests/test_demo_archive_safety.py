from __future__ import annotations

import unittest
from pathlib import PurePosixPath

from rsl_demo_plugin.archive import normalize_archive_member_name
from rsl_demo_plugin.assembly_store import (
    DemoAssemblyError,
    _safe_member_name as validate_assembly_member_name,
)
from rsl_demo_generator import assembly as generator_assembly
from rsl_demo_generator._archive import validate_archive_name
from rsl_demo_plugin.scale_data import _safe_archive_member_name


class DemoArchiveSafetyTests(unittest.TestCase):
    def test_shared_normalizer_accepts_only_canonical_portable_member_names(
        self,
    ) -> None:
        self.assertEqual(
            PurePosixPath("node-a/control-plane.tgz"),
            normalize_archive_member_name("node-a/control-plane.tgz"),
        )
        for unsafe in (
            "",
            ".",
            "../escape",
            "/absolute",
            "C:/absolute",
            "node-a\\member",
            "node-a//member",
            "node-a/./member",
            "node-a/\x00member",
            "node-a/CON",
            "node-a/trailing.",
        ):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(ValueError):
                    normalize_archive_member_name(unsafe)

    def test_generator_archive_api_is_the_shared_normalizer_alias(self) -> None:
        self.assertIs(validate_archive_name, normalize_archive_member_name)

    def test_callers_preserve_context_specific_exception_contracts(self) -> None:
        with self.assertRaisesRegex(
            DemoAssemblyError,
            "unsafe assembly member name",
        ):
            validate_assembly_member_name("../escape")
        with self.assertRaisesRegex(
            RuntimeError,
            "unsafe packed fixture member",
        ):
            _safe_archive_member_name("../escape")
        with self.assertRaisesRegex(
            RuntimeError,
            "unsafe generated archive member",
        ):
            generator_assembly._safe_member_name("../escape")


if __name__ == "__main__":
    unittest.main()
