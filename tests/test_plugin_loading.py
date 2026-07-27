from __future__ import annotations

import unittest

from router_dump_analyzer.plugin_loading import load_plugin_module
from tests.support.plugin_module_fixture import MODULE_PLUGIN


class PluginModuleLoadingTests(unittest.TestCase):
    def test_module_target_defaults_to_plugin_instance(self) -> None:
        loaded = load_plugin_module("tests.support.plugin_module_fixture")

        self.assertIs(loaded, MODULE_PLUGIN)

    def test_module_target_accepts_an_explicit_instance_attribute(self) -> None:
        loaded = load_plugin_module(
            "tests.support.plugin_module_fixture:MODULE_PLUGIN"
        )

        self.assertIs(loaded, MODULE_PLUGIN)

    def test_module_target_rejects_missing_or_factory_targets(self) -> None:
        with self.assertRaisesRegex(LookupError, "has no attribute"):
            load_plugin_module(
                "tests.support.plugin_module_fixture:missing"
            )
        with self.assertRaisesRegex(TypeError, "not a class"):
            load_plugin_module(
                "tests.support.plugin_module_fixture:ClassTarget"
            )
        with self.assertRaisesRegex(TypeError, "not a factory"):
            load_plugin_module(
                "tests.support.plugin_module_fixture:factory_target"
            )

    def test_module_target_requires_module_attribute_syntax(self) -> None:
        for target in (
            "",
            ":plugin",
            "tests.support.plugin_module_fixture:",
            "a:b:c",
        ):
            with self.subTest(target=target):
                with self.assertRaisesRegex(
                    ValueError,
                    "package.module",
                ):
                    load_plugin_module(target)

if __name__ == "__main__":
    unittest.main()
