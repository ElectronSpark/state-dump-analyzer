"""Keep newly declared plug-in APIs from silently escaping the audit map."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts import check_plugin_conformance as runner
from router_dump_analyzer import plugin_api


class PluginConformanceInventoryTests(unittest.TestCase):
    def test_current_public_inventory_and_test_targets_are_complete(self) -> None:
        self.assertEqual(runner.check_inventory(), [])

    def test_new_declared_hook_requires_an_explicit_conformance_owner(self) -> None:
        hooks = dict(plugin_api.PLUGIN_CAPABILITY_HOOKS)
        hooks[plugin_api.PluginCapability.STATUS_PARSE] += ("parse_future_format",)
        with patch.object(plugin_api, "PLUGIN_CAPABILITY_HOOKS", hooks):
            errors = runner.check_inventory()
        self.assertTrue(any("parse_future_format" in error for error in errors))

    def test_removed_test_module_invalidates_the_inventory(self) -> None:
        groups = dict(runner.GROUPS)
        groups["foundation"] += ("nonexistent_plugin_audit_fixture",)
        with patch.object(runner, "GROUPS", groups):
            errors = runner.check_inventory()
        self.assertTrue(any("Missing test module" in error for error in errors))

    def test_generic_protocols_cannot_silently_escape_the_inventory(self) -> None:
        source = """
class Plain(Protocol): pass
class Generic(Protocol[T]): pass
class Qualified(typing.Protocol[T]): pass
class _Private(Protocol): pass
class Concrete: pass
"""
        self.assertEqual(
            runner.public_protocol_names(source), {"Plain", "Generic", "Qualified"}
        )


if __name__ == "__main__":
    unittest.main()
