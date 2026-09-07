"""Construct the optional archive runtime only when its entry point is used."""

from typing import cast

from . import ExampleRouterPlugin, RuntimeAttachedExampleRouterPlugin
from . import session as _session

# Strict registration attests already loaded dependencies. Resolve the runtime
# before publishing the entry point, rather than hiding imports in validation.
_entry_plugin = ExampleRouterPlugin()
plugin: RuntimeAttachedExampleRouterPlugin = cast(
    RuntimeAttachedExampleRouterPlugin,
    _entry_plugin,
)
plugin.runtime = _session.runtime

__all__ = ["plugin"]
