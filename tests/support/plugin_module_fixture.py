"""Stable import target for core plug-in module-loading tests."""

from router_dump_analyzer.plugin_loading import (
    PluginProcessBootstrapDescriptor,
)


MODULE_PLUGIN = object()
plugin = MODULE_PLUGIN


class ClassTarget:
    pass


def factory_target() -> object:
    return object()


class DeclaredProcessPlugin:
    plugin_process_bootstrap = PluginProcessBootstrapDescriptor(
        module_target=(
            "tests.support.plugin_module_fixture:DeclaredProcessPlugin"
        ),
        construct_class=True,
    )


DECLARED_PROCESS_PLUGIN = DeclaredProcessPlugin()


class InheritedProcessPlugin(DeclaredProcessPlugin):
    pass


INHERITED_PROCESS_PLUGIN = InheritedProcessPlugin()


class InvalidProcessPlugin:
    plugin_process_bootstrap = object()


INVALID_PROCESS_PLUGIN = InvalidProcessPlugin()
