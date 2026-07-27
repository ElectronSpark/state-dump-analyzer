"""Stable import target for core plug-in module-loading tests."""


MODULE_PLUGIN = object()
plugin = MODULE_PLUGIN


class ClassTarget:
    pass


def factory_target() -> object:
    return object()
