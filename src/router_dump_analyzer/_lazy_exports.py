"""Small compatibility-facade loader shared with core-dependent demo packages."""

from importlib import import_module
from typing import Any


def resolve_export(
    name: str, namespace: dict[str, Any], exports: dict[str, str]
) -> object:
    module_name = exports.get(name)
    package_name = namespace["__name__"]
    if module_name is None:
        raise AttributeError(f"module {package_name!r} has no attribute {name!r}")
    implementation = import_module(module_name, package_name)
    value = getattr(implementation, name)
    # Publish concrete class targets before attestation and retain annotation
    # globals, without triggering other lazy attributes on the source module.
    namespace.update(
        {
            key: item
            for key, item in vars(implementation).items()
            if exports.get(key) == module_name
        }
    )
    namespace[name] = value
    return value
