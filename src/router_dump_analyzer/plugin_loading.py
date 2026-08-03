"""Core-owned loading for installed or directly named analyzer plug-ins."""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Iterable
from importlib import metadata
from typing import Any

from .plugin_api import PLUGIN_ENTRY_POINT_GROUP
from .process_control import PROCESS_CONTROL_EXCEPTIONS


def installed_plugin_entry_points() -> tuple[metadata.EntryPoint, ...]:
    """Return the installed analyzer plug-in entry points."""

    return tuple(
        metadata.entry_points().select(group=PLUGIN_ENTRY_POINT_GROUP)
    )


def _validated_instance(loaded: Any, *, target: str) -> Any:
    if inspect.isclass(loaded):
        raise TypeError(
            f"{target} must resolve to a module-level plug-in instance, "
            "not a class"
        )
    if inspect.isfunction(loaded):
        raise TypeError(
            f"{target} must resolve to a module-level plug-in instance, "
            "not a factory"
        )
    return loaded


def load_plugin_entry_point(
    name: str,
    *,
    candidates: Iterable[metadata.EntryPoint] | None = None,
) -> Any:
    """Load exactly one installed analyzer plug-in by entry-point name."""

    available = (
        tuple(candidates)
        if candidates is not None
        else installed_plugin_entry_points()
    )
    matches = tuple(item for item in available if item.name == name)
    if not matches:
        raise LookupError(
            f"no {PLUGIN_ENTRY_POINT_GROUP!r} entry point named "
            f"{name!r} is installed"
        )
    if len(matches) > 1:
        distributions = ", ".join(
            sorted(
                item.dist.name if item.dist is not None else "<unknown>"
                for item in matches
            )
        )
        raise LookupError(
            f"entry point {name!r} is ambiguous across distributions: "
            f"{distributions}"
        )
    try:
        loaded = matches[0].load()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception as error:
        raise RuntimeError(
            f"failed to load entry point {name!r}: "
            f"{type(error).__name__}: {error}"
        ) from error
    except BaseException:  # noqa: BLE001 - installed plug-ins are hostile code.
        raise RuntimeError(
            "failed to load the selected plug-in entry point"
        ) from None
    return _validated_instance(
        loaded,
        target=f"entry point {name!r}",
    )


def load_plugin_module(target: str) -> Any:
    """Load ``module[:attribute]``; the default attribute is ``plugin``."""

    module_name, separator, attribute = target.partition(":")
    module_name = module_name.strip()
    attribute = attribute.strip() if separator else "plugin"
    if not module_name or not attribute or ":" in attribute:
        raise ValueError(
            "plug-in module must use 'package.module[:attribute]' syntax"
        )
    try:
        module = importlib.import_module(module_name)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception as error:
        raise RuntimeError(
            f"failed to import plug-in module {module_name!r}: "
            f"{type(error).__name__}: {error}"
        ) from error
    except BaseException:  # noqa: BLE001 - imported module initialization is hostile.
        raise RuntimeError(
            "failed to import the selected plug-in module"
        ) from None
    try:
        loaded = getattr(module, attribute)
    except AttributeError:
        raise LookupError(
            f"plug-in module {module_name!r} has no attribute {attribute!r}"
        ) from None
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception:
        raise
    except BaseException:  # noqa: BLE001 - module attributes may be descriptors.
        raise RuntimeError(
            "could not resolve the selected plug-in module attribute"
        ) from None
    return _validated_instance(
        loaded,
        target=f"module target {module_name}:{attribute}",
    )


__all__ = [
    "installed_plugin_entry_points",
    "load_plugin_entry_point",
    "load_plugin_module",
]
