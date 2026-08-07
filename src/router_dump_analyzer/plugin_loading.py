"""Core-owned loading for installed or directly named analyzer plug-ins."""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Final

from .plugin_api import PLUGIN_ENTRY_POINT_GROUP
from .process_control import PROCESS_CONTROL_EXCEPTIONS

DIRECT_MODULE_DISTRIBUTION_NAME: Final = "direct-module"
DIRECT_MODULE_DISTRIBUTION_VERSION: Final = "0"
DIRECT_MODULE_ENTRY_POINT_NAME: Final = "direct-module"


def _coordinate_text(value: object, label: str, *, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{label} must be a non-empty bounded exact string")
    return value


@dataclass(frozen=True, slots=True)
class PluginArtifactCoordinates:
    """Honest loader coordinates for one selected plug-in artifact."""

    distribution_name: str
    distribution_version: str
    entry_point_name: str
    module_target: str

    def __post_init__(self) -> None:
        _coordinate_text(self.distribution_name, "distribution_name", maximum=256)
        _coordinate_text(
            self.distribution_version,
            "distribution_version",
            maximum=128,
        )
        _coordinate_text(self.entry_point_name, "entry_point_name", maximum=256)
        normalized_target = normalize_plugin_module_target(self.module_target)
        if normalized_target != self.module_target:
            raise ValueError("module_target must already be normalized")

    @classmethod
    def direct_module(cls, target: str) -> PluginArtifactCoordinates:
        """Describe a direct-module selection without claiming a package."""

        return cls(
            distribution_name=DIRECT_MODULE_DISTRIBUTION_NAME,
            distribution_version=DIRECT_MODULE_DISTRIBUTION_VERSION,
            entry_point_name=DIRECT_MODULE_ENTRY_POINT_NAME,
            module_target=normalize_plugin_module_target(target),
        )


def _snapshot_artifact_coordinates(
    coordinates: PluginArtifactCoordinates,
) -> PluginArtifactCoordinates:
    if type(coordinates) is not PluginArtifactCoordinates:
        raise TypeError("coordinates must be PluginArtifactCoordinates")
    return PluginArtifactCoordinates(
        distribution_name=coordinates.distribution_name,
        distribution_version=coordinates.distribution_version,
        entry_point_name=coordinates.entry_point_name,
        module_target=coordinates.module_target,
    )


@dataclass(frozen=True, slots=True)
class LoadedPlugin:
    """A plug-in instance and, when known, its executable coordinates."""

    plugin: Any
    coordinates: PluginArtifactCoordinates | None = None
    process_module_target: str | None = None
    process_construct_class: bool = False

    def __post_init__(self) -> None:
        if self.coordinates is not None:
            object.__setattr__(
                self,
                "coordinates",
                _snapshot_artifact_coordinates(self.coordinates),
            )
        if self.process_module_target is not None:
            object.__setattr__(
                self,
                "process_module_target",
                normalize_plugin_module_target(self.process_module_target),
            )
        if type(self.process_construct_class) is not bool:
            raise TypeError("process_construct_class must be an exact boolean")
        if self.process_construct_class and self.process_module_target is None:
            raise ValueError(
                "process_construct_class requires process_module_target"
            )

    def register(
        self,
        registry: Any,
        *,
        instance_id: str | None = None,
        configuration_digest: str | None = None,
    ) -> Any:
        """Register the instance while preserving known loader coordinates."""

        overrides: dict[str, str] = {}
        if instance_id is not None:
            overrides["instance_id"] = instance_id
        if configuration_digest is not None:
            overrides["configuration_digest"] = configuration_digest
        if self.coordinates is None:
            return registry.register(
                self.plugin,
                plugin_process_module_target=self.process_module_target,
                plugin_process_construct_class=self.process_construct_class,
                **overrides,
            )
        coordinates = _snapshot_artifact_coordinates(self.coordinates)
        return registry.register(
            self.plugin,
            distribution_name=coordinates.distribution_name,
            distribution_version=coordinates.distribution_version,
            entry_point_name=coordinates.entry_point_name,
            module_target=coordinates.module_target,
            plugin_process_module_target=self.process_module_target,
            plugin_process_construct_class=self.process_construct_class,
            **overrides,
        )


def _instance_class_target(value: Any) -> str:
    implementation = type(value)
    module_name = implementation.__module__
    qualified_name = implementation.__qualname__
    if (
        type(module_name) is not str
        or type(qualified_name) is not str
        or not module_name
        or not qualified_name
        or "<locals>" in qualified_name
    ):
        raise ValueError("injected plug-in must have an importable module-level class")
    return normalize_plugin_module_target(f"{module_name}:{qualified_name}")


def installed_plugin_entry_points() -> tuple[metadata.EntryPoint, ...]:
    """Return the installed analyzer plug-in entry points."""

    return tuple(
        metadata.entry_points().select(group=PLUGIN_ENTRY_POINT_GROUP)
    )


def normalize_plugin_module_target(target: str) -> str:
    """Validate and normalize ``module[:attribute]`` to ``module:attribute``."""

    if (
        type(target) is not str
        or len(target) > 512
        or any(ord(character) < 32 for character in target)
    ):
        raise ValueError(
            "plug-in module must use 'package.module[:attribute]' syntax"
        )
    module_name, separator, attribute = target.partition(":")
    module_name = module_name.strip()
    attribute = attribute.strip() if separator else "plugin"
    if not module_name or not attribute or ":" in attribute:
        raise ValueError(
            "plug-in module must use 'package.module[:attribute]' syntax"
        )
    return f"{module_name}:{attribute}"


def _selected_entry_point(
    name: str,
    *,
    candidates: Iterable[metadata.EntryPoint] | None,
) -> metadata.EntryPoint:
    _coordinate_text(name, "entry-point name", maximum=256)
    try:
        available = (
            tuple(candidates)
            if candidates is not None
            else installed_plugin_entry_points()
        )
        named = tuple((item, item.name) for item in available)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise RuntimeError(
            "installed entry-point metadata could not be resolved"
        ) from error
    matches = tuple(
        item
        for item, entry_point_name in named
        if type(entry_point_name) is str and entry_point_name == name
    )
    if not matches:
        raise LookupError(
            f"no {PLUGIN_ENTRY_POINT_GROUP!r} entry point named "
            f"{name!r} is installed"
        )
    if len(matches) > 1:
        try:
            distribution_names = tuple(
                item.dist.name if item.dist is not None else "<unknown>"
                for item in matches
            )
        except PROCESS_CONTROL_EXCEPTIONS:
            raise
        except BaseException as error:
            raise RuntimeError(
                "installed entry-point distribution metadata could not be resolved"
            ) from error
        if any(type(item) is not str for item in distribution_names):
            raise RuntimeError(
                "installed entry-point distribution metadata is invalid"
            )
        distributions = ", ".join(sorted(distribution_names))
        raise LookupError(
            f"entry point {name!r} is ambiguous across distributions: "
            f"{distributions}"
        )
    return matches[0]


def _load_entry_point(
    entry_point: metadata.EntryPoint,
    *,
    name: str,
) -> Any:
    try:
        loaded = entry_point.load()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception as error:
        prefix = f"failed to load entry point {name!r}"
        detail = prefix
        safe_types = (
            ImportError,
            ModuleNotFoundError,
            RuntimeError,
            ValueError,
            TypeError,
            LookupError,
            KeyError,
            OSError,
            FileNotFoundError,
            PermissionError,
        )
        if type(error) in safe_types:
            arguments = error.args
            if (
                type(arguments) is tuple
                and len(arguments) == 1
                and type(arguments[0]) is str
            ):
                error_message = arguments[0]
                if len(error_message) > 1_024:
                    # Do not interpolate an attacker-sized string merely to
                    # discover that the public boundary must reject it.
                    detail = "\x00"
                else:
                    summary = f"{type(error).__name__}: {error_message}"
                    qualified = f"{prefix}: {summary}"
                    if len(qualified) <= 1_024:
                        detail = qualified
                    elif len(summary) <= 1_024:
                        detail = summary
                    else:
                        # Force the outer public-text boundary to use its
                        # closed fallback without retaining the value.
                        detail = "\x00"
        raise RuntimeError(
            detail
        ) from error
    except BaseException:  # noqa: BLE001 - installed plug-ins are hostile code.
        raise RuntimeError(
            "failed to load the selected plug-in entry point"
        ) from None
    return _validated_instance(
        loaded,
        target=f"entry point {name!r}",
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

    entry_point = _selected_entry_point(
        name,
        candidates=candidates,
    )
    return _load_entry_point(entry_point, name=name)


def load_plugin_entry_point_with_coordinates(
    name: str,
    *,
    candidates: Iterable[metadata.EntryPoint] | None = None,
) -> LoadedPlugin:
    """Load an installed plug-in with its exact distribution coordinates."""

    entry_point = _selected_entry_point(name, candidates=candidates)
    try:
        distribution = entry_point.dist
        module_name = entry_point.module
        attribute = entry_point.attr
        entry_point_name = entry_point.name
        distribution_name = distribution.name if distribution is not None else None
        distribution_version = (
            distribution.version if distribution is not None else None
        )
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise RuntimeError(
            f"entry point {name!r} has invalid artifact coordinates"
        ) from error
    if distribution is None:
        raise RuntimeError(
            f"entry point {name!r} has no owning distribution metadata"
        )
    if any(
        type(value) is not str
        for value in (
            module_name,
            attribute,
            entry_point_name,
            distribution_name,
            distribution_version,
        )
    ):
        raise RuntimeError(
            f"entry point {name!r} has invalid artifact coordinates"
        )
    if not module_name or not attribute:
        raise RuntimeError(
            f"entry point {name!r} must resolve to a module attribute"
        )
    module_target = normalize_plugin_module_target(
        f"{module_name}:{attribute}"
    )
    plugin = _load_entry_point(entry_point, name=name)
    assert distribution_name is not None
    assert distribution_version is not None
    return LoadedPlugin(
        plugin=plugin,
        coordinates=PluginArtifactCoordinates(
            distribution_name=distribution_name,
            distribution_version=distribution_version,
            entry_point_name=entry_point_name,
            module_target=module_target,
        ),
        process_module_target=module_target,
    )


def load_plugin_module(
    target: str,
    *,
    _construct_class: bool = False,
) -> Any:
    """Load ``module[:attribute]``; the default attribute is ``plugin``."""

    if type(_construct_class) is not bool:
        raise TypeError("_construct_class must be an exact boolean")
    normalized_target = normalize_plugin_module_target(target)
    module_name, attribute = normalized_target.split(":", 1)
    try:
        module = importlib.import_module(module_name)
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except Exception as error:
        raise RuntimeError(
            f"failed to import plug-in module {module_name!r}"
        ) from error
    except BaseException:  # noqa: BLE001 - imported module initialization is hostile.
        raise RuntimeError(
            "failed to import the selected plug-in module"
        ) from None
    try:
        loaded: Any = module
        for component in attribute.split("."):
            if not component or component in {"<locals>", "<lambda>"}:
                raise ValueError("plug-in module target is not module-level")
            loaded = getattr(loaded, component)
    except AttributeError:
        raise LookupError(
            f"plug-in module {module_name!r} has no attribute {attribute!r}"
        ) from None
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException:  # noqa: BLE001 - module attributes may be descriptors.
        raise RuntimeError(
            "could not resolve the selected plug-in module attribute"
        ) from None
    if not _construct_class:
        return _validated_instance(
            loaded,
            target=f"module target {normalized_target}",
        )
    if not inspect.isclass(loaded):
        raise TypeError("process bootstrap constructor target must be a class")
    try:
        return loaded()
    except PROCESS_CONTROL_EXCEPTIONS:
        raise
    except BaseException as error:
        raise RuntimeError("process bootstrap class construction failed") from error


def load_process_bootstrap_target(
    target: str,
    *,
    construct_class: bool,
) -> Any:
    """Resolve one inert process-bootstrap target in the spawned child.

    The parent passes only the normalized string and this core-owned boolean.
    Import, descriptor resolution, and optional no-argument construction all
    happen after the killable child deadline exists.
    """

    if type(construct_class) is not bool:
        raise TypeError("construct_class must be an exact boolean")
    return load_plugin_module(
        target,
        _construct_class=construct_class,
    )


def load_plugin_module_with_coordinates(target: str) -> LoadedPlugin:
    """Load a direct module and retain its explicit direct-module identity."""

    coordinates = PluginArtifactCoordinates.direct_module(target)
    return LoadedPlugin(
        plugin=load_plugin_module(coordinates.module_target),
        coordinates=coordinates,
        process_module_target=coordinates.module_target,
    )


def loaded_entry_point(
    name: str,
    *,
    loader: Callable[[str], Any],
) -> LoadedPlugin:
    """Adapt a production or injected entry-point loader for composition."""

    if loader is load_plugin_entry_point:
        return load_plugin_entry_point_with_coordinates(name)
    loaded = loader(name)
    if isinstance(loaded, LoadedPlugin):
        return loaded
    # Existing dependency-injected loaders intentionally remain supported.
    # They may return ``LoadedPlugin`` when a test/deployment has coordinates.
    return LoadedPlugin(plugin=loaded)


def loaded_module(
    target: str,
    *,
    loader: Callable[[str], Any],
) -> LoadedPlugin:
    """Adapt a production or injected direct-module loader for composition."""

    if loader is load_plugin_module:
        return load_plugin_module_with_coordinates(target)
    loaded = loader(target)
    if isinstance(loaded, LoadedPlugin):
        plugin = loaded.plugin
        process_module_target = loaded.process_module_target
        process_construct_class = loaded.process_construct_class
    else:
        plugin = loaded
        process_module_target = _instance_class_target(plugin)
        process_construct_class = True
    return LoadedPlugin(
        plugin=plugin,
        coordinates=PluginArtifactCoordinates.direct_module(target),
        process_module_target=process_module_target,
        process_construct_class=process_construct_class,
    )


__all__ = [
    "DIRECT_MODULE_DISTRIBUTION_NAME",
    "DIRECT_MODULE_DISTRIBUTION_VERSION",
    "DIRECT_MODULE_ENTRY_POINT_NAME",
    "LoadedPlugin",
    "PluginArtifactCoordinates",
    "installed_plugin_entry_points",
    "load_plugin_entry_point",
    "load_plugin_entry_point_with_coordinates",
    "load_plugin_module",
    "load_plugin_module_with_coordinates",
    "load_process_bootstrap_target",
    "loaded_entry_point",
    "loaded_module",
    "normalize_plugin_module_target",
]
