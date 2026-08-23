from __future__ import annotations

import unittest
from importlib import metadata
from unittest.mock import patch

from router_dump_analyzer.plugin_api import PLUGIN_ENTRY_POINT_GROUP
from router_dump_analyzer.plugin_loading import (
    DIRECT_MODULE_DISTRIBUTION_NAME,
    DIRECT_MODULE_DISTRIBUTION_VERSION,
    DIRECT_MODULE_ENTRY_POINT_NAME,
    LoadedPlugin,
    PluginArtifactCoordinates,
    PluginProcessBootstrapDescriptor,
    load_plugin_entry_point_with_coordinates,
    load_plugin_module,
    load_plugin_module_with_coordinates,
)
from tests.support.plugin_module_fixture import MODULE_PLUGIN


class _FixtureDistribution:
    name = "vendor-router-plugin"
    version = "2.7.4"


class Boom(BaseException):
    pass


class _HostileException(Exception):
    def __init__(self, private: str) -> None:
        super().__init__()
        self.private = private
        self.rendered = False

    def __str__(self) -> str:
        self.rendered = True
        raise Boom(self.private)


class _BoundaryDistribution:
    name = "vendor-router-plugin"

    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error

    @property
    def version(self) -> str:
        if self.error is not None:
            raise self.error
        return "2.7.4"


class _BoundaryEntryPoint:
    name = "vendor_router"
    module = "tests.support.plugin_module_fixture"
    attr = "MODULE_PLUGIN"

    def __init__(
        self,
        *,
        dist_error: BaseException | None = None,
        version_error: BaseException | None = None,
        load_error: BaseException | None = None,
    ) -> None:
        self.dist_error = dist_error
        self.distribution = _BoundaryDistribution(version_error)
        self.load_error = load_error

    @property
    def dist(self):
        if self.dist_error is not None:
            raise self.dist_error
        return self.distribution

    def load(self):
        if self.load_error is not None:
            raise self.load_error
        return MODULE_PLUGIN


class _HostileString(str):
    def __len__(self) -> int:
        raise AssertionError("string subclass behavior must not execute")


class _HostileModuleAttribute:
    def __init__(self, private: str) -> None:
        self.private = private

    def __getattr__(self, name: str):
        del name
        raise RuntimeError(self.private)


class PluginModuleLoadingTests(unittest.TestCase):
    def test_installed_entry_point_retains_exact_artifact_coordinates(self) -> None:
        entry_point = metadata.EntryPoint(
            name="vendor_router",
            value=(
                "tests.support.plugin_module_fixture:MODULE_PLUGIN "
                "[optional-feature]"
            ),
            group=PLUGIN_ENTRY_POINT_GROUP,
        )
        vars(entry_point)["dist"] = _FixtureDistribution()

        loaded = load_plugin_entry_point_with_coordinates(
            "vendor_router",
            candidates=(entry_point,),
        )

        self.assertIs(loaded.plugin, MODULE_PLUGIN)
        assert loaded.coordinates is not None
        self.assertEqual(
            loaded.coordinates.distribution_name,
            "vendor-router-plugin",
        )
        self.assertEqual(loaded.coordinates.distribution_version, "2.7.4")
        self.assertEqual(loaded.coordinates.entry_point_name, "vendor_router")
        self.assertEqual(
            loaded.coordinates.module_target,
            "tests.support.plugin_module_fixture:MODULE_PLUGIN",
        )

    def test_direct_module_retains_normalized_direct_coordinates(self) -> None:
        loaded = load_plugin_module_with_coordinates(
            " tests.support.plugin_module_fixture : MODULE_PLUGIN "
        )

        self.assertIs(loaded.plugin, MODULE_PLUGIN)
        assert loaded.coordinates is not None
        self.assertEqual(
            loaded.coordinates.distribution_name,
            DIRECT_MODULE_DISTRIBUTION_NAME,
        )
        self.assertEqual(
            loaded.coordinates.distribution_version,
            DIRECT_MODULE_DISTRIBUTION_VERSION,
        )
        self.assertEqual(
            loaded.coordinates.entry_point_name,
            DIRECT_MODULE_ENTRY_POINT_NAME,
        )
        self.assertEqual(
            loaded.coordinates.module_target,
            "tests.support.plugin_module_fixture:MODULE_PLUGIN",
        )

    def test_exact_class_descriptor_selects_process_constructor(self) -> None:
        loaded = load_plugin_module_with_coordinates(
            "tests.support.plugin_module_fixture:DECLARED_PROCESS_PLUGIN"
        )

        self.assertEqual(
            loaded.process_module_target,
            "tests.support.plugin_module_fixture:DeclaredProcessPlugin",
        )
        self.assertTrue(loaded.process_construct_class)

        entry_point = metadata.EntryPoint(
            name="declared_process",
            value=(
                "tests.support.plugin_module_fixture:"
                "DECLARED_PROCESS_PLUGIN"
            ),
            group=PLUGIN_ENTRY_POINT_GROUP,
        )
        vars(entry_point)["dist"] = _FixtureDistribution()
        entry_loaded = load_plugin_entry_point_with_coordinates(
            "declared_process",
            candidates=(entry_point,),
        )
        self.assertEqual(
            entry_loaded.process_module_target,
            "tests.support.plugin_module_fixture:DeclaredProcessPlugin",
        )
        self.assertTrue(entry_loaded.process_construct_class)

    def test_process_descriptor_is_exact_local_and_immutable(self) -> None:
        descriptor = PluginProcessBootstrapDescriptor(
            "tests.support.plugin_module_fixture:DeclaredProcessPlugin",
            construct_class=True,
        )
        with self.assertRaises((AttributeError, TypeError)):
            descriptor.module_target = "tests.hostile:plugin"  # type: ignore[misc]
        with self.assertRaisesRegex(ValueError, "already be normalized"):
            PluginProcessBootstrapDescriptor(
                " tests.support.plugin_module_fixture:DeclaredProcessPlugin "
            )
        with self.assertRaisesRegex(TypeError, "construct_class"):
            PluginProcessBootstrapDescriptor(
                "tests.support.plugin_module_fixture:DeclaredProcessPlugin",
                construct_class=1,  # type: ignore[arg-type]
            )

        inherited = load_plugin_module_with_coordinates(
            "tests.support.plugin_module_fixture:INHERITED_PROCESS_PLUGIN"
        )
        self.assertEqual(
            inherited.process_module_target,
            "tests.support.plugin_module_fixture:INHERITED_PROCESS_PLUGIN",
        )
        self.assertFalse(inherited.process_construct_class)
        with self.assertRaisesRegex(TypeError, "exact.*class attribute"):
            load_plugin_module_with_coordinates(
                "tests.support.plugin_module_fixture:INVALID_PROCESS_PLUGIN"
            )

    def test_installed_coordinate_descriptors_are_contained(self) -> None:
        private = r"coordinate failed at C:\private\tenant\plugin.py"
        for entry_point in (
            _BoundaryEntryPoint(dist_error=Boom(private)),
            _BoundaryEntryPoint(version_error=Boom(private)),
        ):
            with self.subTest(entry_point=entry_point), self.assertRaisesRegex(
                RuntimeError,
                "invalid artifact coordinates",
            ) as caught:
                load_plugin_entry_point_with_coordinates(
                    "vendor_router",
                    candidates=(entry_point,),  # type: ignore[arg-type]
                )
            self.assertNotIn(private, str(caught.exception))

        with self.assertRaises(KeyboardInterrupt):
            load_plugin_entry_point_with_coordinates(
                "vendor_router",
                candidates=(
                    _BoundaryEntryPoint(
                        dist_error=KeyboardInterrupt("process control")
                    ),
                ),  # type: ignore[arg-type]
            )

    def test_coordinate_contract_rejects_string_subclasses(self) -> None:
        with self.assertRaisesRegex(ValueError, "exact string"):
            PluginArtifactCoordinates(
                distribution_name=_HostileString("vendor"),
                distribution_version="1",
                entry_point_name="vendor",
                module_target="vendor:plugin",
            )

        coordinates = PluginArtifactCoordinates(
            distribution_name="vendor",
            distribution_version="1",
            entry_point_name="vendor",
            module_target="vendor:plugin",
        )
        loaded = LoadedPlugin(MODULE_PLUGIN, coordinates)
        object.__setattr__(coordinates, "distribution_version", "2")
        assert loaded.coordinates is not None
        self.assertEqual(loaded.coordinates.distribution_version, "1")

    def test_loader_errors_do_not_format_hostile_exception_text(self) -> None:
        private = r"load failed at C:\private\tenant\plugin.py"
        entry_point_error = _HostileException(private)
        with self.assertRaisesRegex(
            RuntimeError,
            "failed to load entry point",
        ) as entry_point_failure:
            load_plugin_entry_point_with_coordinates(
                "vendor_router",
                candidates=(
                    _BoundaryEntryPoint(
                        load_error=entry_point_error
                    ),
                ),  # type: ignore[arg-type]
            )
        with patch(
            "router_dump_analyzer.plugin_loading.importlib.import_module",
            side_effect=_HostileException(private),
        ), self.assertRaisesRegex(
            RuntimeError,
            "failed to import plug-in module",
        ) as module_failure:
            load_plugin_module("tests.hostile:plugin")
        self.assertNotIn(private, str(entry_point_failure.exception))
        self.assertNotIn(private, str(module_failure.exception))
        self.assertFalse(entry_point_error.rendered)

    def test_module_target_defaults_to_plugin_instance(self) -> None:
        loaded = load_plugin_module("tests.support.plugin_module_fixture")

        self.assertIs(loaded, MODULE_PLUGIN)

    def test_module_target_accepts_an_explicit_instance_attribute(self) -> None:
        loaded = load_plugin_module(
            "tests.support.plugin_module_fixture:MODULE_PLUGIN"
        )

        self.assertIs(loaded, MODULE_PLUGIN)

    def test_module_attribute_failure_is_bounded_without_private_text(self) -> None:
        private = r"failed at C:\private\tenant\secret.py"
        with patch(
            "router_dump_analyzer.plugin_loading.importlib.import_module",
            return_value=_HostileModuleAttribute(private),
        ), self.assertRaisesRegex(
            RuntimeError,
            "could not resolve the selected plug-in module attribute",
        ) as failure:
            load_plugin_module("tests.hostile:plugin")

        self.assertNotIn(private, str(failure.exception))

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
            with self.subTest(target=target), self.assertRaisesRegex(
                ValueError,
                "package.module",
            ):
                load_plugin_module(target)

if __name__ == "__main__":
    unittest.main()
