from __future__ import annotations

import pickle
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from router_dump_analyzer import (
    control_plane,
    control_plane_errors,
    ingestion_contracts,
    session_catalog_publisher,
)
from router_dump_analyzer import ingestion_pipeline as pipeline
from router_dump_analyzer import plugin_registration as registration
from router_dump_analyzer.session_store import SqliteSessionStore


class RegistrationArchitectureTests(unittest.TestCase):
    def test_legacy_exports_preserve_exact_type_and_decoder_context_identity(
        self,
    ) -> None:
        for name in (
            "PluginRegistry",
            "RegisteredPlugin",
            "PluginCandidate",
            "_PluginProcessBootstrap",
            "_ProcessTargetKind",
            "_ProcessTargetIdentityUnavailable",
            "_ACTIVE_DECODER_IDENTITY",
        ):
            with self.subTest(name=name):
                self.assertIs(getattr(pipeline, name), getattr(registration, name))
        for name in (
            "ImportScope",
            "IngestionPipelineError",
            "CatalogExecutionTimeoutError",
            "CatalogPublisherProcessBootstrap",
            "PublisherCallContext",
            "RevisionCatalogPublisher",
        ):
            with self.subTest(name=name):
                self.assertIs(
                    getattr(pipeline, name), getattr(ingestion_contracts, name)
                )
        for name in (
            "ControlPlaneError",
            "ControlPlaneScopeError",
            "DatasetIntegrityError",
            "SubjectResolutionError",
            "HiddenSubjectResolutionError",
        ):
            with self.subTest(name=name):
                self.assertIs(
                    getattr(control_plane, name), getattr(control_plane_errors, name)
                )
        self.assertIs(
            control_plane.SessionCatalogPublisher,
            session_catalog_publisher.SessionCatalogPublisher,
        )

    def test_lower_modules_import_without_queue_or_composition_root(self) -> None:
        for module in (
            "ingestion_contracts",
            "plugin_registration",
            "capability_router",
            "session_catalog_publisher",
        ):
            with self.subTest(module=module):
                process = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        # The public package facade eagerly imports all core
                        # services for compatibility. Isolate the submodule
                        # graph to verify its own layering independently.
                        (
                            "import importlib, sys, types; "
                            "from pathlib import Path; "
                            "package = types.ModuleType('router_dump_analyzer'); "
                            "package.__path__ = [str(Path('src/router_dump_analyzer').resolve())]; "
                            "sys.modules['router_dump_analyzer'] = package; "
                            f"importlib.import_module('router_dump_analyzer.{module}'); "
                            "assert 'router_dump_analyzer.ingestion_pipeline' not in sys.modules; "
                            "assert 'router_dump_analyzer.control_plane' not in sys.modules"
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(process.returncode, 0, process.stderr)

    def test_legacy_pickled_scope_and_bootstrap_class_paths_still_load(self) -> None:
        bootstrap = registration._PluginProcessBootstrap(
            schema_version="router_dump_analyzer.plugin_process_bootstrap.v1",
            plugin_loader_kind="class_constructor",
            plugin_target="example.plugin:Plugin",
            plugin_target_executable_identity="module-sha256:" + "1" * 64,
            coordinator_loader_kind="core_default",
            coordinator_target=None,
            coordinator_target_executable_identity=None,
            decoder_loader_kind="none",
            decoder_target=None,
            decoder_target_executable_identity=None,
            ingestion_limit_values=(1,),
            artifact_limit_values=(1,),
            package_hash="package-sha256:" + "2" * 64,
            verify_package_bytes=True,
            instance_id="example",
            distribution_name="example",
            distribution_version="1",
            entry_point_name="example",
            module_target="example.plugin:Plugin",
            configuration_digest="sha256:" + "3" * 64,
            decoder_identity_values=None,
            expected_registered_execution_identity="sha256:" + "4" * 64,
        )
        for value in (
            bootstrap,
            ingestion_contracts.ImportScope("tenant", "project", "workspace"),
            ingestion_contracts.CatalogPublisherProcessBootstrap(
                loader_kind="core_null"
            ),
            ingestion_contracts.PublisherCallContext("operation", 1, 1, 2),
        ):
            with self.subTest(type=type(value).__name__):
                wire = pickle.dumps(value, protocol=0)
                module = type(value).__module__.encode("ascii")
                self.assertIn(module, wire)
                legacy_wire = wire.replace(
                    module, b"router_dump_analyzer.ingestion_pipeline"
                )
                restored = pickle.loads(legacy_wire)
                self.assertIs(type(restored), type(value))
                self.assertEqual(restored, value)

    def test_session_publisher_bootstrap_reopens_the_exact_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SqliteSessionStore(Path(directory) / "catalog.sqlite3")
            try:
                publisher = control_plane.SessionCatalogPublisher(store)
                bootstrap = pipeline._catalog_publisher_process_bootstrap(
                    publisher, module_target=None
                )
                self.assertEqual(bootstrap.loader_kind, "core_sqlite_session")
                self.assertEqual(
                    bootstrap.constructor_args, (store._process_reopen_path(),)
                )
                restored = pipeline._catalog_publisher_from_process_bootstrap(bootstrap)
                try:
                    self.assertIs(
                        type(restored),
                        session_catalog_publisher.SessionCatalogPublisher,
                    )
                    self.assertEqual(
                        restored.sessions._process_reopen_path(),
                        store._process_reopen_path(),
                    )
                finally:
                    restored.sessions.close()
                legacy_wire = pickle.dumps(publisher, protocol=0).replace(
                    b"router_dump_analyzer.session_catalog_publisher",
                    b"router_dump_analyzer.control_plane",
                )
                legacy = pickle.loads(legacy_wire)
                try:
                    self.assertIs(type(legacy), type(publisher))
                    self.assertEqual(legacy.process_bootstrap(), bootstrap)
                finally:
                    legacy.sessions.close()
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
