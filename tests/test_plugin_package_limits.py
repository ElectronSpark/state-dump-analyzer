from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Barrier
from types import ModuleType
from unittest.mock import patch
from uuid import uuid4

from router_dump_analyzer import plugin_identity
from router_dump_analyzer.control_plane import ControlPlane
from router_dump_analyzer.ingestion import IngestionCoordinator
from router_dump_analyzer.ingestion_pipeline import (
    ImportState,
    IngestionPipelineError,
    PipelineLimits,
    PluginExecutionMode,
    PluginRegistry,
    RegisteredPlugin,
)
from router_dump_analyzer.plugin_execution_plan import PluginExecutionPlanAuthority
from router_dump_analyzer.plugin_identity import (
    PluginExecutableIdentityError,
    executable_module_target_fingerprint,
    executable_plugin_fingerprint,
)

_ABSENT = object()
_SIMPLE_PLUGIN = (
    "class Manifest:\n"
    "    plugin_id = 'tests.package-limit'\n"
    "    plugin_version = '1'\n"
    "class Plugin:\n"
    "    manifest = Manifest()\n"
    "plugin = Plugin()\n"
)
_PROCESS_PLUGIN = (
    "from tests.fixtures.native_alias_plugin import NativeAliasPlugin\n"
    "class Plugin(NativeAliasPlugin):\n"
    "    pass\n"
    "plugin = Plugin()\n"
)


@contextmanager
def _package(*, limit=_ABSENT, source=_SIMPLE_PLUGIN, submodule=False, namespace=False):
    """Each case owns an importable package and removes only its own modules."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        package_name = f"_rda_package_limit_{uuid4().hex}"
        package = root / package_name
        package.mkdir()
        declaration = (
            "" if limit is _ABSENT else f"PLUGIN_PACKAGE_ENTRY_LIMIT = {limit!r}\n"
        )
        if namespace:
            module_name = f"{package_name}.plugin"
            (package / "plugin.py").write_text(source, encoding="utf-8")
        elif submodule:
            module_name = f"{package_name}.plugin"
            (package / "__init__.py").write_text(declaration, encoding="utf-8")
            (package / "plugin.py").write_text(source, encoding="utf-8")
        else:
            module_name = package_name
            (package / "__init__.py").write_text(declaration + source, encoding="utf-8")
        sys.path.insert(0, str(root))
        importlib.invalidate_caches()
        try:
            module = importlib.import_module(module_name)
            owner = sys.modules[package_name]
            if namespace and limit is not _ABSENT:
                owner.PLUGIN_PACKAGE_ENTRY_LIMIT = limit
            yield module, owner, package
        finally:
            sys.path.remove(str(root))
            for name in tuple(sys.modules):
                if name == package_name or name.startswith(package_name + "."):
                    sys.modules.pop(name, None)
            importlib.invalidate_caches()


def _target_fingerprint(module):
    return executable_module_target_fingerprint(
        module.__name__, "Plugin", module.Plugin
    )


class PluginPackageLimitTests(unittest.TestCase):
    def test_module_subclass_quota_uses_real_namespace_not_dynamic_attributes(self):
        class ModuleWithDynamicAttributes(ModuleType):
            def __getattribute__(self, name):
                if name == "__dict__":
                    return {"PLUGIN_PACKAGE_ENTRY_LIMIT": 1}
                return super().__getattribute__(name)

            def __getattr__(self, name):
                if name == "PLUGIN_PACKAGE_ENTRY_LIMIT":
                    return True
                raise AttributeError(name)

        with _package() as (module, owner, package):
            (package / "rules.json").write_text("{}", encoding="utf-8")
            absent = executable_plugin_fingerprint(module.plugin)
            namespace = vars(owner)
            owner.__class__ = ModuleWithDynamicAttributes
            self.assertEqual(executable_plugin_fingerprint(module.plugin), absent)
            namespace["PLUGIN_PACKAGE_ENTRY_LIMIT"] = 2
            self.assertIsNotNone(executable_plugin_fingerprint(module.plugin))
            namespace["PLUGIN_PACKAGE_ENTRY_LIMIT"] = 1
            with self.assertRaisesRegex(
                PluginExecutableIdentityError, "entry limit.*1"
            ):
                executable_plugin_fingerprint(module.plugin)

    def test_exact_integer_declaration_bounds_and_invalid_values(self):
        class IntSubclass(int):
            pass

        with _package() as (module, owner, _):
            for value in (1, 4_096, 16_384, 65_536):
                with self.subTest(valid=value):
                    owner.PLUGIN_PACKAGE_ENTRY_LIMIT = value
                    self.assertRegex(
                        executable_plugin_fingerprint(module.plugin),
                        r"\Apackage-sha256:[0-9a-f]{64}\Z",
                    )
            for value in (
                None,
                True,
                False,
                0,
                -1,
                65_537,
                1.0,
                "16384",
                [],
                IntSubclass(2),
            ):
                with self.subTest(invalid=repr(value)):
                    owner.PLUGIN_PACKAGE_ENTRY_LIMIT = value
                    for fingerprint in (
                        lambda: executable_plugin_fingerprint(module.plugin),
                        lambda: _target_fingerprint(module),
                    ):
                        with self.assertRaisesRegex(
                            PluginExecutableIdentityError, "PLUGIN_PACKAGE_ENTRY_LIMIT"
                        ):
                            fingerprint()

    def test_only_resolved_regular_or_namespace_scope_owns_declaration(self):
        for namespace in (False, True):
            with (
                self.subTest(namespace=namespace),
                _package(limit=8, submodule=True, namespace=namespace) as (
                    module,
                    owner,
                    package,
                ),
            ):
                (package / "rules.json").write_text("{}", encoding="utf-8")
                module.PLUGIN_PACKAGE_ENTRY_LIMIT = 1
                self.assertIsNotNone(executable_plugin_fingerprint(module.plugin))
                owner.PLUGIN_PACKAGE_ENTRY_LIMIT = 1
                with self.assertRaisesRegex(
                    PluginExecutableIdentityError, "entry limit.*1"
                ):
                    executable_plugin_fingerprint(module.plugin)

    def test_declaration_changes_both_fingerprints_and_registered_revalidation(self):
        with _package(limit=16_384) as (module, owner, _):
            first = executable_plugin_fingerprint(module.plugin)
            first_target = _target_fingerprint(module)
            record = RegisteredPlugin(
                plugin=module.plugin,
                coordinator=IngestionCoordinator(),
                package_hash=first,
                verify_package_bytes=True,
            )
            PluginRegistry.revalidate_executable_identity(record)
            owner.PLUGIN_PACKAGE_ENTRY_LIMIT = 32_768
            self.assertNotEqual(executable_plugin_fingerprint(module.plugin), first)
            self.assertNotEqual(_target_fingerprint(module), first_target)
            with self.assertRaisesRegex(
                IngestionPipelineError, "executable bytes changed after registration"
            ):
                PluginRegistry.revalidate_executable_identity(record)
            del owner.PLUGIN_PACKAGE_ENTRY_LIMIT
            absent = executable_plugin_fingerprint(module.plugin)
            absent_target = _target_fingerprint(module)
            self.assertNotEqual(absent, first)
            with self.assertRaisesRegex(
                IngestionPipelineError, "executable bytes changed after registration"
            ):
                PluginRegistry.revalidate_executable_identity(record)
            owner.PLUGIN_PACKAGE_ENTRY_LIMIT = 4_096
            self.assertNotEqual(executable_plugin_fingerprint(module.plugin), absent)
            self.assertNotEqual(_target_fingerprint(module), absent_target)

    def test_late_module_target_attestation_rechecks_declaration_and_owner(self):
        for mutation in ("replace-value", "delete-declaration", "replace-module"):
            with (
                self.subTest(mutation=mutation),
                _package(limit=16_384) as (module, owner, _),
            ):
                original_verify = plugin_identity._verify_source_path_caches
                changed = False

                def verify_then_change(
                    budget, _verify=original_verify, _mutation=mutation
                ):
                    nonlocal changed
                    _verify(budget)
                    changed = True
                    if _mutation == "replace-value":
                        owner.PLUGIN_PACKAGE_ENTRY_LIMIT = 32_768
                    elif _mutation == "delete-declaration":
                        del owner.PLUGIN_PACKAGE_ENTRY_LIMIT
                    else:
                        replacement = ModuleType(owner.__name__)
                        vars(replacement).update(vars(owner))
                        sys.modules[owner.__name__] = replacement

                with (
                    patch.object(
                        plugin_identity,
                        "_verify_source_path_caches",
                        verify_then_change,
                    ),
                    self.assertRaisesRegex(PluginExecutableIdentityError, "changed"),
                ):
                    _target_fingerprint(module)
                self.assertTrue(changed)

    def test_declaration_change_during_enumeration_or_reads_fails_closed(self):
        for phase in ("enumeration", "file-read"):
            for target in (False, True):
                with (
                    self.subTest(phase=phase, module_target=target),
                    _package(limit=16_384) as (module, owner, package),
                ):
                    resource = package / "rules.json"
                    resource.write_text("{}", encoding="utf-8")
                    changed = False
                    original_entries = plugin_identity._package_entries
                    original_open = Path.open

                    def change():
                        nonlocal changed
                        changed = True
                        owner.PLUGIN_PACKAGE_ENTRY_LIMIT = 32_768

                    def enumerate_then_change(
                        *args, _entries=original_entries, **kwargs
                    ):
                        entries = _entries(*args, **kwargs)
                        change()
                        return entries

                    class ChangeAfterRead:
                        def __init__(self, stream):
                            self.stream = stream

                        def __enter__(self):
                            return self.stream.__enter__()

                        def __exit__(self, *args):
                            result = self.stream.__exit__(*args)
                            change()
                            return result

                    def open_then_change(
                        path, *args, _open=original_open, _resource=resource, **kwargs
                    ):
                        stream = _open(path, *args, **kwargs)
                        if path == _resource and args and args[0] == "rb":
                            return ChangeAfterRead(stream)
                        return stream

                    interception = (
                        patch.object(
                            plugin_identity, "_package_entries", enumerate_then_change
                        )
                        if phase == "enumeration"
                        else patch.object(Path, "open", open_then_change)
                    )
                    with (
                        interception,
                        self.assertRaisesRegex(
                            PluginExecutableIdentityError, "changed"
                        ),
                    ):
                        if target:
                            _target_fingerprint(module)
                        else:
                            executable_plugin_fingerprint(module.plugin)
                    self.assertTrue(changed)

    def test_concurrent_package_limits_are_isolated_without_global_mutation(self):
        with _package(limit=1) as small, _package(limit=2) as larger:
            for _, _, package in (small, larger):
                (package / "rules.json").write_text("{}", encoding="utf-8")
            rendezvous = Barrier(4)

            def fingerprint_repeatedly(selected, should_pass):
                rendezvous.wait(timeout=10)
                for _ in range(8):
                    if should_pass:
                        self.assertIsNotNone(
                            executable_plugin_fingerprint(selected.plugin)
                        )
                    else:
                        with self.assertRaisesRegex(
                            PluginExecutableIdentityError, "entry limit.*1"
                        ):
                            executable_plugin_fingerprint(selected.plugin)
                    self.assertEqual(plugin_identity.MAX_PLUGIN_PACKAGE_FILES, 4_096)
                    self.assertEqual(plugin_identity.MAX_PLUGIN_PACKAGE_PATHS, 8_192)

            with ThreadPoolExecutor(max_workers=4) as executor:
                pending = [
                    executor.submit(fingerprint_repeatedly, fixture[0], allowed)
                    for fixture, allowed in ((small, False), (larger, True)) * 2
                ]
                for future in pending:
                    future.result(timeout=30)

    def test_raised_entry_limit_preserves_byte_and_relative_path_limits(self):
        with _package(limit=16_384) as (module, _, package):
            resource = package / "rules.json"
            resource.write_bytes(b"x" * 512)
            for constant, maximum, message in (
                ("MAX_PLUGIN_PACKAGE_FILE_BYTES", 256, "exceeds.*256 bytes"),
                ("MAX_PLUGIN_PACKAGE_BYTES", 256, "byte limit"),
                ("MAX_PLUGIN_PACKAGE_PATH_BYTES", 4, "overlong relative path"),
            ):
                with (
                    self.subTest(bound=constant),
                    patch.object(plugin_identity, constant, maximum),
                    self.assertRaisesRegex(PluginExecutableIdentityError, message),
                ):
                    executable_plugin_fingerprint(module.plugin)

    def test_raised_entry_limit_preserves_alias_containment(self):
        with _package(limit=16_384) as (module, _, package):
            outside = package.parent / "outside"
            outside.mkdir()
            alias = package / "escape"
            if os.name == "nt":
                result = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(alias), str(outside)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    self.skipTest("Windows junction creation is unavailable")
            else:
                try:
                    alias.symlink_to(outside, target_is_directory=True)
                except OSError:
                    self.skipTest("directory symlink creation is unavailable")
            with self.assertRaisesRegex(
                PluginExecutableIdentityError, "alias 'escape' escapes its package root"
            ):
                executable_plugin_fingerprint(module.plugin)


class LargePluginPackageProcessTests(unittest.TestCase):
    def test_real_large_package_registers_ingests_and_publishes_in_processes(self):
        with (
            _package(limit=16_384, source=_PROCESS_PLUGIN) as (module, owner, package),
            tempfile.TemporaryDirectory() as directory,
        ):
            # 4,096 resource files plus __init__.py cross the actual default entry
            # limit without first crossing the independent default path limit.
            for index in range(4_096):
                (package / f"rule-{index:05d}.json").write_bytes(b"{}")
            del owner.PLUGIN_PACKAGE_ENTRY_LIMIT
            with self.assertRaisesRegex(
                PluginExecutableIdentityError, "entry limit.*4096"
            ):
                executable_plugin_fingerprint(module.plugin)
            with self.assertRaisesRegex(ValueError, "entry limit.*4096") as rejected:
                PluginRegistry().register(module.plugin)
            self.assertIn("entry limit", str(rejected.exception.__cause__))

            # This is also larger than 8,192 examined paths, so raising only the
            # entry counter would still break the real child-process workflow.
            owner.PLUGIN_PACKAGE_ENTRY_LIMIT = 16_384
            for index in range(4_096, 8_200):
                (package / f"rule-{index:05d}.json").write_bytes(b"{}")
            registry = PluginRegistry()
            registration = registry.register(
                module.plugin,
                plugin_process_module_target=f"{module.__name__}:plugin",
            )
            self.assertTrue(registration.verify_package_bytes)
            self.assertRegex(registration.package_hash, r"\Apackage-sha256:")
            self.assertIsNotNone(registration.process_bootstrap)
            limits = PipelineLimits(
                max_upload_bytes=1024 * 1024,
                max_workers=1,
                max_attempts=1,
                lease_seconds=120,
                poll_interval_seconds=0.01,
                plugin_execution_mode=PluginExecutionMode.PROCESS,
                publisher_execution_mode=PluginExecutionMode.PROCESS,
                plugin_execution_timeout_seconds=120,
            )
            payload = {
                "captured_at_ns": 100,
                "samples": [
                    {"time": index, "received": index * 2, "sent": index * 3}
                    for index in range(3)
                ],
            }
            raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            control_root = Path(directory)
            with ControlPlane(
                control_root, registry=registry, pipeline_limits=limits
            ) as control:
                control.sessions.create_project(
                    "tenant", "Project", project_id="project"
                )
                control.sessions.create_workspace(
                    "tenant", "project", "Workspace", workspace_id="workspace"
                )
                scope = control.import_scope("tenant", "project", "workspace")
                control.start()
                admitted = control.ingestion.submit_bytes(
                    scope, raw, original_name="counters.json", node_hint="sample-node"
                )
                completed = control.ingestion.wait(
                    scope, admitted.import_id, timeout=180
                )
                with control.ingestion._connect() as connection:
                    failures = [
                        dict(row)
                        for row in connection.execute(
                            "SELECT * FROM ingestion_failure_diagnostics WHERE import_id = ?",
                            (completed.import_id,),
                        )
                    ]
                self.assertEqual(completed.state, ImportState.COMPLETED, failures)
                self.assertEqual(failures, [])
                self.assertIsNone(completed.error_code)
                revisions = control.sessions.list_revisions("tenant", "workspace")
                self.assertEqual(len(revisions), 1)
                revision = revisions[0]
                self.assertEqual(revision.revision_id, completed.revision_id)
                self.assertEqual(
                    revision.execution_plan.execution_plan_authority,
                    PluginExecutionPlanAuthority.PROCESS,
                )
                dataset = control.load_revision_dataset(
                    control.scope("tenant", "project", "workspace"),
                    revision.revision_id,
                )
                self.assertEqual(
                    dataset["resources"][0]["state"]["samples"], payload["samples"]
                )
                source = dataset["source_records"][0]
                self.assertEqual(json.loads(source["copy_text"]), payload)
                self.assertEqual(source["attributes"]["sample_count"], 3)
                self.assertNotEqual(source["attributes"]["parser_pid"], os.getpid())
                self.assertEqual(
                    source["evidence"][0]["excerpt_sha256"],
                    hashlib.sha256(raw).hexdigest(),
                )
                self.assertEqual(dataset["diagnostics"][0]["code"], "JSON_ROUNDTRIP")
                self.assertTrue(
                    (
                        control.ingestion.dataset_root
                        / revision.metadata["dataset_ref"]
                    ).is_file()
                )
                self.assertEqual(tuple(control.ingestion.spool_root.iterdir()), ())
            with ControlPlane(
                control_root, registry=registry, pipeline_limits=limits
            ) as reopened:
                self.assertEqual(
                    reopened.load_revision_dataset(
                        reopened.scope("tenant", "project", "workspace"),
                        revision.revision_id,
                    ),
                    dataset,
                )


if __name__ == "__main__":
    unittest.main()
