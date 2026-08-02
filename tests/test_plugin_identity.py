from __future__ import annotations

import importlib
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer.ingestion import IngestionCoordinator
from router_dump_analyzer.ingestion_pipeline import (
    IngestionPipelineError,
    PluginRegistry,
    RegisteredPlugin,
)
from router_dump_analyzer.plugin_identity import (
    PluginExecutableIdentityError,
    executable_plugin_fingerprint,
)


class PluginExecutableIdentityTests(unittest.TestCase):
    def _directory_alias(self, link: Path, target: Path) -> None:
        if os.name == "nt":
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if completed.returncode != 0:
                self.skipTest("Windows junction creation is unavailable")
        else:
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlink creation is unavailable")

    def test_package_resource_bytes_participate_in_fingerprint(self) -> None:
        package_name = "_rda_plugin_identity_fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / package_name
            package.mkdir()
            (package / "__init__.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            resource = package / "rules.json"
            resource.write_text('{"decision":"allow"}\n', encoding="utf-8")
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(package_name)
                first = executable_plugin_fingerprint(module.plugin)
                unchanged = executable_plugin_fingerprint(module.plugin)
                resource.write_text(
                    '{"decision":"deny"}\n',
                    encoding="utf-8",
                )
                second = executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(package_name, None)

        self.assertIsNotNone(first)
        self.assertTrue(first.startswith("package-sha256:"))
        self.assertEqual(first, unchanged)
        self.assertNotEqual(first, second)

    def test_package_enumeration_is_bounded(self) -> None:
        package_name = "_rda_plugin_identity_bounded_fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / package_name
            package.mkdir()
            (package / "__init__.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            (package / "rules.json").write_text("{}", encoding="utf-8")
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(package_name)
                with (
                    patch(
                        "router_dump_analyzer.plugin_identity."
                        "MAX_PLUGIN_PACKAGE_FILES",
                        1,
                    ),
                    self.assertRaisesRegex(
                        PluginExecutableIdentityError,
                        "entry limit",
                    ),
                ):
                    executable_plugin_fingerprint(module.plugin)
                with (
                    patch(
                        "router_dump_analyzer.plugin_identity."
                        "MAX_PLUGIN_PACKAGE_PATHS",
                        1,
                    ),
                    self.assertRaisesRegex(
                        PluginExecutableIdentityError,
                        "path limit",
                    ),
                ):
                    executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(package_name, None)

    def test_empty_directory_enumeration_is_bounded_before_sorting(self) -> None:
        package_name = "_rda_plugin_identity_path_bound_fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / package_name
            package.mkdir()
            (package / "__init__.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            (package / "empty-a").mkdir()
            (package / "empty-b").mkdir()
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(package_name)
                with (
                    patch(
                        "router_dump_analyzer.plugin_identity."
                        "MAX_PLUGIN_PACKAGE_PATHS",
                        2,
                    ),
                    self.assertRaisesRegex(
                        PluginExecutableIdentityError,
                        "path limit",
                    ),
                ):
                    executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(package_name, None)

    def test_namespace_ancestor_conservatively_includes_sibling_content(self) -> None:
        namespace_name = "_rda_identity_namespace"
        module_name = f"{namespace_name}.selected_plugin"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / namespace_name / "selected_plugin"
            sibling = root / namespace_name / "unrelated_plugin"
            selected.mkdir(parents=True)
            sibling.mkdir(parents=True)
            (selected / "__init__.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            selected_rules = selected / "rules.json"
            selected_rules.write_text('{"selected":true}', encoding="utf-8")
            sibling_rules = sibling / "rules.json"
            sibling_rules.write_text('{"unrelated":1}', encoding="utf-8")
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(module_name)
                first = executable_plugin_fingerprint(module.plugin)
                sibling_rules.write_text('{"unrelated":2}', encoding="utf-8")
                after_sibling_change = executable_plugin_fingerprint(module.plugin)
                selected_rules.write_text('{"selected":false}', encoding="utf-8")
                after_selected_change = executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(module_name, None)
                sys.modules.pop(namespace_name, None)

        self.assertNotEqual(first, after_sibling_change)
        self.assertNotEqual(first, after_selected_change)

    def test_flat_namespace_helper_bytes_participate_in_fingerprint(self) -> None:
        namespace_name = "_rda_identity_flat_namespace"
        module_name = f"{namespace_name}.plugin"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            namespace = root / namespace_name
            namespace.mkdir()
            helper = namespace / "helper.py"
            helper.write_text("VALUE = 'allow'\n", encoding="utf-8")
            (namespace / "plugin.py").write_text(
                "from .helper import VALUE\n"
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(module_name)
                first = executable_plugin_fingerprint(module.plugin)
                unchanged = executable_plugin_fingerprint(module.plugin)
                helper.write_text("VALUE = 'deny'\n", encoding="utf-8")
                changed = executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(module_name, None)
                sys.modules.pop(f"{namespace_name}.helper", None)
                sys.modules.pop(namespace_name, None)

        self.assertIsNotNone(first)
        self.assertTrue(first.startswith("package-sha256:"))
        self.assertEqual(first, unchanged)
        self.assertNotEqual(first, changed)

    def test_nested_namespace_parent_relative_helper_participates(self) -> None:
        namespace_name = "_rda_identity_nested_namespace"
        module_name = f"{namespace_name}.product.plugin"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            namespace = root / namespace_name
            product = namespace / "product"
            product.mkdir(parents=True)
            (product / "__init__.py").write_text("", encoding="utf-8")
            helper = namespace / "shared.py"
            helper.write_text("VALUE = 'allow'\n", encoding="utf-8")
            (product / "plugin.py").write_text(
                "from ..shared import VALUE\n"
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(module_name)
                first = executable_plugin_fingerprint(module.plugin)
                helper.write_text("VALUE = 'deny'\n", encoding="utf-8")
                changed = executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(module_name, None)
                sys.modules.pop(f"{namespace_name}.product", None)
                sys.modules.pop(f"{namespace_name}.shared", None)
                sys.modules.pop(namespace_name, None)

        self.assertNotEqual(first, changed)

    def test_flat_namespace_tamper_is_rejected_during_revalidation(self) -> None:
        namespace_name = "_rda_identity_revalidation_namespace"
        module_name = f"{namespace_name}.plugin"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            namespace = root / namespace_name
            namespace.mkdir()
            helper = namespace / "helper.py"
            helper.write_text("VALUE = 'allow'\n", encoding="utf-8")
            (namespace / "plugin.py").write_text(
                "from .helper import VALUE\n"
                "class Manifest:\n"
                "    plugin_id = 'test.flat'\n"
                "    plugin_version = '1'\n"
                "class Plugin:\n"
                "    manifest = Manifest()\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(module_name)
                fingerprint = executable_plugin_fingerprint(module.plugin)
                assert fingerprint is not None
                record = RegisteredPlugin(
                    plugin=module.plugin,
                    coordinator=IngestionCoordinator(),
                    package_hash=fingerprint,
                    verify_package_bytes=True,
                )
                helper.write_text("VALUE = 'deny'\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    IngestionPipelineError,
                    "executable bytes changed after registration",
                ):
                    PluginRegistry.revalidate_executable_identity(record)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(module_name, None)
                sys.modules.pop(f"{namespace_name}.helper", None)
                sys.modules.pop(namespace_name, None)

    def test_flat_namespace_identity_covers_all_search_locations_and_bounds(
        self,
    ) -> None:
        namespace_name = "_rda_identity_split_namespace"
        module_name = f"{namespace_name}.plugin"
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory)
            primary_root = outer / "primary"
            secondary_root = outer / "secondary"
            primary = primary_root / namespace_name
            secondary = secondary_root / namespace_name
            primary.mkdir(parents=True)
            secondary.mkdir(parents=True)
            (primary / "plugin.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            secondary_helper = secondary / "helper.py"
            secondary_helper.write_text("VALUE = 1\n", encoding="utf-8")
            sys.path[:0] = [str(primary_root), str(secondary_root)]
            try:
                module = importlib.import_module(module_name)
                first = executable_plugin_fingerprint(module.plugin)
                secondary_helper.write_text("VALUE = 2\n", encoding="utf-8")
                changed = executable_plugin_fingerprint(module.plugin)
                with (
                    patch(
                        "router_dump_analyzer.plugin_identity."
                        "MAX_PLUGIN_PACKAGE_FILES",
                        1,
                    ),
                    self.assertRaisesRegex(
                        PluginExecutableIdentityError,
                        "entry limit",
                    ),
                ):
                    executable_plugin_fingerprint(module.plugin)
                with (
                    patch(
                        "router_dump_analyzer.plugin_identity."
                        "MAX_PLUGIN_PACKAGE_PATHS",
                        1,
                    ),
                    self.assertRaisesRegex(
                        PluginExecutableIdentityError,
                        "path limit",
                    ),
                ):
                    executable_plugin_fingerprint(module.plugin)
            finally:
                del sys.path[:2]
                sys.modules.pop(module_name, None)
                sys.modules.pop(namespace_name, None)

        self.assertNotEqual(first, changed)

    def test_runtime_namespace_path_is_hashed_and_cannot_drop_source(self) -> None:
        namespace_name = "_rda_identity_runtime_namespace"
        module_name = f"{namespace_name}.plugin"
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory)
            root = outer / "root"
            namespace = root / namespace_name
            added_root = outer / "added"
            added_namespace = added_root / namespace_name
            namespace.mkdir(parents=True)
            added_namespace.mkdir(parents=True)
            (namespace / "plugin.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            helper = added_namespace / "late_helper.py"
            helper.write_text("VALUE = 1\n", encoding="utf-8")
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(module_name)
                namespace_module = sys.modules[namespace_name]
                namespace_module.__path__ = [  # type: ignore[attr-defined]
                    str(namespace),
                    str(added_namespace),
                ]
                first = executable_plugin_fingerprint(module.plugin)
                helper.write_text("VALUE = 2\n", encoding="utf-8")
                changed = executable_plugin_fingerprint(module.plugin)
                namespace_module.__path__ = [  # type: ignore[attr-defined]
                    str(added_namespace)
                ]
                with self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "do not contain its defining module",
                ):
                    executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(module_name, None)
                sys.modules.pop(namespace_name, None)

        self.assertNotEqual(first, changed)

    def test_empty_directory_changes_identity_and_is_revalidated(self) -> None:
        package_name = "_rda_identity_empty_directory"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / package_name
            package.mkdir()
            (package / "__init__.py").write_text(
                "class Manifest:\n"
                "    plugin_id = 'test.directory'\n"
                "    plugin_version = '1'\n"
                "class Plugin:\n"
                "    manifest = Manifest()\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(package_name)
                first = executable_plugin_fingerprint(module.plugin)
                assert first is not None
                record = RegisteredPlugin(
                    plugin=module.plugin,
                    coordinator=IngestionCoordinator(),
                    package_hash=first,
                    verify_package_bytes=True,
                )
                empty = package / "future_namespace"
                empty.mkdir()
                added = executable_plugin_fingerprint(module.plugin)
                with self.assertRaisesRegex(
                    IngestionPipelineError,
                    "executable bytes changed after registration",
                ):
                    PluginRegistry.revalidate_executable_identity(record)
                empty.rmdir()
                restored = executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(package_name, None)

        self.assertNotEqual(first, added)
        self.assertEqual(first, restored)

    def test_growing_file_read_is_bounded_by_declared_size(self) -> None:
        package_name = "_rda_identity_growing_file"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / package_name
            package.mkdir()
            (package / "__init__.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            resource = package / "rules.bin"
            resource.write_bytes(b"rule")
            declared_size = resource.stat().st_size
            bytes_returned = 0
            original_open = Path.open

            class _GrowingStream:
                def __init__(self, stream):
                    self.stream = stream
                    self.grown = False

                def __enter__(self):
                    self.stream.__enter__()
                    return self

                def __exit__(self, *values):
                    return self.stream.__exit__(*values)

                def fileno(self):
                    return self.stream.fileno()

                def read(self, size=-1):
                    nonlocal bytes_returned
                    chunk = self.stream.read(size)
                    bytes_returned += len(chunk)
                    if not self.grown:
                        self.grown = True
                        descriptor = os.open(resource, os.O_WRONLY | os.O_APPEND)
                        try:
                            os.write(descriptor, b"x" * (2 * 1024 * 1024))
                        finally:
                            os.close(descriptor)
                    return chunk

            def _open(path, *args, **kwargs):
                stream = original_open(path, *args, **kwargs)
                if path == resource and args and args[0] == "rb":
                    return _GrowingStream(stream)
                return stream

            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(package_name)
                with (
                    patch.object(Path, "open", new=_open),
                    self.assertRaisesRegex(
                        PluginExecutableIdentityError,
                        "changed while fingerprinting",
                    ),
                ):
                    executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(package_name, None)

        self.assertLessEqual(bytes_returned, declared_size + 1)

    def test_flat_namespace_aliases_are_path_independent_and_cannot_escape(
        self,
    ) -> None:
        namespace_name = "_rda_identity_flat_alias_namespace"
        module_name = f"{namespace_name}.plugin"
        fingerprints: list[str | None] = []
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory)
            for install_name in ("install-a", "install-b"):
                root = outer / install_name
                namespace = root / namespace_name
                resources = namespace / "resources"
                resources.mkdir(parents=True)
                (namespace / "plugin.py").write_text(
                    "class Plugin:\n"
                    "    pass\n"
                    "plugin = Plugin()\n",
                    encoding="utf-8",
                )
                (resources / "rules.json").write_text(
                    '{"decision":"allow"}', encoding="utf-8"
                )
                self._directory_alias(namespace / "resource-alias", resources)
                sys.path.insert(0, str(root))
                try:
                    module = importlib.import_module(module_name)
                    fingerprints.append(
                        executable_plugin_fingerprint(module.plugin)
                    )
                finally:
                    sys.path.remove(str(root))
                    sys.modules.pop(module_name, None)
                    sys.modules.pop(namespace_name, None)

            escape_root = outer / "escape-install"
            namespace = escape_root / namespace_name
            external = escape_root / "external"
            namespace.mkdir(parents=True)
            external.mkdir()
            (namespace / "plugin.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            self._directory_alias(namespace / "external-alias", external)
            sys.path.insert(0, str(escape_root))
            try:
                module = importlib.import_module(module_name)
                with self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "escapes its package root",
                ):
                    executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(escape_root))
                sys.modules.pop(module_name, None)
                sys.modules.pop(namespace_name, None)

        self.assertEqual(fingerprints[0], fingerprints[1])

    def test_top_level_module_identity_is_not_labeled_as_a_package(self) -> None:
        module_name = "_rda_identity_top_level_module"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / f"{module_name}.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(module_name)
                fingerprint = executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(module_name, None)

        self.assertIsNotNone(fingerprint)
        self.assertTrue(fingerprint.startswith("module-sha256:"))

    def test_contained_directory_alias_is_cycle_safe_and_path_independent(
        self,
    ) -> None:
        package_name = "_rda_identity_alias_fixture"
        fingerprints: list[tuple[str | None, str | None]] = []
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory)
            for install_name in ("install-a", "install-b"):
                root = outer / install_name
                package = root / package_name
                resources = package / "resources"
                resources.mkdir(parents=True)
                (package / "__init__.py").write_text(
                    "class Plugin:\n"
                    "    pass\n"
                    "plugin = Plugin()\n",
                    encoding="utf-8",
                )
                (resources / "rules.json").write_text(
                    '{"decision":"allow"}', encoding="utf-8"
                )
                self._directory_alias(package / "resource-alias", resources)
                self._directory_alias(package / "package-cycle", package)
                sys.path.insert(0, str(root))
                try:
                    module = importlib.import_module(package_name)
                    before = executable_plugin_fingerprint(module.plugin)
                    (resources / "rules.json").write_text(
                        '{"decision":"deny"}', encoding="utf-8"
                    )
                    fingerprints.append(
                        (before, executable_plugin_fingerprint(module.plugin))
                    )
                finally:
                    sys.path.remove(str(root))
                    sys.modules.pop(package_name, None)

        self.assertEqual(fingerprints[0], fingerprints[1])
        self.assertNotEqual(fingerprints[0][0], fingerprints[0][1])

    def test_alias_outside_package_fails_closed_without_host_path(self) -> None:
        package_name = "_rda_identity_external_alias_fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / package_name
            external = root / "external"
            package.mkdir()
            external.mkdir()
            (package / "__init__.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            self._directory_alias(package / "external-alias", external)
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(package_name)
                with self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "alias 'external-alias' escapes its package root",
                ) as raised:
                    executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(package_name, None)

        self.assertNotIn(str(root), str(raised.exception))

    def test_sourceless_bytecode_requires_loader_supplied_identity(self) -> None:
        module_name = "_rda_identity_sourceless_module"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / f"{module_name}.py"
            bytecode = root / f"{module_name}.pyc"
            source.write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            py_compile.compile(
                str(source),
                cfile=str(bytecode),
                dfile="C:/build-host/private/plugin.py",
                doraise=True,
            )
            source.unlink()
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(module_name)
                with self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "sourceless Python bytecode",
                ):
                    executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(module_name, None)

    def test_ignored_metadata_directory_contents_do_not_change_identity(self) -> None:
        package_name = "_rda_identity_ignored_directory_fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / package_name
            package.mkdir()
            (package / "__init__.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            metadata_directory = package / ".git"
            metadata_directory.mkdir()
            metadata_file = metadata_directory / "index"
            metadata_file.write_text("ignored", encoding="utf-8")
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(package_name)
                first = executable_plugin_fingerprint(module.plugin)
                metadata_file.write_text("changed", encoding="utf-8")
                second = executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(package_name, None)

        self.assertEqual(first, second)

    def test_regular_file_with_ignored_directory_name_is_fingerprinted(self) -> None:
        package_name = "_rda_identity_ignored_name_file_fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / package_name
            package.mkdir()
            (package / "__init__.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            named_like_metadata = package / ".git"
            named_like_metadata.write_text("first", encoding="utf-8")
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(package_name)
                first = executable_plugin_fingerprint(module.plugin)
                named_like_metadata.write_text("second", encoding="utf-8")
                second = executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(package_name, None)

        self.assertNotEqual(first, second)

    def test_alias_with_ignored_directory_name_is_fingerprinted(self) -> None:
        package_name = "_rda_identity_ignored_name_alias_fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / package_name
            resources = package / "resources"
            resources.mkdir(parents=True)
            (package / "__init__.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            (resources / "rules.json").write_text("{}", encoding="utf-8")
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(package_name)
                before_alias = executable_plugin_fingerprint(module.plugin)
                self._directory_alias(package / ".git", resources)
                with_alias = executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(package_name, None)

        self.assertNotEqual(before_alias, with_alias)

    def test_alias_with_ignored_name_still_obeys_containment_policy(self) -> None:
        package_name = "_rda_identity_ignored_name_escape_fixture"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / package_name
            external = root / "external-vcs-data"
            package.mkdir()
            external.mkdir()
            (package / "__init__.py").write_text(
                "class Plugin:\n"
                "    pass\n"
                "plugin = Plugin()\n",
                encoding="utf-8",
            )
            self._directory_alias(package / ".git", external)
            sys.path.insert(0, str(root))
            try:
                module = importlib.import_module(package_name)
                with self.assertRaisesRegex(
                    PluginExecutableIdentityError,
                    "escapes its package root",
                ):
                    executable_plugin_fingerprint(module.plugin)
            finally:
                sys.path.remove(str(root))
                sys.modules.pop(package_name, None)


if __name__ == "__main__":
    unittest.main()
