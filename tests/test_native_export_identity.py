from __future__ import annotations

import _io
import _json
import copy
import importlib
import json.encoder
import json.scanner
import sys
import tempfile
import unittest
from contextlib import contextmanager
from importlib.machinery import EXTENSION_SUFFIXES, ExtensionFileLoader, ModuleSpec
from pathlib import Path
from unittest.mock import patch

import router_dump_analyzer.plugin_identity as identity_module
from router_dump_analyzer.ingestion_pipeline import (
    IngestionPipelineError,
    PluginExecutionMode,
    PluginRegistry,
    _ingest_registered_plugin,
)
from router_dump_analyzer.plugin_identity import (
    PluginExecutableIdentityError,
    executable_callable_fingerprint,
    executable_module_target_fingerprint,
)

_ALIASES = (
    ("scanner", _json, "make_scanner"),
    ("encoder", _json, "make_encoder"),
    ("scanner", json.scanner, "make_scanner"),
    ("encoder", json.encoder, "c_make_encoder"),
)


@contextmanager
def _module_fixture(extra=""):
    name = "_rda_native_export_identity_fixture"
    source = (
        "import _json\n"
        "import json\n"
        "import json.encoder\n"
        "import json.scanner\n"
        "from tests.fixtures.native_alias_plugin import NativeAliasPlugin\n\n"
        "def scanner():\n"
        "    return json.scanner.make_scanner\n\n"
        "def encoder():\n"
        "    return json.encoder.c_make_encoder\n\n"
        "def roundtrip(value):\n"
        "    return json.loads(json.dumps(value))\n\n"
        "def replacement_call(self, *args, **kwargs):\n"
        "    return None\n\n"
        "class Parser(NativeAliasPlugin):\n"
        "    def parse_status(self, reader, spec):\n"
        "        assert json.loads(json.dumps({'sample': 1})) == {'sample': 1}\n"
        "        yield from super().parse_status(reader, spec)\n"
        "        with open(reader.inventory.metadata['marker'], 'w', encoding='utf-8') as marker:\n"
        "            marker.write('parsed')\n"
        + ("        " + extra + "\n" if extra else "")
        + "\nplugin = Parser()\n"
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / (name + ".py")).write_text(source, encoding="utf-8")
        sys.path.insert(0, directory)
        importlib.invalidate_caches()
        try:
            yield importlib.import_module(name), root
        finally:
            sys.modules.pop(name, None)
            sys.path.remove(directory)
            importlib.invalidate_caches()


class NativeExportIdentityTests(unittest.TestCase):
    @staticmethod
    def fingerprints(module, name):
        target = getattr(module, name)
        return (
            executable_module_target_fingerprint(module.__name__, name, target),
            executable_callable_fingerprint(target),
        )

    @staticmethod
    def fixture_input(root):
        source = root / "counters.json"
        source.write_text(
            '{"captured_at_ns":100,"samples":[{"time":100,"received":7,"sent":2}]}\n',
            encoding="utf-8",
        )
        return source

    def test_scanner_and_encoder_aliases_use_real_fingerprint_entrypoints(self):
        with _module_fixture() as (module, _root):
            for name, native_name in (
                ("scanner", "make_scanner"),
                ("encoder", "make_encoder"),
            ):
                with self.subTest(name=name):
                    native_type = getattr(_json, native_name)
                    self.assertIs(getattr(module, name)(), native_type)
                    self.assertIsNot(vars(_json).get(native_type.__name__), native_type)
                    identities = self.fingerprints(module, name)
                    self.assertEqual(self.fingerprints(module, name), identities)
            self.assertEqual(
                module.roundtrip({"value": [1, True, None]}), {"value": [1, True, None]}
            )
            self.assertEqual(
                self.fingerprints(module, "roundtrip"),
                self.fingerprints(module, "roundtrip"),
            )

    def test_forged_native_module_metadata_is_rejected(self):
        with _module_fixture() as (module, root):
            forged_path = root / "unrelated.pyd"
            forged_path.write_bytes(b"not a native executable")
            original_spec = _json.__spec__
            for name in ("scanner", "encoder"):
                for field, value in (
                    ("origin", "forged-native"),
                    ("loader", None),
                    ("name", "forged_json"),
                ):
                    spec = copy.copy(original_spec)
                    setattr(spec, field, value)
                    with (
                        self.subTest(name=name, field=field),
                        patch.object(_json, "__spec__", spec),
                    ):
                        for fingerprint in (
                            lambda name=name: executable_module_target_fingerprint(
                                module.__name__, name, getattr(module, name)
                            ),
                            lambda name=name: executable_callable_fingerprint(
                                getattr(module, name)
                            ),
                        ):
                            with self.assertRaises(PluginExecutableIdentityError):
                                fingerprint()
                with (
                    self.subTest(name=name, field="loader_binding"),
                    patch.object(_json, "__loader__", None),
                    self.assertRaises(PluginExecutableIdentityError),
                ):
                    self.fingerprints(module, name)
                with (
                    self.subTest(name=name, field="file_binding"),
                    patch.object(_json, "__file__", str(forged_path), create=True),
                    self.assertRaises(PluginExecutableIdentityError),
                ):
                    self.fingerprints(module, name)

    def test_mutated_native_type_call_is_rejected_by_public_fingerprints(self):
        with _module_fixture() as (module, _root):
            for name, native_name in (
                ("scanner", "make_scanner"),
                ("encoder", "make_encoder"),
            ):
                with self.subTest(name=name):
                    native_type = getattr(_json, native_name)
                    self.fingerprints(module, name)
                    original_call = native_type.__call__
                    try:
                        native_type.__call__ = module.replacement_call
                    except TypeError:
                        self.skipTest(
                            "this runtime makes the native JSON type immutable"
                        )
                    try:
                        for fingerprint in (
                            lambda name=name: executable_module_target_fingerprint(
                                module.__name__, name, getattr(module, name)
                            ),
                            lambda name=name: executable_callable_fingerprint(
                                getattr(module, name)
                            ),
                        ):
                            with self.assertRaises(PluginExecutableIdentityError):
                                fingerprint()
                    finally:
                        native_type.__call__ = original_call

    def test_coherent_forged_extension_metadata_is_rejected(self):
        with _module_fixture() as (module, root):
            forged_path = root / ("_json" + EXTENSION_SUFFIXES[0])
            forged_path.write_bytes(b"not an executable native extension")
            loader = ExtensionFileLoader("_json", str(forged_path))
            spec = ModuleSpec("_json", loader, origin=str(forged_path))
            with (
                patch.object(_json, "__spec__", spec),
                patch.object(_json, "__loader__", loader),
                patch.object(_json, "__file__", str(forged_path), create=True),
            ):
                for name in ("scanner", "encoder"):
                    with self.subTest(name=name):
                        for fingerprint in (
                            lambda name=name: executable_module_target_fingerprint(
                                module.__name__, name, getattr(module, name)
                            ),
                            lambda name=name: executable_callable_fingerprint(
                                getattr(module, name)
                            ),
                        ):
                            with self.assertRaises(PluginExecutableIdentityError):
                                fingerprint()

    def test_real_native_type_cannot_be_retagged_to_another_native_module(self):
        with _module_fixture() as (module, _root):
            for name, native_name in (
                ("scanner", "make_scanner"),
                ("encoder", "make_encoder"),
            ):
                with self.subTest(name=name):
                    native_type = getattr(_json, native_name)
                    self.fingerprints(module, name)
                    original_module = native_type.__module__
                    try:
                        native_type.__module__ = "_io"
                    except TypeError:
                        self.skipTest(
                            "this runtime makes the native JSON type immutable"
                        )
                    try:
                        for export in (
                            "native_alias_identity_trial",
                            native_type.__qualname__,
                        ):
                            with (
                                self.subTest(export=export),
                                patch.object(_io, export, native_type, create=True),
                            ):
                                for fingerprint in (
                                    lambda name=name: (
                                        executable_module_target_fingerprint(
                                            module.__name__, name, getattr(module, name)
                                        )
                                    ),
                                    lambda name=name: executable_callable_fingerprint(
                                        getattr(module, name)
                                    ),
                                ):
                                    with self.assertRaises(
                                        PluginExecutableIdentityError
                                    ):
                                        fingerprint()
                    finally:
                        native_type.__module__ = original_module

    def test_native_qualname_drift_is_rejected_by_final_attestation(self):
        original_verify = identity_module._verify_native_export_indexes
        with _module_fixture() as (module, _root):
            for name, native_name in (
                ("scanner", "make_scanner"),
                ("encoder", "make_encoder"),
            ):
                native_type = getattr(_json, native_name)
                original_qualname = native_type.__qualname__

                def mutate_then_verify(
                    budget,
                    native_type=native_type,
                    original_qualname=original_qualname,
                ):
                    native_type.__qualname__ = "Changed." + original_qualname
                    original_verify(budget)

                for fingerprint in (
                    lambda name=name: executable_module_target_fingerprint(
                        module.__name__, name, getattr(module, name)
                    ),
                    lambda name=name: executable_callable_fingerprint(
                        getattr(module, name)
                    ),
                ):
                    with self.subTest(name=name, fingerprint=fingerprint):
                        self.fingerprints(module, name)
                        try:
                            with (
                                patch.object(
                                    identity_module,
                                    "_verify_native_export_indexes",
                                    mutate_then_verify,
                                ),
                                self.assertRaises(PluginExecutableIdentityError),
                            ):
                                fingerprint()
                        finally:
                            native_type.__qualname__ = original_qualname

    def test_python_types_cannot_claim_native_alias_provenance(self):
        class SpoofFlags(type):
            @property
            def __flags__(cls):
                return 0x100

        with _module_fixture() as (module, _root):
            for factory in (type, SpoofFlags):
                for name, native_name, owner, alias in (
                    ("scanner", "make_scanner", json.scanner, "make_scanner"),
                    ("encoder", "make_encoder", json.encoder, "c_make_encoder"),
                ):
                    native_type = getattr(_json, native_name)
                    forged = factory(native_type.__name__, (), {"__module__": "_json"})
                    with (
                        self.subTest(name=name, metaclass=factory.__name__),
                        patch.object(_json, native_name, forged),
                        patch.object(owner, alias, forged),
                    ):
                        for fingerprint in (
                            lambda name=name: executable_module_target_fingerprint(
                                module.__name__, name, getattr(module, name)
                            ),
                            lambda name=name: executable_callable_fingerprint(
                                getattr(module, name)
                            ),
                        ):
                            with self.assertRaises(PluginExecutableIdentityError):
                                fingerprint()

    def test_replaced_native_and_stdlib_exports_fail_before_registered_ingestion(self):
        with _module_fixture() as (module, root):
            source = self.fixture_input(root)
            marker = root / "parsed.txt"
            for name, owner, alias in _ALIASES:
                with self.subTest(name=name, owner=owner.__name__, alias=alias):
                    registered = PluginRegistry().register(module.plugin)
                    with (
                        patch.object(owner, alias, None),
                        self.assertRaises(IngestionPipelineError),
                    ):
                        _ingest_registered_plugin(
                            registered,
                            source,
                            execution_mode=PluginExecutionMode.INLINE,
                            node_hint=None,
                            metadata={"marker": str(marker)},
                        )
                    self.assertFalse(
                        marker.exists(),
                        "replaced export must fail before parser invocation",
                    )

    def test_replaced_native_and_stdlib_exports_fail_after_parser_invocation(self):
        for name, owner, alias in _ALIASES:
            with self.subTest(name=name, owner=owner.__name__, alias=alias):
                original = getattr(owner, alias)
                try:
                    with _module_fixture(f"{owner.__name__}.{alias} = None") as (
                        module,
                        root,
                    ):
                        source = self.fixture_input(root)
                        marker = root / "parsed.txt"
                        registered = PluginRegistry().register(module.plugin)
                        with self.assertRaises(IngestionPipelineError):
                            _ingest_registered_plugin(
                                registered,
                                source,
                                execution_mode=PluginExecutionMode.INLINE,
                                node_hint=None,
                                metadata={"marker": str(marker)},
                            )
                        self.assertEqual(marker.read_text(encoding="utf-8"), "parsed")
                        self.assertIsNone(getattr(owner, alias))
                finally:
                    setattr(owner, alias, original)


if __name__ == "__main__":
    unittest.main()
