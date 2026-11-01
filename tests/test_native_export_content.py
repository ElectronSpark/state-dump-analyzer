"""Exercise real extension bytes on a private copy, never the installed binary."""

from __future__ import annotations

import _json
import _socket
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import ExtensionFileLoader
from pathlib import Path

from router_dump_analyzer.plugin_identity import _native_type_image_path


class NativeImageOriginTests(unittest.TestCase):
    @unittest.skipUnless(
        sys.implementation.name == "cpython"
        and type(_socket.__spec__.loader) is ExtensionFileLoader,
        "requires a separate native socket extension image",
    )
    def test_constructor_resolves_actual_loaded_image(self):
        self.assertTrue(
            os.path.samefile(
                _native_type_image_path(_socket.socket),
                _socket.__file__,
            )
        )


@unittest.skipUnless(
    type(_json.__spec__.loader) is ExtensionFileLoader,
    "JSON accelerator is built-in; no separate native binary to copy",
)
class NativeExportContentTests(unittest.TestCase):
    def run_copy(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copied = root / Path(_json.__file__).name
            shutil.copyfile(_json.__file__, copied)
            (root / "alias_fixture.py").write_text(
                "from _json import make_scanner, make_encoder\n"
                "def scanner():\n    return make_scanner\n"
                "def encoder():\n    return make_encoder\n",
                encoding="utf-8",
            )
            script = r"""
import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import _json
import alias_fixture
from router_dump_analyzer import plugin_identity as identity

copied = Path(sys.argv[2])
assert Path(_json.__file__).resolve() == copied.resolve()

def fingerprint(name):
    return identity.executable_module_target_fingerprint(
        "alias_fixture", name, getattr(alias_fixture, name),
    )

if sys.argv[3] == "between":
    before = [fingerprint(name) for name in ("scanner", "encoder")]
    with copied.open("ab") as stream:
        stream.write(b"synthetic-content-change")
    after = [fingerprint(name) for name in ("scanner", "encoder")]
    assert all(first != second for first, second in zip(before, after))
else:
    original = identity._verify_native_export_indexes
    def mutate_then_verify(budget):
        assert any(index.content is not None for index in budget.native_export_indexes.values())
        with copied.open("ab") as stream:
            stream.write(b"changed-during-attestation")
        original(budget)
    with patch.object(identity, "_verify_native_export_indexes", mutate_then_verify):
        try:
            fingerprint("scanner")
        except identity.PluginExecutableIdentityError as error:
            assert "native executable content changed" in str(error), str(error)
        else:
            raise AssertionError("changed extension bytes were accepted")
print("native content verification passed")
"""
            result = subprocess.run(
                [sys.executable, "-c", script, str(root), str(copied), mode],
                env=os.environ.copy(),
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("native content verification passed", result.stdout)

    def test_binary_changes_affect_both_native_alias_identities(self):
        self.run_copy("between")

    def test_binary_changes_during_fingerprinting_are_rejected(self):
        self.run_copy("during")


if __name__ == "__main__":
    unittest.main()
