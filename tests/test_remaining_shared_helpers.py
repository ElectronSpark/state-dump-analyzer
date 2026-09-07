"""Small boundary parity gates for the remaining shared-core helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from router_dump_analyzer import canonical, ingestion_pipeline, plugin_execution_plan
from router_dump_analyzer import plugin_registration, private_analysis_run_store, value_core
from router_dump_analyzer.private_analysis import contracts, evidence
from tests.test_private_ai_architecture import _private_analysis_import_violations


class _HostileString(str):
    def __len__(self):
        raise AssertionError("must reject subclasses before reading their values")


class _IntegerSubclass(int):
    pass


class SharedDigestTests(unittest.TestCase):
    def test_bare_digest_adapters_are_one_exact_grammar_with_unchanged_errors(self):
        self.assertIs(contracts._bare_sha256, canonical.validate_lowercase_sha256)
        self.assertIs(evidence._sha256, canonical.validate_lowercase_sha256)
        for digest in ("0" * 64, "0123456789abcdef" * 4):
            self.assertEqual(contracts._bare_sha256(digest, "digest"), digest)
            self.assertEqual(evidence._sha256(digest, "digest"), digest)
        for value in (
            None,
            True,
            123,
            b"a" * 64,
            "a" * 63,
            "a" * 65,
            "A" * 64,
            "g" * 64,
            "ａ" * 64,
            "a" * 63 + "\n",
            "sha256:" + "a" * 64,
            _HostileString("a" * 64),
        ):
            with self.subTest(type=type(value), value=value):
                with self.assertRaisesRegex(
                    ValueError, "^digest must be a lowercase SHA-256 digest$"
                ):
                    contracts._bare_sha256(value, "digest")

    def test_prefixed_adapter_uses_bare_grammar_without_changing_its_error_text(self):
        digest = "sha256:" + "a" * 64
        with patch.object(
            canonical,
            "validate_lowercase_sha256",
            wraps=canonical.validate_lowercase_sha256,
        ) as validate:
            self.assertEqual(
                canonical.validate_prefixed_lowercase_sha256(digest, "id"), digest
            )
            validate.assert_called_once_with("a" * 64, "id")
        for value in (
            None,
            "a" * 64,
            "SHA256:" + "a" * 64,
            "sha256:" + "A" * 64,
            _HostileString(digest),
        ):
            with self.subTest(type=type(value), value=value):
                with self.assertRaisesRegex(
                    ValueError, "^id must be a sha256-prefixed lowercase digest$"
                ):
                    canonical.validate_prefixed_lowercase_sha256(value, "id")


class SharedExactIntegerTests(unittest.TestCase):
    def test_integer_adapters_share_predicate_and_keep_boundary_wording(self):
        self.assertIs(evidence._integer, value_core.require_bounded_integer)
        self.assertIs(
            contracts.require_bounded_integer, value_core.require_bounded_integer
        )
        self.assertIs(
            private_analysis_run_store.require_bounded_integer,
            value_core.require_bounded_integer,
        )
        for value in (0, 1, 2):
            self.assertEqual(contracts._integer(value, "count", 0, 2), value)
            self.assertEqual(
                private_analysis_run_store._bounded_integer(
                    value, "count", minimum=0, maximum=2
                ),
                value,
            )
        for value in (False, True, -1, 3, 1.0, "1", None, _IntegerSubclass(1)):
            with self.subTest(value=value, type=type(value)):
                with self.assertRaisesRegex(
                    ValueError, "^count must be between 0 and 2$"
                ):
                    contracts._integer(value, "count", 0, 2)
                with self.assertRaisesRegex(
                    ValueError, "^count must be an integer from 0 to 2$"
                ):
                    private_analysis_run_store._bounded_integer(
                        value, "count", minimum=0, maximum=2
                    )

    def test_private_import_boundary_approves_only_selected_shared_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture.py"
            fixture.write_text(
                "from ..canonical import validate_lowercase_sha256\n"
                "from ..value_core import require_bounded_integer\n",
                encoding="utf-8",
            )
            self.assertEqual(_private_analysis_import_violations(root), ())
            fixture.write_text(
                "from ..value_core import normalize_enum_value\n", encoding="utf-8"
            )
            violations = _private_analysis_import_violations(root)
            self.assertTrue(any("unapproved members" in item for item in violations))


class SharedDecoderSnapshotTests(unittest.TestCase):
    def test_pipeline_adapter_delegates_to_one_detaching_revalidating_implementation(
        self,
    ):
        snapshot = plugin_execution_plan._snapshot_decoder_identity
        self.assertIs(plugin_registration._plan_snapshot_decoder_identity, snapshot)
        self.assertIs(
            ingestion_pipeline._snapshot_decoder_identity,
            plugin_registration._snapshot_decoder_identity,
        )
        original = plugin_execution_plan.DecoderIdentity(
            "decoder", "1", "sha256:" + "a" * 64
        )
        detached = ingestion_pipeline._snapshot_decoder_identity(original)
        self.assertEqual(detached, original)
        self.assertIsNot(detached, original)
        object.__setattr__(original, "decoder_id", "changed")
        self.assertEqual(detached.decoder_id, "decoder")
        for field, value, error in (
            ("decoder_id", _HostileString("decoder"), TypeError),
            ("decoder_version", " contains space", ValueError),
            ("executable_digest", "sha256:" + "A" * 64, ValueError),
        ):
            for adapter in (snapshot, ingestion_pipeline._snapshot_decoder_identity):
                with self.subTest(field=field, adapter=adapter):
                    corrupted = plugin_execution_plan.DecoderIdentity(
                        "decoder", "1", "sha256:" + "a" * 64
                    )
                    object.__setattr__(corrupted, field, value)
                    with self.assertRaises(error):
                        adapter(corrupted)

    def test_decoder_adapters_keep_exact_type_and_contextual_error_contracts(self):
        class DerivedDecoder(plugin_execution_plan.DecoderIdentity):
            pass

        for value in (
            None,
            object(),
            DerivedDecoder("decoder", "1", "sha256:" + "a" * 64),
        ):
            with self.assertRaisesRegex(TypeError, "^decoder must be DecoderIdentity$"):
                plugin_execution_plan._snapshot_decoder_identity(value)
            with self.assertRaisesRegex(
                TypeError, "^decoder identity must be an exact DecoderIdentity$"
            ):
                ingestion_pipeline._snapshot_decoder_identity(value)


if __name__ == "__main__":
    unittest.main()
