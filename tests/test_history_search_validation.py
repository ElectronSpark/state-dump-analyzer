from __future__ import annotations

import gc
import os
import sqlite3
import struct
import unittest
import weakref
import zlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from hashlib import sha256
from tempfile import TemporaryDirectory
from unittest.mock import patch

from router_dump_analyzer._history_search_cache import _SearchResultCache
from router_dump_analyzer._history_search_validation import _ValidationCache
from router_dump_analyzer.history_search_core import HistorySearchCorpus


class CompressedValidationReuseTests(unittest.TestCase):
    def setUp(self):
        self.validation_cache = _ValidationCache()
        self.results = _SearchResultCache()
        self.folder = TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "search.sqlite"
        self.documents = tuple(
            f"route-{index}: " + ("rare-雪\0tail" if index % 11 == 0 else "common")
            for index in range(70)
        )
        for target, value in (
            ("_validated_compressed", self.validation_cache),
            ("_shared_results", self.results),
        ):
            patcher = patch(f"router_dump_analyzer.history_search_core.{target}", value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(HistorySearchCorpus, "_BLOCK_TARGET_BYTES", 100)
        patcher.start()
        self.addCleanup(patcher.stop)

    def corpus(self, **kwargs):
        return HistorySearchCorpus(
            sidecar_path=self.path, identity="safe-projection",
            max_eager_candidate_characters=1, **kwargs,
        )

    def build(self):
        corpus = self.corpus()
        matches = corpus.query("rare-雪\0tail", lambda: self.documents)
        self.assertGreater(len(corpus._block_digests), 1)
        corpus.close()
        return matches

    def test_cached_navigation_hashes_bytes_without_decompression_or_postings_expansion(self):
        expected = self.build()
        for eager in (True, False):
            with self.subTest(eager=eager), patch(
                "router_dump_analyzer.history_search_core.zlib.decompressobj",
                side_effect=AssertionError("repeated decompression"),
            ):
                reopened = self.corpus(eager_validate_sidecar=eager)
                with patch.object(reopened, "_query_ready", side_effect=AssertionError("rescan")):
                    self.assertIs(reopened.query("rare-雪\0tail", lambda: self.fail("builder")), expected)
                reopened.close()

    def test_uncached_navigation_fuses_matching_with_validated_utf8_bytes(self):
        self.build()
        reopened = self.corpus(eager_validate_sidecar=False)
        iterator = reopened._iter_disk_documents
        with patch.object(reopened, "_iter_disk_documents", wraps=iterator) as scans:
            for needle in ("common", "rare-雪", "\0tail", "", "absent", "\ud800"):
                self.assertEqual(list(reopened.query(needle, lambda: self.fail("builder"))),
                                 [index for index, text in enumerate(self.documents) if needle in text])
            self.assertTrue(scans.call_args_list)
            self.assertTrue(all(call.kwargs.get("_matching_needle") is not None
                                for call in scans.call_args_list))
        reopened.close()

    def test_empty_process_cache_performs_complete_validator(self):
        self.build()
        self.validation_cache = _ValidationCache()
        with patch("router_dump_analyzer.history_search_core._validated_compressed", self.validation_cache):
            with patch(
                "router_dump_analyzer.history_search_core.zlib.decompressobj", wraps=zlib.decompressobj,
            ) as decoder, patch.object(
                HistorySearchCorpus, "_compressed_snapshot",
                side_effect=AssertionError("speculative payload pass on cold cache"),
            ):
                reopened = self.corpus()
                self.assertTrue(reopened.ready)
                self.assertEqual(decoder.call_count, len(reopened._block_digests))
                self.assertEqual(len(self.validation_cache._entries), 1)
                maximum, _ = next(iter(self.validation_cache._entries.values()))
                self.assertEqual(maximum, max(len(text.encode("utf-8")) for text in self.documents))
                reopened.close()
            with patch(
                "router_dump_analyzer.history_search_core.zlib.decompressobj",
                side_effect=AssertionError("cold validation must certify subsequent reuse"),
            ):
                reused = self.corpus()
                self.assertTrue(reused.ready)
                reused.close()

    def test_cold_validation_hashes_original_utf8_frames_and_fuses_exact_matching(self):
        self.documents = ("", "雪", "é\0🛤", "end", "start", "", "tail")
        first = self.corpus()
        first.query("雪", lambda: self.documents)
        first.close()
        canonical = sha256()
        for ordinal, text in enumerate(self.documents):
            encoded = text.encode("utf-8")
            canonical.update(ordinal.to_bytes(8, "big"))
            canonical.update(len(encoded).to_bytes(8, "big"))
            canonical.update(encoded)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute(
                "SELECT documents_digest FROM metadata"
            ).fetchone()[0], canonical.hexdigest())
        for needle in ("", "雪", "é\0🛤", "endstart", "\ud800"):
            encoded_types = []
            update = HistorySearchCorpus._update_documents_digest
            def observe(digest, ordinal, encoded):
                encoded_types.append(type(encoded))
                update(digest, ordinal, encoded)
            with self.subTest(needle=needle), patch(
                "router_dump_analyzer.history_search_core._validated_compressed", _ValidationCache(),
            ), patch.object(HistorySearchCorpus, "_update_documents_digest", side_effect=observe):
                reopened = self.corpus(eager_validate_sidecar=False)
                self.assertEqual(list(reopened.query(needle, lambda: self.fail("builder"))),
                                 [i for i, text in enumerate(self.documents) if needle in text])
                self.assertEqual(reopened.character_count, sum(map(len, self.documents)))
                self.assertEqual(encoded_types, [memoryview] * len(self.documents))
                reopened.close()

    def test_cold_validator_rejects_valid_utf8_block_with_invalid_document_boundaries(self):
        self.build()
        # The combined bytes are valid UTF-8, but neither one-byte document is.
        # Stored raw and corpus digests are consistent with these corrupt frames.
        for lengths, text in (((1, 1), b"\xc3\xa9"), ((2, 0, 1), b"\xf0\x9f\x9b"), ((1, 1), b"\xffx")):
            raw = struct.pack(f">{len(lengths)}I", *lengths) + text
            digest = sha256()
            offset = 0
            for ordinal, length in enumerate(lengths):
                HistorySearchCorpus._update_documents_digest(digest, ordinal, text[offset:offset + length])
                offset += length
            with closing(sqlite3.connect(self.path)) as connection, connection:
                connection.execute("DELETE FROM document_blocks")
                connection.execute("INSERT INTO document_blocks VALUES (?, ?, ?, ?, ?)",
                                   (0, len(lengths), len(raw), zlib.compress(raw, 1), sha256(raw).hexdigest()))
                connection.execute("UPDATE metadata SET document_count=?, character_count=1, documents_digest=?",
                                   (len(lengths), digest.hexdigest()))
            with self.subTest(lengths=lengths, text=text), patch(
                "router_dump_analyzer.history_search_core._validated_compressed", _ValidationCache(),
            ):
                reopened = self.corpus()
                self.assertFalse(reopened.ready)
                self.assertEqual(reopened._block_digests, {})
                reopened.close()

    def test_last_payload_same_size_restored_timestamp_still_runs_full_validator(self):
        self.build()
        before = self.path.stat()
        connection = sqlite3.connect(self.path)
        try:
            first, payload = connection.execute(
                "SELECT first_ordinal, payload FROM document_blocks ORDER BY first_ordinal DESC LIMIT 1"
            ).fetchone()
            changed = payload[:-1] + bytes([payload[-1] ^ 1])
            connection.execute("UPDATE document_blocks SET payload=? WHERE first_ordinal=?", (changed, first))
            connection.commit()
        finally:
            connection.close()
        os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(self.path.stat().st_size, before.st_size)
        with patch("router_dump_analyzer.history_search_core.zlib.decompressobj", wraps=zlib.decompressobj) as decoder:
            reopened = self.corpus()
            self.assertFalse(reopened.ready)
            self.assertGreater(decoder.call_count, 0)
        self.assertEqual(list(reopened.query("common", lambda: self.documents)),
                         [index for index, text in enumerate(self.documents) if "common" in text])
        reopened.close()

    def test_metadata_and_projection_changes_do_not_reuse_validation(self):
        self.build()
        for statement in (
            "UPDATE metadata SET documents_digest='" + "0" * 64 + "'",
            "UPDATE metadata SET character_count=character_count+1",
            "UPDATE document_blocks SET raw_bytes=raw_bytes+1 WHERE first_ordinal=0",
        ):
            with self.subTest(statement=statement):
                original = self.path.read_bytes()
                connection = sqlite3.connect(self.path)
                try:
                    connection.execute(statement)
                    connection.commit()
                finally:
                    connection.close()
                reopened = self.corpus()
                self.assertFalse(reopened.ready)
                reopened.close()
                self.path.write_bytes(original)
        other_projection = HistorySearchCorpus(sidecar_path=self.path, identity="other-projection")
        self.assertFalse(other_projection.ready)
        other_projection.close()

    def test_current_limits_apply_to_validation_reuse(self):
        self.build()
        maximum = max(len(text.encode("utf-8")) for text in self.documents)
        for limits in (
            {"max_documents": len(self.documents) - 1},
            {"max_characters": sum(map(len, self.documents)) - 1},
            {"max_database_bytes": self.path.stat().st_size - 1},
            {"max_document_bytes": maximum - 1},
            {"expected_documents": len(self.documents) + 1},
        ):
            with self.subTest(limits=limits):
                reopened = self.corpus(**limits)
                self.assertFalse(reopened.ready)
                reopened.close()
        with patch("router_dump_analyzer.history_search_core.zlib.decompressobj",
                   side_effect=AssertionError("current document maximum is already certified")):
            reopened = self.corpus(max_document_bytes=maximum)
            self.assertTrue(reopened.ready)
            reopened.close()

    def test_replacement_between_stat_and_sqlite_open_is_not_admitted(self):
        self.build()
        replacement = self.path.with_suffix(".replacement")
        replacement.write_bytes(self.path.read_bytes())
        stamp = self.path.stat()
        os.utime(replacement, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        connect = sqlite3.connect

        def replace_then_connect(*args, **kwargs):
            os.replace(replacement, self.path)
            return connect(*args, **kwargs)

        with patch("router_dump_analyzer.history_search_core.sqlite3.connect", side_effect=replace_then_connect):
            reopened = self.corpus()
        self.assertFalse(reopened.ready)
        reopened.close()
        retry = self.corpus()
        self.assertTrue(retry.ready)
        retry.close()

    def test_validation_and_matching_share_a_read_transaction_and_no_connection_survives(self):
        self.build()
        original = HistorySearchCorpus._compressed_snapshot
        connections = []

        def inspect(corpus, connection, metadata):
            self.assertTrue(connection.in_transaction)
            connections.append(connection)
            return original(corpus, connection, metadata)

        with patch.object(HistorySearchCorpus, "_compressed_snapshot", inspect):
            reopened = self.corpus(eager_validate_sidecar=False)
            reopened.query("common", lambda: self.fail("builder"))
        self.assertEqual(len(connections), 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            connections[0].execute("SELECT 1")
        reopened.close()

    def test_read_snapshot_blocks_in_place_writer_until_validation_finishes(self):
        self.build()
        original = HistorySearchCorpus._compressed_snapshot
        attempted = []

        def inspect(corpus, connection, metadata):
            result = original(corpus, connection, metadata)
            writer = sqlite3.connect(self.path, timeout=0)
            try:
                writer.execute("UPDATE metadata SET character_count=character_count+1")
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                    writer.commit()
                attempted.append(True)
                writer.rollback()
            finally:
                writer.close()
            return result

        with patch.object(HistorySearchCorpus, "_compressed_snapshot", inspect):
            reopened = self.corpus()
        self.assertEqual(attempted, [True])
        self.assertTrue(reopened.ready)
        # Validation leaves no read lease behind: a normal writer can finish.
        writer = sqlite3.connect(self.path, timeout=0)
        try:
            writer.execute("UPDATE metadata SET character_count=character_count+1")
            writer.commit()
        finally:
            writer.close()
        self.assertEqual(list(reopened.query("common", lambda: self.documents)),
                         [index for index, text in enumerate(self.documents) if "common" in text])
        self.assertEqual(reopened.storage_mode, "memory")
        reopened.close()

    def test_wal_page_changes_invalidate_queries_after_reopen(self):
        self.build()
        writer = sqlite3.connect(self.path)
        try:
            writer.execute("PRAGMA journal_mode=WAL")
            reopened = self.corpus()
            self.assertTrue(reopened.ready)
            writer.execute("UPDATE document_blocks SET payload=x'00' WHERE first_ordinal=0")
            writer.commit()
            self.assertEqual(list(reopened.query("common", lambda: self.documents)),
                             [index for index, text in enumerate(self.documents) if "common" in text])
            self.assertEqual(reopened.storage_mode, "memory")
            reopened.close()
        finally:
            writer.close()

    def test_concurrent_reopens_and_close_release_runtime_and_builder(self):
        class Builder:
            def __call__(owner):
                return self.documents

        builder = Builder()
        builder_ref = weakref.ref(builder)
        first = self.corpus()
        first.query("common", builder)
        first_ref = weakref.ref(first)
        first.close()
        del first, builder
        gc.collect()
        self.assertIsNone(first_ref())
        self.assertIsNone(builder_ref())

        def query(_):
            corpus = self.corpus()
            result = corpus.query("rare-雪\0tail", lambda: self.fail("builder"))
            corpus.close()
            return list(result)

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(query, range(12)))
        self.assertTrue(all(result == list(range(0, 70, 11)) for result in results))


class ValidationCacheBoundsTests(unittest.TestCase):
    def test_bounds_eviction_and_active_facts_survive_concurrent_replacement(self):
        cache = _ValidationCache(max_entries=2, max_bytes=1000)
        self.assertFalse(cache)
        cache.put("one", 100)
        self.assertTrue(cache)
        cache.put("two", 200)
        retained = cache.get("one")
        cache.put("three", 300)
        self.assertIsNone(cache.get("two"))
        cache.put("x" * 1000, 1)
        self.assertIsNone(cache.get("x" * 1000))

        def exchange(worker):
            for index in range(100):
                cache.put(f"{worker}-{index}", index)
                cache.get("one")

        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(exchange, range(4)))
        self.assertEqual(retained, 100)
        self.assertLessEqual(len(cache._entries), 2)
        self.assertLessEqual(cache._bytes, 1000)
        self.assertEqual(cache._bytes, sum(size for _, size in cache._entries.values()))


if __name__ == "__main__":
    unittest.main()
