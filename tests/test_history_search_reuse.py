from __future__ import annotations

import gc
import sqlite3
import unittest
import weakref
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from unittest.mock import patch

from router_dump_analyzer._history_search_cache import _SearchResultCache
from router_dump_analyzer.history_search_core import HistorySearchCorpus
from router_dump_analyzer.history_search_matches import MatchSet


class HistorySearchReuseTests(unittest.TestCase):
    def setUp(self):
        self.cache = _SearchResultCache()
        self.patcher = patch("router_dump_analyzer.history_search_core._shared_results", self.cache)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_reopen_validates_then_reuses_without_query_scan(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "search.sqlite"
            corpus = HistorySearchCorpus(sidecar_path=path, identity="projection-a")
            expected = corpus.query("alpha", lambda: ("alpha", "beta"))
            retired = weakref.ref(corpus)
            corpus.close()
            del corpus
            gc.collect()
            self.assertIsNone(retired())
            reopened = HistorySearchCorpus(sidecar_path=path, identity="projection-a")
            with patch.object(reopened, "_query_ready", side_effect=AssertionError("rescan")):
                self.assertIs(reopened.query("alpha", lambda: self.fail("builder")), expected)
            reopened.close()
            lazy = HistorySearchCorpus(
                sidecar_path=path, identity="projection-a", eager_validate_sidecar=False
            )
            self.assertFalse(lazy.ready)
            with patch.object(lazy, "_query_ready", side_effect=AssertionError("rescan")):
                self.assertIs(lazy.query("alpha", lambda: self.fail("builder")), expected)
            self.assertTrue(lazy.ready)
            lazy.close()

    def test_memory_builders_are_not_retained_and_memory_results_are_not_shared(self):
        class Builder:
            def __call__(self):
                return ("alpha", "beta")

        builder = Builder()
        reference = weakref.ref(builder)
        first = HistorySearchCorpus()
        expected = first.query("alpha", builder)
        first.close()
        del builder
        gc.collect()
        self.assertIsNone(reference())
        second = HistorySearchCorpus()
        second.ensure(lambda: ("alpha", "beta"))
        with patch.object(second, "_query_ready", wraps=second._query_ready) as scan:
            actual = second.query("alpha", lambda: ())
            self.assertEqual(list(actual), list(expected))
            self.assertIsNot(actual, expected)
            scan.assert_called_once_with("alpha")
        self.assertEqual(len(self.cache._entries), 0)
        second.close()
        self.assertEqual(len(self.cache._entries), 0)

    def test_content_and_projection_identity_isolate_results(self):
        first = HistorySearchCorpus(identity="same-label")
        expected = first.query("alpha", lambda: ("alpha", "beta"))
        first.close()
        changed = HistorySearchCorpus(identity="same-label")
        self.assertEqual(list(changed.query("alpha", lambda: ("beta", "alpha"))), [1])
        projection = HistorySearchCorpus(identity="other-projection")
        self.assertIsNot(projection.query("alpha", lambda: ("alpha", "beta")), expected)

    def test_sidecar_failure_falls_back_without_sharing_or_content_hashing(self):
        with TemporaryDirectory() as folder:
            corpus = HistorySearchCorpus(
                sidecar_path=Path(folder) / "failed.sqlite", identity="fallback",
                eager_validate_sidecar=False,
            )
            with patch.object(
                corpus, "_build_sidecar", side_effect=sqlite3.OperationalError("unavailable")
            ), patch.object(
                corpus, "_set_reuse_identity", side_effect=AssertionError("fallback hash")
            ):
                self.assertEqual(list(corpus.query("alpha", lambda: ("alpha", "beta"))), [0])
            self.assertEqual(corpus.storage_mode, "memory")
            self.assertIsNone(corpus._reuse_identity)
            corpus.close()
            self.assertEqual(len(self.cache._entries), 0)

    def test_corrupt_sidecar_rebuild_does_not_admit_old_results(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "search.sqlite"
            first = HistorySearchCorpus(sidecar_path=path, identity="same-label")
            first.query("alpha", lambda: ("alpha", "beta"))
            first.close()
            with sqlite3.connect(path) as connection:
                connection.execute("UPDATE metadata SET documents_digest = ?", ("0" * 64,))
            connection.close()
            reopened = HistorySearchCorpus(sidecar_path=path, identity="same-label", eager_validate_sidecar=False)
            self.assertEqual(list(reopened.query("alpha", lambda: ("beta", "alpha"))), [1])
            reopened.close()

    def test_global_entry_byte_key_bounds_and_concurrent_readers(self):
        cache = _SearchResultCache(max_entries=2, max_bytes=2000)
        matches = MatchSet([0], 2)
        cache.put("a", "one", matches)
        cache.put("a", "two", matches)
        cache.get("a", "one")
        cache.put("a", "three", matches)
        self.assertIsNone(cache.get("a", "two"))
        cache.put("a", "x" * 2000, matches)
        self.assertIsNone(cache.get("a", "x" * 2000))
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _: cache.get("a", "one"), range(100)))
        self.assertTrue(all(result is matches for result in results))
        self.assertLessEqual(cache._bytes, 2000)
        self.assertLessEqual(len(cache._entries), 2)

    def test_subclass_keys_cannot_change_literal_identity_or_retain_owners(self):
        class Owner:
            pass

        class HostileText(str):
            def __str__(self):
                raise AssertionError("conversion must not run")

            def __hash__(self):
                raise AssertionError("custom hashing must not run")

            def __eq__(self, other):
                raise AssertionError("custom equality must not run")

        owner = Owner()
        reference = weakref.ref(owner)
        needle = HostileText("literal")
        needle.owner = owner
        matches = MatchSet([0], 2)
        self.cache.put("corpus", "literal", matches)
        self.cache.put("corpus", needle, matches)
        self.cache.put(needle, "literal", matches)
        self.assertIsNone(self.cache.get("corpus", needle))
        self.assertIsNone(self.cache.get(needle, "literal"))
        self.assertIs(self.cache.get("corpus", "literal"), matches)
        self.assertEqual(len(self.cache._entries), 1)
        del owner, needle
        gc.collect()
        self.assertIsNone(reference())

    def test_compressed_corpus_revalidates_before_shared_reuse(self):
        documents = tuple(
            f"route-{ordinal} " + ("rare-δ\x00" if ordinal % 11 == 0 else "common")
            for ordinal in range(50)
        )
        with TemporaryDirectory() as folder, patch.object(
            HistorySearchCorpus, "_BLOCK_TARGET_BYTES", 96
        ):
            path = Path(folder) / "compressed.sqlite"
            first = HistorySearchCorpus(
                sidecar_path=path, identity="compressed-reuse",
                max_eager_candidate_characters=1,
            )
            expected = first.query("rare-δ\x00", lambda: documents)
            self.assertEqual(list(expected), [0, 11, 22, 33, 44])
            self.assertEqual(first.candidate_backend, first._BLOCK_BACKEND)
            self.assertGreater(len(first._block_digests), 1)
            retired = weakref.ref(first)
            first.close()
            del first
            gc.collect()
            self.assertIsNone(retired())
            reopened = HistorySearchCorpus(
                sidecar_path=path, identity="compressed-reuse",
                max_eager_candidate_characters=1, eager_validate_sidecar=False,
            )
            with patch.object(
                reopened, "_iter_disk_documents", wraps=reopened._iter_disk_documents
            ) as validation, patch.object(
                reopened, "_query_ready", side_effect=AssertionError("query scan")
            ):
                self.assertIs(
                    reopened.query("rare-δ\x00", lambda: self.fail("builder")), expected
                )
                self.assertGreater(validation.call_count, 0)
            reopened.close()

    def test_concurrent_eviction_preserves_owned_results_and_releases_key_owners(self):
        class Owner:
            pass

        class OwnedText(str):
            pass

        cache = _SearchResultCache(max_entries=3, max_bytes=2400)
        owner = Owner()
        owner_reference = weakref.ref(owner)
        needle = OwnedText("owned")
        needle.owner = owner
        retained = MatchSet([1, 3], 8)
        cache.put("corpus", needle, retained)
        del owner, needle
        gc.collect()
        self.assertIsNone(owner_reference())
        barrier = Barrier(4)

        def exchange(worker):
            barrier.wait(timeout=5)
            for index in range(100):
                term = f"worker-{worker}-{index}"
                result = MatchSet([worker], 8)
                cache.put("corpus", term, result)
                observed = cache.get("corpus", term)
                if observed is not None:
                    self.assertEqual(list(observed), [worker])
                self.assertEqual(list(retained), [1, 3])

        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(exchange, range(4)))
        self.assertIsNone(cache.get("corpus", "owned"))
        self.assertEqual(list(retained), [1, 3])
        self.assertLessEqual(cache._bytes, 2400)
        self.assertLessEqual(len(cache._entries), 3)
        self.assertEqual(cache._bytes, sum(size for _, size in cache._entries.values()))
