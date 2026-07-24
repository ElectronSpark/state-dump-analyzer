from __future__ import annotations

import unittest
from random import Random
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
from unittest.mock import patch

from router_dump_analyzer.history_search_core import (
    HistorySearchCapacityError,
    HistorySearchCorpus,
)


class HistorySearchCorpusTests(unittest.TestCase):
    def test_different_needles_reuse_one_safe_corpus_build(self) -> None:
        corpus = HistorySearchCorpus()
        build_calls = 0

        def documents():
            nonlocal build_calls
            build_calls += 1
            return iter(("alpha route", "beta route", "alpha backup"))

        self.assertEqual(list(corpus.query("alpha", documents)), [0, 2])
        self.assertEqual(list(corpus.query("beta", documents)), [1])
        self.assertEqual(build_calls, 1)
        self.assertTrue(corpus.ready)
        self.assertEqual(corpus.document_count, 3)

    def test_matching_is_case_folded_literal_substring_search(self) -> None:
        corpus = HistorySearchCorpus()
        safe_documents = tuple(
            value.casefold()
            for value in (
                "Straße PEER[1]",
                "STRASSE peer.1",
                "Unrelated peer1",
            )
        )

        self.assertEqual(
            list(corpus.query("STRASSE".casefold(), lambda: safe_documents)),
            [0, 1],
        )
        # Brackets are literal characters rather than a regular expression.
        self.assertEqual(
            list(corpus.query("PEER[1]".casefold(), lambda: safe_documents)),
            [0],
        )
        self.assertEqual(
            list(corpus.query("peer.1".casefold(), lambda: safe_documents)),
            [1],
        )

    def test_capacity_failure_is_persistent_and_never_rebuilds(self) -> None:
        corpus = HistorySearchCorpus(max_documents=1)
        first_build_calls = 0
        replacement_build_calls = 0

        def oversized_documents():
            nonlocal first_build_calls
            first_build_calls += 1
            return iter(("first", "second"))

        def replacement_documents():
            nonlocal replacement_build_calls
            replacement_build_calls += 1
            return iter(("would otherwise fit",))

        with self.assertRaises(HistorySearchCapacityError) as first_failure:
            corpus.query("first", oversized_documents)
        with self.assertRaises(HistorySearchCapacityError) as repeated_failure:
            corpus.query("would", replacement_documents)

        self.assertIs(repeated_failure.exception, first_failure.exception)
        self.assertEqual(first_build_calls, 1)
        self.assertEqual(replacement_build_calls, 0)
        self.assertFalse(corpus.ready)
        self.assertEqual(corpus.document_count, 0)

    def test_query_count_lru_eviction_recomputes_exact_result(self) -> None:
        corpus = HistorySearchCorpus(
            max_cached_queries=2,
            max_cached_ordinals=100,
        )
        build_calls = 0

        def documents():
            nonlocal build_calls
            build_calls += 1
            return iter(("alpha beta", "beta gamma", "gamma alpha"))

        alpha = corpus.query("alpha", documents)
        first_beta = corpus.query("beta", documents)
        self.assertIs(corpus.query("alpha", documents), alpha)
        corpus.query("gamma", documents)  # Evicts beta, the least-recent query.
        second_beta = corpus.query("beta", documents)

        self.assertEqual(list(first_beta), [0, 1])
        self.assertEqual(list(second_beta), [0, 1])
        self.assertIsNot(second_beta, first_beta)
        self.assertEqual(build_calls, 1)

    def test_ordinal_budget_evicts_oversized_result_without_losing_correctness(self) -> None:
        corpus = HistorySearchCorpus(
            max_cached_queries=10,
            max_cached_ordinals=1,
        )
        documents = lambda: iter(("shared", "shared", "other"))

        first = corpus.query("shared", documents)
        second = corpus.query("shared", documents)

        self.assertEqual(list(first), [0, 1])
        self.assertEqual(list(second), [0, 1])
        self.assertIsNot(second, first)

    def test_completed_sidecar_is_reused_by_a_second_instance(self) -> None:
        with TemporaryDirectory() as directory:
            sidecar = Path(directory) / "history-search.sqlite3"
            first_build_calls = 0

            def first_documents():
                nonlocal first_build_calls
                first_build_calls += 1
                return iter(("alpha route", "beta route", "alpha backup"))

            first = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-a:safe-projection-v1",
                expected_documents=3,
            )
            self.assertEqual(list(first.query("alpha", first_documents)), [0, 2])
            self.assertEqual(first_build_calls, 1)
            self.assertTrue(sidecar.is_file())

            def unexpected_rebuild():
                raise AssertionError("a completed matching sidecar must be reused")

            second = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-a:safe-projection-v1",
                expected_documents=3,
            )
            self.assertTrue(second.ready)
            self.assertEqual(second.document_count, 3)
            self.assertEqual(list(second.query("beta", unexpected_rebuild)), [1])
            first.close()
            second.close()

    def test_mismatched_sidecar_metadata_rebuilds_atomically(self) -> None:
        with TemporaryDirectory() as directory:
            sidecar = Path(directory) / "history-search.sqlite3"
            original = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-a:safe-projection-v1",
                expected_documents=2,
            )
            self.assertEqual(
                list(original.query("old", lambda: iter(("old one", "old two")))),
                [0, 1],
            )
            original.close()

            replacement_build_calls = 0

            def replacement_documents():
                nonlocal replacement_build_calls
                replacement_build_calls += 1
                return iter(("new zero", "new one"))

            replacement = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-b:safe-projection-v2",
                expected_documents=2,
            )
            self.assertFalse(replacement.ready)
            self.assertEqual(
                list(replacement.query("new", replacement_documents)),
                [0, 1],
            )
            self.assertEqual(replacement_build_calls, 1)
            self.assertEqual(list(replacement.query("old", replacement_documents)), [])
            replacement.close()

            def unexpected_rebuild():
                raise AssertionError("the atomically replaced sidecar must be reusable")

            reopened = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-b:safe-projection-v2",
                expected_documents=2,
            )
            self.assertEqual(list(reopened.query("new", unexpected_rebuild)), [0, 1])
            reopened.close()

    def test_expected_document_count_mismatch_rebuilds(self) -> None:
        with TemporaryDirectory() as directory:
            sidecar = Path(directory) / "history-search.sqlite3"
            original = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-a:safe-projection-v1",
                expected_documents=2,
            )
            self.assertEqual(
                list(original.query("route", lambda: iter(("route a", "route b")))),
                [0, 1],
            )
            original.close()

            rebuild_calls = 0

            def expanded_documents():
                nonlocal rebuild_calls
                rebuild_calls += 1
                return iter(("route a", "route b", "route c"))

            expanded = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-a:safe-projection-v1",
                expected_documents=3,
            )
            self.assertFalse(expanded.ready)
            self.assertEqual(
                list(expanded.query("route", expanded_documents)),
                [0, 1, 2],
            )
            self.assertEqual(rebuild_calls, 1)
            expanded.close()

    def test_corrupt_sidecar_rebuilds_and_then_reopens(self) -> None:
        with TemporaryDirectory() as directory:
            sidecar = Path(directory) / "history-search.sqlite3"
            sidecar.write_bytes(b"not a sqlite database")
            build_calls = 0

            def documents():
                nonlocal build_calls
                build_calls += 1
                return iter(("recovered alpha", "recovered beta"))

            recovered = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-recovered:safe-projection-v1",
                expected_documents=2,
            )
            self.assertFalse(recovered.ready)
            self.assertEqual(list(recovered.query("beta", documents)), [1])
            self.assertEqual(build_calls, 1)
            recovered.close()

            def unexpected_rebuild():
                raise AssertionError("the recovered sidecar must be valid")

            reopened = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-recovered:safe-projection-v1",
                expected_documents=2,
            )
            self.assertEqual(list(reopened.query("alpha", unexpected_rebuild)), [0])
            reopened.close()

    def test_persistent_exact_matching_keeps_bounded_result_lru(self) -> None:
        temporary_root: Path
        with TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            sidecar = temporary_root / "history-search.sqlite3"
            documents = tuple(
                value.casefold()
                for value in (
                    "Stra\u00dfe peer%_1",
                    "STRASSE peerxy1",
                    "unrelated",
                )
            )
            corpus = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-literal:safe-projection-v1",
                expected_documents=3,
                max_cached_queries=1,
                max_cached_ordinals=10,
            )

            first_literal = corpus.query("PEER%_1".casefold(), lambda: documents)
            self.assertEqual(list(first_literal), [0])
            self.assertEqual(
                list(corpus.query("STRASSE".casefold(), lambda: documents)),
                [0, 1],
            )
            recomputed_literal = corpus.query(
                "PEER%_1".casefold(),
                lambda: documents,
            )
            self.assertEqual(list(recomputed_literal), [0])
            self.assertIsNot(recomputed_literal, first_literal)
            corpus.close()

        # The sidecar must not retain handles that defeat temporary workspace
        # cleanup, especially on Windows where open SQLite files are stricter.
        self.assertFalse(temporary_root.exists())

    def test_fts_candidates_are_always_rechecked_as_exact_substrings(self) -> None:
        with TemporaryDirectory() as directory:
            corpus = HistorySearchCorpus(
                sidecar_path=Path(directory) / "history-search.sqlite3",
                identity="revision-candidate-recheck",
                expected_documents=3,
            )
            documents = ("abc---bcd", "xxabcdyy", "bcd abc")

            self.assertEqual(list(corpus.query("abcd", lambda: documents)), [1])
            self.assertIn(
                corpus.candidate_backend,
                {"fts5-trigram", "sqlite-scan"},
            )
            corpus.close()

    def test_short_empty_and_parser_sensitive_needles_remain_literal(self) -> None:
        with TemporaryDirectory() as directory:
            corpus = HistorySearchCorpus(
                sidecar_path=Path(directory) / "history-search.sqlite3",
                identity="revision-literal-edge-cases",
                expected_documents=6,
            )
            documents = tuple(
                text.casefold()
                for text in (
                    "",
                    "a",
                    "ba",
                    "ab",
                    'prefix "quoted" suffix',
                    "left\0after-marker Straße\npeer%_1",
                )
            )

            self.assertEqual(list(corpus.query("", lambda: documents)), list(range(6)))
            self.assertEqual(list(corpus.query("a", lambda: documents)), [1, 2, 3, 5])
            self.assertEqual(list(corpus.query("ab", lambda: documents)), [3])
            self.assertEqual(list(corpus.query('"quoted"', lambda: documents)), [4])
            self.assertEqual(list(corpus.query("\0a", lambda: documents)), [5])
            self.assertEqual(list(corpus.query("after-marker", lambda: documents)), [5])
            self.assertEqual(list(corpus.query("strasse\npeer", lambda: documents)), [5])
            self.assertEqual(list(corpus.query("peer%_1", lambda: documents)), [5])
            corpus.close()

    def test_missing_fts_table_forces_atomic_rebuild(self) -> None:
        with TemporaryDirectory() as directory:
            sidecar = Path(directory) / "history-search.sqlite3"
            documents = ("alpha route", "beta route")
            original = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-missing-index",
                expected_documents=2,
            )
            self.assertEqual(list(original.query("alpha", lambda: documents)), [0])
            backend = original.candidate_backend
            original.close()
            if backend != "fts5-trigram":
                self.skipTest("SQLite runtime does not provide FTS5 trigram")

            import sqlite3

            connection = sqlite3.connect(sidecar)
            try:
                connection.execute("DROP TABLE documents_fts")
                connection.commit()
            finally:
                connection.close()

            build_calls = 0

            def rebuild_documents():
                nonlocal build_calls
                build_calls += 1
                return iter(documents)

            rebuilt = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-missing-index",
                expected_documents=2,
            )
            self.assertFalse(rebuilt.ready)
            self.assertEqual(list(rebuilt.query("beta", rebuild_documents)), [1])
            self.assertEqual(build_calls, 1)
            self.assertEqual(rebuilt.candidate_backend, "fts5-trigram")
            rebuilt.close()

    def test_changed_safe_text_or_ordinal_invalidates_persistent_digest(self) -> None:
        for mutation in (
            "UPDATE documents SET safe_text = 'stale text' WHERE ordinal = 0",
            "UPDATE documents SET ordinal = 7 WHERE ordinal = 1",
        ):
            with self.subTest(mutation=mutation), TemporaryDirectory() as directory:
                sidecar = Path(directory) / "history-search.sqlite3"
                documents = ("alpha route", "beta route")
                original = HistorySearchCorpus(
                    sidecar_path=sidecar,
                    identity="revision-digest-validation",
                    expected_documents=2,
                )
                self.assertEqual(
                    list(original.query("alpha", lambda: documents)),
                    [0],
                )
                original.close()

                import sqlite3

                connection = sqlite3.connect(sidecar)
                try:
                    connection.execute(mutation)
                    connection.commit()
                finally:
                    connection.close()

                build_calls = 0

                def rebuild_documents():
                    nonlocal build_calls
                    build_calls += 1
                    return iter(documents)

                rebuilt = HistorySearchCorpus(
                    sidecar_path=sidecar,
                    identity="revision-digest-validation",
                    expected_documents=2,
                )
                self.assertFalse(rebuilt.ready)
                self.assertEqual(
                    list(rebuilt.query("beta", rebuild_documents)),
                    [1],
                )
                self.assertEqual(build_calls, 1)
                rebuilt.close()

    def test_semantically_incomplete_fts_index_is_rebuilt(self) -> None:
        with TemporaryDirectory() as directory:
            sidecar = Path(directory) / "history-search.sqlite3"
            documents = ("alpha route", "beta route")
            original = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-fts-coherence",
                expected_documents=2,
            )
            self.assertEqual(list(original.query("alpha", lambda: documents)), [0])
            if original.candidate_backend != "fts5-trigram":
                original.close()
                self.skipTest("SQLite runtime does not provide FTS5 trigram")
            original.close()

            import sqlite3

            connection = sqlite3.connect(sidecar)
            try:
                connection.execute(
                    """
                    INSERT INTO documents_fts(documents_fts)
                    VALUES ('delete-all')
                    """
                )
                connection.commit()
            finally:
                connection.close()

            build_calls = 0

            def rebuild_documents():
                nonlocal build_calls
                build_calls += 1
                return iter(documents)

            rebuilt = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-fts-coherence",
                expected_documents=2,
            )
            self.assertFalse(rebuilt.ready)
            self.assertEqual(list(rebuilt.query("alpha", rebuild_documents)), [0])
            self.assertEqual(build_calls, 1)
            rebuilt.close()

    def test_fts_unavailable_persists_exact_sqlite_scan_backend(self) -> None:
        with TemporaryDirectory() as directory:
            sidecar = Path(directory) / "history-search.sqlite3"
            documents = ("alpha route", "beta route")
            corpus = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-no-fts",
                expected_documents=2,
            )
            with patch.object(
                HistorySearchCorpus,
                "_build_fts5_candidate_index",
                return_value=None,
            ):
                self.assertEqual(list(corpus.query("alpha", lambda: documents)), [0])
            self.assertEqual(corpus.storage_mode, "sqlite")
            self.assertEqual(corpus.candidate_backend, "sqlite-scan")
            corpus.close()

            def unexpected_rebuild():
                raise AssertionError("the scan sidecar must reopen without a builder")

            reopened = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-no-fts",
                expected_documents=2,
            )
            self.assertEqual(reopened.candidate_backend, "sqlite-scan")
            self.assertEqual(list(reopened.query("beta", unexpected_rebuild)), [1])
            reopened.close()

    def test_match_parser_failure_falls_back_without_rebuilding_sidecar(self) -> None:
        with TemporaryDirectory() as directory:
            sidecar = Path(directory) / "history-search.sqlite3"
            documents = ("xxabcdyy", "unrelated")
            corpus = HistorySearchCorpus(
                sidecar_path=sidecar,
                identity="revision-match-fallback",
                expected_documents=2,
            )
            self.assertEqual(list(corpus.query("unrelated", lambda: documents)), [1])
            if corpus.candidate_backend != "fts5-trigram":
                corpus.close()
                self.skipTest("SQLite runtime does not provide FTS5 trigram")

            with patch.object(
                HistorySearchCorpus,
                "_fts5_candidate_expression",
                return_value='"unterminated',
            ):
                self.assertEqual(list(corpus.query("abcd", lambda: documents)), [0])
            self.assertTrue(corpus.ready)
            self.assertEqual(corpus.storage_mode, "sqlite")
            self.assertEqual(corpus.candidate_backend, "fts5-trigram")
            corpus.close()

    def test_persistent_results_match_python_for_varied_literal_needles(self) -> None:
        generator = Random(20260722)
        alphabet = 'abcxyz012 -_:%[]"\nßδU0001f642'
        documents = tuple(
            "".join(generator.choice(alphabet) for _ in range(48)).casefold()
            for _ in range(80)
        )
        needles = ["", "a", "ab", "%_", '"', "strasse", "δ", "U0001f642"]
        for _ in range(40):
            document = generator.choice(documents)
            start = generator.randrange(len(document) + 1)
            end = min(len(document), start + generator.randrange(0, 12))
            needles.append(document[start:end])
        needles.extend("absent-" + str(index) for index in range(8))

        with TemporaryDirectory() as directory:
            corpus = HistorySearchCorpus(
                sidecar_path=Path(directory) / "history-search.sqlite3",
                identity="revision-randomized-parity",
                expected_documents=len(documents),
            )
            for needle in needles:
                expected = [
                    ordinal
                    for ordinal, document in enumerate(documents)
                    if needle in document
                ]
                self.assertEqual(
                    list(corpus.query(needle, lambda: documents)),
                    expected,
                    needle,
                )
            corpus.close()

    def test_close_waits_for_active_build_and_corpus_stays_closed(self) -> None:
        corpus = HistorySearchCorpus()
        build_started = Event()
        release_build = Event()
        close_finished = Event()
        errors: list[BaseException] = []

        def documents():
            build_started.set()
            if not release_build.wait(5):
                raise RuntimeError("test did not release history builder")
            return iter(("alpha",))

        def warm() -> None:
            try:
                corpus.ensure(documents)
            except BaseException as error:  # pragma: no cover - diagnostic path
                errors.append(error)

        def close() -> None:
            corpus.close()
            close_finished.set()

        warmup = Thread(target=warm)
        warmup.start()
        self.assertTrue(build_started.wait(2))
        closer = Thread(target=close)
        closer.start()
        self.assertFalse(close_finished.wait(0.05))
        release_build.set()
        warmup.join(2)
        closer.join(2)

        self.assertEqual(errors, [])
        self.assertTrue(close_finished.is_set())
        self.assertFalse(corpus.ready)
        with self.assertRaisesRegex(RuntimeError, "closed"):
            corpus.query("alpha", documents)

    def test_sidecar_symlink_is_not_resolved_or_replaced(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "outside-cache.txt"
            target.write_bytes(b"must remain untouched")
            link = root / "history-search.sqlite3"
            try:
                link.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")

            corpus = HistorySearchCorpus(
                sidecar_path=link,
                identity="revision-symlink",
                expected_documents=1,
            )
            self.assertEqual(corpus.sidecar_path, link.absolute())
            self.assertEqual(list(corpus.query("alpha", lambda: ("alpha",))), [0])
            self.assertEqual(corpus.storage_mode, "memory")
            self.assertEqual(target.read_bytes(), b"must remain untouched")
            self.assertTrue(link.is_symlink())
            corpus.close()


if __name__ == "__main__":
    unittest.main()
