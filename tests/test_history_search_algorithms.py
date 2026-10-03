from pathlib import Path
from random import Random
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from router_dump_analyzer.history_search_core import HistorySearchCorpus
from router_dump_analyzer.history_search_matches import MatchSet


def load_tests(loader, tests, pattern):
    """Keep these direct algorithm checks in the documented unittest runner."""
    tests.addTests(
        unittest.FunctionTestCase(check)
        for name, check in sorted(globals().items())
        if name.startswith("test_") and callable(check)
    )
    return tests


def test_adaptive_postings_rank_select_and_bounded_pages():
    random = Random(442)
    for count in (0, 3, 4999, 9997, 10000):
        expected = sorted(random.sample(range(10000), count))
        matches = MatchSet(expected, 10000)
        assert list(matches) == expected
        for position in (0, count // 2, count - 1):
            if count:
                assert matches[position] == expected[position]
                assert matches[position - count] == expected[position - count]
        assert matches[4500:4600] == tuple(expected[4500:4600])
        assert matches[::-1] == tuple(reversed(expected))
    assert MatchSet([2, 99], 10000).kind == "sparse"
    assert MatchSet(range(10000), 10000).kind == "complement"
    assert MatchSet(range(0, 10000, 2), 10000).kind == "bitmap"


def test_dense_result_survives_legacy_ordinal_limit_and_reuses_identity():
    corpus = HistorySearchCorpus(max_documents=20000, max_cached_ordinals=100)
    documents = lambda: ("hit" for _ in range(10000))
    result = corpus.query("hit", documents)
    assert len(result) == 10000
    assert result[9900:9910] == tuple(range(9900, 9910))
    assert corpus.query("hit", documents) is result
    assert corpus._cached_bytes <= corpus._max_cached_bytes


def test_fused_first_query_avoids_scan_even_when_result_is_not_cached():
    corpus = HistorySearchCorpus(max_cached_bytes=1)
    with patch.object(
        corpus, "_query_ready", side_effect=AssertionError("second pass")
    ):
        assert list(corpus.query("a", lambda: ("a", "b", "aa"))) == [0, 2]
    assert not corpus._results


def test_deferred_validation_fuses_exact_unicode_nul_query():
    with TemporaryDirectory() as directory:
        path = Path(directory) / "search.sqlite3"
        texts = ("left\0Straße".casefold(), "strasse", "unrelated")
        original = HistorySearchCorpus(sidecar_path=path, identity="revision")
        original.ensure(lambda texts=texts: texts)
        corpus = HistorySearchCorpus(
            sidecar_path=path, identity="revision", eager_validate_sidecar=False
        )
        with patch.object(
            corpus, "_query_ready", side_effect=AssertionError("second pass")
        ):
            assert list(corpus.query("\0strasse", lambda: (_ for _ in ()))) == [0]


def test_narrower_cached_substring_refines_memory_and_sqlite():
    with TemporaryDirectory() as directory:
        for path in (None, Path(directory) / "search.sqlite3"):
            texts = (
                "prefix\0needleß".casefold(),
                "prefix other",
                *("unrelated" for _ in range(98)),
            )
            corpus = HistorySearchCorpus(
                sidecar_path=path, identity="revision" if path else None
            )
            corpus.query("prefix", lambda texts=texts: texts)
            # The exact candidate branch bypasses the FTS compiler, even for NUL.
            with patch.object(
                corpus,
                "_fts5_candidate_expression",
                side_effect=AssertionError("full scan"),
            ):
                assert list(
                    corpus.query("prefix\0needless", lambda texts=texts: texts)
                ) == [0]
            assert list(corpus.query("needle", lambda texts=texts: texts)) == [0]
            assert list(corpus.query("", lambda texts=texts: texts)) == list(range(100))


def test_invalid_validation_matches_are_not_published():
    import sqlite3

    with TemporaryDirectory() as directory:
        path = Path(directory) / "search.sqlite3"
        original = HistorySearchCorpus(sidecar_path=path, identity="revision")
        original.ensure(lambda: ("needle", "other"))
        with sqlite3.connect(path) as connection:
            connection.execute(
                "UPDATE documents SET safe_text = 'needle corrupt' WHERE ordinal = 1"
            )
        connection.close()
        corpus = HistorySearchCorpus(
            sidecar_path=path, identity="revision", eager_validate_sidecar=False
        )
        assert list(corpus.query("needle", lambda: ("needle", "other"))) == [0]
