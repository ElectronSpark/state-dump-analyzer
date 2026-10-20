"""Focused boundaries for the offline, bounded search-index comparison."""

import importlib.util
import sqlite3
import struct
import sys
import tempfile
import unittest
import zlib
from hashlib import sha256
from pathlib import Path

_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "profile_history_search_indexes.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "profile_history_search_indexes", _SCRIPT
)
profile = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = profile
_SPEC.loader.exec_module(profile)


def block(first, docs):
    raw = struct.pack(f">{len(docs)}I", *(len(x) for x in docs)) + b"".join(docs)
    return profile.Block(
        first, len(docs), len(raw), zlib.compress(raw), sha256(raw).hexdigest()
    )


class SearchIndexProfileTests(unittest.TestCase):
    def test_exact_candidates_unicode_nul_and_document_boundaries(self):
        blocks = [
            block(0, [b"ab", b"c", b"aaaaa"]),
            block(3, ["café雪".encode(), b"a\0bc", b"xabcx", b"abxxbc"]),
        ]
        docs = [profile.decode(b, 4096) for b in blocks]
        for mode in ("block", "document"):
            index, docmap, _ = profile.build_index(docs, mode, 100000, 1000)
            for needle in [
                b"abc",
                b"aaaa",
                "é雪".encode(),
                b"\0bc",
                b"bc",
                b"",
                b"missing",
            ]:
                selected, positions = profile.candidates(
                    index, docmap, mode, needle, len(blocks)
                )
                actual = profile.exact_scan(blocks, needle, 4096, selected)
                expected = profile.exact_scan(blocks, needle, 4096)
                self.assertEqual(actual, expected)
                if needle == b"abc":
                    self.assertEqual(actual, [5])
                if positions is not None:
                    self.assertTrue(set(expected) <= {docmap[i][0] for i in positions})

    def test_corruption_and_bounded_decompression(self):
        good = block(0, [b"abc"])
        for bad in [
            profile.Block(0, 1, good.raw_size, good.payload, "0" * 64),
            profile.Block(0, 1, 4, zlib.compress(b"x" * 100000), good.digest),
            profile.Block(0, 1, good.raw_size, good.payload + b"trailing", good.digest),
        ]:
            with self.assertRaises(ValueError):
                profile.decode(bad, 4096)
        with self.assertRaises(ValueError):
            profile.decode(good, 4)

    def test_posting_and_vocabulary_budgets(self):
        docs = [[(0, b"abcdef"), (1, b"abcdef")]]
        for mode in ("block", "document"):
            with self.assertRaises(ValueError):
                profile.build_index(docs, mode, 1, 100)
            with self.assertRaises(ValueError):
                profile.build_index(docs, mode, 10000, 1)

    def test_cli_requires_source_and_cannot_overwrite_it(self):
        with self.assertRaises(SystemExit) as missing:
            profile.main([])
        self.assertEqual(missing.exception.code, 2)
        with self.assertRaises(SystemExit) as same:
            profile.main(["--sidecar", "same.sqlite3", "--output", "same.sqlite3"])
        self.assertEqual(same.exception.code, 2)

    def test_sampling_bounds_readonly_and_tail(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source.sqlite3"
            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE metadata(singleton,format_version,identity,documents_digest,complete,backend)"
            )
            connection.execute(
                "INSERT INTO metadata VALUES(1,'history-search-sqlite-v7','id','digest',1,'sqlite-zlib-blocks-v1')"
            )
            connection.execute(
                "CREATE TABLE document_blocks(first_ordinal PRIMARY KEY,document_count,raw_bytes,payload,digest)"
            )
            for i in range(3):
                b = block(i, [b"abcdef"])
                connection.execute(
                    "INSERT INTO document_blocks VALUES(?,?,?,?,?)",
                    (b.first, b.count, b.raw_size, b.payload, b.digest),
                )
            connection.commit()
            connection.close()
            before = sha256(path.read_bytes()).digest()
            blocks, _docs, info = profile.sample(
                path,
                max_blocks=32,
                max_raw_bytes=1000,
                max_documents=3,
                max_block_bytes=100,
            )
            self.assertEqual([b.first for b in blocks], [0, 1, 2])
            self.assertEqual(info["sample_documents"], 3)
            blocks, _, _ = profile.sample(
                path,
                max_blocks=2,
                max_raw_bytes=1000,
                max_documents=3,
                max_block_bytes=100,
            )
            self.assertEqual([b.first for b in blocks], [0, 2])
            blocks, _, _ = profile.sample(
                path,
                max_blocks=3,
                max_raw_bytes=10,
                max_documents=3,
                max_block_bytes=100,
            )
            self.assertEqual(len(blocks), 1)
            self.assertEqual(sha256(path.read_bytes()).digest(), before)
            with self.assertRaises(ValueError):
                profile.sample(
                    path,
                    max_blocks=3,
                    max_raw_bytes=1,
                    max_documents=3,
                    max_block_bytes=100,
                )


if __name__ == "__main__":
    unittest.main()
