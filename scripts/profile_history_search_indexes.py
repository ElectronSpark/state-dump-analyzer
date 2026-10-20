"""Bounded offline comparison of optional trigram indexes over a search sidecar.

This never modifies the sidecar or enables a production index. Only sampled blocks
are validated. Compressed posting sizes are estimates; queries use resident arrays
or integer bitsets, NOT compressed postings. Run with --help for explicit bounds.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import struct
import sys
import time
import zlib
from array import array
from bisect import bisect_left
from dataclasses import dataclass
from functools import partial
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True)
class Block:
    first: int
    count: int
    raw_size: int
    payload: bytes
    digest: str


def decode(block: Block, max_block_bytes: int) -> list[tuple[int, bytes]]:
    """Validate a bounded frame before admitting its documents to the sample."""
    if (
        not 0 < block.count <= 65536
        or not block.count * 4 <= block.raw_size <= max_block_bytes
    ):
        raise ValueError("invalid or oversized block framing")
    if len(block.payload) > max_block_bytes + 1024:
        raise ValueError("oversized compressed payload")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(block.payload, block.raw_size + 1)
    if (
        len(raw) != block.raw_size
        or not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
        or sha256(raw).hexdigest() != block.digest
    ):
        raise ValueError("invalid block stream or digest")
    lengths = struct.unpack_from(f">{block.count}I", raw)
    offset = block.count * 4
    docs = []
    for index, length in enumerate(lengths):
        end = offset + length
        if end > len(raw):
            raise ValueError("document exceeds frame")
        document = raw[offset:end]
        document.decode("utf-8")
        docs.append((block.first + index, document))
        offset = end
    if offset != len(raw):
        raise ValueError("trailing document bytes")
    return docs


def sample(
    source: Path,
    *,
    max_blocks: int,
    max_raw_bytes: int,
    max_documents: int,
    max_block_bytes: int,
) -> tuple[list[Block], list[list[tuple[int, bytes]]], dict]:
    if min(max_blocks, max_raw_bytes, max_documents, max_block_bytes) <= 0:
        raise ValueError("sample bounds must be positive")
    connection = sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        connection.execute(
            "BEGIN"
        )  # Stable read snapshot for framing and payload reads.
        metadata = connection.execute(
            "SELECT format_version, identity, documents_digest, complete, backend FROM metadata WHERE singleton=1"
        ).fetchone()
        if not metadata or metadata[3] != 1 or metadata[4] != "sqlite-zlib-blocks-v1":
            raise ValueError("expected a complete compressed sidecar")
        total = connection.execute("SELECT count(*) FROM document_blocks").fetchone()[0]
        sample_count = min(total, max_blocks)
        positions = sorted(
            {i * (total - 1) // max(1, sample_count - 1) for i in range(sample_count)}
        )
        blocks, documents = [], []
        raw_total = doc_total = 0
        corpus_hash = sha256()
        for position in positions:
            # Inspect lengths before asking SQLite to allocate a payload object.
            framing = connection.execute(
                "SELECT first_ordinal, document_count, raw_bytes, length(payload) FROM document_blocks ORDER BY first_ordinal LIMIT 1 OFFSET ?",
                (position,),
            ).fetchone()
            first, count, size, payload_size = framing
            if (
                type(first) is not int
                or first < 0
                or type(count) is not int
                or not 0 < count <= 65536
                or type(size) is not int
                or not count * 4 <= size <= max_block_bytes
                or type(payload_size) is not int
                or not 0 < payload_size <= max_block_bytes + 1024
            ):
                raise ValueError("invalid or oversized source frame")
            if raw_total + size > max_raw_bytes or doc_total + count > max_documents:
                continue
            payload, digest = connection.execute(
                "SELECT payload, digest FROM document_blocks WHERE first_ordinal=?",
                (first,),
            ).fetchone()
            block = Block(first, count, size, payload, digest)
            docs = decode(block, max_block_bytes)
            for ordinal, document in docs:
                corpus_hash.update(struct.pack(">QI", ordinal, len(document)))
                corpus_hash.update(document)
            blocks.append(block)
            documents.append(docs)
            raw_total += size
            doc_total += count
        if not blocks:
            raise ValueError("sample budget admits no blocks")
        return (
            blocks,
            documents,
            {
                "format_version": metadata[0],
                "identity": metadata[1],
                "declared_corpus_digest": metadata[2],
                "sample_digest": corpus_hash.hexdigest(),
                "source_blocks": total,
                "sample_blocks": len(blocks),
                "sample_documents": doc_total,
                "sample_raw_bytes": raw_total,
                "sample_compressed_bytes": sum(len(b.payload) for b in blocks),
                "first_ordinals": [b.first for b in blocks],
                "validation": "sampled blocks only; not full corpus validation",
            },
        )
    finally:
        connection.close()


def grams(value: bytes, limit: int | None = None) -> set[bytes]:
    result = set()
    for i in range(len(value) - 2):
        result.add(value[i : i + 3])
        if limit is not None and len(result) > limit:
            raise ValueError("trigram vocabulary budget exceeded")
    return result


def build_index(
    documents: list[list[tuple[int, bytes]]],
    mode: str,
    max_posting_bytes: int,
    max_grams: int,
) -> tuple[dict, list[tuple[int, int]], int]:
    """Cap logical posting payload and vocabulary; fail without publishing on excess."""
    index = {}
    docmap = []
    payload_bytes = 0
    for block_index, docs in enumerate(documents):
        if mode == "block":
            unique = set()
            for _, document in docs:
                unique.update(grams(document, max_grams))
                if len(unique) > max_grams:
                    raise ValueError("trigram vocabulary budget exceeded")
            postings = [(g, block_index) for g in unique]
        else:
            postings = None
        if postings is not None:
            for gram, bit in postings:
                old = index.get(gram, 0)
                new = old | (1 << bit)
                payload_bytes += (new.bit_length() + 7) // 8 - (
                    old.bit_length() + 7
                ) // 8
                if payload_bytes > max_posting_bytes or (
                    gram not in index and len(index) >= max_grams
                ):
                    raise ValueError("index posting or vocabulary budget exceeded")
                index[gram] = new
        else:
            for ordinal, document in docs:
                position = len(docmap)
                docmap.append((ordinal, block_index))
                for gram in grams(document, max_grams):
                    if payload_bytes + 4 > max_posting_bytes or (
                        gram not in index and len(index) >= max_grams
                    ):
                        raise ValueError("index posting or vocabulary budget exceeded")
                    index.setdefault(gram, array("I")).append(position)
                    payload_bytes += 4
    return index, docmap, payload_bytes


def contains(row, position):
    offset = bisect_left(row, position)
    return offset < len(row) and row[offset] == position


def candidates(
    index: dict, docmap: list, mode: str, needle: bytes, block_count: int
) -> tuple[list[int], list[int] | None]:
    terms = grams(needle)
    if not terms:
        return list(range(block_count)), None
    if mode == "block":
        mask = (1 << block_count) - 1
        for term in terms:
            mask &= index.get(term, 0)
        return [i for i in range(block_count) if mask >> i & 1], None
    postings = sorted((index.get(term, ()) for term in terms), key=len)
    ids = []
    for position in postings[0]:
        if all(contains(row, position) for row in postings[1:]):
            ids.append(position)
    return sorted({docmap[i][1] for i in ids}), ids


def exact_scan(
    blocks: list[Block],
    needle: bytes,
    max_block_bytes: int,
    selected: list[int] | None = None,
) -> list[int]:
    return [
        ordinal
        for i in (range(len(blocks)) if selected is None else selected)
        for ordinal, document in decode(blocks[i], max_block_bytes)
        if needle in document
    ]


def timed(call):
    wall, cpu = time.perf_counter(), time.process_time()
    result = call()
    return result, {
        "wall_s": time.perf_counter() - wall,
        "cpu_s": time.process_time() - cpu,
    }


def varints(values):
    previous = 0
    for value in values:
        delta = value - previous
        previous = value
        while delta >= 128:
            yield (delta & 127) | 128
            delta >>= 7
        yield delta


def storage(index, mode, block_count):
    # Stream encoded bytes into compression; never retain another complete index.
    compressor = zlib.compressobj()
    encoded_size = compressed_size = 0
    for gram, posting in sorted(index.items()):
        values = (
            [i for i in range(block_count) if posting >> i & 1]
            if mode == "block"
            else posting
        )
        data = bytes(varints(values))
        frame = gram + struct.pack(">I", len(data)) + data
        encoded_size += len(frame)
        compressed_size += len(compressor.compress(frame))
    compressed_size += len(compressor.flush())
    resident = sys.getsizeof(index) + sum(
        sys.getsizeof(k) + sys.getsizeof(v) for k, v in index.items()
    )
    return {
        "resident_index_shallow_owned_bytes": resident,
        "delta_varint_bytes": encoded_size,
        "delta_varint_zlib_bytes": compressed_size,
        "query_representation": "resident bitsets or uint32 arrays; compressed postings are NOT queried",
    }


def run(args):
    (blocks, documents, info), preparation = timed(
        lambda: sample(
            args.sidecar,
            max_blocks=args.max_blocks,
            max_raw_bytes=args.max_sample_bytes,
            max_documents=args.max_documents,
            max_block_bytes=args.max_block_bytes,
        )
    )
    report = {
        "sample": info,
        "preparation": preparation,
        "limits": vars(args).copy(),
        "notes": [
            "Offline experiment only; no production index is enabled.",
            "Input sample and posting payload are capped; Python object overhead exceeds logical bytes.",
            "Query phases decode and digest-check sampled blocks in memory; SQLite I/O and full reopen validation are excluded.",
            "Resident sample documents are retained to build both indexes; this is not streaming full-corpus peak RSS.",
            "Compressed posting storage is an estimate; compressed-posting query costs are unmeasured.",
        ],
        "indexes": {},
    }
    report["limits"]["sidecar"] = str(args.sidecar.resolve())
    if report["limits"].get("output") is not None:
        report["limits"]["output"] = str(args.output.resolve())
    needles = args.term or [
        "failure",
        "success",
        "missing-literal-probe",
        "interface",
        "a",
        "é",
        "\0",
        "route",
    ]
    baselines = []
    for term in needles:
        needle = term.encode("utf-8")
        expected, phase = timed(
            partial(exact_scan, blocks, needle, args.max_block_bytes)
        )
        baselines.append((term, needle, expected, phase))
    for mode in ["block", "document"]:
        try:
            (index, docmap, size), build = timed(
                partial(
                    build_index, documents, mode, args.max_posting_bytes, args.max_grams
                )
            )
        except ValueError as error:
            report["indexes"][mode] = {"skipped": str(error)}
            continue
        result = {
            "build": build,
            "posting_payload_bytes": size,
            "storage": storage(index, mode, len(blocks)),
            "queries": [],
        }
        for term, needle, expected, baseline in baselines:
            (selected, positions), candidate_phase = timed(
                partial(candidates, index, docmap, mode, needle, len(blocks))
            )
            actual, exact_phase = timed(
                partial(exact_scan, blocks, needle, args.max_block_bytes, selected)
            )
            if actual != expected:
                raise AssertionError("candidate exclusions changed exact output")
            # Independently validate document postings, including false positives.
            if positions is not None:
                allowed = {docmap[i][0] for i in positions}
                if [ordinal for ordinal in actual if ordinal in allowed] != expected:
                    raise AssertionError("document postings excluded a match")
            result["queries"].append(
                {
                    "term": term,
                    "matches": len(actual),
                    "exact": True,
                    "ordinal_sha256": sha256(
                        b"".join(struct.pack(">Q", i) for i in actual)
                    ).hexdigest(),
                    "blocks_visited": len(selected),
                    "candidate_documents": None
                    if positions is None
                    else len(positions),
                    "compressed_scan": baseline,
                    "candidate_selection": candidate_phase,
                    "candidate_block_decode_exact": exact_phase,
                }
            )
        report["indexes"][mode] = result
        del index, docmap
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-blocks", type=int, default=32)
    parser.add_argument("--max-sample-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-documents", type=int, default=50000)
    parser.add_argument("--max-block-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--max-posting-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--max-grams", type=int, default=65536)
    parser.add_argument("--term", action="append")
    args = parser.parse_args(argv)
    if (
        min(
            args.max_blocks,
            args.max_sample_bytes,
            args.max_documents,
            args.max_block_bytes,
            args.max_posting_bytes,
            args.max_grams,
        )
        <= 0
    ):
        parser.error("all bounds must be positive")
    if args.output is not None and args.output.resolve() == args.sidecar.resolve():
        parser.error("output must differ from sidecar")
    report = json.dumps(run(args), indent=2)
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
