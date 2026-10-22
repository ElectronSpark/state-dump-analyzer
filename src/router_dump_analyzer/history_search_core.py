"""Bounded, revision-local search support for immutable history streams.

The core owns literal search over the client-safe projection. Plug-ins still
own the vocabulary and sensitivity declarations used to create that
projection. A host can persist the safe corpus in a SQLite sidecar so later
queries avoid both a large private-memory copy and a repeated rebuild.
"""

from __future__ import annotations

import os
import sqlite3
import struct
import zlib
from array import array
from bisect import bisect_left
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from threading import Condition, RLock
from typing import Any
from uuid import uuid4

from ._history_search_cache import _shared_results
from ._history_search_validation import _validated_compressed
from ._import_scheduling import _cooperate_with_durable_import
from .cancellation import query_cancellation_checkpoint, query_checked
from .history_search_matches import MatchSet as _MatchSet
from .load_progress import AnalysisLoadStage as _AnalysisLoadStage
from .load_progress import report_analysis_load as _report_analysis_load


class HistorySearchCapacityError(RuntimeError):
    """The exact history corpus exceeded its configured safety bound."""


class _SidecarUnavailable(RuntimeError):
    """The optional disk cache cannot be used; memory fallback remains exact."""


class HistorySearchCorpus:
    """Cache exact safe search documents and bounded result postings.

    Search documents must already be redacted and case-folded by the caller.
    A configured sidecar is built through a same-directory temporary database
    and atomically published only after its metadata and row count are complete.
    A matching second process or later launch can reopen it read-only without
    invoking the document builder.

    Production storage can implement the same contract with PostgreSQL
    ``pg_trgm``. SQLite is deliberately a local serving cache and never
    receives raw plug-in payloads.
    """

    _FORMAT_VERSION = "history-search-sqlite-v7"
    _INSERT_BATCH_SIZE = 512
    _FTS5_BACKEND = "fts5-trigram"
    _SCAN_BACKEND = "sqlite-scan"
    _BLOCK_BACKEND = "sqlite-zlib-blocks-v1"
    _BLOCK_TARGET_BYTES = 256 * 1024
    _BLOCK_MAX_DOCUMENTS = 65536
    _MAX_CANDIDATE_TERMS = 64

    def __init__(
        self,
        *,
        sidecar_path: Path | None = None,
        identity: str | None = None,
        expected_documents: int | None = None,
        eager_validate_sidecar: bool = True,
        max_documents: int = 250_000,
        max_characters: int = 256 * 1024 * 1024,
        max_document_bytes: int = 8 * 1024 * 1024,
        max_database_bytes: int = 512 * 1024 * 1024,
        max_eager_candidate_characters: int = 64 * 1024 * 1024,
        max_cached_queries: int = 12,
        max_cached_ordinals: int = 1_000_000,
        max_cached_bytes: int | None = None,
    ) -> None:
        if sidecar_path is not None and not identity:
            raise ValueError("a persistent history corpus requires an identity")
        if expected_documents is not None and expected_documents < 0:
            raise ValueError("expected_documents must be non-negative")
        if (
            min(
                max_documents,
                max_characters,
                max_document_bytes,
                max_database_bytes,
                max_eager_candidate_characters,
                max_cached_queries,
                max_cached_ordinals,
            )
            <= 0
        ):
            raise ValueError("history search bounds must be positive")
        self._sidecar_path = (
            Path(os.path.abspath(os.fspath(sidecar_path.expanduser())))
            if sidecar_path is not None
            else None
        )
        self._identity = identity
        self._expected_documents = expected_documents
        self._max_documents = max_documents
        self._max_characters = max_characters
        self._max_document_bytes = max_document_bytes
        self._max_database_bytes = max_database_bytes
        self._max_eager_candidate_characters = max_eager_candidate_characters
        self._max_cached_queries = max_cached_queries
        self._max_cached_ordinals = max_cached_ordinals
        self._max_cached_bytes = (
            max_cached_ordinals * 4 if max_cached_bytes is None else max_cached_bytes
        )
        if self._max_cached_bytes <= 0:
            raise ValueError("history search cache byte bound must be positive")
        self._condition = Condition(RLock())
        self._documents: tuple[str, ...] | None = None
        self._block_digests: dict[int, tuple[int, int, str, str]] = {}
        self._sidecar_ready = False
        self._bypass_sidecar = False
        self._candidate_backend = "pending"
        self._document_count = 0
        self._character_count = 0
        self._building = False
        self._closed = False
        self._error: Exception | None = None
        self._results: OrderedDict[str, _MatchSet] = OrderedDict()
        self._reuse_identity: str | None = None
        self._reuse_file_stamp: tuple[int, ...] | None = None
        self._cached_ordinals = 0
        self._cached_bytes = 0
        # Hosts that explicitly warm the corpus later can defer the linear
        # digest/index validation to that first-use or startup operation. The
        # default remains eager for callers that use ``ready`` as a startup
        # contract.
        if self._sidecar_path is not None and eager_validate_sidecar:
            try:
                opened = self._open_valid_sidecar(self._sidecar_path)
            except (OSError, sqlite3.DatabaseError):
                opened = None
            if opened is not None:
                document_count, character_count, backend = opened
                self._sidecar_ready = True
                self._document_count = document_count
                self._character_count = character_count
                self._candidate_backend = backend

    @property
    def ready(self) -> bool:
        with self._condition:
            return self._documents is not None or self._sidecar_ready

    @property
    def document_count(self) -> int:
        with self._condition:
            return self._document_count

    @property
    def character_count(self) -> int:
        with self._condition:
            return self._character_count

    @property
    def storage_mode(self) -> str:
        with self._condition:
            if self._sidecar_ready:
                return "sqlite"
            if self._documents is not None:
                return "memory"
            return "pending"

    @property
    def candidate_backend(self) -> str:
        """Describe the optional candidate accelerator without warming it."""

        with self._condition:
            if self._sidecar_ready:
                return self._candidate_backend
            if self._documents is not None:
                return "memory-scan"
            return "pending"

    @property
    def sidecar_path(self) -> Path | None:
        return self._sidecar_path

    def status_snapshot(self) -> dict[str, object]:
        """Return one internally consistent, non-sensitive health snapshot."""

        with self._condition:
            ready = self._documents is not None or self._sidecar_ready
            if self._sidecar_ready:
                storage = "sqlite"
                backend = self._candidate_backend
            elif self._documents is not None:
                storage = "memory"
                backend = "memory-scan"
            else:
                storage = "pending"
                backend = "pending"
            return {
                "ready": ready,
                "document_count": self._document_count if ready else 0,
                "storage": storage,
                "backend": backend,
            }

    @staticmethod
    def _path_uses_link(path: Path) -> bool:
        for component in (path, *path.parents):
            try:
                if component.is_symlink() or (
                    hasattr(component, "is_junction") and component.is_junction()
                ):
                    return True
            except OSError:
                return True
        return False

    def _open_valid_sidecar(
        self,
        path: Path,
        *,
        _needle: str | None = None,
        _matches: array[int] | None = None,
        _shared_matches: list[_MatchSet] | None = None,
    ) -> tuple[int, int, str] | None:
        if not path.exists():
            return None
        if self._path_uses_link(path) or not path.is_file():
            raise OSError("history search sidecar must be a regular file")
        opening_stamp = self._sidecar_stamp(path)
        if opening_stamp is None or opening_stamp[0] > self._max_database_bytes:
            return None
        connection = sqlite3.connect(
            f"{path.as_uri()}?mode=ro",
            uri=True,
            check_same_thread=False,
        )
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA cache_size=-8192")
            # A read transaction binds metadata, payload checks and any fused
            # matching to one SQLite snapshot. immutable=1 does not lock pages.
            connection.execute("BEGIN")
            row = connection.execute(
                """
                SELECT format_version, identity, document_count,
                       character_count, documents_digest, backend,
                       candidate_digest, complete
                FROM metadata
                WHERE singleton = 1
                """
            ).fetchone()
            if row is None:
                return None
            (
                format_version,
                identity,
                document_count,
                character_count,
                documents_digest,
                backend,
                candidate_digest,
                complete,
            ) = row
            if (
                format_version != self._FORMAT_VERSION
                or identity != self._identity
                or backend not in {self._FTS5_BACKEND, self._SCAN_BACKEND, self._BLOCK_BACKEND}
                or int(complete) != 1
                or int(document_count) < 0
                or int(character_count) < 0
                or int(document_count) > self._max_documents
                or int(character_count) > self._max_characters
                or len(str(documents_digest)) != 64
                or (backend == self._FTS5_BACKEND and len(str(candidate_digest)) != 64)
                or (backend != self._FTS5_BACKEND and str(candidate_digest) != "")
                or (
                    self._expected_documents is not None
                    and int(document_count) != self._expected_documents
                )
            ):
                return None
            digest = sha256()
            validated_blocks: dict[int, tuple[int, int, str, str]] = {}
            validated_maximum = [0]
            # A cold process has no certified bytes to reuse. Its complete
            # validator already hashes each compressed payload while pinning
            # the blocks, so a speculative payload pass would repeat that work.
            if backend == self._BLOCK_BACKEND and _validated_compressed:
                fingerprint, snapshot_blocks = self._compressed_snapshot(connection, row)
                previous_maximum = _validated_compressed.get(fingerprint)
                if previous_maximum is not None and previous_maximum <= self._max_document_bytes:
                    if self._sidecar_stamp(path) != opening_stamp:
                        return None
                    previous_blocks = self._block_digests
                    previous_identity = self._reuse_identity
                    self._block_digests = snapshot_blocks
                    shared = None
                    try:
                        if _needle is not None and _matches is not None:
                            self._set_reuse_identity(str(documents_digest), int(document_count))
                            assert self._reuse_identity is not None
                            shared = _shared_results.get(self._reuse_identity, _needle)
                            if shared is not None and _shared_matches is None:
                                _matches.extend(shared)
                            elif shared is None:
                                try:
                                    encoded_needle = _needle.encode("utf-8")
                                except UnicodeEncodeError:
                                    encoded_needle = None
                                if encoded_needle is not None:
                                    _matches.extend(ordinal for ordinal, _ in self._iter_disk_documents(
                                        connection, self._BLOCK_BACKEND,
                                        _matching_needle=encoded_needle,
                                    ))
                        if self._sidecar_stamp(path) != opening_stamp:
                            return None
                    finally:
                        self._block_digests = previous_blocks
                        self._reuse_identity = previous_identity
                    self._block_digests = snapshot_blocks
                    self._set_reuse_identity(str(documents_digest), int(document_count))
                    self._reuse_file_stamp = opening_stamp
                    if shared is not None and _shared_matches is not None:
                        _shared_matches.append(shared)
                    return int(document_count), int(character_count), str(backend)
                del snapshot_blocks
            actual_count = 0
            actual_character_count = 0
            if backend == self._BLOCK_BACKEND:
                try:
                    encoded_needle = _needle.encode("utf-8") if _needle is not None else None
                except UnicodeEncodeError:
                    encoded_needle = None
                counts = [0, 0]
                for ordinal, _ in self._iter_disk_documents(
                    connection, str(backend), _validated_blocks=validated_blocks,
                    _validated_maximum=validated_maximum, _validation_digest=digest,
                    _validation_counts=counts, _matching_needle=encoded_needle,
                ):
                    if _matches is not None:
                        _matches.append(ordinal)
                actual_count, actual_character_count = counts
            else:
                for expected_ordinal, (ordinal, safe_text) in enumerate(
                    self._iter_disk_documents(connection, str(backend))
                ):
                    if int(ordinal) != expected_ordinal:
                        return None
                    if not isinstance(safe_text, str):
                        return None
                    try:
                        encoded = safe_text.encode("utf-8")
                    except UnicodeEncodeError:
                        return None
                    if len(encoded) > self._max_document_bytes:
                        return None
                    self._update_documents_digest(digest, expected_ordinal, encoded)
                    if _needle is not None and _matches is not None and _needle in safe_text:
                        _matches.append(expected_ordinal)
                    actual_count += 1
                    actual_character_count += len(safe_text)
                    if actual_count % 1024 == 0:
                        _report_analysis_load(
                            _AnalysisLoadStage.INDEXING, records_processed=actual_count,
                        )
            if (
                actual_count != int(document_count)
                or actual_character_count != int(character_count)
                or not compare_digest(digest.hexdigest(), str(documents_digest))
            ):
                return None
            if backend == self._FTS5_BACKEND:
                fts_schema = connection.execute(
                    """
                    SELECT sql
                    FROM sqlite_master
                    WHERE type = 'table' AND name = 'documents_fts'
                    """
                ).fetchone()
                if (
                    fts_schema is None
                    or "content='documents'" not in str(fts_schema[0]).lower()
                    or "content_rowid='ordinal'" not in str(fts_schema[0]).lower()
                    or "tokenize='trigram case_sensitive 1'"
                    not in str(fts_schema[0]).lower()
                    or "detail='none'" not in str(fts_schema[0]).lower()
                    or "columnsize=0" not in str(fts_schema[0]).lower()
                ):
                    return None
                vocab_schema = connection.execute(
                    """
                    SELECT sql
                    FROM sqlite_master
                    WHERE type = 'table' AND name = 'documents_fts_vocab'
                    """
                ).fetchone()
                exception_schema = connection.execute(
                    """
                    SELECT sql
                    FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'documents_fts_exceptions'
                    """
                ).fetchone()
                if (
                    vocab_schema is None
                    or "fts5vocab(documents_fts,'row')"
                    not in "".join(str(vocab_schema[0]).lower().split())
                    or exception_schema is None
                    or not compare_digest(
                        self._fts5_candidate_digest(connection),
                        str(candidate_digest),
                    )
                ):
                    return None
            validated = int(document_count), int(character_count), str(backend)
            if self._sidecar_stamp(path) != opening_stamp:
                return None
            # Publish pins only after the complete canonical corpus and any
            # candidate index have passed validation. A rejected existing cache
            # must not replace the pins of our newly built temporary database.
            self._block_digests = validated_blocks
            self._set_reuse_identity(str(documents_digest), int(document_count))
            self._reuse_file_stamp = opening_stamp
            if backend == self._BLOCK_BACKEND:
                fingerprint = self._compressed_fingerprint(row, validated_blocks)
                _validated_compressed.put(fingerprint, validated_maximum[0])
        finally:
            connection.close()
        return validated

    def _compressed_snapshot(
        self, connection: sqlite3.Connection, metadata: tuple[Any, ...],
    ) -> tuple[str, dict[int, tuple[int, int, str, str]]]:
        """Hash every bounded payload freshly inside the caller's transaction.

        Stored raw digests are metadata only; the fingerprint also covers the
        actual compressed bytes, ordered framing and complete metadata. Only a
        prior full validator can associate that fingerprint with reusable facts.
        """
        blocks: dict[int, tuple[int, int, str, str]] = {}
        expected = 0
        maximum = max(self._BLOCK_TARGET_BYTES, self._max_document_bytes + 4)
        for first, count, size, payload_size, digest_size in query_checked(connection.execute(
            "SELECT first_ordinal, document_count, raw_bytes, length(payload), length(digest) "
            "FROM document_blocks ORDER BY first_ordinal"
        )):
            if (type(first) is not int or first != expected or type(count) is not int
                or not 1 <= count <= self._BLOCK_MAX_DOCUMENTS
                or expected + count > self._max_documents or type(size) is not int
                or not count * 4 <= size <= maximum
                or type(payload_size) is not int or not 0 < payload_size <= maximum + 1024
                or digest_size != 64):
                raise sqlite3.DatabaseError("invalid compressed search block framing")
            payload, raw_digest = connection.execute(
                "SELECT payload, digest FROM document_blocks WHERE first_ordinal=?", (first,),
            ).fetchone()
            if (type(payload) is not bytes or len(payload) != payload_size
                or type(raw_digest) is not str):
                raise sqlite3.DatabaseError("invalid compressed search block payload")
            payload_digest = sha256(payload).hexdigest()
            block = (count, size, raw_digest, payload_digest)
            blocks[first] = block
            expected += count
        if expected != metadata[2]:
            raise sqlite3.DatabaseError("compressed search document count mismatch")
        return self._compressed_fingerprint(metadata, blocks), blocks

    @staticmethod
    def _compressed_fingerprint(
        metadata: tuple[Any, ...], blocks: dict[int, tuple[int, int, str, str]],
    ) -> str:
        digest = sha256(repr(metadata).encode("utf-8"))
        # Both callers collect blocks in canonical ordinal order. Full
        # validation can use its existing compressed-byte pins directly.
        for first, block in blocks.items():
            digest.update(repr((first, *block)).encode("utf-8"))
        return digest.hexdigest()

    @staticmethod
    def _update_documents_digest(
        digest: Any,
        ordinal: int,
        encoded: bytes | memoryview,
    ) -> None:
        digest.update(struct.pack(">QQ", ordinal, len(encoded)))
        digest.update(encoded)

    def _bounded_documents(
        self,
        documents: Callable[[], Iterable[str]],
    ) -> Iterable[tuple[int, str]]:
        character_count = 0
        document_count = 0
        for document_count, document in enumerate(documents(), start=1):
            if document_count > self._max_documents:
                raise HistorySearchCapacityError(
                    "history search corpus exceeds the document limit"
                )
            character_count += len(document)
            if character_count > self._max_characters:
                raise HistorySearchCapacityError(
                    "history search corpus exceeds the character limit"
                )
            yield document_count - 1, document
            if document_count % 64 == 0:
                _cooperate_with_durable_import()
            if document_count % 1024 == 0:
                _report_analysis_load(
                    _AnalysisLoadStage.INDEXING,
                    records_processed=document_count,
                )
        if (
            self._expected_documents is not None
            and document_count != self._expected_documents
        ):
            raise RuntimeError(
                "history search document count does not match the revision"
            )
        self._document_count = document_count
        self._character_count = character_count
        _report_analysis_load(
            _AnalysisLoadStage.INDEXING, records_processed=document_count
        )

    def _build_memory(
        self,
        documents: Callable[[], Iterable[str]],
    ) -> tuple[str, ...]:
        # Memory-only histories keep their original construction cost. Reuse
        # belongs to persistent corpora whose normal lifecycle already hashes
        # and validates the complete safe projection.
        self._reuse_identity = None
        self._reuse_file_stamp = None
        return tuple(document for _, document in query_checked(self._bounded_documents(documents)))

    def _set_reuse_identity(self, documents_digest: str, count: int) -> None:
        digest = sha256()
        for part in (self._FORMAT_VERSION, self._identity or "", documents_digest,
                     str(count), "safe-folded-literal-v1"):
            encoded = part.encode("utf-8", errors="surrogatepass")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        self._reuse_identity = digest.hexdigest()

    @staticmethod
    def _sidecar_stamp(path: Path) -> tuple[int, ...] | None:
        try:
            stat = path.stat()
            stamp: tuple[int, ...] = (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns,
                                     stat.st_dev, stat.st_ino)
            # A writer may switch a derived sidecar to WAL mode. Main-file
            # timestamps alone would then miss committed page changes.
            for suffix in ("-wal", "-journal"):
                try:
                    journal = path.with_name(path.name + suffix).stat()
                except FileNotFoundError:
                    stamp += (0, 0, 0, 0, 0)
                else:
                    if journal.st_size == 0:
                        # Opening an otherwise unchanged WAL database can
                        # create an empty WAL; it carries no page changes.
                        stamp += (0, 0, 0, 0, 0)
                    else:
                        stamp += (journal.st_size, journal.st_mtime_ns, journal.st_ctime_ns,
                                  journal.st_dev, journal.st_ino)
            return stamp
        except OSError:
            return None

    def _shared_match(self, needle: str) -> _MatchSet | None:
        if self._reuse_identity is None:
            return None
        if (
            self._sidecar_ready
            and self._sidecar_path is not None
            and (
                self._reuse_file_stamp is None
                or self._sidecar_stamp(self._sidecar_path) != self._reuse_file_stamp
            )
        ):
            return None
        return _shared_results.get(self._reuse_identity, needle)

    def _build_sidecar(
        self,
        documents: Callable[[], Iterable[str]],
        *,
        _needle: str | None = None,
        _matches: array[int] | None = None,
    ) -> tuple[int, int, str]:
        if self._sidecar_path is None:
            raise _SidecarUnavailable("no history search sidecar was configured")
        target = self._sidecar_path
        if self._path_uses_link(target):
            raise _SidecarUnavailable("refusing a linked sidecar path")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if self._path_uses_link(target):
                raise _SidecarUnavailable("refusing a linked sidecar path")
            try:
                os.chmod(target.parent, 0o700)
            except OSError:
                pass
        except OSError as error:
            raise _SidecarUnavailable(str(error)) from error
        temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}-{uuid4().hex}")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(temporary)
            connection.execute("PRAGMA page_size=4096")
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA cache_size=-8192")
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            max_page_count = max(1, self._max_database_bytes // page_size)
            connection.execute(f"PRAGMA max_page_count={max_page_count}")
            connection.execute(
                """
                CREATE TABLE metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    format_version TEXT NOT NULL,
                    identity TEXT NOT NULL,
                    document_count INTEGER NOT NULL,
                    character_count INTEGER NOT NULL,
                    documents_digest TEXT NOT NULL,
                    backend TEXT NOT NULL,
                    candidate_digest TEXT NOT NULL,
                    complete INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE documents (
                    ordinal INTEGER PRIMARY KEY,
                    safe_text TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE documents_fts_exceptions (
                    ordinal INTEGER PRIMARY KEY
                        REFERENCES documents(ordinal)
                )
                """
            )
            connection.execute("""CREATE TABLE document_blocks (
                first_ordinal INTEGER PRIMARY KEY, document_count INTEGER NOT NULL,
                raw_bytes INTEGER NOT NULL, payload BLOB NOT NULL,
                digest TEXT NOT NULL)""")
            documents_digest = sha256()
            pending: list[tuple[int, str]] = []
            pending_characters = 0
            compressed = False
            block: list[bytes] = []
            block_bytes = 0
            block_first = 0
            maximum_document_bytes = 0
            reusable_projection = True

            def flush_block() -> None:
                nonlocal block_bytes
                if not block:
                    return
                raw = b"".join(struct.pack(">I", len(item)) for item in query_checked(block)) + b"".join(block)
                assert connection is not None
                connection.execute("INSERT INTO document_blocks VALUES (?, ?, ?, ?, ?)",
                    (block_first, len(block), len(raw), zlib.compress(raw, 1), sha256(raw).hexdigest()))
                block.clear()
                block_bytes = 0

            def append_block(ordinal: int, encoded: bytes) -> None:
                nonlocal block_first, block_bytes
                if block and (block_bytes + len(encoded) + 4 > self._BLOCK_TARGET_BYTES
                              or len(block) >= self._BLOCK_MAX_DOCUMENTS):
                    flush_block()
                if not block:
                    block_first = ordinal
                block.append(encoded)
                block_bytes += len(encoded) + 4

            for ordinal, text in query_checked(self._bounded_documents(documents)):
                reusable_projection = reusable_projection and type(text) is str
                try:
                    encoded = text.encode("utf-8")
                except UnicodeEncodeError as error:
                    raise _SidecarUnavailable("safe search text is not a Unicode scalar string") from error
                encoded_size = len(encoded)
                if encoded_size > self._max_document_bytes:
                    raise _SidecarUnavailable("one history search document exceeds the disk bound")
                if encoded_size > maximum_document_bytes:  # noqa: PLR1730 - avoid max() call overhead in this hot loop.
                    maximum_document_bytes = encoded_size
                self._update_documents_digest(documents_digest, ordinal, encoded)
                if not compressed:
                    pending.append((ordinal, text))
                    pending_characters += len(text)
                    if (pending_characters <= self._max_eager_candidate_characters
                        and len(pending) < self._BLOCK_MAX_DOCUMENTS):
                        continue
                    compressed = True
                    for pending_ordinal, pending_text in query_checked(pending):
                        append_block(pending_ordinal, pending_text.encode("utf-8"))
                    pending.clear()
                else:
                    append_block(ordinal, encoded)
            if compressed:
                flush_block()
            else:
                connection.executemany("INSERT INTO documents VALUES (?, ?)", pending)
                connection.executemany("INSERT INTO documents_fts_exceptions VALUES (?)",
                    ((ordinal,) for ordinal, text in query_checked(pending) if "\0" in text))
            pending.clear()
            # Persist the exact corpus first.  The FTS table is only a candidate
            # accelerator, so a SQLite build without FTS5/trigram support still
            # publishes a reusable, exact scan sidecar.
            connection.commit()
            if not compressed:
                connection.execute("DROP TABLE document_blocks")
                connection.commit()
            if compressed or self._character_count >= 1024 * 1024:
                connection.execute("PRAGMA page_size=65536")
                connection.execute("VACUUM")
                connection.execute(f"PRAGMA max_page_count={max(1, self._max_database_bytes // 65536)}")
            backend = self._BLOCK_BACKEND if compressed else self._SCAN_BACKEND
            candidate_digest = ""
            # Trigram indexing is O(total safe-text characters) and can dwarf
            # parsing for large immutable histories.  Exact SQLite substring
            # scans remain bounded and correct, so large corpora publish the
            # scan backend immediately instead of delaying availability for an
            # accelerator.  Smaller corpora retain the responsive FTS path.
            if not compressed:
                try:
                    built_candidate_digest = self._build_fts5_candidate_index(
                        connection
                    )
                    if built_candidate_digest is not None:
                        connection.commit()
                        backend = self._FTS5_BACKEND
                        candidate_digest = built_candidate_digest
                    else:
                        connection.rollback()
                except sqlite3.DatabaseError:
                    # An optional accelerator must not make the exact corpus
                    # unavailable.  Roll back its transaction and compact any
                    # pages it allocated before publishing the scan backend.
                    connection.rollback()
                    connection.execute("DROP TABLE IF EXISTS documents_fts")
                    connection.commit()
                    connection.execute("VACUUM")
            connection.execute(
                """
                INSERT INTO metadata(
                    singleton, format_version, identity, document_count,
                    character_count, documents_digest, backend,
                    candidate_digest, complete
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    self._FORMAT_VERSION,
                    self._identity,
                    self._document_count,
                    self._character_count,
                    documents_digest.hexdigest(),
                    backend,
                    candidate_digest,
                ),
            )
            connection.commit()
            if compressed:
                metadata = connection.execute(
                    "SELECT format_version, identity, document_count, character_count, "
                    "documents_digest, backend, candidate_digest, complete "
                    "FROM metadata WHERE singleton=1"
                ).fetchone()
                assert metadata is not None
                fingerprint, self._block_digests = self._compressed_snapshot(connection, metadata)
                if reusable_projection:
                    _validated_compressed.put(fingerprint, maximum_document_bytes)
            connection.close()
            connection = None
            if temporary.stat().st_size > self._max_database_bytes:
                raise _SidecarUnavailable(
                    "history search sidecar exceeds the disk bound"
                )
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass

            # If another process already published the same complete cache,
            # prefer it. Otherwise atomically replace only this derived cache.
            try:
                existing_matches = array("I")
                existing = self._open_valid_sidecar(
                    target, _needle=_needle, _matches=existing_matches
                )
            except sqlite3.DatabaseError:
                existing = None
            if existing is not None:
                if _matches is not None:
                    _matches[:] = existing_matches
                temporary.unlink(missing_ok=True)
                return existing
            os.replace(temporary, target)
            self._set_reuse_identity(documents_digest.hexdigest(), self._document_count)
            self._reuse_file_stamp = self._sidecar_stamp(target)
            # The just-committed database was built from the bounded source
            # iterator, and its exact document/accelerator digests were
            # computed in this process. Re-reading every document (and the
            # complete FTS vocabulary) here only repeats O(corpus) work. A
            # later process still performs the full validation before reuse.
            return (
                self._document_count,
                self._character_count,
                backend,
            )
        except HistorySearchCapacityError:
            raise
        except (OSError, sqlite3.DatabaseError) as error:
            raise _SidecarUnavailable(str(error)) from error
        finally:
            if connection is not None:
                connection.close()
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _iter_disk_documents(
        self, connection: sqlite3.Connection, backend: str, candidates: Sequence[int] | None = None,
        *, _matching_needle: bytes | None = None,
        _validated_blocks: dict[int, tuple[int, int, str, str]] | None = None,
        _validated_maximum: list[int] | None = None,
        _validation_digest: Any = None,
        _validation_counts: list[int] | None = None,
    ) -> Iterable[tuple[int, str]]:
        if backend != self._BLOCK_BACKEND:
            yield from query_checked(connection.execute("SELECT ordinal, safe_text FROM documents ORDER BY ordinal"))
            return
        expected = 0
        validated_digests: dict[int, tuple[int, int, str, str]] = {}
        maximum = max(self._BLOCK_TARGET_BYTES, self._max_document_bytes + 4)
        try:
            for first, count, size, payload_size, digest_size in query_checked(connection.execute(
                "SELECT first_ordinal, document_count, raw_bytes, length(payload), length(digest) FROM document_blocks ORDER BY first_ordinal"
            )):
                if (type(first) is not int or first != expected or type(count) is not int
                    or not 1 <= count <= self._BLOCK_MAX_DOCUMENTS
                    or expected + count > self._max_documents or type(size) is not int
                    or not count * 4 <= size <= maximum
                    or type(payload_size) is not int or not 0 < payload_size <= maximum + 1024
                    or digest_size != 64):
                    raise ValueError("invalid compressed search block framing")
                if _matching_needle is not None and _validation_digest is None:
                    pinned = self._block_digests.get(first)
                    if pinned is None or pinned[:2] != (count, size):
                        raise ValueError("compressed search block framing changed")
                if candidates is not None:
                    candidate_index = bisect_left(candidates, first)
                    if candidate_index == len(candidates) or candidates[candidate_index] >= first + count:
                        expected += count
                        continue
                payload, digest = connection.execute(
                    "SELECT payload, digest FROM document_blocks WHERE first_ordinal=?", (first,)
                ).fetchone()
                if not isinstance(payload, bytes) or len(payload) > maximum + 1024:
                    raise ValueError("invalid compressed search block payload")
                if _matching_needle is not None and _validation_digest is None:
                    pinned = self._block_digests.get(first)
                    if (pinned is None or pinned[:3] != (count, size, digest)
                        or not compare_digest(sha256(payload).hexdigest(), pinned[3])):
                        raise ValueError("compressed search block generation changed")
                decoder = zlib.decompressobj()
                raw = decoder.decompress(payload, size + 1)
                if (len(raw) != size or not decoder.eof or decoder.unused_data
                    or decoder.unconsumed_tail or not isinstance(digest, str)):
                    raise ValueError("invalid compressed search block stream")
                if _matching_needle is None or _validation_digest is not None:
                    if not compare_digest(sha256(raw).hexdigest(), digest):
                        raise ValueError("invalid compressed search block digest")
                    # Pin exact compressed bytes only after validating raw bytes.
                    # Later queries verify this smaller immutable representation,
                    # which decompresses to the already validated UTF-8 corpus.
                    validated_digests[first] = (count, size, digest, sha256(payload).hexdigest())
                offset = count * 4
                lengths = struct.unpack_from(f">{count}I", raw)
                if _validation_digest is not None:
                    # Validate UTF-8 once for the bounded block, then ensure no
                    # document starts inside a scalar. This proves each framed
                    # document is valid without decoding and re-encoding every
                    # row merely to hash its original bytes again.
                    character_count = len(raw[offset:].decode("utf-8"))
                    raw_view = memoryview(raw)
                    assert _validation_counts is not None
                    _validation_counts[1] += character_count
                if _validated_maximum is not None:
                    block_maximum = max(lengths)
                    if block_maximum > _validated_maximum[0]:  # noqa: PLR1730 - avoid another max() call in this hot loop.
                        _validated_maximum[0] = block_maximum
                for length in query_checked(lengths):
                    end = offset + length
                    if length > self._max_document_bytes or end > size:
                        raise ValueError("invalid compressed search document length")
                    if _validation_digest is not None:
                        if offset < size and raw[offset] & 0xC0 == 0x80:
                            raise ValueError("UTF-8 scalar crosses a search document boundary")
                        self._update_documents_digest(_validation_digest, expected, raw_view[offset:end])
                        if _matching_needle is not None and raw.find(_matching_needle, offset, end) >= 0:
                            yield expected, ""
                    elif _matching_needle is None:
                        yield expected, raw[offset:end].decode("utf-8")
                    else:
                        # UTF-8 literal matching is equivalent to scalar substring
                        # matching on validated UTF-8 and never crosses framing.
                        if raw.find(_matching_needle, offset, end) >= 0:
                            yield expected, ""
                    offset = end
                    expected += 1
                    if _validation_digest is not None and expected % 1024 == 0:
                        _report_analysis_load(_AnalysisLoadStage.INDEXING, records_processed=expected)
                if offset != size:
                    raise ValueError("trailing compressed search document bytes")
            declared_count = connection.execute("SELECT document_count FROM metadata WHERE singleton=1").fetchone()
            if declared_count is None or declared_count[0] != expected:
                raise ValueError("compressed search document count mismatch")
            if _validation_counts is not None:
                _validation_counts[0] = expected
            if (_matching_needle is None or _validation_digest is not None) and _validated_blocks is not None:
                _validated_blocks.update(validated_digests)
        except (ValueError, zlib.error, UnicodeError, struct.error) as error:
            raise sqlite3.DatabaseError("corrupt compressed search corpus") from error

    @staticmethod
    def _fts5_capability_error(error: sqlite3.OperationalError) -> bool:
        message = str(error).casefold()
        return any(
            marker in message
            for marker in (
                "no such module: fts5",
                "no such tokenizer",
                "unrecognized option",
                "parse error in tokenize directive",
            )
        )

    def _build_fts5_candidate_index(
        self,
        connection: sqlite3.Connection,
    ) -> str | None:
        """Build an optional external-content, case-sensitive trigram index."""

        try:
            connection.execute(
                """
                CREATE VIRTUAL TABLE documents_fts USING fts5(
                    safe_text,
                    content='documents',
                    content_rowid='ordinal',
                    tokenize='trigram case_sensitive 1',
                    detail='none',
                    columnsize=0
                )
                """
            )
        except sqlite3.OperationalError as error:
            if self._fts5_capability_error(error):
                return None
            raise
        connection.execute(
            """
            INSERT INTO documents_fts(documents_fts)
            VALUES ('rebuild')
            """
        )
        connection.execute(
            """
            INSERT INTO documents_fts(documents_fts, rank)
            VALUES ('integrity-check', 1)
            """
        )
        connection.execute(
            """
            CREATE VIRTUAL TABLE documents_fts_vocab USING fts5vocab(
                documents_fts,
                'row'
            )
            """
        )
        return self._fts5_candidate_digest(connection)

    @staticmethod
    def _fts5_candidate_digest(connection: sqlite3.Connection) -> str:
        digest = sha256()
        digest.update(b"fts5-vocabulary\0")
        for term, document_count, total_count in connection.execute(
            """
            SELECT term, doc, cnt
            FROM documents_fts_vocab
            ORDER BY term
            """
        ):
            encoded = str(term).encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big", signed=False))
            digest.update(encoded)
            digest.update(int(document_count).to_bytes(8, "big", signed=False))
            digest.update(
                (0 if total_count is None else int(total_count)).to_bytes(
                    8,
                    "big",
                    signed=False,
                )
            )
        digest.update(b"nul-exception-ordinals\0")
        for (ordinal,) in connection.execute(
            """
            SELECT ordinal
            FROM documents_fts_exceptions
            ORDER BY ordinal
            """
        ):
            digest.update(int(ordinal).to_bytes(8, "big", signed=False))
        return digest.hexdigest()

    @contextmanager
    def _query_lock(self) -> Iterator[None]:
        # A disconnected waiter owns neither the builder nor its result. Keep
        # waiting bounded while the independent reader retains the same lock.
        while not self._condition.acquire(timeout=0.05):
            query_cancellation_checkpoint()
        try:
            query_cancellation_checkpoint()
            yield
        finally:
            self._condition.release()

    def ensure(
        self, documents: Callable[[], Iterable[str]], *, _needle: str | None = None
    ) -> Sequence[int] | None:
        """Build or reopen the exact safe corpus once."""

        with self._query_lock():
            if self._closed:
                raise RuntimeError("history search corpus is closed")
            while self._building and (
                self._documents is None and not self._sidecar_ready
            ):
                self._condition.wait(timeout=0.05)
                query_cancellation_checkpoint()
            if self._closed:
                raise RuntimeError("history search corpus is closed")
            if self._documents is not None or self._sidecar_ready:
                return None
            if self._error is not None:
                raise self._error
            self._building = True

        collected = array("I")
        original_documents = documents

        # Keep the source closure independent of the reassigned builder.
        def collect_documents() -> Iterable[str]:
            del collected[:]
            for ordinal, text in enumerate(original_documents()):
                if _needle is not None and _needle in text:
                    collected.append(ordinal)
                yield text

        documents = collect_documents
        validation_matches = array("I")
        shared_validation_matches: list[_MatchSet] = []
        try:
            if self._sidecar_path is not None and not self._bypass_sidecar:
                try:
                    try:
                        opened = self._open_valid_sidecar(
                            self._sidecar_path,
                            _needle=_needle,
                            _matches=validation_matches,
                            _shared_matches=shared_validation_matches,
                        )
                    except sqlite3.DatabaseError:
                        if self._sidecar_path.is_symlink():
                            raise _SidecarUnavailable(
                                "refusing to replace a symbolic-link sidecar"
                            )
                        opened = None
                    if opened is None:
                        opened = self._build_sidecar(
                            documents, _needle=_needle, _matches=collected
                        )
                    else:
                        collected = validation_matches
                    document_count, character_count, backend = opened
                    completed: tuple[str, ...] | None = None
                    sidecar_ready = True
                except (OSError, sqlite3.DatabaseError, _SidecarUnavailable):
                    completed = self._build_memory(documents)
                    sidecar_ready = False
                    document_count = self._document_count
                    character_count = self._character_count
                    backend = "memory-scan"
            else:
                completed = self._build_memory(documents)
                sidecar_ready = False
                document_count = self._document_count
                character_count = self._character_count
                backend = "memory-scan"
            query_cancellation_checkpoint()
        except Exception as error:
            from .revision_queries import RevisionQueryCancellationError

            with self._condition:
                self._building = False
                # Cancellation belongs to this reader, not the shared corpus.
                # Completed sidecars stay intact; interrupted temporary builds
                # are cleaned by _build_sidecar and a waiting reader may retry.
                self._error = None if isinstance(error, RevisionQueryCancellationError) else error
                self._condition.notify_all()
            raise

        with self._condition:
            self._documents = completed
            self._sidecar_ready = sidecar_ready
            self._candidate_backend = backend
            self._document_count = document_count
            self._character_count = character_count
            result = self._remember(
                _needle, shared_validation_matches[0] if shared_validation_matches else collected,
            ) if _needle is not None else None
            self._building = False
            self._condition.notify_all()
            return result

    def _query_ready(self, needle: str) -> array[int]:
        candidates = min(
            (
                matches
                for term, matches in query_checked(self._results.items())
                if term in needle and len(matches) * 2 < self._document_count
            ),
            key=len,
            default=None,
        )
        if self._documents is not None:
            if candidates is not None:
                return array(
                    "I",
                    (
                        ordinal
                        for ordinal in query_checked(candidates)
                        if needle in self._documents[ordinal]
                    ),
                )
            return array(
                "I",
                (
                    index
                    for index, document in query_checked(enumerate(self._documents))
                    if needle in document
                ),
            )
        try:
            needle.encode("utf-8")
        except UnicodeEncodeError:
            # A validated SQLite corpus contains Unicode scalar strings only.
            return array("I")
        if not self._sidecar_ready or self._sidecar_path is None:
            raise RuntimeError("history search corpus is not ready")
        opening_stamp = self._sidecar_stamp(self._sidecar_path)
        if opening_stamp is None or opening_stamp != self._reuse_file_stamp:
            raise sqlite3.DatabaseError("history search generation changed")
        connection = sqlite3.connect(
            f"{self._sidecar_path.as_uri()}?mode=ro",
            uri=True,
            check_same_thread=False,
        )
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA cache_size=-8192")
            connection.execute("BEGIN")
            metadata = connection.execute(
                "SELECT format_version, identity, document_count, character_count, backend, complete FROM metadata WHERE singleton=1"
            ).fetchone()
            if metadata != (self._FORMAT_VERSION, self._identity, self._document_count,
                            self._character_count, self._candidate_backend, 1):
                raise sqlite3.DatabaseError("history search generation changed")
            if self._candidate_backend == self._BLOCK_BACKEND:
                matches = array("I")
                for ordinal, _ in query_checked(self._iter_disk_documents(
                    connection, self._BLOCK_BACKEND, candidates,
                    _matching_needle=needle.encode("utf-8"),
                )):
                    if candidates is not None:
                        index = bisect_left(candidates, ordinal)
                        if index == len(candidates) or candidates[index] != ordinal:
                            continue
                    matches.append(ordinal)
                return matches
            if candidates is not None:
                matches = array("I")
                for start in query_checked(range(0, len(candidates), self._INSERT_BATCH_SIZE)):
                    batch = candidates[start : start + self._INSERT_BATCH_SIZE]
                    placeholders = ",".join("?" for _ in query_checked(batch))
                    rows = connection.execute(
                        f"SELECT ordinal, safe_text FROM documents WHERE ordinal IN ({placeholders}) ORDER BY ordinal",
                        batch,
                    )
                    matches.extend(
                        int(ordinal) for ordinal, text in query_checked(rows) if needle in text
                    )
                return matches
            candidate = self._fts5_candidate_expression(needle)
            if self._candidate_backend == self._FTS5_BACKEND and candidate is not None:
                try:
                    rows = connection.execute(
                        """
                        SELECT documents.ordinal
                        FROM documents
                        WHERE instr(documents.safe_text, ?) > 0
                          AND (
                            documents.ordinal IN (
                              SELECT rowid
                              FROM documents_fts
                              WHERE documents_fts MATCH ?
                            )
                            OR documents.ordinal IN (
                              SELECT ordinal
                              FROM documents_fts_exceptions
                            )
                          )
                        ORDER BY documents.ordinal
                        """,
                        (needle, candidate),
                    )
                    return array("I", (int(row[0]) for row in query_checked(rows)))
                except sqlite3.OperationalError:
                    # MATCH is an accelerator only.  If a platform-specific
                    # FTS parser rejects a candidate, preserve exact behavior
                    # with the ordinary documents table.
                    pass
            return array(
                "I",
                (
                    int(row[0])
                    for row in query_checked(connection.execute(
                        """
                        SELECT ordinal
                        FROM documents
                        WHERE instr(safe_text, ?) > 0
                        ORDER BY ordinal
                        """,
                        (needle,),
                    ))
                ),
            )
        finally:
            connection.close()
            if self._sidecar_stamp(self._sidecar_path) != opening_stamp:
                raise sqlite3.DatabaseError("history search generation changed")

    @classmethod
    def _fts5_candidate_expression(cls, needle: str) -> str | None:
        """Compile safe necessary trigrams for candidate-only MATCH.

        Each exact three-codepoint window is quoted as one FTS term. Embedded
        quotes are doubled and NUL/surrogate windows are omitted because SQLite
        cannot parse or bind them reliably. If no safe trigram exists the exact
        SQLite scan is used instead. Every emitted term is a substring of
        ``needle``, so candidates are always a superset of literal matches.
        """

        trigrams: list[str] = []
        seen: set[str] = set()
        for offset in range(max(0, len(needle) - 2)):
            trigram = needle[offset : offset + 3]
            if "\0" in trigram:
                continue
            try:
                trigram.encode("utf-8")
            except UnicodeEncodeError:
                continue
            if trigram in seen:
                continue
            seen.add(trigram)
            trigrams.append(trigram)
            if len(trigrams) >= cls._MAX_CANDIDATE_TERMS:
                break
        if not trigrams:
            return None
        return " AND ".join(
            '"' + trigram.replace('"', '""') + '"' for trigram in trigrams
        )

    def _remember(self, needle: str, matches: Sequence[int]) -> Sequence[int]:
        cached = self._results.get(needle)
        if cached is not None:
            self._results.move_to_end(needle)
            return cached
        compact = self._shared_match(needle)
        if compact is None:
            compact = matches if type(matches) is _MatchSet else _MatchSet(matches, self._document_count)
        self._results[needle] = compact
        self._cached_bytes += compact.nbytes
        self._cached_ordinals += len(compact)
        while self._results and (
            len(self._results) > self._max_cached_queries
            or self._cached_bytes > self._max_cached_bytes
        ):
            _, evicted = self._results.popitem(last=False)
            self._cached_ordinals -= len(evicted)
            self._cached_bytes -= evicted.nbytes
        return compact

    def query(
        self,
        needle: str,
        documents: Callable[[], Iterable[str]],
    ) -> Sequence[int]:
        """Return time-ordered ordinals containing one literal folded string."""

        with self._query_lock():
            if self._closed:
                raise RuntimeError("history search corpus is closed")
            cached = self._results.get(needle)
            if cached is not None:
                self._results.move_to_end(needle)
                return cached

        first_matches = self.ensure(documents, _needle=needle)
        with self._query_lock():
            if self._closed:
                raise RuntimeError("history search corpus is closed")
            if first_matches is not None:
                return first_matches
            cached = self._results.get(needle)
            if cached is not None:
                self._results.move_to_end(needle)
                return cached
            if self._reuse_identity is not None:
                shared = self._shared_match(needle)
                if shared is not None:
                    return self._remember(needle, shared)
            try:
                matches = self._query_ready(needle)
            except sqlite3.DatabaseError:
                # The authoritative SQLite corpus became unreadable.  Keep
                # the published cache intact for other processes and rebuild
                # this instance from the safe projection supplied by the core.
                self._sidecar_ready = False
                self._candidate_backend = "pending"
                self._documents = None
                self._reuse_identity = None
                self._document_count = 0
                self._character_count = 0
                self._results.clear()
                self._cached_ordinals = 0
                self._cached_bytes = 0
                # Do not unlink a published cache that another process may be
                # reading.  This instance falls back to the exact safe memory
                # corpus; a later launch can independently validate/rebuild.
                self._bypass_sidecar = True
                matches = None
        if matches is None:
            first_matches = self.ensure(documents, _needle=needle)
            with self._query_lock():
                if self._closed:
                    raise RuntimeError("history search corpus is closed")
                if first_matches is not None:
                    return first_matches
                matches = self._query_ready(needle)
                return self._remember(needle, matches)
        with self._query_lock():
            if self._closed:
                raise RuntimeError("history search corpus is closed")
            return self._remember(needle, matches)

    def close(self) -> None:
        """Release the local serving corpus and its bounded result cache."""

        with self._condition:
            while self._building:
                self._condition.wait()
            if self._reuse_identity is not None:
                for needle, matches in self._results.items():
                    _shared_results.put(self._reuse_identity, needle, matches)
            self._closed = True
            self._sidecar_ready = False
            self._candidate_backend = "pending"
            self._bypass_sidecar = False
            self._documents = None
            self._reuse_identity = None
            self._block_digests.clear()
            self._document_count = 0
            self._character_count = 0
            self._results.clear()
            self._cached_ordinals = 0
            self._cached_bytes = 0
            self._error = None
