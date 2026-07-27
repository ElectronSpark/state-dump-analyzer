"""Bounded, revision-local search support for immutable history streams.

The core owns literal search over the client-safe projection. Plug-ins still
own the vocabulary and sensitivity declarations used to create that
projection. A host can persist the safe corpus in a SQLite sidecar so later
queries avoid both a large private-memory copy and a repeated rebuild.
"""

from __future__ import annotations

import os
import sqlite3
from array import array
from collections import OrderedDict
from collections.abc import Callable, Iterable
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from threading import Condition, RLock
from typing import Any
from uuid import uuid4


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

    _FORMAT_VERSION = "history-search-sqlite-v6"
    _INSERT_BATCH_SIZE = 512
    _FTS5_BACKEND = "fts5-trigram"
    _SCAN_BACKEND = "sqlite-scan"
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
    ) -> None:
        if sidecar_path is not None and not identity:
            raise ValueError("a persistent history corpus requires an identity")
        if expected_documents is not None and expected_documents < 0:
            raise ValueError("expected_documents must be non-negative")
        if min(
            max_documents,
            max_characters,
            max_document_bytes,
            max_database_bytes,
            max_eager_candidate_characters,
            max_cached_queries,
            max_cached_ordinals,
        ) <= 0:
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
        self._max_eager_candidate_characters = (
            max_eager_candidate_characters
        )
        self._max_cached_queries = max_cached_queries
        self._max_cached_ordinals = max_cached_ordinals
        self._condition = Condition(RLock())
        self._documents: tuple[str, ...] | None = None
        self._sidecar_ready = False
        self._bypass_sidecar = False
        self._candidate_backend = "pending"
        self._document_count = 0
        self._character_count = 0
        self._building = False
        self._closed = False
        self._error: Exception | None = None
        self._results: OrderedDict[str, array[int]] = OrderedDict()
        self._cached_ordinals = 0
        # Hosts that already warm the corpus in a background worker can defer
        # the linear digest/index validation to that worker.  The default
        # remains eager for callers that use ``ready`` as a startup contract.
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
                    hasattr(component, "is_junction")
                    and component.is_junction()
                ):
                    return True
            except OSError:
                return True
        return False

    def _open_valid_sidecar(
        self,
        path: Path,
    ) -> tuple[int, int, str] | None:
        if not path.exists():
            return None
        if self._path_uses_link(path) or not path.is_file():
            raise OSError("history search sidecar must be a regular file")
        if path.stat().st_size > self._max_database_bytes:
            return None
        connection = sqlite3.connect(
            f"{path.as_uri()}?mode=ro&immutable=1",
            uri=True,
            check_same_thread=False,
        )
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA cache_size=-8192")
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
                or backend not in {self._FTS5_BACKEND, self._SCAN_BACKEND}
                or int(complete) != 1
                or int(document_count) < 0
                or int(character_count) < 0
                or int(document_count) > self._max_documents
                or int(character_count) > self._max_characters
                or len(str(documents_digest)) != 64
                or (
                    backend == self._FTS5_BACKEND
                    and len(str(candidate_digest)) != 64
                )
                or (
                    backend == self._SCAN_BACKEND
                    and str(candidate_digest) != ""
                )
                or (
                    self._expected_documents is not None
                    and int(document_count) != self._expected_documents
                )
            ):
                return None
            digest = sha256()
            actual_count = 0
            actual_character_count = 0
            for expected_ordinal, (ordinal, safe_text) in enumerate(
                connection.execute(
                    """
                    SELECT ordinal, safe_text
                    FROM documents
                    ORDER BY ordinal
                    """
                )
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
                self._update_documents_digest(
                    digest,
                    expected_ordinal,
                    encoded,
                )
                actual_count += 1
                actual_character_count += len(safe_text)
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
                    or "content_rowid='ordinal'"
                    not in str(fts_schema[0]).lower()
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
        finally:
            connection.close()
        return validated

    @staticmethod
    def _update_documents_digest(
        digest: Any,
        ordinal: int,
        encoded: bytes,
    ) -> None:
        digest.update(ordinal.to_bytes(8, "big", signed=False))
        digest.update(len(encoded).to_bytes(8, "big", signed=False))
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
        if (
            self._expected_documents is not None
            and document_count != self._expected_documents
        ):
            raise RuntimeError(
                "history search document count does not match the revision"
            )
        self._document_count = document_count
        self._character_count = character_count

    def _build_memory(
        self,
        documents: Callable[[], Iterable[str]],
    ) -> tuple[str, ...]:
        return tuple(
            document for _, document in self._bounded_documents(documents)
        )

    def _build_sidecar(
        self,
        documents: Callable[[], Iterable[str]],
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
        temporary = target.with_name(
            f".{target.name}.tmp-{os.getpid()}-{uuid4().hex}"
        )
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(temporary)
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
            documents_digest = sha256()
            batch: list[tuple[int, str]] = []
            exception_batch: list[tuple[int]] = []
            for item in self._bounded_documents(documents):
                try:
                    encoded = item[1].encode("utf-8")
                except UnicodeEncodeError as error:
                    raise _SidecarUnavailable(
                        "safe search text is not a Unicode scalar string"
                    ) from error
                if len(encoded) > self._max_document_bytes:
                    raise _SidecarUnavailable(
                        "one history search document exceeds the disk bound"
                    )
                self._update_documents_digest(
                    documents_digest,
                    item[0],
                    encoded,
                )
                batch.append(item)
                if "\0" in item[1]:
                    # Some SQLite/FTS5 builds truncate text at NUL while the
                    # ordinary TEXT column and Python input retain it. Those
                    # documents must bypass the candidate accelerator and
                    # receive the same exact ``instr`` recheck.
                    exception_batch.append((item[0],))
                if len(batch) >= self._INSERT_BATCH_SIZE:
                    connection.executemany(
                        "INSERT INTO documents(ordinal, safe_text) VALUES (?, ?)",
                        batch,
                    )
                    batch.clear()
                if len(exception_batch) >= self._INSERT_BATCH_SIZE:
                    connection.executemany(
                        """
                        INSERT INTO documents_fts_exceptions(ordinal)
                        VALUES (?)
                        """,
                        exception_batch,
                    )
                    exception_batch.clear()
            if batch:
                connection.executemany(
                    "INSERT INTO documents(ordinal, safe_text) VALUES (?, ?)",
                    batch,
                )
            if exception_batch:
                connection.executemany(
                    """
                    INSERT INTO documents_fts_exceptions(ordinal)
                    VALUES (?)
                    """,
                    exception_batch,
                )
            # Persist the exact corpus first.  The FTS table is only a candidate
            # accelerator, so a SQLite build without FTS5/trigram support still
            # publishes a reusable, exact scan sidecar.
            connection.commit()
            backend = self._SCAN_BACKEND
            candidate_digest = ""
            # Trigram indexing is O(total safe-text characters) and can dwarf
            # parsing for large immutable histories.  Exact SQLite substring
            # scans remain bounded and correct, so large corpora publish the
            # scan backend immediately instead of delaying availability for an
            # accelerator.  Smaller corpora retain the responsive FTS path.
            if (
                self._character_count
                <= self._max_eager_candidate_characters
            ):
                try:
                    built_candidate_digest = (
                        self._build_fts5_candidate_index(connection)
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
                existing = self._open_valid_sidecar(target)
            except sqlite3.DatabaseError:
                existing = None
            if existing is not None:
                temporary.unlink(missing_ok=True)
                return existing
            os.replace(temporary, target)
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

    def ensure(self, documents: Callable[[], Iterable[str]]) -> None:
        """Build or reopen the exact safe corpus once."""

        with self._condition:
            if self._closed:
                raise RuntimeError("history search corpus is closed")
            while self._building and (
                self._documents is None and not self._sidecar_ready
            ):
                self._condition.wait()
            if self._closed:
                raise RuntimeError("history search corpus is closed")
            if self._documents is not None or self._sidecar_ready:
                return
            if self._error is not None:
                raise self._error
            self._building = True

        try:
            if self._sidecar_path is not None and not self._bypass_sidecar:
                try:
                    try:
                        opened = self._open_valid_sidecar(self._sidecar_path)
                    except sqlite3.DatabaseError:
                        if self._sidecar_path.is_symlink():
                            raise _SidecarUnavailable(
                                "refusing to replace a symbolic-link sidecar"
                            )
                        opened = None
                    if opened is None:
                        opened = self._build_sidecar(documents)
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
        except Exception as error:
            with self._condition:
                self._building = False
                self._error = error
                self._condition.notify_all()
            raise

        with self._condition:
            self._documents = completed
            self._sidecar_ready = sidecar_ready
            self._candidate_backend = backend
            self._document_count = document_count
            self._character_count = character_count
            self._building = False
            self._condition.notify_all()

    def _query_ready(self, needle: str) -> array[int]:
        if self._documents is not None:
            return array(
                "I",
                (
                    index
                    for index, document in enumerate(self._documents)
                    if needle in document
                ),
            )
        if not self._sidecar_ready or self._sidecar_path is None:
            raise RuntimeError("history search corpus is not ready")
        connection = sqlite3.connect(
            f"{self._sidecar_path.as_uri()}?mode=ro&immutable=1",
            uri=True,
            check_same_thread=False,
        )
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA cache_size=-8192")
            candidate = self._fts5_candidate_expression(needle)
            if (
                self._candidate_backend == self._FTS5_BACKEND
                and candidate is not None
            ):
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
                    return array("I", (int(row[0]) for row in rows))
                except sqlite3.OperationalError:
                    # MATCH is an accelerator only.  If a platform-specific
                    # FTS parser rejects a candidate, preserve exact behavior
                    # with the ordinary documents table.
                    pass
            return array(
                "I",
                (
                    int(row[0])
                    for row in connection.execute(
                        """
                        SELECT ordinal
                        FROM documents
                        WHERE instr(safe_text, ?) > 0
                        ORDER BY ordinal
                        """,
                        (needle,),
                    )
                ),
            )
        finally:
            connection.close()

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
            '"' + trigram.replace('"', '""') + '"'
            for trigram in trigrams
        )

    def _remember(self, needle: str, matches: array[int]) -> array[int]:
        cached = self._results.get(needle)
        if cached is not None:
            self._results.move_to_end(needle)
            return cached
        self._results[needle] = matches
        self._cached_ordinals += len(matches)
        while self._results and (
            len(self._results) > self._max_cached_queries
            or self._cached_ordinals > self._max_cached_ordinals
        ):
            _, evicted = self._results.popitem(last=False)
            self._cached_ordinals -= len(evicted)
        return matches

    def query(
        self,
        needle: str,
        documents: Callable[[], Iterable[str]],
    ) -> array[int]:
        """Return time-ordered ordinals containing one literal folded string."""

        with self._condition:
            cached = self._results.get(needle)
            if cached is not None:
                self._results.move_to_end(needle)
                return cached

        self.ensure(documents)
        with self._condition:
            cached = self._results.get(needle)
            if cached is not None:
                self._results.move_to_end(needle)
                return cached
            try:
                matches = self._query_ready(needle)
            except sqlite3.DatabaseError:
                # The authoritative SQLite corpus became unreadable.  Keep
                # the published cache intact for other processes and rebuild
                # this instance from the safe projection supplied by the core.
                self._sidecar_ready = False
                self._candidate_backend = "pending"
                self._documents = None
                self._document_count = 0
                self._character_count = 0
                self._results.clear()
                self._cached_ordinals = 0
                # Do not unlink a published cache that another process may be
                # reading.  This instance falls back to the exact safe memory
                # corpus; a later launch can independently validate/rebuild.
                self._bypass_sidecar = True
                matches = None
        if matches is None:
            self.ensure(documents)
            with self._condition:
                matches = self._query_ready(needle)
                return self._remember(needle, matches)
        with self._condition:
            return self._remember(needle, matches)

    def close(self) -> None:
        """Release the local serving corpus and its bounded result cache."""

        with self._condition:
            while self._building:
                self._condition.wait()
            self._closed = True
            self._sidecar_ready = False
            self._candidate_backend = "pending"
            self._bypass_sidecar = False
            self._documents = None
            self._document_count = 0
            self._character_count = 0
            self._results.clear()
            self._cached_ordinals = 0
            self._error = None
