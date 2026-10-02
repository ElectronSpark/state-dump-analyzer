# Memory and storage investigation — 2026-10-02

The experiments found a practical storage reduction with lower query CPU than
the current layout. A smaller memory experiment also supports replacing rich
top-level event dictionaries with compact rows while keeping fast query indexes.
These are isolated prototypes; production code has not changed.

## Search storage: full 1,250,005-document corpus

The source is the saved safe-text sidecar from the
[million-event measurement](million-node-measurement-2026-10-02.md). SQLite's
`dbstat` reports 699,931,202 unused bytes in its documents table, explaining a
substantial part of the current 2,492,391,424-byte file. The table payload is
1,773,382,892 bytes; canonical document text totals 1,768,382,872 characters.

After a stratified 100,000-document sample, the full corpus was copied into two
isolated layouts. No redaction or canonical search text was changed:

| Layout | File bytes | Reduction | `failure` CPU | `success` CPU |
|---|---:|---:|---:|---:|
| Current SQLite, 4 KiB pages | 2,492,391,424 | baseline | 2.578 s | 2.828 s |
| SQLite text rows, 64 KiB pages | 1,804,599,296 | 27.60% | 1.594 s | 1.734 s |
| Compressed blocks, 64 KiB pages | 74,645,504 | 97.01% | 1.797 s | 1.766 s |

CPU figures are medians of three warm scans with no query-result cache. Six
queries covered common, uncommon, absent, resource-ID, JSON-punctuation and
two-character needles. All ordered result ordinals matched the current database.
Compressed-block median CPU ranged from 1.609 to 1.906 s across those queries;
the current layout ranged from 2.031 to 2.922 s. Larger plain pages remained
faster than compressed blocks for most tested terms.

Blocks group approximately 256 KiB of uncompressed text plus length framing,
then apply standard-library zlib level 1. Each block contains a length table and
the unchanged UTF-8 document bytes. Matching is confined to each document's
boundaries. Only a block is decompressed at a time; each match still returns its
original ordinal. Fewer database rows and less data read offset decompression
cost in this corpus and scan implementation.

A separate digest over every ordinal, byte length and complete UTF-8 document
matched across all three layouts. All 1,250,005 documents and 1,768,382,872
characters were preserved. This digest is a probe invariant, not a replacement
for production cache validation.

Copy/build CPU was 4.344 s for the larger-page plain database and 5.781 s for
compressed blocks. Experimental full-corpus verification CPU was 4.109 s for
the existing database, 2.781 s for the larger-page copy and 3.047 s for blocks.
These measurements start with already-redacted text; they do not establish an
improvement to the original 106-second first-search build.

## Event memory: 50,000 actual generated events

Fresh sequential child processes read a bounded prefix of CE-East's raw
generated events and use the current `_compact_event` projection. These tests
isolate representation choices, excluding runtime indexes and node switching.

| Experiment | Observed memory effect | Observed CPU effect |
|---|---|---|
| Recursively pool repeated string values | Private-commit increase fell only 1.25% | Representation build rose from 0.313 to 0.719 s |
| Replace the fixed 20-field top-level event dictionary with a tuple | Retained heap fell 12.00%; private-commit increase fell 11.90% | Build remained 0.281 s in both runs; reconstructing 50,000 ordinary dictionaries took 0.047 s |
| Replace one timestamp list with checked signed 64-bit storage | Owned index bytes fell 82.17%, from 2,244,376 to 400,080 | 400,000 bisections rose from median 0.109 to 0.172 s |

The tuple experiment kept all nested values unchanged. Identity-aware heap
accounting fell from 110,073,636 to 96,864,307 bytes. Every reconstructed event
equaled the existing projection. It is a promising first step, not evidence that
the complete 3.22 GiB runtime will shrink by the same percentage. A shallow
reconstructed dictionary still shares nested values; production must retain
immutable storage or isolate mutations appropriately.

The string-pooling pass is not recommended. The installed `pydantic_core`
decoder already benefits from string caching, and this extra Python traversal
provided little retained-memory benefit on the sample. The timestamp result
also rules out claiming that Python bisection on a typed array is automatically
faster. Keep hot indexes fast until an end-to-end comparison justifies changing
them. Existing timestamp lists can share integer objects with other indexes;
the owned-object probe must not be multiplied across those indexes as if every
list independently owned those integers.

## Recommended design and order

1. Use larger SQLite pages for large plain-text sidecars as the simplest change.
   It recovered 27.6% of storage and reduced scan CPU here without decompression.
2. Introduce a versioned compressed-block search backend for large corpora. It
   gives the much larger storage reduction while remaining faster than the
   current backend in these warm scans. Preserve the existing small-corpus
   accelerator and bounded query-result cache.
3. Store event payloads as compact immutable rows, while retaining direct access
   to hot timestamp/type/resource indexes. Materialize ordinary dictionaries for
   bounded detail requests and stream projections for whole-corpus search.
   Extend beyond the proven top-level tuple only after measuring nested payload
   and effect representation. Reuse the existing UID-to-ordinal lookup instead
   of retaining a second UID-to-event hash table where lookup semantics permit.
4. Repeat the full load/search/zoom/A→B→A scenario before accepting memory work.
   Compact rows should reduce both resident history and the transient two-node
   peak. Early eviction alone changes failed-load behavior and cannot reclaim
   histories pinned by active readers.

Core keeps redaction, search semantics, cache verification and generic querying.
The compatibility adapter can change its internal event representation without
moving device interpretation into core. Generalizing the public timestamp
contract from `list[int]` to a sequence, if chosen, requires corresponding
protocol/stub/documentation and conformance changes. No new device-specific
core API is needed for these designs.

For production compressed blocks, retain exact canonical text, Unicode/literal
substring semantics, ordinals and ordering. Add bounded decompression and strict
length/count validation; document, block and database limits; identity and digest
checks; versioned metadata; atomic publication; concurrent-reader safety; and
corrupt-cache fallback. The probe trusts its newly created files and does not
implement those protections. Unicode, NUL, empty needles, cross-document
boundaries and malformed blocks need dedicated conformance cases.

## Algorithmic follow-up

A subsequent source review identified work that can be avoided, beyond changing
representation or compression:

1. **Align query-cache lifetime with history lifetime.** `_density_index` retains
   `(runtime, index)` entries on the long-lived query owner for up to two
   histories. That strong reference can retain the full event heap after the
   plug-in's one-node cache evicts it. A small weak-reference probe confirmed
   that deleting the caller's runtime reference did not reclaim the runtime
   until the density cache was cleared. Timeline caches also retain source
   event lists and intervals. Give derived caches generation-scoped ownership
   or explicit retirement with active-reader protection. The earlier full-node
   benchmark did not use zoom, so its navigation memory figures exclude this
   additional retention path. This is a reproduced ownership issue; a full
   browser/navigation memory test is still needed to quantify its impact.
2. **Use adaptive cached match sets under a byte budget.** The current limit is
   1,000,000 cached ordinals. A 1,225,080-match result, such as the measured
   `success` result, evicts itself immediately. A direct `_remember` probe
   confirmed the empty cache. Its uint32 ordinal payload is 4,900,320 bytes;
   a bitmap over 1,250,005 documents needs 156,251 bytes, or the complement's
   24,925 ordinals need 99,700 bytes, before representation metadata. Sparse
   arrays, dense bitmaps and complements can preserve exact counts and order.
   Paging needs rank/select or equivalent bounded access so it does not expand
   a million ordinals again for each 100-row page.
3. **Reuse candidate sets.** A longer literal needle containing a cached shorter
   needle only needs exact checks against that shorter needle's matches.
   Precomputed layer postings can intersect with text matches instead of
   recalculating each event's layers on every page. Pick a full scan when a
   candidate set is too broad; batch candidates by compressed block. Deleting
   query characters cannot reuse a narrower result as a complete candidate set.
4. **Fuse first-query matching with mandatory corpus passes.** Collect query
   matches while producing new safe documents, or while validating an existing
   corpus, to avoid a separate full text scan. Publish results only after the
   complete corpus and identity checks succeed. This removes an extra pass;
   it does not eliminate the first ever redaction/serialization pass.
5. **Page a merge of indexed event/source streams.** The mixed log path currently
   allocates candidate tuples for all matches and sorts them before slicing the
   requested page. Reuse sorted ordinal streams and counts; add rank information
   for efficient offset/locate handling. Preserve timestamp ties, source sequence,
   stable IDs, untimed rows and inside/outside grouping. A naive merge from the
   beginning still costs linear work for deep offsets.
6. **Consider conservative block pruning after measuring selectivity.** A small
   necessary-substring summary per compressed block could skip blocks that
   cannot contain a needle, then exact-check every survivor. Repeated JSON keys,
   common values and short needles may defeat pruning. Summaries must have no
   false negatives and retain the same integrity guarantees as the corpus.
7. **Bound cold timeline work by the requested window and detail budget.** Cold
   cross-lane union construction currently walks complete lane histories and
   sorts their unique timestamps; selections above the cache budget can repeat
   that work. For narrow windows, merge and deduplicate only window-bounded
   ordinals. Keep lightweight state-change/condition indexes separate from full
   property dictionaries so summary counts do not require hydrating every state
   interval. Preserve exact cross-lane counts, timestamp bounds and state meaning;
   retain generic fallbacks for sources without ordered indexes.

Only the two cache behaviors above were reproduced in this follow-up. The
remaining items are source-grounded proposals, not measured speedups. A first
arbitrary literal query with exact whole-corpus counts still needs to inspect
all relevant text unless a suitable index was built earlier. A visible-row
limit does not justify returning an incomplete match count.

## Evidence and limits

The same installed Python 3.12 environment and host as the baseline were used.
Storage and memory CPU experiments ran sequentially. Full storage scans use one
connection per variant, an 8 MiB SQLite cache and a warm OS cache after verification.
The two new layouts both use 64 KiB pages: comparing them isolates the layout
tradeoff more closely than comparing either against the current 4 KiB database.
Three repeats describe these warm scans, not cold-disk or browser latency.

Memory probes use a single 50,000-event prefix, allocator-dependent process
deltas and Windows CPU timing granularity. Bisection trials alternate order;
the tuple scan repeats five times. Full application CPU parity, total RAM
savings, small-corpus behavior and first-search latency remain unmeasured for
the proposed production design.

Local scripts and results:

- `.runtime/compact-storage-probe/probe.py` and `result.json`: stratified sample.
- `.runtime/compact-storage-probe/full_probe.py`, `full-result.json` and
  `full-run.log`: full storage and ordered-result comparisons.
- `.runtime/compact-memory-probe/probe.py` and `result.json`: string pooling.
- `.runtime/compact-memory-probe/tuple_probe.py` and `tuple-result.json`: event rows.
- `.runtime/compact-memory-probe/numeric_probe.py` and `numeric-result.json`: indexes.

Two fresh `gpt-6.1-sol` subagents reviewed the storage and history designs; the
history agent ran the bounded memory probes. The search agent also reviewed the
full storage harness and its interpretation. Their findings are incorporated
above. Author-documentation drift check: no production or author-visible API
behavior changed, so no skill, contract or runnable-example update is required.
