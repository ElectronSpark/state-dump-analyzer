# Validation reuse and event projection — 2026-10-20

This change implements the first two recommendations after search-result reuse
in checkpoint `f4076ce`: reduce navigation's compressed-corpus validation cost
and reduce initial safe-projection allocations. Full validation itself retains
the existing format, canonical digest and document traversal. No production
candidate index or new plug-in API is introduced.

## Implementation

Two fresh GPT 6.1 Sol agents used the updated author skill with short task and
file-ownership prompts. The parent reviewed both changes, ran independent checks,
and measured the actual production path against an archived checkpoint.

### Compressed validation reuse

A private process-local LRU holds at most 128 validation facts within 256 KiB,
including keys and conservative bookkeeping. Each fact stores only the largest
previously validated UTF-8 document length. Its SHA-256 key binds complete
metadata and ordered block framing, stored raw digests, and freshly computed
compressed-payload hashes. The record is created only after full validation or
construction from exact built-in strings. Caller string subclasses cannot
establish the construction shortcut.

Every reopen reads and hashes every compressed block, checks current bounds and
projection identity, and reconstructs reader-owned block pins. A matching fact
allows skipping repeated decompression, UTF-8 decoding and canonical document
hashing. A cached first query reuses its compact match set directly; a new query
still scans the exact framed bytes. Cache misses, changed content, cold processes
and tighter document bounds retain full validation and exact rebuild/fallback.
An empty validation cache skips the speculative compressed-payload pass. The
full validator derives the fingerprint from its already verified block pins and
the largest document length from decoded block headers, avoiding duplicate
payload hashing and added per-document maximum bookkeeping on cold opens.

Read-only SQLite transactions bind metadata and payload reads to one snapshot.
File stamps include device/inode and nonempty WAL/journal state, with pre/post
checks to reject observed replacement or mutation. Queries retain compressed
payload verification against their generation's block pins. No connection or
file lock survives an operation, and the global cache retains no event rows,
builders, runtimes, block maps, authorization or executable-trust decisions.
File timestamps are an additional invalidation signal, never a substitute for
rehashing the actual compressed bytes on reopen.

### Initial projection

Core now selects the effective disclosure policy once per event and passes its
compiled path trie through nested payloads. A path-aware helper replaces
temporary one-property dictionaries while preserving ancestor and literal
dotted-key rules. Constant subject payload fields are hoisted out of the loop.

The existing bounded trie cache provides reuse across events; no additional
policy-combination or projected-event cache is introduced. Supplied mutable
policies still observe changes on each event call. Generic mappings, subclasses,
conservative unknown-resource handling, independently owned containers, JSON
encoding and case folding retain their behavior.

## Independent validation

The parent compared 10,000 complete safe documents with the archived checkpoint
implementation, using seeded nested values, generic mappings, scalar numeric
distinctions, Unicode/NUL, unknown resources and policy mutation. Both complete
document-stream hashes are
`39470651a696c8c950e60ab044b696a60e41236be09c549b978839cac44f39ef`.

The final focused regression/integration run completed 247 tests: 246 passed
and one existing Windows symlink-privilege case skipped. It covers both search
suites, reuse and the 12 new validation tests, projection/property policy,
query algorithms, revision queries, HTTP redaction and cancellation, timeline,
density, assembly navigation and archive safety, scale data, load progress and
documented plug-in authoring smoke checks. All ten typing-contract tests pass.

The initial sandboxed combined run stalled entering Windows async tests. The
parent stopped only that identified process and reran the complete suite with
the process permissions required on this host. The final run completed in
15.464 seconds. Initial agent TEMP/interpreter problems are recorded separately
and are not counted as passing tests or product regressions.

Coverage includes checking all payload bytes before reuse, cold-cache fallback,
same-size last-block corruption with restored timestamps, changed metadata and
limits, replacement before SQLite open, read locks against concurrent writers,
WAL mutation, concurrent reopen/close, collection of retired owners and global
cache budgets. The parent reviewed the implementation and these assertions.
One agent run observed a transient storage-mode assertion in
`CompressedHistorySearchTests.test_corrupt_blocks_rebuild_before_reuse_and_fallback_during_query`,
for `UPDATE document_blocks SET document_count=0`: the safe rebuild used memory
instead of SQLite. Its isolated rerun, the agent's complete rerun and the parent's
final complete run passed. No cause was established; this is not claimed fixed.
That initial failure survives in the agent conversation output, not a saved log.

Stub export/check verifies 148 modules across four packages. The exporter
preserves the new private cache binding. Parent strict mypy found three new
tuple-assignment errors; Sol added the missing variable annotation. Final
focused mypy has the same 17 diagnostics as the checkpoint after normalizing
line references, with none introduced. This is not a clean repository-wide
typing result. Ruff reports four pre-existing diagnostics in unchanged import
blocks and an existing dict/Mapping fast path; changed search/helper/test code
has no new diagnostics. Conformance inventory passes and now includes the
validation-reuse tests in the presentation group.
After measurement, Sol added two scoped lint-suppression comments to keep the
deliberate hot-loop comparisons instead of restoring `max()` calls. The parent
verified that removing only those comments reproduces the measured source hash
exactly and that the Python AST is identical. All other measured source hashes
remain unchanged; the final focused Ruff check passes.

## Fresh skill trials

Two more GPT 6.1 Sol agents started without inherited conversation and received
only short task/skill/output prompts. They could read source, contracts, tests
and skills, but were excluded from prior reports, parent diagnoses and other
runtime artifacts. Skills and the API map remained fixed during the trial batch.
The parent read their code and reran all seven newly authored tests; the combined
trial rerun used fresh sidecar directories.

- Individual validation: four tests with 83 documents compare complete ordered
  literal results, navigation reuse and owner collection, changed content and
  projection, every metadata/framing field, and last-block corruption with
  restored timestamps. Existing focused tests supply additional concurrency,
  limits and mutation coverage.
- Combined author workflow: three tests compose disclosure-policy replacement,
  scan/indexed event search, one-item filtered pages, locate, selected ranges,
  timeline counts/selection and corpus retirement/reopen. A → restricted B → A
  uses fresh immutable generations with the same revision label. This is
  headless core composition over small plain sidecars, not browser navigation,
  durable ingestion or large compressed storage. Those have separate checks.

All seven parent trial checks passed. Two initial combined harness issues
(weak-referencing a SimpleNamespace and an undersized test result-cache budget)
were fixed by the trial agent and preserved in its report. They were not product
defects. Exact prompts and SHA-256 hashes are recorded in
`.runtime/validation-projection-2026-10-20/skill-trials.json`.

## Measurement method

The unchanged generated archive contains 1,250,005 events on PE-A and 1,250,002
on PE-B. It is 286,496,584 bytes with SHA-256
`4cea20db78aa3fede9dc79a89a9277c5a9a72905fbff76a5f8436efd1c4aec30`.
Baseline code was extracted from `f4076ce`; the working tree was never rolled
back. Both runs use the configured Python 3.12.13 environment, a fresh process,
empty sidecar/bytecode directories and `PYTHONHASHSEED=0`. Tests and profilers
were deferred during timed runs. OS disk caches were not flushed.

The driver extends the previous 39-phase workload with an uncached `interface`
query after returning to A, producing 40 phase occurrences including five dense
repeats. Comparisons retain every occurrence and complete response hashes. Total
CPU is not directly comparable to earlier 39-phase reports. Validation-cache
telemetry was added outside timed phases for the optimized run.

Windows memory is sampled every 100 ms, with process lifetime peaks also
recorded. CPU excludes browser and separate ingestion workers. These are
backend measurements, not browser readiness. Separate fresh-process probes
measure full reopen validation and same-process reuse against an existing corpus.

## Final 1M results

The final comparison uses `before-1` against `after-2`, after the cold-path
correction. These are single full-workload runs, not confidence intervals.

| Measurement | Checkpoint | Final change |
| --- | ---: | ---: |
| First search: projection, corpus construction and query CPU | 55.656 s | 47.891 s |
| First search wall time | 57.063 s | 52.878 s |
| First cached search after A → B → A CPU | 4.969 s | 0.109 s |
| First cached search after A → B → A wall time | 5.158 s | 0.107 s |
| New `interface` term after return CPU | 1.844 s | 1.891 s |
| New `interface` term after return wall time | 1.890 s | 1.949 s |
| Sum of all 40 measured phase CPU times | 181.672 s | 167.781 s |
| Entire driver elapsed time | 187.031 s | 176.594 s |
| A loaded RSS | 2.35297 GiB | 2.35373 GiB |
| Sampled navigation peak RSS | 2.36861 GiB | 2.36898 GiB |
| Process lifetime peak RSS | 2.43269 GiB | 2.43331 GiB |
| Search sidecar storage | 75,038,720 bytes | 75,038,720 bytes |

First-search CPU fell 14.0%; this measures the whole first-search phase, not an
isolated projection timer. Cached navigation's first-search wall time fell 97.9%.
The new uncached term remains an exact scan at about 1.9 seconds; its final
2.5% CPU increase is reported rather than treated as a speedup. The preliminary
optimized run measured 1.813 CPU seconds for that term, illustrating run variation.
Total measured CPU fell 7.6%, though small load-time differences also contribute.
Memory stayed effectively flat: the sampled navigation peak increased 0.38 MiB,
and the lifetime peak increased 0.63 MiB. No memory reduction is claimed.

The new validation cache retained one fact with 389 accounted bytes after
navigation and after runtime close, within its 128-entry/256-KiB bounds. This is
the cache's bounded accounting, not a claim that the Python process allocates
exactly 389 additional bytes. The existing result cache retained six entries
with 486,962 accounted bytes, within its 16-MiB budget. Retired corpus ownership
and service-cache retirement matched the baseline.

Separate fresh-process probes against the same existing sidecar measured:

| Reopen probe | Checkpoint CPU / wall | Final CPU / wall |
| --- | ---: | ---: |
| First query in a fresh process | 5.000 / 5.110 s | 5.078 / 5.114 s |
| Reopen again in that process | 5.031 / 5.119 s | 0.094 / 0.093 s |

Process restart still costs roughly five seconds because it has no certified
validation fact. The initial optimized probe added a redundant payload pass and
per-document maximum bookkeeping (5.234 CPU / 5.320 wall seconds). Parent review
sent that finding back to Sol; the final implementation removes that duplicate
work. Final fresh-process wall time is approximately unchanged, with CPU 0.078 s
higher in this one probe. The navigation shortcut does not persist trust to disk.

All 40 ordered phase results match exactly, including repeated phases and full
page hashes. An independent decoder traversed every block in both corpora,
checked framing, raw SHA-256 and the full canonical document digest, then compared
all ordered matches with production queries. Both corpora have 1,250,005 documents,
1,768,382,872 characters and canonical digest
`e822d341feb8f3d1172725004d2e286614416d42c07e21446f4de725faef6b36`.
The `failure`, `success` and absent-term counts are 24,925, 1,225,080 and zero;
their complete ordered-match hashes match. SQLite quick checks pass.

Local evidence is under `.runtime/validation-projection-2026-10-20/`:

- `before-1/result.json`, `after-2/result.json` and their `child.jsonl` files
  contain raw phase results, process memory, source hashes and environment.
- `comparison-before-1-after-2.json` contains exact parity, CPU/memory deltas,
  storage integrity and both cache-budget checks; `comparison-final.log` is the
  successful independent comparison run.
- `cold-before.json`, `cold-after.json` and `cold-after-final.json` preserve the
  checkpoint, initial overhead finding and corrected fresh-process probes.
- `parent-tests-final-2.log`, `typing-tests-final.log`,
  `parent-skill-individual-final.log` and `parent-skill-combined-final.log` record
  the final regression, typing and fresh-trial reruns.
- `typing-comparison-final.json`, `stubs-check-final.log`,
  `parent-projection-result.json` and `skill-trials.json` record the remaining
  type, source-equivalence and skill provenance checks.
- `final-source-verification.json` records exact source hashes and the two
  comments-only differences after measurement. Both final skill-format checks
  passed, and the skills/API-map hashes still match the fresh trial batch.

## Documentation stewardship

This is core-owned derived-cache and projection work. No plug-in hook, manifest,
parser workflow, public signature or disclosure semantic changes. The maintained
quickstart, contract, runnable example and README remain applicable; smoke checks
pass. The required drift check found no necessary changes to those materials.
Both skills and the performance map were updated for the new implementation and
its validation boundaries.
