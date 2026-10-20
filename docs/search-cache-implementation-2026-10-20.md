# Search cache and index work — 2026-10-20

The identity repair and projection optimization were committed first as
`da9291b` (`Repair executable identity and optimize safe event projection`).

## Scope and decisions

The requested implementation follows the comparison of Zoekt, Loki,
Elasticsearch, ClickHouse and Perfetto:

1. Preserve compact exact search results across navigation with bounded memory
   and validated corpus identity, without retaining retired event runtimes.
   Disk persistence of frequently reused results is optional and must justify
   its additional integrity and lifecycle machinery.
2. Prototype a block-level trigram candidate index for large compressed corpora.
   Compare build CPU, storage, memory, and exact query work before selecting a
   production default. Keep scanning available when indexing is not beneficial.
3. Evaluate compact document-level postings if block pruning is insufficient.
   Adopt them only when measured query benefit justifies their construction and
   storage cost. A full positional index is outside this proposal.

Core continues to own search over the existing safe projection; no new plug-in
capability is proposed. Search caches do not replace disclosure, source identity,
or sidecar integrity validation.

References: [Zoekt design](https://github.com/sourcegraph/zoekt/blob/main/doc/design.md),
[Loki caching](https://grafana.com/docs/loki/latest/operations/caching/),
[Elasticsearch query cache](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/node-query-cache-settings),
[ClickHouse skipping indexes](https://clickhouse.com/docs/concepts/best-practices/using-data-skipping-indices),
[Perfetto parsed-trace reuse](https://perfetto.dev/docs/visualization/large-traces).

## Implemented result reuse

GPT 6.1 Sol used the author skill to add a private core cache. Retiring a
`HistorySearchCorpus` publishes only its retained compact `MatchSet` values.
The global LRU holds at most 128 results and 16 MiB, counting keys and a
conservative bookkeeping allowance. Entries have no event, builder, service or
runtime references. Evicting an entry does not invalidate a result already held
by an active reader.

Reuse is bound to the complete validated document digest, projection identity,
format version, document count and literal matching version. Reopening still
performs the existing full integrity scan. Changed sidecar stamps disable
shared lookup; corrupt storage still rebuilds or falls back exactly. String
subclasses are declined before conversion, equality or hashing can affect a
shared key. This is a bounded process-local cache, not disk result persistence.
It improves later queries after navigation, not the initial projection or full
reopen validation cost.

Sharing is enabled only for successfully built or validated persistent
sidecars. The parent's CPU probe found that hashing memory-only corpora for
sharing increased five cold-query runs over 50,000 prebuilt documents (50.7M
characters) from 0.125 to 0.359375 CPU seconds. Sol restored the original
no-hash memory construction and disabled sharing on disk-failure fallback;
the final five-run probe returned to 0.125 CPU seconds. The probe excludes
projection/input generation and has coarse process-clock resolution; it checks
this specific added cost rather than predicting application latency.

The parent found the string-subclass normalization issue during review; Sol
repaired it and added a hostile-subclass regression. The parent independently
reviewed the implementation and reran the tests described below.

## Candidate-index experiment and decision

The second Sol agent implemented block and document trigram prototypes, then a
maintained [bounded comparison script](../scripts/profile_history_search_indexes.py).
It requires an explicit compressed sidecar and never enables production indexes.
The parent inspected and reran this script on 80 evenly spaced blocks from the
existing million-event corpus: 14,608 documents, 20,777,897 raw framed bytes,
819,690 compressed bytes. All selected frames and hashes were validated; all
ordered query results match exact scans. This is sample validation, not another
full-corpus integrity result.

| Parent measurement | Block postings | Document postings |
| --- | ---: | ---: |
| In-memory build CPU | 3.422 s | 4.578 s |
| In-memory build wall | 3.494 s | 4.728 s |
| Shallow owned index memory | 382,268 bytes | 28,410,424 bytes |
| Posting payload | 24,080 bytes | 26,648,100 bytes |
| Delta-varint serialization estimate | 125,810 bytes | 6,722,280 bytes |
| Further zlib storage estimate | 16,258 bytes | 105,626 bytes |

For `failure`, both indexes select 17 of 80 blocks; for `interface`, one; for
an absent long literal, zero; for `success`, all 80. Document postings skip no
additional blocks for the measured queries. The `route` query still selects
18 blocks for two matches because trigrams can co-occur without the full term.
Exact verification removes these false positives.

The parent measured `failure` at 49.66 ms for the compressed scan versus
8.80 ms for block candidate selection plus exact verification. For `interface`,
44.67 ms became 0.41 ms. These are single-pass, OS-warm sample measurements;
CPU clock granularity is too coarse for most individual query phases.
The comparison includes frame decoding and raw digest verification, excludes
SQLite query I/O and full reopen validation, and retains sampled input in RAM.
Owned-index size excludes sample/docmap buffers and allocator overhead. The
compressed-posting figures are storage estimates only: queries use resident
bitsets or uint32 arrays, not decoded compressed posting lists. Build times do
not include serialization, durable publication, or validation of a new index.

Decision: ship compact result reuse, keep both index implementations in the
offline comparison tool, and leave production's large-corpus compressed scan
default intact. The measured block build needs many distinct selective queries
to amortize its cost; repeated terms already benefit from exact result caching.
The document prototype adds construction and memory cost without additional
block pruning. These results do not establish a universal rejection of indexes
or a full-scale speedup. A production optional index needs a streaming builder,
persisted-index integrity validation, and evidence from a workload with enough
distinct selective searches before enabling it.

Reproduce the bounded comparison with the configured Python 3.12 interpreter:

```powershell
python scripts/profile_history_search_indexes.py --sidecar <compressed-sidecar.sqlite3> --max-blocks 80 --max-sample-bytes 25165824 --output <report.json>
python -m unittest tests.test_profile_history_search_indexes -v
```

The parent's raw sample results are in
`.runtime/search-cache-2026-10-20/index/parent-profile.json`.

## Independent validation and skill use

The parent ran 196 focused regression/integration tests: 195 passed and one
Windows symlink-privilege case skipped. Coverage includes both search suites,
nine new reuse tests, generation ownership, zoom/timeline/density, revision
queries, HTTP event redaction, assembly navigation and archive safety, scale
data, load progress, the documented authoring smoke tests, and five tests for
the comparison script. Final log:
`.runtime/search-cache-2026-10-20/parent-tests-final.log`.

Focused Ruff passes. Stub export/check verifies 147 modules across four
packages; the only added stub is the private cache helper. The exporter now
preserves its private shared-cache binding, which a core-only type check needs.
All ten typing-contract tests pass. No public plug-in signature changed.
Focused strict mypy, including a separate core-only check, reports the same
pre-existing `_import_scheduling._cooperate_with_durable_import` stub error
as the checkpoint, with no introduced diagnostics. Conformance inventory passes;
the presentation group now includes the reuse regression suite.

Both skills and the API validation map were updated. Two fresh GPT 6.1 Sol
agents used short task/skill/output prompts with no inherited conversation.
They could read source, contracts and tests, but could not read prior reports,
other agents' runtime artifacts or parent diagnoses. The parent inspected and
reran their drivers against the final source; the combined run used a fresh
synthetic sidecar.

- Individual validator trial: one differential driver checks complete ordered
  results across compressed reopen, validation before reuse, corruption,
  same-label replacement, projection identity, concurrent readers, retirement
  collection and cache bounds.
- Combined author trial: one synthetic query driver plus four existing tiny
  assembly lifecycle tests. The driver checks safe search/refinement, retained
  results after reopen, filtered pages, replacement generation identity and
  exact narrow/same-timestamp timeline windows. The lifecycle cases check active
  leases, failed load/retry, reclaim-before-allocation and concurrent releases.
  These are separate fixtures in one process, not an HTTP or durable-import
  composition. The full-scale driver separately exercises actual A → B → A
  runtime navigation and query service calls.

All six trial checks passed. Initial sandbox TEMP/interpreter problems and
harness corrections are retained in the agents' reports; they are not product
failures or successful checks. Exact trial prompts and hashes are recorded in
`.runtime/search-cache-2026-10-20/skill-trials.json`. Skill entrypoints remained
fixed during the batch. The map was clarified afterward to record the measured
persistent-sidecar-only eligibility; parent trial reruns used the final code.

Author skill SHA-256:
`9286671207aeef570fe6c8d95d4ea63215052e3be2a54d4301a76c017fe862bc`.
Validator skill SHA-256:
`6cc4070882a192b37cb054fd35350c1717673442a3d2d189e29d4d8495c0421d`.

## Measurement method

The benchmark uses the actual production code, the configured Python 3.12.13
interpreter, the same 286,496,584-byte generated archive and a source snapshot
of checkpoint `da9291b`. PE-A has 1,250,005 events and PE-B has 1,250,002.
Each run has a fresh process, empty search sidecar directory and fresh bytecode
cache, with `PYTHONHASHSEED=0`. No tests or agent workloads run concurrently.
OS disk caches are not flushed.

The previous 36-phase workload is extended by three searches after returning
to A: `success`, `fail`, and an absent refinement. This yields 39 phase
occurrences with five repeated dense queries. Full ordered phases, response
hashes and retirement records are retained; comparisons do not drop repeated
names. Total CPU cannot be compared directly with earlier 36-phase reports.
Memory is sampled at 100 ms and Windows lifetime peaks are recorded. Browser
memory and separate ingestion worker CPU are outside this backend measurement.

## Million-event results

The fresh checkpoint/final pair completed all 39 phases without triggering
the memory or time guards. These are single-run observations, not statistical
confidence intervals.

| Metric | Checkpoint | Final |
| --- | ---: | ---: |
| Three repeated searches after returning to A, CPU | 4.375 s | 0.03125 s |
| Same searches, wall time | 4.414 s | 0.0196 s |
| First search after return, including corpus validation, CPU | 4.953 s | 4.828 s |
| Same first search, wall time | 5.093 s | 5.154 s |
| Loaded A RSS | 2.354 GiB | 2.353 GiB |
| Sampled navigation peak RSS | 2.369 GiB | 2.369 GiB |
| Process lifetime peak RSS | 2.433 GiB | 2.432 GiB |
| Search sidecar size | 71.5625 MiB | 71.5625 MiB |
| Total measured phase CPU | 183.203 s | 174.281 s |
| Total elapsed time | 188.438 s | 180.110 s |

The three returned searches use 99.29% less measured CPU and 99.56% less wall
time. Individual near-zero CPU readings are limited by the Windows process
clock's 15.625 ms resolution. Shared results occupy 480,331 accounted bytes
across five entries, below the 128-entry/16 MiB limits. The retired A runtime
is collected and its service caches are empty in both runs.

Memory and storage are effectively unchanged. Reopen validation still costs
about five seconds; this cache does not bypass it. The observed overall CPU
reduction also includes variation in cold-load and first-projection work, so it
must not all be attributed to result reuse. No cross-process reuse is claimed.

All 39 ordered phase result records match, including complete response hashes
and repeated phase occurrences. A separate full-corpus verifier decoded every
compressed block, checked framing and raw hashes, and reconstructed the
canonical document digest and ordered literal-match digests. All 1,250,005
documents match between versions, as do all 24,925 `failure` matches, 1,225,080
`success` matches and the absent-query result. SQLite integrity checks pass.
The final measured runtime source hashes still match the working source.

Artifacts under `.runtime/search-cache-2026-10-20/`:

- `before-1/result.json` and `after-1/result.json`: complete phase and memory data.
- `comparison-before-1-after-1.json`: timing deltas, retirement checks and exact
  corpus/query parity.
- `measure.py` and `compare.py`: production benchmark and independent verifier.

## Documentation stewardship

The implementation changes core-derived cache retention and adds an offline
comparison command. It adds no plug-in hook, manifest requirement, parser
workflow, disclosure semantic or author-facing ingestion command. Existing
quickstart, contract and runnable example remain valid; their smoke tests pass.
The required drift check found no reason to change those maintained materials.
Skills and the performance map document the relevant validation and cost rules.
