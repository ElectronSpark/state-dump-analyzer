# Navigation memory validation — 2026-10-20

The preceding compact-event changes were committed as `aaf9758`.
GPT-6.1 Sol used `router-plugin-author` to implement the subsequent navigation
optimization. The parent reviewed the code, added independent checks, and
measured it against that commit in an isolated source tree.

## Behavior

Before a cold node load, the demo assembly store verifies the prepared private
pack's regular-file status, bounded compressed size, and SHA-256 against the
assembly manifest. Reads are streamed in chunks of at most 1 MiB; the check
does not repeat decompression or event parsing. Unknown, missing, resized, or
checksum-mismatched destinations fail before reclaiming idle histories.

After validation, the store reserves one incoming slot within its existing
cache capacity and closes eligible idle LRU generations before materializing
the destination. The reservation remains active during the load, so an active
reader's final release can reclaim its generation before the new load finishes.
Cache hits and lease releases use the short bookkeeping lock; checksum I/O and
materialization occur outside that lock. Cold materializations remain serialized.

Live readers and copied leases remain usable. They may temporarily exceed the
cache capacity; it is not a hard process-memory limit. Explicitly releasing a
shallow dataset view does not clear a dictionary that the caller still retains.
Such caller-owned references can continue retaining values.

Preflight failure preserves the idle cache. A later materialization failure
can leave the old idle history evicted, but its validated private archive
remains available for navigation back or retry. Partial invalid runtimes are
closed, and failures never publish a partial destination. In-progress
validation/load accounting defers private archive cleanup during shutdown.

This is an internal demo compatibility-adapter change. Core querying, public
plug-in protocols, parser emissions, archive formats, and eviction of live
readers are unchanged. No forced collection or process-wide GC policy was added.

## Matched million-event measurement

Baseline: `aaf9758`, extracted before implementation into
`.runtime/navigation-memory-validation/baseline-tree`.
Candidate source SHA-256 (`demo/rsl_demo_plugin/assembly_store.py`):
`c084ed7ee156b762ea486239e99ae3c0ffe6f3a49606d6d7fed31767c7091ce9`.

Both runs use Python 3.12.13 from the configured demo Conda environment and
the unchanged `demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz`
(286,496,584 bytes). A has 1,250,005 events / 7,510 resources; B has
1,250,002 events / 7,509 resources.

The same driver performs archive preparation, A loading, cold and warm literal
searches, refinements, filtered pages, density queries, A→B→A navigation,
sidecar reopening, close, and final collection. Each run has a fresh process
and empty search-cache directory. Memory is sampled every 100 ms and includes
Windows lifetime peak counters. CPU uses `time.process_time`; wall time uses
`time.perf_counter`. OS disk caches are not flushed.

| Measurement | Baseline | Candidate |
| --- | ---: | ---: |
| Loaded A RSS | 2.355 GiB | 2.357 GiB |
| Full-workflow lifetime peak RSS | 4.632 GiB | 2.436 GiB |
| Full-workflow lifetime peak commit | 4.633 GiB | 2.432 GiB |
| Navigation sampled peak RSS (100 ms) | 4.631 GiB | 2.370 GiB |
| RSS immediately after A→B | 3.590 GiB | 2.361 GiB |
| A→B load CPU / wall | 31.08 / 31.93 s | 27.05 / 27.94 s |
| B→A load CPU / wall | 31.27 / 32.15 s | 27.19 / 27.90 s |
| Initial A load CPU / wall | 27.92 / 28.37 s | 28.86 / 29.24 s |
| First search and sidecar build CPU / wall | 59.11 / 60.98 s | 62.13 / 63.63 s |
| Warm dense-page median wall (7 calls) | 7.49 ms | 7.68 ms |
| Reopened sidecar search CPU / wall | 5.11 / 5.15 s | 4.89 / 4.96 s |
| Sum of measured phase CPU | 187.92 s | 184.25 s |
| RSS after close and final collection | 0.158 GiB | 0.148 GiB |

The full-workflow peak fell **47.4%**, while loaded memory stayed essentially
unchanged. Both navigation loads used about **13% less CPU**. The candidate's
full-workflow peak occurred during the first search; its navigation-only number
is sampled and may miss sub-100-ms peaks. The lifetime workflow peak is therefore
the conservative upper bound for navigation in this run.

Initial load CPU increased 3.4%, and first-search/build CPU increased 5.1%.
Preflight introduces a bounded sequential archive read before cold materialization;
the search-build path itself is unchanged. A single before/after pair cannot
attribute these timing differences reliably or establish a confidence interval.
The measured navigation improvement does not imply a uniform CPU improvement.

Both processes completed successfully. Every measured phase's result summary
matched, including repeated filtered-page phases. Final search-sidecar size
(75,038,720 bytes), table inventory, and metadata matched: 1,250,005 documents,
1,768,382,872 source characters, and the same stored digest and identity. This
comparison does not claim a row-by-row comparison of all SQLite contents.
The retired A runtime was gone after switch/collection; service caches and the
loaded-revision list were empty after close.

## Validation

- Sol implementation: 49 assembly-store, archive-safety, and documentation
  tests passed, including executable quickstart smoke commands.
- Parent HTTP/query regression: 59 passed.
- Parent independent checks: missing/resized/same-size modified destination
  preserves A; final reader release during blocked B loading reclaims A;
  invalid loaded identity closes the partial runtime and permits revisit/retry;
  release during failed preflight preserves the current cache.
- Independent validator preparation: two tiny archive checks establish
  collectibility before the next loader and preservation of original/copied
  leases through navigation and shutdown. Parent inspected and reran both.
- Stub consistency: 145 modules across four packages verified. Parent strict
  mypy passes for the changed implementation and both public API typing fixtures;
  fatal Ruff checks pass for the changed source and tests. Both updated skills
  pass the skill validator. The implementation agent compared full Ruff output
  with committed HEAD: 13 existing diagnostics, no new findings. These checks
  do not establish whole-repository strict lint cleanliness.

The parent found two omissions in the first candidate: the incoming reservation
was not honored by reader releases during a load, and a known destination
descriptor alone did not detect a missing or changed prepared pack. Sol fixed
both before the final measurement and added focused regressions.

The author and validator skills now cover preflight integrity, reservation
lifetime, active readers, failure recovery, and checks inside the next loader.
Fresh skill trials and their evidence are recorded below.

Two fresh GPT-6.1 Sol agents ran without inherited conversation. They could
read repository source, tests, and skills, but were explicitly excluded from
prior trial artifacts, parent diagnostics, and other agents' outputs. The
parent inspected their code and logs and independently reran all four new trial
tests successfully.

- Author trial: three new runnable navigation examples passed, plus the
  documented 31-test assembly/archive command. It exercised overlapping
  readers, shutdown, failure/navigation back, and concurrent cache hits and
  release during loading. Its weak-reference demonstration includes collection;
  it establishes collectibility, not measured RSS.
- Validator trial: one new combined history-query/recovery scenario and seven
  focused lifecycle tests passed; declaration inventory passed. Exact search
  counts, bounded page identity, sensitive omission, inclusive same-time
  timeline membership, live-reader survival after failure/retry, same-revision
  replacement evidence, retirement, and close-once behavior were checked.
  Its tiny search result retained zero cache bytes; that is not evidence of
  nontrivial search-cache efficiency or bounded timeline computation.

Both trials discovered the configured Conda environment. Initial missing
dependencies in default Python, sandbox temporary-directory permissions, and
incomplete synthetic metadata were corrected in their own fixtures/environment;
they did not require production changes. The trials establish small correctness
scenarios, not full-scale performance or browser readiness.

Frozen skill SHA-256 values:

- Author: `40ddf9ef70e80215a7e37158dc2b5f6e7778850c63605ddec6421ef95ed075d6`
- Validator: `99dc0e98767822f51152e132d7fb6d266d372594d5d0337d75dfba352b9e0793`

Minimal prompts:

> Use .agents/skills/router-plugin-author/SKILL.md to build and test a small runnable demo of node navigation with overlapping readers. Production is read-only; write only under .runtime/navigation-memory-validation/author-trial. Do not read prior trial artifacts, parent check logs or diagnoses, or other agents' outputs. Use tiny synthetic inputs only.

> Use .agents/skills/router-plugin-validate/SKILL.md to validate node navigation through a combined history-query and failure-recovery workflow. Production is read-only; write only under .runtime/navigation-memory-validation/validator-trial. Do not read prior trial artifacts, parent check logs or diagnoses, or other agents' outputs. Use tiny synthetic inputs only.

## Documentation and reproduction

The documentation drift check found no public API/signature or parser behavior
change. The demo README and API validation map explain the internal lifecycle
and recovery behavior. Existing quickstart and teaching-parser source remain
unchanged; their documented smoke commands passed.

Run from the repository root with the configured interpreter and writable
`TEMP`, `TMP`, and `PYTHONPYCACHEPREFIX` directories:

```text
python .runtime/algorithm-improvements/measure.py --archive demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz --output .runtime/navigation-memory-validation/after-1 --repeats 7 --dense-term success
python .runtime/navigation-memory-validation/compare.py before-1 after-1
python .runtime/navigation-memory-validation/parent_checks.py
```

Use a new output directory for a rerun. Baseline and candidate retain phase
JSONL, 100-ms memory samples, complete result JSON, and error logs under
`.runtime/navigation-memory-validation/`. These are local evidence artifacts,
not tracked source files. The driver uses the same inputs for both versions;
the isolated baseline copy resolves imports against the committed tree.
