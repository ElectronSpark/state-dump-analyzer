# Compact event memory validation — 2026-10-20

This change implements the shared UID index and compact immutable event rows.
GPT-6.1 Sol implemented the change using `router-plugin-author`; the parent
agent reviewed the implementation, ran independent differential and integration
checks, and measured the complete million-event workflow.

## Implementation

- One UID-to-ordinal dictionary backs the UID-to-row Mapping view. Sparse
  overrides preserve the previously accepted duplicate/empty UID behavior.
- Fixed event fields occupy an immutable tuple-backed Mapping. Nested payloads
  use owned read-only JSON-compatible containers; public projections remain
  ordinary dictionaries and lists.
- Bounded load-local pools share complete immutable subjects and subject lists
  (up to 131,072 identities), and one-string-field result dictionaries (up to
  128 identities). Only exact string identities enter these pools. Other
  payloads retain the normal construction path, preserving JSON types and
  dictionary order. Pool indexes are discarded after loading.
- The loader reuses admitted temporal values instead of validating them again
  for every derived index. Generic consumers accept Mapping/Sequence; the
  compact representation and device interpretation remain inside the demo
  plug-in. No capability hook, eviction policy, or fixture format changed.

The first full trial reduced memory but increased cold-load CPU by 30.7%.
That version was revised. Small retained-row probes helped
identify construction and garbage-collection costs; their `timeit` results
measure elapsed time, not process CPU.

A subsequent state-map reuse prototype was rejected: four interleaved bounded
loader measurements showed median CPU of 0.422 s for the retained design and
0.430 s for the prototype. It reduced retained GC work, but its key construction
and guards did not provide a reliable overall CPU benefit. It is not included.

Parent review also reproduced borrowed mutable containers in unusual subject
and effect metadata. The final correction owns and freezes those containers,
with ordinary scalar metadata retaining a fast path.

## Matched full-scale measurement

Baseline: committed `c272689`, extracted into an isolated source tree before
implementation, measured twice (`before-2` and `before-3`). Candidate: final
working-tree source (`after-3`). Both run on the same
Windows host with Python 3.12.13 from the configured demo Conda environment.
The final `scale_data.py` SHA-256 is
`449d35d2a34a2e15daec9e7c2b2d2ccca4ea6f7b7cbc699c5bbeb6f923a91808`.

Input: `demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz`,
286,496,584 bytes. PE-A has 1,250,005 events and 7,510 resources; PE-B has
1,250,002 events and 7,509 resources. The archive was reused unchanged.

Each trial uses a fresh process and empty search-sidecar directory, then runs
archive preparation, A load/bootstrap, cold and warm sparse/dense searches,
refinements, layer-filtered pages, three density windows, A→B→A navigation,
sidecar reopening, runtime close, and final collection. Seven warm dense pages
are measured. Windows process memory is sampled every 100 ms, and the process
lifetime peak counters capture peaks between samples. CPU is measured with
`time.process_time`; wall time uses `time.perf_counter`. Cold here means a fresh
application process/cache, not flushed operating-system disk caches.

| Measurement | Baseline run 1 | Baseline run 2 | Final implementation |
|---|---:|---:|---:|
| Loaded RSS, GiB | 3.216 | 3.241 | **2.358** |
| Navigation lifetime peak RSS, GiB | 6.347 | 6.397 | **4.638** |
| Lifetime peak commit, GiB | 6.352 | 6.403 | **4.639** |
| Cold A load, CPU seconds | 25.453 | 28.172 | **28.766** |
| Cold A load, wall seconds | 26.570 | 29.335 | 29.580 |
| First search/build, CPU seconds | 57.781 | 56.531 | 59.656 |
| First search/build, wall seconds | 59.440 | 58.147 | 61.402 |
| First layer-filtered page, CPU seconds | 1.438 | 1.516 | 1.828 |
| A→B load, CPU seconds | 30.313 | 31.891 | 33.078 |
| A→B load, wall seconds | 30.780 | 32.673 | 34.117 |
| B→A load, CPU seconds | 31.125 | 31.594 | 33.609 |
| B→A load, wall seconds | 31.619 | 32.861 | 34.896 |
| Reopened-sidecar search, CPU seconds | 5.531 | 4.859 | 4.813 |
| Warm dense page median, wall milliseconds | 7.110 | 7.393 | 7.920 |
| Final RSS after close and collection, GiB | 0.153 | 0.143 | 0.146 |

Loaded memory falls 26.7–27.3%, and navigation peak falls 26.9–27.5%.
The change is **not CPU-neutral**: final cold-load CPU is 2.1–13.0% higher,
first search/build CPU is 3.2–5.5% higher, and navigation load CPU is
3.7–9.1% higher across the two baseline comparisons. The first layer-filtered
page costs an extra 0.31–0.39 CPU seconds; subsequent filtered pages remain
about 5–7 ms wall time. Warm density windows remain about 1.1 ms.

Bounded actual-loader profiling identified immutable-container construction
and retained GC work as costs; Python Mapping field access also affects query
projection. These memory gains therefore do not establish unchanged CPU
efficiency. This is one host, two baseline runs, and one final-code run;
the observed ranges are not confidence intervals. Short-query CPU values are
quantized in roughly 15.625 ms increments, so their wall medians are more useful
than individual CPU samples. No browser-readiness claim is made.

RSS immediately after A→B is 3.595 GiB, compared with 3.293–3.326 GiB for the
baseline. Explicit collection reduces it to 2.473 GiB; loaded RSS must not be
mistaken for the post-navigation reading before collection. The old A runtime
weak reference is dead after switch/collection. Closing the runtime empties
the loaded revision list and all measured service caches; final collection
returns RSS to 0.146 GiB. The change does not add an early-eviction or forced-GC
policy.

Every measured phase result summary matches both baselines. Search-sidecar
table inventory, metadata, and size are unchanged: 75,038,720 bytes, 1,250,005
documents, and 1,768,382,872 characters. The canonical corpus digest is
`e822d341feb8f3d1172725004d2e286614416d42c07e21446f4de725faef6b36`
in both versions. This implementation reduces in-memory representation;
archive and sidecar storage sizes are unchanged.

## Correctness and skill validation

- Parent history/storage/zoom/archive regression run: 111 tests, 110 passed,
  one skipped because Windows symbolic-link privileges were unavailable.
- Parent normalized-data and revision-query run: 37 passed, including HTTP
  parity. Parent scale-history HTTP run: 22 passed.
- Independent reference harness: 27 complete query scenarios, repeated through
  the shared UID view, plus normalization, disclosure, ownership, and
  source-record copy checks.
- Independent FastAPI/Starlette encoding checks: 28 public projected payloads.
  Internal dataclass rows must continue to pass through public dictionary
  projection before transport encoding.
- Final metadata correction: the parent independently reproduced the alias,
  verified input ownership and published immutability with/without pooling,
  reran all 28 focused storage tests, and repeated the differential, JSON
  projection, and combined skill scenario checks on the final source.
- Implementation agent: 28 focused storage tests and 18 documentation smoke
  tests, including the documented quickstart commands. The maintained authoring
  documentation, example README, skills, and checked-in stubs were updated.

Public consumer strict typing and all 145 module-stub checks pass, as do the
10 typing-contract tests. Focused implementation strict typing still reports
the same 28 diagnostics as the committed baseline; the parent compared the
diagnostic messages after removing shifted line numbers. This is not a claim
that whole-repository strict typing is clean. Focused Ruff fatal-error checks,
both skill validators, and the whitespace check pass.

The initial HTTP attempt stalled in Windows `socket._fallback_socketpair`
while TestClient created its event loop, before application startup. A bounded
faulthandler trace established this environment limitation; the tests passed
outside the sandbox with local loopback available. It was not counted as a
product failure or a passing test before the successful rerun.

Fresh GPT-6.1 Sol agents receive short task prompts and the skill path, without
implementation steps or expected assertions. Trial artifacts and skill hashes
are retained under `.runtime/compact-event-validation/`. The parent inspects
their code and results. These small trials establish skill use and bounded
correctness, not million-event performance or exhaustive API coverage.

The parent rejected one author trial despite its own passing checks: it used
the first canonical duplicate ordinal and assigned an ordinal to an empty UID.
Production already preserved the legacy behavior correctly. Both skills were
clarified to distinguish canonical-sort-last ordinal lookup, arrival-last row
lookup, and the empty-UID exception. The first retry reused the earlier trial
and read its diagnosis, so it is regression evidence rather than an independent
skill-only trial. The final isolated retry excluded other trial artifacts.
It built a small independent storage adapter and passed three synthetic tests
for UID semantics, ownership, JSON types/order, pool bounds/isolation, and
collection. It did not implement the complete `IndexedHistory` protocol or
exercise core integration; its default interpreter lacked the installed
package. The parent reran its tests with the configured interpreter.

The separate isolated validator discovered the configured environment through
the skill's documentation and passed 22 distinct focused tests plus its own
combined compact-row query/search/generation scenario. The parent inspected
and reran that combined scenario. Its search cache retained 168 bytes within a
256-byte budget. Existing bounded-query tests checked fewer than 40 index
reads for a cold five-event window in 30,000 events and prohibited complete
lane iteration. The active-lease test confirmed eviction preserves live
readers and closes resources once on final release.

The generated-archive validator also
loaded a real 245-event node, compared query results with dictionary references,
and passed all 27 archive safety/store tests.

The final isolated prompts were:

> Use .agents/skills/router-plugin-author/SKILL.md to build and test a small compact indexed-history adapter for repeated input values. Read only repository source, tests, docs and skills; do not read other .runtime artifacts or agents’ outputs. Write only under .runtime/compact-event-validation/isolated-author. Use small synthetic checks only.

> Use .agents/skills/router-plugin-validate/SKILL.md to validate the compact-history changes through a combined synthetic history query and lifecycle workflow. Read only repository source, tests, docs and skills; do not read other .runtime artifacts or agents’ outputs. Write only under .runtime/compact-event-validation/isolated-validator. Use small synthetic checks only.

Skill SHA-256 values:

- Author: `421e2063801a9f1b04f7390a6141402c8f0bf9c1b08e89dcbb2cb7b1d7b7b442`
- Validator: `d153714b60059c07eb9dc888bf6083be7d310e22c14ea8a7ad8ada532c81e5aa`

The documentation drift check covered the quickstart, normative contract,
author guide, teaching-demo README, root links, API contract, architecture,
validation map, and stubs. Ordinary parser behavior and the runnable parser
source remain unchanged. The exercised compatibility-storage contract is
documented separately from ordinary parser emissions.

## Reproduction and evidence

The existing measurement driver is
`.runtime/algorithm-improvements/measure.py`; the baseline copy runs against
the isolated tree in `.runtime/compact-event-validation/baseline-tree`.
Set `TEMP`, `TMP`, and `PYTHONPYCACHEPREFIX` to writable task-local directories.
Use the same interpreter and archive for both runs:

```text
python .runtime/algorithm-improvements/measure.py --archive demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz --output .runtime/compact-event-validation/after-3 --repeats 7 --dense-term success
python .runtime/compact-event-validation/compare.py before-2 after-3
python .runtime/compact-event-validation/compare.py before-3 after-3
```

The actual runs used absolute paths. Use a fresh output directory on a rerun.
`before-2`, `before-3`, and `after-3` retain JSONL phase records, sampled memory,
final JSON results, and separate error logs. `after-1` and `after-2` are
intermediate implementations, not final results. The comparison preserves repeated
phase names and checks result summaries and search-sidecar metadata. Runtime
artifacts are local evidence, not part of the tracked source distribution.
