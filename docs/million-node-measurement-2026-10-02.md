# Million-event node measurement — 2026-10-02

The largest observed latency was the first normalized-event search: **106.25 s**.
Opening PE-A through archive preparation, history materialization and bootstrap
took **56.54 s**, excluding imports. A loaded node occupied about **3.22 GiB** of
process working set; switching nodes briefly raised it to **6.34 GiB**.

## Scope and method

This is one successful run of the current working tree, including the zoom
changes following checkpoint `4609c61`. It uses the retained generated demo
assembly, not a vendor capture or lightweight timestamp-only benchmark:

- Archive: `demo/fixtures/router-state-lab-demo.generated.tgz`, 286,514,932 bytes.
- PE-A: 1,250,005 rich events and 7,506 resources.
- PE-B: 1,250,002 rich events and 7,507 resources.
- The assembly contains ten nodes. Preparation checks/extracts their node packs
  and bounded projections; only PE-A and PE-B histories are materialized.
- Windows 11 build 26300, Intel Core i7-12650H, 63.71 GiB usable physical RAM;
  Python 3.12.13 from the installed demo environment, SQLite 3.53.3.

A fresh child process opens the real demo runtime and uses
`NormalizedDataService` and `RevisionQueryService`. The runtime's actual history
cache size is **one**. Search uses `EventLogQuery(source_types=(), search=...,
limit=100)` so it exercises normalized indexed history. A new empty search-cache
directory under the local system temporary directory prevents an existing
sidecar from hiding first-search work.

The sequence is A load → bootstrap → first and repeated searches → B load → A
reload → search-sidecar reuse → close. Dataset leases and references are released
before each switch. Explicit garbage collections are measured separately;
they are harness work, not included in the node-switch times below.

Wall and CPU time surround each operation. An external supervisor samples the
child's working set and private committed bytes every 100 ms. Windows lifetime
peak counters capture short process-wide spikes missed by sampling. The run
completed in 266.08 s with exit code zero, no stderr, and no memory/time guard
activation.

## Results

| Operation | Wall time | CPU time | Working set after operation |
|---|---:|---:|---:|
| Runtime imports | 1.575 s | 1.516 s | 0.049 GiB |
| Prepare ten-node archive | 21.300 s | 20.313 s | 0.086 GiB |
| Materialize PE-A | 35.188 s | 34.172 s | 3.215 GiB |
| Build initial client payload | 0.055 s | 0.047 s | 3.216 GiB |
| First search: `failure` | 106.255 s | 101.344 s | 3.216 GiB |
| Repeat `failure`, same loaded history | 0.00457 s | timer resolution limited | 3.216 GiB |
| Different term: `success` | 3.904 s | 3.781 s | 3.216 GiB |
| Switch A → B, materialization | 40.860 s | 39.766 s | 3.302 GiB |
| Return B → A, materialization | 36.817 s | 35.500 s | 3.289 GiB |
| Search `failure` after A reload | 11.301 s | 10.969 s | 3.289 GiB |

Runtime context entry and service/query object construction each took less than
0.1 ms. Preparation, materialization and bootstrap sum to 56.543 s, or 58.118 s
including measured imports. These sums exclude interpreter startup, transport,
JSON response encoding and browser work. Bootstrap returned 7,506 resources and
zero embedded events, consistent with windowed history loading.

Search built a **2,492,391,424-byte (2.321 GiB)** SQLite sidecar containing
1,250,005 documents. Its backend was **`sqlite-scan`**, not trigram FTS. Both
initial and returned `failure` queries counted 24,925 matches and returned 100;
`success` counted 1,225,080 and returned 100. Repeating `failure` while A remained
loaded used the in-memory query-result cache. After eviction, A's search corpus
was pending again; its next search reopened and validated the saved sidecar.

Memory observations:

- Maximum Windows working set: **6,810,243,072 bytes (6.343 GiB)**.
- Maximum Windows private-commit counter: **6,814,441,472 bytes (6.346 GiB)**.
- Switching to B and returning to A each reached about 6.34 GiB. The store builds
  the replacement before trimming the old entry, briefly retaining both rich
  histories even with a one-node cache.
- Minimum sampled host-available RAM: **32.70 GiB**. The test did not approach
  its memory guard; page-fault counters do not distinguish hard from soft faults.
- After runtime close and final collection, working set fell to 0.148 GiB.
  This single lifecycle is not a long-running leak test.

## What to optimize next

The subsequent [memory and storage investigation](compact-storage-investigation-2026-10-02.md)
tests larger SQLite pages, compressed search blocks and compact event rows. It
records measured savings and CPU tradeoffs without changing production behavior.

1. **Measure and reduce core search-corpus construction.** The first search is
   dominated by preparation collectively: it takes 106 s, versus 3.9 s for an
   uncached different term on the prepared corpus. Core redacts every event,
   emits canonical sorted JSON, casefolds it, then encodes/hashes and writes the
   safe text to SQLite. CPU time is close to wall time. This run does not isolate
   redaction, serialization, hashing and database writes; profile those stages
   before selecting the implementation. Reusing more prepared redaction context,
   such as cached resource-kind sensitivity decisions, is a candidate, with
   byte-for-byte search-document parity required. The current code already
   computes the overall redaction policy once per search operation.
2. **Reduce history materialization and the navigation memory peak.** The
   35–41 s loads and 3.2 GiB retained per node remain material at this size.
   Evaluate compact immutable storage and loading event details on demand.
   Cache changes must preserve active leases, concurrent readers and failed-load
   recovery; simply doubling the cache would retain substantially more memory.
3. **Make sidecar reuse cheaper while retaining integrity checks.** Reuse saves
   a fresh 106 s build, but its first query still costs 11.3 s. The implementation
   validates all saved documents before querying; that split was not separately
   timed. Do not remove verification based on this measurement.
4. **Revisit archive preparation after these paths.** Its 21.3 s covers the
   whole ten-node container even though one node is initially selected. A
   plug-in-owned independently accessible node-pack layout is a candidate.

The search recommendation stays within the core/plug-in boundary: core owns
redaction and generic search; the demo plug-in owns archive layout and its rich
history representation. Raising the eager trigram threshold would add work to
the first-search path. Moving search preparation to the background changes when
the cost is paid, but does not by itself reduce it.

## Limits, evidence and checks

“Cold” here means a fresh process, history runtime and search cache. The OS file
cache was not cleared; archive preparation itself warms node-pack reads. A and
B switches measure backend materialization only, without a second bootstrap.
The search terms have different selectivity, so subtracting their timings does
not isolate a precise build duration. This is one observation, not a latency
distribution. It does not benchmark HTTP/browser readiness or zoom rendering.
Fresh bytecode-cache paths also add compilation/write work to imports.

Phase memory peaks are sampled and may include small gaps before the next phase;
the reported overall peaks are Windows lifetime counters. Memory refers only to
the measured child process, not the browser, other demo servers, or OS file cache.

Local evidence is retained under `.runtime/million-node-measure-2026-10-02/`:

- `measure.py`: harness; a complete 305-event smoke run passed before the large run.
- `full-run-1/result.json`: timings, result counts, environment and memory peaks.
- `full-run-1/child.jsonl`, `memory.jsonl`, `stderr.log`: raw phase and sample logs.
- `full-run-1.log`: supervisor output.

The measured search sidecar remains in
`C:/Users/82046/AppData/Local/Temp/rsl-million-measure-search-sfpvdae6`.
The fixture and its preexisting lock file were not changed. To repeat locally,
choose a new output directory (the harness refuses to overwrite one):

```powershell
& 'C:/Users/82046/anaconda3/envs/router-dump-analyzer-demo/python.exe' `
  .runtime/million-node-measure-2026-10-02/measure.py `
  --archive demo/fixtures/router-state-lab-demo.generated.tgz `
  --output .runtime/million-node-measure-2026-10-02/full-run-2
```

A `gpt-6.1-sol` subagent independently reviewed the measurement method and
interpretation without running a competing large load. The documentation drift
check found no author-visible API or behavior changes from this measurement;
the authoring documents, runnable example and skills need no update for it.
