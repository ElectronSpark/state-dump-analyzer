# Current 1M measurements and cursor cost investigation

Ran the unchanged 1M workload, unchanged cursor workload, and one new followed-topology diagnostic sequentially after the parent stopped demo PID 36604 and completed browser/tests. No browser/HTTP requests or concurrent test workloads were issued by this agent. All measurement processes exited before the parent restarted the demo. Product code was not modified by this investigation.

## Comparable 1M workload

The valid result is `after-1m-sqlite-quiet/result.json`; compare it with the latest v4 baseline using `comparison-sqlite.json`. The earlier `after-1m-quiet` run is explicitly excluded for a diagnosed cache-path fallback described below.

| Metric | Historical v4 | Current valid rerun |
| --- | ---: | ---: |
| Loaded PE-A RSS | 2.175423 GiB | 2.175972 GiB |
| Process lifetime peak RSS | 2.254967 GiB | 2.255966 GiB |
| Process lifetime peak private commit | 2.248951 GiB | 2.251320 GiB |
| Sum of measured phase CPU | 187.546875 s | 159.984375 s |
| Overall elapsed | 196.750 s | 166.672 s |
| Search sidecar | 75,038,720 bytes | 75,038,720 bytes |

Both runs returned zero with no stop reason. All **52 ordered phase results**, **35 ordered page hashes**, and all five cache/search invariant groups match. The runtime build, fixture identity/size, random hash-seed mode, and six recorded core source hashes match. The actual backend is `sqlite-zlib-blocks-v1`. `1m-review.json` retains metadata equality and every per-phase CPU delta.

RSS and disk footprint remain essentially unchanged. CPU is 27.5625s lower (14.70%) in this sample, primarily in B load, return-to-A load and initial search. This is a historical comparison, not a controlled source A/B experiment; it does not establish that the navigation/popup fixes improved CPU or resolve the previously unattributed timing variation. The harness does not execute frontend JavaScript. OS caches were not flushed; browser/GPU memory is excluded. Memory JSONL samples are taken every 100ms, while the table separately uses process lifetime high-water counters.

## Isolated cursor components

The existing cursor diagnostic repeats eight native offsets in two rounds with reversed empty/active search order. It uses PE-A's 1,250,005 events and 7,510 resources, 500-row DTE resource pages, focused correlations, and the two default-open live dashboards. Fresh timestamp cases clear only the existing search-document snapshot cache; temporal histories stay warm. cProfile queries are separate from the uninstrumented timing occurrences.

| Component | Fresh median wall | Exact repeat median wall | Fresh median CPU |
| --- | ---: | ---: | ---: |
| Searched resource page | 1.643272 s | 0.003015 s | 1.593750 s |
| Empty-search page | 0.097185 s | 0.096957 s | 0.093750 s |
| Focused correlation graph | 0.030155 s | 0.027665 s | 0.031250 s |
| Two live dashboards | 1.179266 s | 1.197334 s | 1.156250 s |
| Followed topology, separate process | 1.247223 s | 1.251901 s | 1.203125 s |

For the original four components, 128 timed occurrences passed 64 exact-repeat and 64 cross-round comparisons; all four separately profiled outputs match. All **133 ordered response digests** match the prior complete v4 run, including first-use and profile occurrences. All 33 unique compressed response archives were decompressed, rehashed and parsed. Observed at most one 7,510-document snapshot within the existing two-timestamp capacity; this sequence is not an eviction test.

The first lazy searched cursor costs **7.226300s wall / 7.156250s CPU**, increasing RSS by **600.582MiB** (2.171707→2.758213GiB). The largest query-boundary RSS snapshot is **2.776974GiB**, with private commit 2.774067GiB. These are before/after snapshots from the historical-resource workload, **not** process lifetime peaks and **not** the separate 1M navigation workload's 2.255966GiB peak. Allocation profiling was not collected, so the added memory is not apportioned among expanded histories, text documents and allocator retention.

The separate followed-topology process reproduces the current frontend request literally: request-owned provider/service per call, `plugin.resource-association`, `data-bridge-layer`, node A, best effort, native cursor number passed in the absolute UTC input as current follow logic does, limits 80 resources/80 connectivity/100 changes, preceding 120 seconds, and all four includes. Its 32 timed queries passed 16 exact-repeat and 16 cross-round comparisons plus the separate cProfile output; all nine full response archives were verified. It retains requests, resolved node times, counts and truncation. It does not pretend the first 80 resources cover all 7,510 resources or paginate the UI's intentionally bounded view.

First followed-topology use costs **1.365687s / 1.328125 CPU s** and grows RSS by **83.531MiB**. Largest query-boundary RSS/private snapshots are **2.307156/2.303234GiB** in this separate process. It neither includes the all-resource search workload nor measures a combined-process peak.

## Measured contributors and limits

- **Search projection:** 5.223s under cProfile, with 7,510 `resource_search_text` calls and 1,252,040 interval checks. Client-safe projection, repeated declared-field traversal and state reconstruction dominate; 16.7 million calls occur despite the one matching visible row. Global counts require preserving the existing all-resource search semantics. Exact timestamp reuse already cuts repeated searched pages to about 3ms.
- **Dashboards:** 3.399s under cProfile, 7,125 state-reader calls and 1,250,200 interval checks. Reconstruction and disclosure consume most time; aggregation itself is small. Existing request-context reuse could avoid repeated dataset/descriptor lookup (0.153s and 0.077s cumulative respectively), but those nested totals are not additive or a proven uninstrumented gain. This modest opportunity does not account for the multi-second composed workflow.
- **Followed topology:** 4.777s under cProfile. Relationship reconstruction uses 2.354s cumulative and 465,674 presence checks; bounded change extraction 1.262s; resource uncertainty reconstruction 1.073s. The request issues 708 ordinary state-reader calls and 438,095 strict temporal integer conversions. Service construction is negligible. A bounded output still scans substantial endpoint histories and evaluates uncertainty; caching only the provider factory would miss the dominant work. Nested cumulative times overlap.
- **Correlation graph:** ordinary cases are a few to tens of milliseconds. High-fanout cases reach 500 nodes/499 edges, 504,120 relationship-presence checks and roughly 0.25–0.31s uninstrumented wall time. The separate profile is 1.083s, not an application latency measurement.

Outliers are preserved. Dashboard exact repeat at ordinal 90 again costs **3.892875s wall / 3.765625s CPU**, despite matching output. Followed topology exact repeat at ordinal 14 costs **3.975391s / 3.750000 CPU s**. GC, allocation, lock wait and request cancellation were not instrumented; these samples do not establish a permanent stall or a specific cause for the outliers.

The measured repeated work is population-wide safe search text, live dashboard state reconstruction, and followed-topology relationship/history processing. A useful future algorithmic investigation would preserve the existing ambiguity/overlap rules while indexing sorted disjoint intervals and reducing repeated disclosure-plan traversal. No new cache, semantic shortcut or speculative architecture was added as part of the three functional fixes. Request-context hoisting is a smaller candidate, with a limited expected ceiling.

These service timings are not an exact replay of the PE-D audit or a measurement of HTTP scheduling, serialization, browser rendering, overlapping requests or event-detail/lane refresh. Do not sum the medians into a claimed browser refresh latency or subtract them from the observed 8-CPU-second brackets to infer a missing cause. The new topology profile supplies the previously absent component attribution, while the full composed workflow remains only process-bracket evidence.

## Excluded run and new environment finding

The first run completed normally but used `memory-scan` and no sidecar because its nested evidence/temp directory made SQLite's temporary path too long. It preserved all 35 page hashes but failed cache-mode comparability and reached approximately 3.97GiB RSS. `probe_sidecar_path.py` directly reproduces `OperationalError: unable to open database file` at a 272-character temporary path. The same directory succeeds with a shorter filename (223 characters), and the original filename succeeds with a shorter root (178 characters). This isolates the SQLite path-length limitation from a general directory permission failure.

All diagnostic outputs are retained. The valid fresh-process rerun uses the shorter task-local `.runtime/h5perf-t` tree and explicitly verifies matching SQLite mode. Product behavior was not altered to mask the fallback. Long custom cache paths remain an environment limitation discovered by this measurement setup; default application cache paths were not changed or measured in this probe.

Documentation drift check for this investigation: only ignored runtime scripts and evidence were created. No public plug-in hooks, author-facing behavior or product source changed in this subtask.
