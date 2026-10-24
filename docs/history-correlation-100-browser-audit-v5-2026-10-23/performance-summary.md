# Fifth browser audit: process performance observations

The primary agent performed 100 recorded browser workflows on commit `d29f981`: 93 passed their scoped checks, five observations exposed defects, and two attempts were inconclusive. Four defect observations concern two functional defects sharing a missing resolved-time handoff; the fifth concerns VPN popup activation during focus scroll, confirmed by late native-keyboard verification. This process audit does not convert those workflow observations into independent performance benchmarks. It sends no HTTP requests and changes no product code.

## Scope and integrity

The sampled target was the existing Python demo PID **9620**, created 2026-10-23T23:16:17.684287-04:00, serving the declared `router-state-lab-history-correlation-2026-10-23.tgz` on loopback port 8883. Its command line, executable, and listener were verified before sampling without `/health` or other application requests. This was already a warm server; initial process-lifetime RSS high-water was 2.957 GiB before the audit began. The sampler records process creation identity at every sample and uses a read/query handle only.

Sampling ran **2026-10-24T03:38:04.502Z–04:00:21.490Z**, with **1,337 samples** over a **1,335.987-second first-to-last sample span** (1,337 seconds sampler elapsed). The stop-file marker produced a clean final record; the sampler exited and demo PID 9620 remained running. One process creation identity, monotonic timestamps/CPU, sample count, and extrema were checked against the final stop record. `analyze_performance.py` reproduces `performance-stats.json` from the original samples and the finalized 100-move log.

**Coverage ends at the last process sample, 04:00:20.490Z.** Move 100's original action and first observation were sampled, but subsequent native-keyboard reproduction extended its final observation to **04:02:52.676Z**, after sampling stopped. Those later actions are excluded from all CPU/memory measurements below. The sampler was not restarted. The updated machine-readable report marks move 100 and its containing final phase as partially covered, preserves their actual requested endpoints, and leaves full-window CPU/outer-bracket values null; separately named available-sample brackets report only covered evidence. The earlier report is retained as `performance-stats-before-late-verification.json` to preserve the original 04:00:04.117Z observation boundary.

| Metric | Audit start | Audit end | Maximum sampled during audit |
| --- | ---: | ---: | ---: |
| Working set / RSS | 2.836582 GiB | 2.938278 GiB | **3.258217 GiB** |
| Private commit | 2.828468 GiB | 2.931278 GiB | **3.250980 GiB** |
| Cumulative process CPU | 279.203125 s | 642.906250 s | delta **363.703125 s** |

RSS peaked at **03:44:21.489Z** and private commit at **03:44:18.501Z**, within the cold PE-D entry workflow (move 35). The final process-lifetime peaks equal these sampled maxima in this run. Reported sampled maxima are still one-second snapshots and can miss shorter peaks; the lifetime counters are reported separately in the machine-readable data. Browser heap, GPU memory, child processes, and other host processes are not sampled.

The process ended about **104.14 MiB RSS** above its initial warm state. A rise in retained memory over this mixed workload is not evidence of a leak. The approximately 17-second sampled tail after the original move-100 observation used 0.344 CPU seconds and held RSS at 2.938 GiB; no persistent background CPU spin is established by that bracket. This tail does not cover the later native-keyboard reproduction.

## Broad workflow brackets

These are actual sample brackets, not isolated endpoint timings. The final row includes only available samples up to sampling end and does not enclose the later move-100 verification. Boundary samples can overlap, so do not sum this table to obtain total CPU; use the total cumulative-counter difference above.

| Workflow phase | Bracket wall time | Bracket CPU | RSS first → last |
| --- | ---: | ---: | ---: |
| Initial fabric/route operations, moves 1–34 | 357.002 s | 50.109 s | 2.837 → 2.850 GiB |
| Cold PE-D entry, move 35 to next action | 161.002 s | 78.391 s | 2.850 → 2.844 GiB |
| PE-D history/correlations, moves 36–65 | 387.991 s | 115.109 s | 2.844 → 2.895 GiB |
| Relative fabric/node roundtrips, moves 66–72 | 100.992 s | 30.281 s | 2.895 → 2.903 GiB |
| Node topology/history cross-checks, moves 73–77 | 73.999 s | 33.641 s | 2.903 → 2.933 GiB |
| Final fabric/route workflows, moves 78–100, sampled portion only | 248.998 s | 57.078 s | 2.933 → 2.938 GiB |

Cold PE-D entry is a substantial first-use episode: its saved action-to-settled observation is 157.946 seconds and the enclosing observation bracket uses 78.313 CPU seconds. That includes loading and initial panels, not a timed loader endpoint. Warm PE-D reopen workflows 69 and 72 used 9.328 and 9.625 CPU seconds in their observation brackets, materially less than the cold entry; those operations also populate initial panels and are not bare reopen-validation timings.

## Repeated cursor cost

| Move | Operation | Action to saved settled observation | Enclosing sampled CPU |
| --- | --- | ---: | ---: |
| 44 | Seek ES1 before attachment, then edit resource search | 21.422 s | 8.016 s |
| 51 | Withdraw ES1 while retaining focus | 14.236 s | 9.484 s |
| 57 | Jump from overview to failed DTE update | 25.444 s | 7.922 s |
| 73–77 | Five topology/history cursor cross-checks | 9.644–17.810 s each | 6.047–7.422 s each |

The long observation gaps are **not measured response completion times**. Move 44's process was near one CPU core from about 03:48:32.5–40.5, then mostly idle before the saved 03:48:52.810 follow-up. Move 57 was near one core from about 03:51:04.5–12.5, then mostly idle before 03:51:29.636. Both establish substantial roughly eight-CPU-second work, but not 21–25 seconds of continuous server execution. Their eventual resource/graph results were correct. Graph-only focus/scope operations 45, 55, and 56 each used under one CPU second in their enclosing brackets.

Source review explains why a small visible graph can accompany much more work:

- A cursor change schedules graph, resource, and dashboard reads together after 100ms (`frontend/assets/app.js:4232`), and followed topology separately after 260ms (`:9211`).
- Editing resource search schedules another query after 180ms (`:12512`), potentially superseding the cursor-triggered request. Canceled work actually executed was not instrumented here.
- A failure-event jump can add a timeline-lane refresh and event-detail query (`selectEvent`, `:4339`) alongside cursor work.
- Fresh searched timestamps build client-safe text for the full resource population before kind/page filtering (`src/router_dump_analyzer/normalized_data.py:3894`). The two-timestamp cache builds under a lock (`demo/rsl_demo_plugin/scale_data.py:331`). Live dashboard populations are independently reconstructed (`normalized_data.py:4064`).

The preceding controlled cursor investigation already measured population-wide search/disclosure work and roughly 1.25 million interval checks per search/dashboard case. This live audit confirms recurring CPU cost in composed workflows, but does not isolate GIL contention, request queueing, lock wait, topology, serialization, or cancellation costs. It does not establish a new algorithmic regression or permanent stall. Per-request timing/profiling, or controlled UI comparisons with dashboards closed and topology follow disabled, would be needed to apportion the work.

## Route operations and limits

Exact-admission VPN tracing in move 85 used 5.125 CPU seconds in an 18.999-second enclosing bracket; reversed table-seeded tracing in move 90 used 5.594 CPU seconds in a 22.000-second bracket. The process was mostly idle well before the latter's follow-up observation. These successful workflows show route computation cost, not a 22-second backend latency measurement. Move 100's original popup keypress used 0.078 CPU seconds in its one-second enclosing bracket; that sampled action does not measure the later defect verification or establish activation success.

This warm live-server sequence is different from the isolated 52-phase 1M navigation workload and the direct-service cursor profile. The preceding repair's benchmark CPU increase remains unattributed; this audit neither resolves it nor measures a new before/after change. No frontend suite or fresh 1M benchmark was run by this sampler task.

Evidence: `process-samples.jsonl`, `moves.json`, `performance-stats.json`, `analyze_performance.py`, sampler source/hash, process/listener identity, and the preliminary notes. Only task-local evidence was written. Documentation drift check complete: no public plug-in or author-facing behavior changed, so maintained authoring materials required no update.
