# V4 browser audit performance review

The live-server samples support costly cold node switches and repeated historical projection work. They do **not** establish a new algorithmic regression, persistent stall, or memory leak. The newly confirmed unbound startup-form defect causes extra document navigation while loading; that is a supported functional defect with avoidable workflow disruption. These samples cannot isolate how much additional backend work each native submission caused.

This is an offline review at commit `4f49279` of `process-samples.jsonl`, all 100 move records, selected saved follow-up snapshots, and the runtime source notes. No browser/server requests, process changes, tests, or benchmarks were performed. Reproduce the arithmetic with `analyze_performance.py`; complete move windows, measured sample brackets, broad phases, CPU episodes, and interpretation limits are in `performance-stats.json`.

## Sampling scope and validation

- PID 35624 has one process-creation identity across all 1,473 samples. CPU counters and timestamps are monotonic. Sampling ran from **2026-10-24 02:13:25.269 to 02:37:57.257 UTC**, for **1,471.988 measured seconds**, and stopped cleanly through the stop file. All 100 action windows are covered. Local audit date remains October 23.
- Actual intervals are 0.984–1.017 seconds, median 1.001 seconds. The stop record's sample count, sampled maxima, and CPU delta agree with raw records.
- CPU increased **486.766 seconds** across the measured window. It is cumulative process CPU, not browser CPU or a sum of isolated request durations.
- The ledger currently contains **83 pass, 11 bug, and 6 inconclusive rows**. Repeated bug rows are not distinct-defect counts. This analysis does not change those classifications.

| Server process memory | First sample | Maximum sampled in this audit | Last sample |
| --- | ---: | ---: | ---: |
| RSS | 2.88518 GiB | **2.97205 GiB** | 2.95784 GiB |
| Private committed bytes | 2.87910 GiB | **2.96669 GiB** | 2.95068 GiB |

The RSS maximum occurred at **02:34:18.259 UTC**, around the VIF neighbor-birth workflow. The separate end-of-run process-lifetime peaks are 2.97384 GiB RSS and 2.97108 GiB private commit. Those lifetime counters are **not** audit sampled peaks and can include work before sampling. One-Hz sampling can miss shorter peaks. Browser heap and other processes are excluded.

The server already had 263.906 lifetime CPU seconds and 2.885 GiB RSS at the first sample. This is a previously used live process, unlike a fresh-process 52-phase benchmark. Ending RSS is about 74.4 MiB above the first sample and below the audit maximum. That observation alone does not distinguish bounded retained caches from a leak. The final approximately 12-second observation window consumed about 0.273 interpolated CPU seconds; no continuing high-CPU episode remained at the end.

## Broad phases

CPU values below are interpolated at move boundaries from adjacent cumulative samples. Machine-readable output preserves the wider directly measured brackets. Windows include deliberate inspection/tool gaps and are **not task completion latency**; broad windows are used to distinguish workloads, not to compare endpoint speed.

| Window | Wall seconds | Estimated CPU seconds | Maximum contained RSS GiB |
| --- | ---: | ---: | ---: |
| Initial fabric/route work, moves 1–33 | 365.060 | 95.950 | 2.887 |
| P2 cold entry and initial search, moves 34–36 | 84.944 | 74.306 | 2.887 |
| P2 warm inspection, moves 37–39 | 58.873 | 4.511 | 2.857 |
| P2 → fabric return/filter, moves 40–41 | 22.423 | 4.157 | 2.859 |
| PE-A cold entry plus native-form reload reproductions, moves 42–48 | 147.467 | 113.141 | 2.929 |
| PE-A historical resource/correlation work, moves 49–87 | 645.863 | 159.873 | 2.972 |
| Fabric return and CE route work, moves 88–100 | 119.552 | 34.226 | 2.957 |

The first substantial P2 episode, **02:19:46.268–02:21:01.263 UTC**, consumed **73.891 CPU seconds over 74.996 wall seconds**. The node-link action itself lasted only 0.377 seconds. The first follow-up at +67.852 seconds already had the event/resource counts but still showed resource/dashboard loading; the subsequent saved search result was observed at +75.531 seconds from navigation. These are observation bounds, not an exactly instrumented request duration. The single-materialized-revision cache makes a cold node switch expected; it does not make the first link-click duration a measure of loading speed.

The largest episode, **02:22:32.261–02:24:04.269 UTC**, consumed **90.828 CPU seconds over 92.007 wall seconds**. It overlaps PE-A cold entry and the first early range submission. Further episodes around Back/re-submit (moves 46–47) and recovery (48) used **11.703 CPU / 13.009 wall seconds** and **9.594 CPU / 11.007 wall seconds**, respectively. Source and browser evidence establish native navigation/context loss before the form handler binds. The sampler has no request spans, so it cannot establish whether each server load restarted, overlapped, reused completed work, or continued after navigation. Do not count all 113.141 phase CPU seconds as avoidable reload overhead.

The intervening **P2 → fabric** window used only about **4.157 CPU seconds**, with little memory change. This and `fabric-navigation-load-review.md` do not support attributing another full default-node history load to fabric return. Its progress indicator can represent normal bounded reconstruction. The source-only first-use topology metadata dependency and the root `/health` loading behavior are separate optimization candidates; neither was invoked or demonstrated as a new repeated-navigation defect by this analysis.

## Warm route and cursor behavior

The 46 fabric/route action steps (1–33 and 88–100) have a median recorded action duration of **1.190 seconds**. The 39 warm PE-A action steps (49–87) have a median of **1.702 seconds**. These numbers include UI actions and browser automation; they are **not backend latency** and should not be compared to the old direct-service probe as if they measured the same thing.

| Move | Recorded action seconds | Navigation/action start to saved follow-up seconds | CPU in the wider measured follow-up bracket |
| --- | ---: | ---: | ---: |
| 4, exact-boundary route submission | 1.053 | 6.623 | 4.797 s |
| 51, exact service376 attachment | 1.829 | 8.074 | 7.000 s |
| 74, first-service restoration | 1.990 | 8.878 | 9.859 s |
| 84, first-neighbor restoration | 1.702 | 8.984 | 9.922 s |
| 90, CE-West → Edge-C route | 0.989 | 7.016 | 5.266 s |
| 100, seeded Edge-C → CE-East route | 0.478 | 6.705 | 6.078 s |

Follow-ups above record the relevant route/resource assertion, not necessarily the completion of every component. For example, resource follow-up snapshots can still show an asynchronous topology reconstruction. Wider CPU brackets can include the start of the next operation and can exceed their corresponding observation window; they are retained as measured context, not precise request attribution.

There are clear examples of why action time and follow-up gaps must remain separate:

- Move 7's direction/view actions lasted **7.323 seconds** while their wider server sample bracket consumed only **0.250 CPU seconds**. That is not evidence of a seven-second server computation.
- Move 2's saved route follow-up was observed **23.415 seconds** after submission started, but its wider sample bracket contained **4.250 CPU seconds**. The long observation gap cannot be reported as continuous backend latency.
- Move 49's first searched historical cursor action lasted **2.114 seconds**. Its +10.863-second follow-up still displayed loading, so it is not a valid final completion time. The nearby continuous CPU episode used **11.562 CPU seconds over 11.993 wall seconds**. The subsequent ES1 focus/check succeeded; no persistent stall was demonstrated.
- Between moves 74 and 75, the ledger has a **193.206-second tool/inspection gap**. Only **13.408 CPU seconds** accrued across that full gap, including completion of prior work. It is not a 193-second cursor stall.

Repeated warm cursor operations remain visibly expensive. The episode across VIF focus/birth/withdrawal/restoration moves 80–85 consumed **36.234 CPU seconds over 42.004 wall seconds** while the recorded state/relationship checks progressed successfully. The prior controlled v2 investigation already identified population-wide search projection at fresh timestamps and default-open dashboard state reconstruction as CPU costs. This audit has no request profiles to assign its CPU exactly to those components and no matched controlled baseline to establish a regression. It supports keeping that existing optimization target open, not adding a distinct newly diagnosed algorithmic defect.

No event-log search is recorded among these 100 moves. The previous audit's approximately 51-second cold event-index construction and later 0.660-second warm search are background context only; this run does not remeasure either cost.

## Interpretation and remaining limits

The three browser findings are correctness/interaction issues; this analysis adds **no separately confirmed performance defect**. The startup-control issue can cause unnecessary navigation during an expensive cold load, but quantifying its incremental server cost requires request-level tracing or a controlled comparison after repair. Keep the existing search/dashboard reconstruction cost and the source-only initial metadata-load candidate distinct from that functional root cause.

CPU episodes group adjacent sample intervals using a 15%-of-one-core activity threshold with gaps of at most 2.05 seconds. Group totals use the enclosing cumulative counters, including the small gaps. They show when the process worked; overlap with a move does not prove which request caused the work. Interpolated per-move CPU is an estimate, while raw brackets may include neighboring operations. This audit does not claim statistical speedup/regression, a memory bound for other workflows, or exact UI paint latency.

Documentation drift check: this is audit-only runtime analysis. No public plug-in behavior, product code, tests, skills, or maintained authoring materials were changed.
