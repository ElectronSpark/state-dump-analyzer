# Repeated lane, log, and review-marker audit — 2026-10-21

Status: both functional findings repaired and browser-validated. The original
audit is retained below, followed by the repair validation and traced search
investigation. Performance observations distinguish measurements from unproven
causes.

## Scope and environment

- Commit `65d235c700c990908124962679c359f74255eded` on
  `codex/comprehensive-router-dump-demo`.
- Live demo at `http://127.0.0.1:8883/node#overview`, server PID 34860.
- Archive `demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz`, revision
  `demo/node-a/revision-0001`: 1,250,005 normalized events, 7,510 resources,
  and 5,000 retained source records.
- Manual browser operations at a 608 × 668 CSS-pixel viewport. UI controls,
  keyboard actions, and native pointer dispatch were used; DOM reads recorded
  rendered identities, geometry, and settled state. No application state was
  injected.
- Evidence directory: `.runtime/frontend-cross-audit-2026-10-21/` (ignored).
  `records.json` contains timestamped observations and exact identities.

## RM01 — Distinct review markers overlap and pointer activation selects the wrong event

Priority: P2. Confirmed in the browser.

Reproduction:

1. In the merged event log, search for `evpn_mass_service_failover`.
2. Select the first two normalized rows with Space and Shift+ArrowDown:
   `node-a/scale-event-00500375` and `node-a/scale-event-00500376`.
3. Add browser-only review markers, then use Fit for the complete capture.
4. Activate the first review marker with Enter, dismiss its popup, then click
   the same marker's center.

The first event is at `1759680360033500000` ns and affects service 000000;
the second is at `1759680360033600000` ns and affects service 000001. Keyboard
activation opens the first event. Pointer activation opens the second, focuses
its button, and shows `etg-000001`. Their timestamps differ by 100 microseconds,
but the fixed marker footprints overlap at this zoom.

Expected: preserve exact event identity while providing a reachable marker or
an explicit shared cluster/drill-down when the available space is insufficient.
Do not silently substitute the adjacent event.

Cause: `buildAnnotationGlyphs()` in `frontend/assets/app.js:3302` clusters
groups only when there are at least three entries. `reviewMarkerLaneHtml()`
places the remaining entries directly at their timestamp positions without
the `timelineGlyphLayout()` spacing used by normalized/source marks.
`frontend/assets/styles.css:6210` gives review markers a fixed 22 px width,
with an additional hover/focus scale. Later DOM entries intercept earlier
markers. The 64-entry cluster boundary uses a similarly fixed cluster width;
that larger selection case was identified in code but not manually reproduced
and is not counted as another finding.

Evidence: `distinct-review-keyboard` and `distinct-review-pointer` records;
`distinct-review-marker-overlap.png`.

The earlier two-marker test at exactly equal timestamps is deliberately
excluded from the new-finding count. Coincident evidence was already documented
in `docs/audit-repairs-2026-10-21.md`; the reproduction above uses distinct
timestamps.

## RM02 — Review/log hover loses the known state duration and claims it lasts until capture end

Priority: P2. Confirmed for review markers and ordinary log-row hover.

Reproduction:

1. Keep the review marker for `node-a/scale-event-00500375`.
2. Set the timeline range to 360–361 seconds. Inspect the event through a
   resource lane, then through its review marker.
3. Expose `node-a/data-bridge-layer/ETE/etg-000000/backup` through the lane
   picker to compare the same affected resource explicitly.

At 19:03:41 UTC, the review popup identified **backup**, result **active**, and
duration **until capture end**. At 19:04:06 UTC, the resource-lane popup for the
same event, timestamp, backup resource, and active result correctly reported
**2m 0s**. The selected-event inspector also reported 2m 0s for that lane.
This is a false duration claim, not merely rounding or a different event.

A second exact-resource comparison confirmed the ordinary log path: at
19:07:27 UTC, the DTE0 lane popup showed 2m 0s for the same event. After jumping
to its log row and moving keyboard focus down and back up, the DTE0 log popup
showed “until capture end” at 19:08:37 UTC. The timestamp, resource, programmed
result, and next-hop state matched.

Cause: `eventLogHoverModel()` at `frontend/assets/app.js:9534` finds the loaded
occurrence lanes but then rebuilds a mark from the raw log/annotation entry at
line 9568. That raw entry lacks the per-resource
`duration_to_next_change_ns` which the backend supplies on timeline marks
(`src/router_dump_analyzer/revision_queries.py:2666`). `normalizeMark()` at
line 2315 treats absent duration as null, and `formatDuration()` at line 701
interprets null as “until capture end.” `eventHoverHtml()` then presents that
fallback as fact. Both review markers and ordinary log-row hover call this
model builder.

Expected: reuse the matching loaded mark's known duration. If duration has not
been loaded, distinguish unknown data from a proven open-ended state. Keep
the resource identity paired with its duration.

Related observation, not an additional counted bug: the popup chooses the
first loaded occurrence lane, whereas review-marker activation selects the
event's first declared affected resource. Thus one activation can show backup
or DTE details in the popup while the inspector selects ETG. Loading other
lanes can change the popup's resource context. That also makes preserving
per-resource duration essential.

Evidence: `duration-lane`, `duration-review`, `duration-backup-lane`, and
`duration-review-repeat`; `lane-duration-correct.png` and
`review-duration-mismatch.png`. Use the JSON records for the exact same-backup
comparison; subsequent screenshots may show another loaded occurrence.
The additional `duration-dte-lane` and `duration-log-popup` records, with
`dte-lane-duration-correct.png` and `log-duration-mismatch.png`, preserve the
same-DTE comparison. `audit-final.png` shows the log popup left for review.

## Performance observations

An event-text search after repeated lane/range/log operations remained blank
with “loading visible page.” It was still pending at 18:55:50 UTC; clearing
the search at 18:56:00 restored the unfiltered merged stream immediately.
The initial input time and completion were not instrumented, so this is not
reported as an exact end-to-end latency measurement.

During a passive 26.053 s sample in that interval, the server consumed
27.234 CPU seconds, approximately one busy core. The following 143.506 s
sample consumed 11.969 CPU seconds, so the work subsequently subsided.
The observed RSS rose from 3.040 GiB to about 3.123 GiB at the 18:58 checkpoint;
lifetime peak then reached 3.134 GiB. At the later 19:06:56 query checkpoint,
RSS was 3.225 GiB and lifetime peak 3.247 GiB. These process snapshots after
different operations do not establish a memory leak.

Code inspection found two relevant boundaries, neither independently proven
to account for the whole delay:

- Frontend-serving startup defers search corpus build/reopen validation until
  first search. A matching sidecar existed on disk, so the progress label alone
  does not prove a new corpus build. Concurrent searches single-flight that
  initialization.
- Browser fetches for old temporal requests are aborted, but server disconnect
  cancellation is currently installed only for density and timeline queries.
  Event-log, graph, resource, and dashboard work may continue after the browser
  abandons its response. Access logs lack request timings, so passive CPU
  samples cannot attribute work to a particular superseded request.

The previous RF04 repair already disclosed that filtered merged log requests
retain a different path from the optimized unfiltered merge. This audit does
not relabel that existing limitation as a newly confirmed regression.

Two sequential warm service queries isolated the same search from browser
rendering and active browser operations. Both requested normalized events plus
CTF sources, all layers, no time range, offset 0, and limit 120:

| Repeat | Wall time | Process CPU delta | RSS delta | Result |
| --- | ---: | ---: | ---: | --- |
| 1 | 41.7 ms | 15.6 ms | 0 | HTTP 200; 751 matches; 120 items |
| 2 | 15.7 ms | 15.6 ms | 0 | HTTP 200; 751 matches; 120 items |

The 309,592-byte response hashes matched exactly. CPU deltas have the process
counter's resolution and include any background work: the preceding quiet-log
2.037 s baseline still consumed 0.219 CPU seconds, which was not subtracted.
RSS readings are before/after snapshots, not a sampled interval peak.

Thus the prolonged browser delay was **not reproduced by warm service
queries**. The warm search resolves indexed matching ordinals and merges/sorts
matching candidates; these measurements do not support a claim that it scans
all 1.25M event payloads on each repeated term. Initial sidecar validation and
overlapping temporal work remain diagnostic leads requiring request-level
tracing before assigning the observed delay to either cause.

Evidence: `runtime-notes.md`, `runtime-*.json`,
`filtered-log-service-timings.json`, and `measure-filtered-log.ps1` in the
evidence directory. These focused probes are not a rerun of the complete 1M
memory/CPU benchmark suite.

## Repeated operations that behaved correctly

- Selected two explicit ETG roots while preserving both unmatched-source lanes.
- Selected an ETE child from a filtered resource bundle, then repeatedly
  switched Combined → Separate and preserved custom roots and disclosure state.
- Expanded related roots with duplicate canonical descendants, hid ETG9 through
  a child instance, and restored it through a resource-table checkbox. All
  copies and checkbox states reconciled.
- Zoomed to 360–361 seconds, selected a multi-effect failure, used its context
  menu to jump to the exact log row, and extended selection by keyboard.
- Hid and restored two selected events across their visible lane copies, then
  revealed them from the log. After Show marks, Reveal focused the correct
  destination marker.
- Clearing a pending text search recovered the exact unfiltered stream. A
  repeat search returned 751 matches; its initial browser observation was too
  coarse to report precise latency.

Hidden marks remaining hidden after Reveal are not counted as a defect: the UI
has a separate Show marks action. Native locator misses, a hidden context-menu
item, unhandled Shift+PageDown, and coincident equal-time marks are also excluded.
The attempted All-lanes preset showed 13 loaded roots; it did not establish a
100-root cap reproduction, so no cap-related finding is claimed.

## Original audit validation and documentation stewardship

- No browser console errors were captured during the checks; server error
  logs contained startup messages only at the sampled points.
- Conformance group inventory command passed:
  `python -B -X utf8 scripts/check_plugin_conformance.py --list`.
  This lists coverage groups; it is not an executed conformance suite.
- Product code and skills were not modified. Frontend tests and full 1M
  benchmarks were not rerun for this audit-only change.
- Plug-in documentation drift check completed: this report changes no public
  plug-in API, author command, or behavior. The maintained authoring materials
  and runnable example require no update.

## Repairs and validation

Repair evidence is in `.runtime/review-repairs-2026-10-21/` (ignored). The
baseline is the commit above; repairs remain in the working tree.

### RM01: share the existing glyph layout

`buildAnnotationGlyphs()` now groups two nearby review items. The existing
`timelineGlyphLayout()` also positions review clusters and constrains each
review glyph to its available space. CSS respects that width and no longer
expands the pointer target on hover/focus. A narrow glyph can hide its inner
count while preserving the accessible count and every drill-down identity.
The existing 64-item group bound is unchanged.

Browser checks used the original pair, events `00500375` and `00500376`, whose
timestamps differ by 100 microseconds. Native pointer and Enter activation
opened one explicit two-item cluster; both exact drill-down IDs survived.
Choosing each entry selected its corresponding event/resource. Repeated
Combined → Separate → Combined and Fit → 360–361 second range operations
preserved both IDs. The final pointer check also returned both IDs.

Evidence: `browser-records.json`, records `two-review-cluster-keyboard`,
`two-review-cluster-pointer`, `review-cluster-select-first`,
`review-cluster-select-second`, `review-cluster-separate-fit`,
`review-cluster-combined-range-repeat`, and `review-cluster-final-pointer`;
`review-cluster-final.png`. Larger cluster boundaries and zoom separation were
covered by executable tests, not claimed as additional manual reproductions.

### RM02: retain resource history and preserve unknown values

`eventLogHoverModel()` now reuses the matching loaded lane mark, including its
resource-specific operation and duration. `normalizeMark()` and
`formatDuration()` preserve three distinct facts: finite duration, explicitly
open-ended duration, and unavailable duration (`unknown`).

The first independent GPT-6.1-Sol skill trial found two related ways the old
logic could still fabricate a duration. Both were corrected in existing
functions: `deriveLaneIntervals()` now returns before inferring durations from
bounded authoritative previews, and `renderEventInspector()` no longer borrows
a duration from another resource when the selected resource's mark is absent.
Explicit zero, finite, and open-ended values remain intact.

The exact event `node-a/scale-event-00500375` and DTE resource
`node-a/data-bridge-layer/DTE/blue/dte-000000` now report **2m 0s**, operation
**modify**, result **programmed**, and the same timestamp in the lane popup,
log popup, review popup, and inspector. This includes a lane → log jump and
removing/re-adding the adjacent browser-only review marker. A direct pointer
check of unloaded event `00500003`, resource `es-00003`, reported **unknown**
and explicitly said the resource was not in the loaded lanes.

Evidence: `dte-lane-duration`, `dte-log-duration-popup`, `dte-review-duration`,
and `unloaded-log-pointer-duration` in `browser-records.json`;
`log-duration-fixed.png` and `review-duration-fixed.png`. Earlier unknown-check
attempts in that log retained a pinned popup and are not counted as successful
identity/duration checks. No browser console errors were captured.

### Search stall: separate validation, construction, and contention

The live process's effective cache root was verified from its allowlisted
environment paths. `ROUTER_DUMP_SEARCH_CACHE_DIR` was unset; Windows
`LOCALAPPDATA` selected the cache. The process's isolated TEMP/TMP directory
does not control this cache path. The matching 75,038,720-byte sidecar existed
before the original stall, with complete v7 metadata and 1,250,005 documents.
Its old last-write time rules out a successfully published replacement at that
time, but does not prove that no fallback was attempted.

Fresh-process core-service traces copied that sidecar into isolated caches and
wrapped the existing validation/build entry points. Both seeded runs opened a
valid sidecar; neither invoked corpus construction.

| Controlled request | Wall time | Search-thread CPU |
| --- | ---: | ---: |
| First search, valid sidecar, idle | 4.969 s | 4.859 s |
| Same-term warm repeat | 12.0 ms | 15.6 ms |
| First search with four concurrent temporal queries | 16.644 s | 5.750 s |
| Warm repeat after concurrent work | 11.1 ms | 15.6 ms |

The isolated validation span itself took 4.951 s; contention extended it to
16.623 s. All four search responses had the same canonical JSON hash, 751
matches, and 120 returned items. These are service timings, not browser latency;
CPU counters have finite resolution. The separate empty-cache benchmark below
measures actual construction and must not be confused with sidecar reopening.

This reproduces a substantial first-search delay from lazy validation plus
concurrent temporal work. It does not establish the entire original untraced
browser stall's duration or assign every CPU second to a request. Warm indexed
search is fast in these probes. Superseded resource/dashboard requests may
continue server work because cooperative disconnect cancellation currently
covers density/timeline routes; that remains a follow-up cancellation concern,
not proven attribution for the original stall. No speculative backend change
was made. Detailed provenance and spans are in `search-stall-diagnosis.md`,
`live-demo-cache-paths.json`, `search-seeded-alone/`, and `search-seeded-busy/`.

### Tests, skill trial, and documentation drift

- `npm run check`: **524 passed**, zero failed/skipped. The initial sandboxed
  attempt blocked localhost proxy tests with EACCES; the complete final run
  allowed local sockets and passed. Log: `frontend-final-check.log`.
- Python frontend regression guards: **63 passed**. Log:
  `frontend-python-check.log`.
- Both updated skills passed `quick_validate.py`. The conformance declaration
  inventory passed; this is not an executed behavioral conformance suite.
- Two fresh GPT-6.1-Sol trials used a short skill-led prompt and were excluded
  from prior audit reports, runtime evidence, and parent conversation. The
  initial trial exposed the two related duration gaps above. After repair, the
  final trial passed **11 independent executable checks** and **92 existing
  tests**, with no confirmed defect. The parent inspected the checks and
  independently performed browser validation. Trial limits: extracted-function
  tests do not replace browser hit testing or million-event measurements.
- Updated author and validation skills plus their linked API map document
  shared review-glyph spacing, per-resource duration provenance, and search
  attribution. Plug-in documentation drift check completed: these core UI
  repairs change no public plug-in API, schema, author command, or runnable
  example. No maintained quickstart/contract/example update was required.

### Full 1M memory and CPU rerun

The established harness was rerun against frozen baseline and final backend
snapshots, each in a fresh process with an empty search cache, fixed hash seed,
and 100 ms memory sampling. The same 286,496,584-byte archive and unchanged
52-phase workload were used. Browser operations and search traces were idle
during these runs. Both processes exited successfully with empty stderr.

| Metric | Before | After |
| --- | ---: | ---: |
| Loaded RSS | 2.355 GiB | 2.366 GiB |
| Lifetime peak RSS | 2.436 GiB | 2.444 GiB |
| Sampled navigation peak RSS | 2.372 GiB | 2.380 GiB |
| Summed phase CPU | 167.906 s | 169.016 s |
| Total supervised wall time | 180.031 s | 172.578 s |
| Empty-cache first-search wall time | 55.831 s | 49.437 s |
| Empty-cache first-search CPU | 47.766 s | 48.469 s |
| Search sidecar storage | 75,038,720 bytes | unchanged |

All **52 ordered phase occurrences**, **35 complete response/page hashes**,
phase summaries, and cache-retirement results matched. Repeated phase names
were compared by occurrence, not collapsed into a dictionary. The parent also
compared the raw ordered phase-result dictionaries independently.

Backend source was substantively unchanged; these small memory/CPU differences
and wall-time variation do not demonstrate a frontend performance improvement
or regression. This measures server work, not browser rendering or browser heap.
The OS file cache was not cleared. Navigation sampling covers release of A,
load of B, return to A, and returned-A searches; its sampled peak is distinct
from the child's lifetime peak. Do not compare either with the original
long-running live server's 3.247 GiB historical peak as a controlled before/after.

Provenance and results: `provenance.json`, `source-diff.json`,
`measurement-report.json`, `summary.json`, `comparison.json`, `before-1/`, and
`after-1/` in the repair evidence directory.
