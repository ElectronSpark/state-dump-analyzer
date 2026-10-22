# Repeated lane and cross-component audit — 2026-10-22 UTC

Status: FP01–FP03 repaired and browser-validated in the follow-up below. FP04 and
the repeated temporal-topology history scans were subsequently repaired and
validated in [the follow-up report](frontend-topology-scan-repairs-2026-10-22.md).
The original observations below describe the pre-repair version; the preceding
LR01/LR02 fixes remain in place.

## Environment and method

- Commit `4a1d8728387e3ac1956875bdbe5e7c2d13fa3de5`, branch
  `codex/comprehensive-router-dump-demo`.
- Existing demo: `http://127.0.0.1:8883/node#overview`, PID 34860.
- Archive `demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz`, revision
  `demo/node-a/revision-0001`: 1,250,005 normalized events, 7,510 resources,
  and 5,000 retained source records.
- Browser viewport 608 × 668 CSS pixels. Actions used actual pointer/keyboard
  controls; observations used read-only DOM geometry, text, identity and hit
  testing. No application-state injection, response delay or product patch.
- Observations started at 03:29 UTC on October 22 (October 21 locally).
  Evidence is retained under `.runtime/frontend-followup-2026-10-22/`.
- The router-plugin-validate skill and its frontend validation map guided the
  audit. A read-only agent suggested additional scenarios and checked source
  causes; the parent performed the browser reproductions. A separate observer
  sampled the existing server without issuing requests.

## FP01 — A pinned timeline popup intercepts the lane picker

Priority: P2. Confirmed pointer hit-test failure, with keyboard control.

1. Use Separate layout and range 360–361. Enable Unmatched external,
   Unmatched CTF and EVPN ES source presets.
2. Pin the EVPN instance of `source-ctf-unmatched-000502` at +360.200 s.
3. Open Lanes. Filter resources to `etg-000020` so the source preset controls
   appear below the short resource list.
4. Try to uncheck Unmatched CTF with the pointer.

The checkbox remains checked: the older pinned popup is above the newly opened
picker. At the failed interaction, the checkbox rectangle was
`(216.5, 319.71, 13, 13)` and its center hit a `<dd>` inside `#timeline-hover`,
not the checkbox. The popup covered `(96.6, 218.64)` through `(486.6, 449.04)`.
Pressing Space on the checkbox successfully changed it, proving the underlying
lane operation was available.

Expected: opening the lane picker makes its controls usable, without a previous
inspection card intercepting them.

Source cause: the picker toggle at `frontend/assets/app.js:12464` opens/focuses
the picker without dismissing a pinned hover. `scheduleHoverClose()` preserves
pinned cards. In `frontend/assets/styles.css`, the timeline card uses fixed
positioning and z-index 200 (`:3487`); the picker uses z-index 40 (`:2695`).
This is a new picker interaction, distinct from previously repaired log-jump
and correlation-hover interception paths.

Evidence: `records.json` (`picker-pointer-intercept`),
`popup-over-lane-picker.png`. The automation's failed checkbox assertion was
followed by screenshot and independent DOM hit testing; it is not counted as
a product bug solely because an automation action failed.

## FP02 — Timeline rerenders leave pinned popup geometry and ownership stale

Priority: P2. Confirmed movement and removed-anchor variants.

Continue FP01 using the keyboard to change source presets:

1. Uncheck the preceding Unmatched CTF lane while the EVPN popup is open.
2. Wait for the asynchronous source-lane response and settled render.
3. Restore the preceding preset; then disable EVPN ES, the popup's own lane.
4. Wait again without scrolling.

The live EVPN marker moved upward by **50.8 pixels**, from top 457.64 to
406.84. Both observations had document scrollY 1787.20 and timeline scrollTop
zero. The popup stayed at top **218.64** instead of following the layout change.
After disabling EVPN ES, its marker was absent but the popup remained visible,
still showing `evpn_es_telemetry`. Later scrolling can repair placement or close
the orphan; it does not make the settled no-scroll state correct.

Expected: after a timeline render, an open card stays aligned to its current
instance, or closes when that instance no longer exists.

Source cause: `setRecordLanePreset()` (`app.js:8042`) calls
`refreshRecordLanes()` (`:8037`), which replaces timeline DOM through
`renderTimeline()` (`:3435`). That render does not reconcile the existing card.
`positionHover()` currently runs on open, scroll and resize only. LR01 fixed
anchor replacement during activation; LR02 fixed movement caused by scrolling.
Neither covered movement/removal caused by a later, stationary timeline render.

Evidence: `records.json` entries `after-keyboard-remove-preceding-lane`,
`settled-after-preceding-lane-removed` and `settled-own-source-lane-removed`;
`orphan-popup-after-source-disable.png`. The screenshot after closing the picker
is supporting context only: closing caused additional focus scrolling and can
correct geometry, so the unchanged-scroll DOM records establish the drift.
A later CTF-lane removal did close its card while focus scrolling occurred;
the defect is conditional on the render not being followed by a positioning
event, rather than every preset removal failing.

## FP03 — Open cluster cards retain obsolete selected-range facts

Priority: P2. Confirmed Apply and Clear paths for source clusters.

1. With selected range 360–361, click Fit.
2. Open the CTF cluster beginning at `source-ctf-unmatched-000001`:
   36 records from +120.100 to +123.600 seconds.
3. Enter start 120 and end 124, then click **Apply range** (not Apply and zoom).
4. Compare the existing popup with closing/reopening the same cluster.
5. With that reopened card still visible, click **Clear range**.

After Apply, the timeline cluster correctly reports **36 of 36** in the range,
but the open popup still has zero “in selected range” labels. Reopening adds
all 36 labels. Clearing the range then removes membership from the timeline
glyph and empties both range inputs, while all **36** popup labels remain.

Expected: visible range membership stays consistent across timeline and detail
card after Apply and Clear, without losing detail scroll/focus or loaded pages.

Source cause: `applyRangeEditor()` (`app.js:5211`) and
`clearRangeSelection()` (`:5357`) use `updateRangeBands()` (`:4135`). Its
`applyRangeHighlight()` updates timeline marks, but not the open cluster's
derived classes/text. `sourceClusterHoverHtml()` (`:4977`) computes those facts
only when the card is built. The normalized cluster renderer (`:4840`) has the
same dependency, but that sibling is a code-supported hypothesis, not an
additional browser-confirmed finding.

This is distinct from the previously repaired bounded-preview count issue:
the glyph count is correct here, and reopening the card hides this defect.

Evidence: `cluster-range-before-after.json`, `records.json`
(`cleared-range-card-still-36-selected-labels`),
`cluster-range-reopened.png`, `cluster-range-cleared-stale.png`.
A fresh Apply 120–124 → open → Clear repeat again retained all 36 stale labels;
see `repeat-cleared-range-card-stale` and `final-range-cleared-stale.png`.

## Other repeated and composed operations

The following checks did not establish new functional failures:

- None → custom ETG20 selection; resource-table search/selection; Combined ↔
  Separate transitions. Combined follows the selected resource, not merely a
  checked Separate root; this existing distinction was not reported as a bug.
- Four forward pans followed by four Back actions. The status interval popup
  closed during navigation, preventing the hypothesized reuse of a positional
  interval key from leaving a visible card with the old interval's facts.
- ETG20 failure event `node-a/scale-event-00500395` → context Reveal in normalized
  log → Space selection → Hide marks → Reveal in timeline. The event was restored
  and focused; the aggregate event's DTE20 occurrence was selected as expected.
- Hide DTE20 using its event context menu, then Reveal from the selected log row:
  the lane returned while the explicit ETG20 root remained.
- Log End reached `node-a/scale-event-01249999`, display index 1,250,004 in the
  normalized-only stream. A reveal superseded by Combined/Back/Separate did not
  later steal the view. Retrying loaded DTE249 and focused the cluster containing
  the exact destination, retaining the previous custom roots.
- DTE249 expansion revealed its IP-routing child. Pinning the child's status
  and collapsing the parent closed the card in this run; focus scrolling occurred,
  so this is not evidence that the no-scroll removal case is handled.
- Browser console collection contained no warnings or errors. No durable review
  data, import, publication or external service operation was performed.

## Performance lead — Sustained refresh work after repeated navigation

Not yet assigned a root cause or counted as a fourth confirmed functional bug.

During repeated distant reveal, layout changes and retry, passive process samples
over **03:36:31–03:37:31 UTC** measured **60.359 CPU seconds / 60.153 wall
seconds**, approximately one fully occupied logical core. RSS stayed within
**3.261–3.270 GiB**, ending 6.31 MiB lower; the pre-existing lifetime peak stayed
**3.441 GiB**. Error-log size did not change. A browser screenshot during the
sequence showed pending load work.

The sampled access-log segment through 03:38:33 contained 213 successful
responses: 207 analysis-load polls and one each for timeline, event detail,
graph, topology, resources and dashboards. Between 03:36:41 and 03:37:31 only
poll completions were appended while CPU remained near one core. Access-log
growth finally stopped at **03:38:12.221**.

With browser actions paused, the next 30.074-second observation consumed only
**0.922 CPU seconds**, with exactly stable RSS (3.259 GiB) and no log growth.
This disproves a continuous idle CPU loop in the observed state.

A cleaner follow-up changed only the cursor from +624.999 to +360.200 using
Enter on CTF source 502 at **03:40:29.208 UTC**, after preparing the zoom window.
At +147 ms, resources were busy and dashboards correctly said they were updating.
Access-log activity ended at **03:40:34.284**, about 5.076 seconds after the action;
the first two sampling intervals used 5.516 CPU seconds. A DOM observation at
+14.452 seconds confirmed both resources and dashboards settled at the new time.
This is a response-activity bound, not a precisely instrumented browser latency.
The target time had been visited before, so this was not a cold-cache test.
The remaining 70.090 seconds of passive sampling consumed 2.250 CPU seconds,
with no further log growth. The full scenario's RSS changed by +1.85 MiB and
the lifetime peak was unchanged.

The long sequence merits attribution of superseded/overlapping temporal refresh
work versus an expensive first query at the later time. Process-wide CPU and
untimestamped Uvicorn completion lines cannot identify the responsible endpoint
or prove that cancellation failed. No memory leak or new storage regression is
claimed. These observations are not a replacement for the separate 1M service
benchmark and do not measure browser heap or rendering CPU.

Code-supported profiling targets, not established causes: cursor updates fan out
to graph/resources/dashboards after a 100 ms debounce and separately to follow-
cursor topology. Frontend fetch cancellation is present. The backend disconnect
cancellation scope in `src/router_dump_analyzer/web/runtime_api.py:397` covers
timeline and density handlers; it does not cover those other temporal queries.
Dashboard evaluation also materializes temporal rows across the relevant resource
population. Profile superseded work and repeated temporal projection before
choosing an optimization. The analysis-load poll itself reads the progress
tracker; its frequency alone does not implicate it as the CPU bottleneck.

Artifacts: `process-observation.json`, `process-idle-observation.json`,
`access-log-observation.json`, `access-log-observed-segment.txt`,
`scenario-process-observation.json`, `single-cursor-refresh.json`,
`idle-pending-view.json`.

## Original audit checks and documentation stewardship

The configured Python environment passed
`python -B -X utf8 scripts/check_plugin_conformance.py --list` (declaration
inventory only). This audit changed no executable code, so frontend/backend
test suites and the full 1M benchmark were not rerun. The previous commit's
validation remains recorded in the preceding repair report.

Plug-in documentation drift check completed: this change records observations
only and changes no public plug-in boundary, author command or runnable example.
No maintained authoring-document or skill update was required. The unrelated
fixture lock was left untouched.

## Repair and browser validation — 2026-10-22 UTC

The follow-up changes existing frontend paths only; no backend, CSS, cache,
new state variable or new product function was introduced:

- **FP01:** the existing picker-opening handler calls `closeHover()` before
  focusing its filter. This retires both pending timers and pinned ownership.
- **FP02:** `renderTimeline()` calls the existing `positionHover()` after
  rebuilding lanes and restoring focus. That function resolves the current
  instance and closes the card when its anchor has disappeared.
- **FP03:** the existing range-highlight pass updates displayed cluster rows
  from their own timestamp metadata. Their range suffix is isolated from the
  semantic label, so the existing card, loaded detail and controls remain intact.
  Range changes also reconcile card placement. Source and normalized cards
  retain their existing, different outside-range label conventions.

The parent reloaded the actual 8883 demo and used pointer/keyboard controls.
Evidence is under `.runtime/popup-state-repairs-2026-10-22/browser/`:

- Pin EVPN source 502 → open Lanes → pointer-uncheck CTF: the card is hidden
  and the checkbox changes. Keyboard activation of Lanes after a normalized
  cluster also dismisses the card and focuses the filter.
- With the picker already open and the EVPN card pinned, remove a preceding
  external lane. The anchor moves from **406.841 to 356.041 px** and card top
  from **430.975 to 380.175 px**. Document scrollY remains **1787.200**, nested
  timeline scrollTop remains zero. Removing EVPN then removes the anchor and
  hides the card. Restoring a source preset appends it after existing presets;
  it need not move a preceding anchor. Intermediate records are retained rather
  than misreported as settled layout evidence.
- The already-open 36-row CTF cluster changes from zero selected labels to
  **36** for Apply 120–124, **zero** for Clear, **11** for inclusive 121–122,
  and **zero** for a second Clear. Once PageDown settles, its detail scrollTop
  remains **271.200 px** through the latter changes.
- A hydrated 14-row normalized cluster has **8 in-range / 6 outside** for
  360–361, zero suffixes on Clear, **14 outside** for disjoint 120–124, then
  zero suffixes on another Clear. All 14 rows and detail scrollTop **271.200**
  remain. The real cluster fits in one detail page; retained multi-page metadata
  is covered by the executable harness, not claimed as a browser check.
- Two Later/Back cycles at narrow zoom return to the source-502 interval;
  Enter activation still opens the correct source card after focus scrolling.
  Later is correctly disabled at full Fit, so that disabled action is not a bug.
- Browser warnings/errors: **zero**. Final resource/dashboard refresh is settled
  at +360.200s before the isolated performance runs.

`records.json` contains timestamps, actual rectangles, focus, selected inputs,
label lists and scroll values. Screenshots include
`source-cluster-clear-retains-scroll.png`, `normalized-cluster-clear.png` and
`final-source-popup.png`. The browser deliberately moves focus to Apply/Clear
when those controls are used; the no-replacement/focus-preservation invariant
inside the range updater is separately exercised by the regression harness.

## FP04 — Off-screen pinned anchor can cover the picker trigger

Priority: P2, newly observed during the initial repair validation; subsequently
**repaired and browser-validated** in the
[follow-up](frontend-topology-scan-repairs-2026-10-22.md). The description below
preserves the original reproduction.
This is separate from FP01: FP01 concerns an already-open picker underneath an
old card. FP04 prevents the opening click from reaching the picker at all.

After the normalized-cluster Apply/Clear sequence above, click Lanes while the
cluster remains pinned. At the failed click, the trigger rectangle is
`(296.700, 318.313, 138.288, 32)`, its center hits the popup's `hover-heading`,
and the picker remains hidden. The popup occupies `(206, 329.313)` through
`(596, 693.212)`; its anchor is below the viewport at y=701.313–728.313 while
the viewport height is 668. Enter on the same Lanes button opens the picker,
closes the card and focuses the filter.

The unchanged `positionHover()` checks whether the anchor is connected, but
does not check visibility within the document and nested scrollport. Its
below/above calculation also permits off-screen card coordinates. The existing
high stacking order can then obstruct unrelated controls. A future repair should
define behavior for fully clipped anchors and use the existing viewport/scroll
bounds, rather than bypassing hit testing or raising the picker z-index.
Evidence: `picker-trigger-overlap-observation.png` and the recorded keyboard
control `picker-keyboard-repeat-dismisses-popup`. This finding is not counted
as a regression introduced by the three repairs.

## CPU investigation result

A fresh-process sequential diagnostic calls the real production endpoints with
runtime and revision scope, including provider acquisition and core identity
checks. It excludes ASGI parsing/serialization, network and browser rendering.
The topology request matches the audited projection, layer, time basis, limits
and change window. The searched-resource diagnostic used limit 160, whereas
the UI uses 500; it returned four items in one bundle. That workload difference
is retained as a limit rather than described as an exact UI reproduction.

| Endpoint | +360.200s wall / CPU | +624.999s wall / CPU | Identical late repeat wall / CPU |
| --- | ---: | ---: | ---: |
| Graph | 0.034 / 0.031s | 0.303 / 0.313s | 0.302 / 0.281s |
| Searched resources | 6.357 / 6.266s | 1.899 / 1.859s | 1.863 / 1.828s |
| Visible dashboards | 2.119 / 2.125s | 1.227 / 1.203s | 1.221 / 1.141s |
| Topology | 1.123 / 1.047s | 19.700 / 19.438s | 19.982 / 19.578s |

All identical repeated responses have matching full hashes. The late topology
cost is therefore repeatable, not just initial projection or a first cache miss.
A separate cProfile run attributes **65.575 / 66.625 profiled seconds (98.4%)**
to `_relationship_views()`: **104** calls to `_relationship_candidates()`,
**14,247,432** interval checks and **28,103,678** decimal timestamp parses.
Provider acquisition takes only **1.54 ms**. Profile overhead is substantial;
the unprofiled ~19.6 CPU seconds is the latency evidence.

Root cause: the query collects relationship transition probes throughout the
clock-uncertainty window, then rescans selected endpoint histories for each
probe. The visible 80-row result limit does not bound this intermediate work.
The next algorithmic improvement is a request-local interval sweep/coverage
calculation, preserving half-open intervals, clock uncertainty, tri-state
presence, overlap ordering and the center-or-first representative. It does not
require a new persistent cache or a change to the plug-in boundary.

A separate synthetic ASGI barrier using the production route wrapper confirms
that timeline/density receive a disconnect probe; graph/resources/dashboards/
topology do not. This permits superseded work to continue. It does not establish
how many real requests overlapped in the earlier audit or assign all of its
60-second sample to topology. Extending the existing cancellation scope would
also need cooperative checkpoints in the long loops. Neither backend change
is included in this frontend repair; the request here was to investigate the
CPU spike. No idle loop or memory leak was demonstrated.

Parent review inspected the production loop, raw profile and disconnect results.
Full scripts, hashes, request selections, unprofiled timings and pstats are under
`.runtime/popup-state-repairs-2026-10-22/cpu-investigation/`.

## Fresh 1M memory and CPU measurements

Serial fresh-process runs used the same archive and configured Python, separate
empty search caches, `PYTHONHASHSEED=0`, and 100 ms memory sampling. The preserved
harness contains **52 ordered phase occurrences / 49 distinct names**, including
search, normalized/source/merged log probes and A→B→A navigation. Before source
was frozen at 04:09 UTC before implementation; after source was frozen at 04:23
UTC and verified unchanged. The browser server was idle, with no access-log
growth across the measurement observation windows.
The existing server still consumed 7.188 CPU seconds over the wider 234.314-second
before observation and 4.391 over the 189.402-second after observation. Its RSS
was unchanged. Thus the browser was inactive, not the entire host CPU-idle;
reported benchmark CPU and memory belong only to the measured child.

| Metric | Before | After |
| --- | ---: | ---: |
| Node A loaded RSS | 2.353035 GiB | 2.353401 GiB |
| Navigation sampled peak RSS | 2.367676 GiB | 2.367878 GiB |
| Overall OS lifetime peak RSS | 2.431374 GiB | 2.432217 GiB |
| All 52 measured phases, CPU | 168.453125 s | 168.453125 s |
| Supervised run wall time | 173.359 s | 172.093 s |
| Cold load CPU | 27.718750 s | 27.640625 s |
| First search CPU | 48.312500 s | 48.093750 s |
| Return-to-A load CPU | 27.875000 s | 28.343750 s |
| Returned search-sidecar CPU | 0.109375 s | 0.125000 s |
| Final RSS after release/GC | 0.166553 GiB | 0.164871 GiB |

Both runs exited zero, without a memory guard. All **52 ordered result summaries**
and **35 complete response hashes** match. Parent verification independently read ordered raw results,
checked both 399-file frozen trees against their hashes and the final working
tree, confirmed **323 byte-identical backend files**, and rehashed the archive.
Only `app.js` and its focused test differ among executable/frontend snapshot
files. The exact equal CPU totals are the sum of individually measured phases;
individual phase timings vary between runs.

These are fresh service-process measurements, not browser heap or the existing
server's multi-hour retained memory. OS file cache was not cleared. Query timers
exclude response-summary hashing, HTTP and browser rendering. Navigation peak
is sampled RSS; overall peak is the OS process lifetime peak. The unchanged
backend means this single pair is a regression check, not evidence of a service
speedup from frontend changes. It also does not include the separate late-cursor
topology diagnostic above.

Raw outputs, phase comparisons, snapshot/archive provenance and the parent's
independent `parent-verification.json` are in
`.runtime/popup-state-repairs-2026-10-22/`.

## Follow-up checks and skill validation

- `npm run check`: **543 passed**, zero failures/skips. Four new regressions
  invoke the actual picker handler, timeline render and Apply/Clear paths with
  bounded DOM doubles. They cover repeated anchor movement/removal, source and
  hydrated normalized detail, inclusive bounds and retained row/page state.
- Configured Conda Python, `-B -X utf8 -m unittest
  tests.test_scale_history_frontend tests.test_frontend_audit_regressions -v`:
  **63 passed**. Logs are in the current runtime directory's `tests/` folder.
- Both repository skills were updated and pass `quick_validate.py`.
  `check_plugin_conformance.py --list` passes as a declaration inventory.
- A fresh GPT-6.1-Sol trial used a short prompt directing it to the validator
  skill, linked map, current code and tests; prior audits and other outputs were
  excluded. Its initial checks passed three cases and failed one by inventing
  source/normalized outside-label symmetry. Parent review rejected that
  unsupported expectation. The agent preserved the initial artifacts and added
  a corrected comparison against each stream's own renderer: **4 passed**.
  That reassessment was coached, not an independent fresh success. Its existing
  focused run passed **24 tests**. Exact prompt, skill hash, checks and evidence
  limits are retained in `skill-trial/`.
- The validation map now explicitly distinguishes each stream's presentation
  convention and explains how to attribute cursor-refresh CPU independently of
  polling and frontend aborts.

Plug-in documentation drift check completed: these generic frontend repairs
change no public plug-in API, semantic ownership, author command or runnable
example. No quickstart, normative contract or example update was required. The
unrelated fixture lock remains untouched. No commit or push was requested for
this repair.
