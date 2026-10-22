# Repeated resource-lane and cross-component audit — 2026-10-21

Status: LR01's two detached-anchor activation paths and LR02's focus-scroll
positioning defect are repaired and browser validated. The original observations
and subsequent repair/measurement results are preserved below.

## Environment and evidence

- Commit `f72b877a8f07e5e56ee0033a6db8b523d9f412b1`, branch
  `codex/comprehensive-router-dump-demo`.
- Existing demo at `http://127.0.0.1:8883/node#overview`, PID 34860.
- Archive `demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz`, revision
  `demo/node-a/revision-0001`: 1,250,005 normalized events, 7,510 resources,
  and 5,000 source records.
- Browser viewport: 608 × 668 CSS pixels. Native pointer dispatch and keyboard
  input through UI controls; read-only DOM observations recorded exact IDs and
  geometry. No application state injection or artificial response delays.
- Evidence: `.runtime/frontend-lane-repeat-audit-2026-10-21/` (ignored), with
  timestamped `records.json`, screenshots, and process counter samples.
  Browser records span 2026-10-21T23:48–23:59Z; passive sampling ends at
  2026-10-22T00:00:22Z (still October 21 in the local timezone).
- The restricted process view initially hid PID 34860. An attempted second
  launch failed to bind the occupied port; an elevated read-only listener check
  confirmed the original server. The existing page was reloaded. The bind
  failure is an audit-environment issue, not an application finding.

## LR01 — Popup placement uses a detached marker after selection rerenders the timeline

Priority: P2. Confirmed in the browser, including repeated reproductions.

Expected: details stay anchored to the actual marker that was activated, across
pointer and keyboard input. Selection may replace timeline DOM, but the popup
must use the corresponding replacement element.

### A. Keyboard activation of a source-record diamond

1. Apply and zoom to the 360–361 second range with the Unmatched CTF source
   preset enabled.
2. Click source `source-ctf-unmatched-000501` (`ctf_clock_pulse`).
3. Close its popup, then activate the same diamond with Enter.
4. Repeat with `source-ctf-unmatched-000502` after disabling and re-enabling the
   Unmatched CTF preset; use Space for this repeat.

The pointer control opens the card beside the marker: marker center about
`(337.6, 334.3)`, popup top-left `(142.6, 351.4)`. Enter on the same marker opens
the same record at **`(12, 10)`**, detached from its timeline location. The
second UID and Space activation reproduce **`(12, 10)`** while the actual
marker remains around `(396.4, 333.9)`. Record identity is correct; popup
placement is wrong and covers unrelated page controls.

Cause: the source-mark click handler at `frontend/assets/app.js:3692` calls
`selectSourceRecord()` at line 3700, which calls `renderTimeline()` at line
4410. `content.innerHTML` at line 3466 replaces the button. The handler then
passes the old `mark` to `showHover()` at line 3701. Its detached rectangle is
zero; the popup's edge clamps produce `(12, 10)`. The native pointer path in
`activateShortGestureTarget()` already reacquires the source-lane-specific
replacement, explaining the working control.

Evidence records: `source-pointer-anchor`, `source-keyboard-anchor`,
`source-keyboard-anchor-after-preset-toggle`. Screenshots:
`source-pointer-anchor.png` and `source-keyboard-anchor.png`.

### B. Pointer activation of a single normalized review marker

1. Select ETG20 from the resource table and inspect its failure event
   `node-a/scale-event-00500395` at `1759680360035500000` ns.
2. Use the event's context action to reveal its log row. Clear the previous
   row selection, select this row, and add one browser-only review marker.
3. Click the single star, close its popup, and activate the star with Enter.
4. Repeat pointer activation after Combined/Separate changes and hiding the
   selected Combined root.

The native pointer path places the popup at **`(12, 10)`**, although the star
is at roughly `(302.0, 334.1)`. Enter on that same star correctly places the
popup beside it at `(107.0, 355.1)`. The later pointer repeat again yields
`(12, 10)`. Event UID, timestamp, backup resource, active status, and **2m 0s**
duration remain correct. This is not a recurrence of the fixed review-marker
overlap or duration-loss findings.

Cause: pointer target classification retains `data-event-uid` but loses the
review-marker kind. `activateShortGestureTarget()` at line 3945 selects the
event, then searches only `.event-mark[data-event-uid]` for a replacement with
the original resource ID. A review marker has no lane resource ID. The search
cannot reacquire its replacement and falls back to the detached original
element at line 3953. The review-specific keyboard handler already finds the
replacement review button. Two-item review clusters do not use this
selection/rerender path, so the previous cluster tests did not cover it.

Evidence records: `review-single-pointer-anchor`,
`review-single-keyboard-anchor`, `review-single-pointer-after-hide-layout`.
Screenshots: `review-single-pointer-anchor.png`,
`review-single-pointer-final.png`.

These are grouped as one finding because both lose a live anchor across the
same timeline replacement boundary. Each affected input path needs coverage.
Source review stars may have a related pointer replacement mismatch, but that
variant was not browser-tested and is not counted as confirmed.

## Repeated operations that behaved correctly

- Source diamond → Ctrl-click to exact source log row → Space selection →
  Reveal in timeline preserved `source-ctf-unmatched-000502` and brought the
  destination diamond into the viewport.
- Removing and restoring Unmatched CTF retained the correct record identity.
- Enabling overlapping Unmatched CTF and EVPN ES presets created two instances
  of the same source UID. Clicking the later EVPN instance preserved its
  `source-record:plugin-evpn-es-signals:...` focus key and popup placement.
- None → explicitly choosing ETG20 and its backup → Combined → selecting ETG20
  in the resource table → Separate preserved custom roots and selected focus.
- Event context → merged log → End found event `01249999` at display index
  1,252,504. Reveal loaded DTE249, moved to the +624.4–625.5 second viewport,
  and focused its exact event marker within the visible track.
- Back → Forward → Separate retained the distant event and added DTE249
  alongside the two custom ETG20/backup roots. The resource search remained
  `etg-000020`.
- Hiding DTE249 removed its visible root; End → Reveal from the log restored
  it without losing the custom roots. Closing the selected Combined root
  correctly left zero combined resource lanes while retaining source lanes.
- Repeated End/Home returned the correct group boundary. With range 360–361,
  **Selected period** legitimately starts with event `00500000` at display
  index zero while the total includes outside records. Clearing the range
  restored the capture's first source/event records at +30 seconds.

## Exclusions and performance observations

The Combined lane badge counts the selected resource and its association lane;
it does not count checked Separate roots. Thus selecting canonical checkboxes
without changing the selected resource does not move Combined focus. This
documented behavior and selected-period-first log ordering are excluded from
new findings. Early record names such as `separate-custom-to-combined` and
`home-first-page-settled` capture investigations, not confirmed bugs.

A loading banner seen during an intermediate screenshot settled to
`hidden`, `data-state="ready"`, `aria-busy="false"`, and zero geometry. No
stuck-loading finding is claimed. Read-only console checks captured no errors;
the original server's error log contained its startup messages only.

The first distant reveal was still pending at the first observation and correct
at the subsequent observation. Tool observation timings include dispatch and
snapshot overhead and do not establish an exact request latency. No new search
stall or new request-level performance defect was isolated in this pass.

Passive counters for the existing long-lived server:

| Checkpoint | RSS | Lifetime peak RSS |
| --- | ---: | ---: |
| 23:53:30Z, during this audit | 3.243 GiB | 3.262 GiB |
| 00:00:22Z, final passive sample | 3.227 GiB | 3.268 GiB |

After final UI activity, the first 5.040 s passive interval consumed 3.188 CPU
seconds and the access log grew, so background request work was still settling.
The next 5.021 s consumed 0.156 CPU seconds, with no access-log growth and
unchanged RSS. These process-wide samples do not attribute work to particular
requests and do not establish a leak. The existing lazy-search validation and
superseded-request cancellation concerns remain as documented in
`frontend-review-marker-audit-2026-10-21.md`; they are not counted again here.

This was a live browser audit, not another fresh-process 1M benchmark. Evidence:
`process-before.json`, `process-settled.json`. No controlled memory/CPU change
is claimed from these long-running process snapshots.

## Original audit validation and documentation stewardship

- Used `router-plugin-validate` and its frontend state/recovery guidance.
- Conformance inventory passed:
  `python -B -X utf8 scripts/check_plugin_conformance.py --list`.
  Inventory listing is not behavioral conformance coverage.
- A read-only subagent identified candidate paths and checked the related
  existing logic; the parent independently reproduced findings in the browser.
- Product files and skills were unchanged. Frontend tests and full 1M
  measurements were not rerun for this audit-only report.
- Plug-in documentation drift check completed: the report changes no public
  plug-in behavior, API, schema, author command, or example. No maintained
  authoring-material update was required. The pre-existing fixture lock was
  left untouched.

## LR01 repair and validation

The existing hover key already identifies the specific resource/tree/source
instance or review marker. Source keyboard activation now captures that key
before selection and resolves its live replacement afterward. Pointer activation
uses the same lookup for every marker kind, replacing five duplicated branches
that could mistake a review star for a resource-lane event. Neither path falls
back to detached DOM. Normalized and review button handlers also skip opening
when selection removes their target. Product JavaScript is 23 lines shorter;
there is no new state, helper, cache, API, or backend behavior.

The parent reloaded the working-tree frontend in the existing 1M demo and used
real pointer and keyboard actions at 608 × 668 CSS pixels. Evidence is in
`.runtime/popup-anchor-repairs-2026-10-21/browser-evidence.json`, with screenshots
in that directory. Key checks:

| Browser operation | Observed result |
| --- | --- |
| Source 501 pointer → Close → Enter | Both place the popup at `(142.6, 351.4)`, beside the diamond centered at `(337.6, 334.3)`; correct record and timestamp |
| Source 502 pointer → Close → Space with stationary viewport | Both place the popup at `(195.0, 351.4)` beside the live diamond |
| CTF preset off/on; overlapping EVPN preset | Correct source UID and instance key preserved; later EVPN instance pointer and Enter both use `(201.4, 351.0)` |
| Source Ctrl-click → log → Space → Add review marker → Reveal | Exact source row selected; source star pointer and Space both use `(201.4, 354.7)` |
| Normalized event pointer and Space | Correct event, ETG occurrence and finite `0.112 s` duration after the page settles |
| Single normalized review star pointer → Enter → Separate/Combined → pointer → Space | Popup remains beside the star at `(107.0, 355.1)`, never `(12, 10)` |
| Fit capture; review, source and normalized clusters | Pointer and keyboard open the same cluster contents and coordinates; tall cards legitimately clamp vertically at `y=12` |

The source and normalized cross-component jumps were verified after their
asynchronous log rows arrived. An initial row action preceded completion and
found no matching DOM row; the later observation and selection succeeded. This
is not evidence of an incorrect destination or a measured request latency.
Console capture contains no warnings or errors.

Executable validation:

- `cd frontend; npm run check`: **535 passed**, zero failures/skips, including
  11 new regressions for repeated replacement, competing instances, removed
  anchors and retained Ctrl-click navigation.
- `python -B -X utf8 -m unittest tests.test_scale_history_frontend
  tests.test_frontend_audit_regressions -v`: **63 passed**.
- Both author and validator skills passed `quick_validate.py`.
- A fresh GPT-6.1-Sol agent received a short task to use the validator skill,
  with access to linked contracts/current code/tests and no parent audit or
  runtime evidence. Its first trial exposed detached fallbacks in the other
  button handlers; those were removed. A second fresh trial passed **28 own
  checks**, **11 selected existing regressions**, and the conformance inventory.
  The parent read the executable checks and results. These use extracted real
  helpers/installed click callbacks with DOM doubles; native dispatch, scrolling
  and geometry are established by the parent's browser checks above, not by the
  synthetic trial. Missing-anchor behavior is unit-tested, not claimed as a
  reproduced browser removal flow.

The author and validator skills and their linked frontend validation map now
require live instance-specific anchors and comparisons of individual pointer,
Enter and Space activation, including duplicate source presets. Plug-in
documentation drift check completed: no discovery, manifest, parser, identity,
provider, schema, author command or runnable-example contract changed. The
maintained author quickstart, contract and example need no update.

### Fresh-process 1M memory and CPU measurements

The unchanged established harness ran against frozen baseline `f72b877` and
the working-tree backend, with a fresh child and empty search cache per run,
hash seed zero and 100 ms memory sampling. The same 286,496,584-byte archive
was used. Browser activity stopped before the after run; a passive precheck
waited for outstanding requests to finish. The OS file cache was not cleared.

| Child-process metric | Before | After |
| --- | ---: | ---: |
| Loaded RSS | 2.355 GiB | 2.352 GiB |
| Navigation sampled peak RSS | 2.369 GiB | 2.368 GiB |
| Whole-run lifetime peak RSS | 2.434 GiB | 2.431 GiB |
| Sum of phase CPU time | 166.063 s | 168.344 s |
| Supervised wall time | 175.984 s | 172.078 s |
| Cold-search wall / CPU | 52.083 / 47.719 s | 49.409 / 48.688 s |
| Search sidecar | 75,038,720 bytes | 75,038,720 bytes |

Both runs exited zero with empty stderr and no guard termination. The parent
independently compared all **52 ordered phase occurrences**, including repeated
names, all phase result summaries, and **35 full response hashes**: all match.
All 323 frozen backend/input source files match after CRLF normalization;
296 have only Git-archive versus working-tree line-ending differences.

These are single-run backend measurements, not browser heap/rendering timings.
No backend logic changed. The 1.4% CPU increase and small RSS/wall differences
do not establish a regression or improvement. The live server's access log did
not grow during the after-run observation window, though it consumed 6.016 CPU
seconds over the wider preparation/measurement interval; the host was not
exclusive. Navigation peak covers release A, switch to B, return to A and its
searches; lifetime peak covers the whole child workload.

Raw artifacts are under `.runtime/popup-anchor-repairs-2026-10-21/`:
`before-1/result.json`, `after-1/result.json`, `comparison.json`,
`measurement-report.json`, `source-diff.json`, and
`parent-verification.json`. The harness SHA-256 is
`05a586a092289fe65a10462bba61e79f988bc8588d121bad727df1eed752a92a`;
archive SHA-256 is
`4cea20db78aa3fede9dc79a89a9277c5a9a72905fbff76a5f8436efd1c4aec30`.

## LR02 — Popup can retain an earlier vertical position during focus scrolling

Priority: P2. Resolved; the original follow-up observation and subsequent
root-cause diagnosis are recorded here.

During repair validation, Space activation of source 502 after lane/preset
changes produced popup tops `406.24` and `194.64` while the live marker settled
at `y=327.24`, height `14.14`. Both observations retained the exact CTF instance
key and correct record. A stationary pointer → Close → Space control placed
both cards correctly at `y=351.38`. These are the records
`source502-Space-after-preset-toggle`, `source502-Space-settled-repeat`, and
`source502-Space-fixed-viewport` in the repair evidence.

Unlike LR01, the live replacement is found and the card is not clamped to the
page origin. `showHover()` measures its anchor once and writes fixed viewport
coordinates; global smooth scrolling is enabled. Subsequent focus scrolling is
a plausible cause, but activation-time rectangles and scroll coordinates were
not captured in that pass. The detached-anchor repair did not fix this separate
movement problem; the subsequent trace and repair below do.

Review cards sometimes showed the DTE occurrence while the inspector showed
ETG for the same event. This follows existing aggregate behavior:
`eventLogHoverModel()` chooses the first loaded occurrence and explicitly lists
other occurrences; the inspector uses its selected resource. Different
resource effects and durations do not demonstrate another regression. An
unloaded inspector occurrence legitimately reports duration as unknown.

### LR02 root cause and repair

The parent repeated the CTF preset off/on → enable overlapping EVPN preset →
Close picker → Space on CTF source 502 sequence in the live 1M demo. Temporary
diagnostic logging captured opening and settled geometry without changing the
scroll behavior:

| Original sequence | At popup opening | After focus scrolling |
| --- | ---: | ---: |
| Document `scrollY` | 1787.20 | 1867.20 |
| Timeline `scrollTop` | 0 | 0 |
| Marker top | 406.84 | 326.84 |
| Popup top | 430.98 | **430.98 (stale)** |

The page moved exactly 80 pixels after opening. The live marker moved by that
amount; the fixed-position card retained its opening coordinates. This confirms
document focus scrolling as the cause in this reproduction. The temporary
logging and timer were removed before final validation.

The repair extracts the existing placement calculation into `positionHover()`.
Opening, passive capture-phase scroll notifications and the existing resize
handler reuse it. Capture covers both document and nested scrollports. Later
positioning resolves the current instance by the existing hover key, so a
rerender cannot leave a retained detached anchor. A missing anchor closes the
card. Scrolling inside the card is ignored, and a closed card performs no anchor
lookup. Geometry updates do not replace contents, rebind controls or request
cluster detail. This repair adds 12 net product lines relative to the preceding
uncommitted popup fix; it adds no polling loop, timer or retained anchor state.

### LR02 browser and executable validation

On the repaired frontend, the exact same sequence again moved document
`scrollY` from 1787.20 to 1867.20. The marker settled at `y=326.84` and the popup
followed to **`y=350.98`**, a 10-pixel gap below the diamond. Further checks:

- ArrowDown moved the nested timeline from 0 to 44 pixels: marker top 282.84,
  popup top 306.98. ArrowUp plus document focus scrolling also preserved the gap.
- Enter and pointer activation of the later duplicate EVPN instance selected
  the exact preset key and placed the popup at `y=351.38`.
- Fit → source cluster → return to 360–361 → Space reproduced the correct
  settled position again.
- PageDown inside a 36-record cluster moved its detail scroll to 271.2 pixels.
  Card HTML remained byte-identical, the first source-detail button retained
  focus, and the card remained pinned.
- Browser console capture contains no warnings or errors.

Evidence is in `.runtime/focus-scroll-repairs-2026-10-21/`:
`before-geometry-trace.json`, `browser-evidence.json`,
`cluster-scroll-preservation.json`, `before-focus-scroll.png`,
`after-focus-scroll.png` and `final-popup.png`.

`npm run check` passes **539 tests**, zero failures/skips. Four new tests call
the production popup functions and installed scroll callback to exercise
document/nested movement, replacement/removal, retained details/focus and idle
work avoidance. The Python frontend regression modules pass **63 tests**.
Both skills pass `quick_validate.py`; the configured Python environment passes
the conformance inventory (declaration coverage only).

A fresh GPT-6.1-Sol agent used the changed validator skill with a short prompt
and no parent audit/runtime evidence. It passed seven isolated checks (four
reused repository scenarios plus three added movement/placement cases) and 68
focused repository tests. The parent inspected the executable checks and
results. These are synthetic DOM tests, not proof of natural browser timing;
the native checks above establish that behavior. The trial ran its declaration
inventory using a different Python with a source-path override; the parent
separately reran it in the configured installed environment.

The author/validator skills and linked validation map now cover movement after
opening and preservation of card contents/focus. Documentation drift check:
this changes generic core frontend placement, with no public plug-in API,
schema, author command or runnable-example change. No maintained authoring
material update is required.

### LR02 fresh 1M measurements

Both runs used fresh frozen working-tree snapshots, including the preceding
uncommitted LR01 fix, and the unchanged 52-phase harness/archive recorded above.
Each run used a new child, empty search cache, hash seed zero and 100 ms memory
sampling. Browser activity was paused and the existing server checked for idle
requests before each run. The OS file cache was not cleared.

| Child-process metric | Before LR02 fix | After LR02 fix |
| --- | ---: | ---: |
| Loaded RSS | 2.356 GiB | 2.351 GiB |
| Navigation sampled peak RSS | 2.3681 GiB | 2.3676 GiB |
| Whole-run lifetime peak RSS | 2.435 GiB | 2.431 GiB |
| Sum of phase CPU time | 165.313 s | 167.359 s |
| Supervised wall time | 168.953 s | 171.282 s |
| Cold-search wall / CPU | 48.626 / 47.859 s | 49.259 / 48.250 s |
| Search sidecar | 75,038,720 bytes | 75,038,720 bytes |

Both runs exited zero, with empty stderr and no guard termination. The parent
independently verified all **52 ordered phase results** and **35 complete
response hashes**, including repeated phase names: identical. All **323 backend
files are byte-identical** between snapshots; the final `app.js` matches the
measured after snapshot. Frontend differences are the placement repair and its
new test file.

These service-harness measurements do not execute browser JavaScript or measure
browser heap/rendering. The 1.24% CPU increase and small RSS/wall differences in
one pair do not establish a performance change. The host was not exclusive: the
live server used 6.594 CPU seconds across the wider 211.662-second after-run
observation interval, with no access/error-log growth. The new UI scroll path
is separately checked for no card rebuild, network/detail request or closed-card
anchor lookup.

Artifacts under `.runtime/focus-scroll-repairs-2026-10-21/` include raw run
directories, `measurement-report.json`, `comparison.json`, source snapshot
hashes, idle checks and `parent-verification.json`.
