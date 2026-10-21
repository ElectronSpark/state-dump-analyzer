# Stateful and cross-component browser audit — 2026-10-20

Resolution: both findings below and the preceding audit's findings are fixed
and validated in [Nine audit repairs](nine-audit-fixes-2026-10-20.md).
The original observations follow.

This continuation found **two new browser-confirmed bugs** on commit
`1e9a2d75d396ae27f43700c879626d8d94c9439f`. The three findings in the
[repeated-navigation audit](repeated-navigation-audit-2026-10-20.md) remain
open; these are additional cases, not fixes or duplicates of that report.

The parent explored the actual in-app browser at
`http://127.0.0.1:8883/node`, PE-A, with **1,250,005 normalized events and
7,510 resources**. Including Non-CTF records produced a merged log of
**1,252,505 records**. Tests combined ranges, log grouping and selection,
browser-only review markers, resource selection, layout/reset, custom source
lanes, zoom, and manual time-cursor input. No product code, tests or skills
were changed. Local evidence is under
`.runtime/cross-component-audit-2026-10-20/`.

## P2 — A rejected custom source lane blocks subsequent timeline refreshes

The frontend and backend accept different regex subsets. The UI commits a rule
and clears its form before the server validates it. A rejected rule stays in
the active collection and is sent with every later timeline request, so the
failure spreads from lane creation to zoom and otherwise valid lane changes.

Browser reproduction:

1. Open **Lanes**. In Source-record lanes, enter name **Audit grouped warnings**
   and Safe regex **`(warning|error)`**, leaving Source at All retained sources.
2. Activate **Add lane**. The form clears, the rule remains listed, and capacity
   changes from **2 / 8** to **3 / 8**.
3. The result reports: **Timeline query rejected: record lane patterns do not
   support groups; use top-level alternatives**. No usable new lane is loaded.
4. Close the picker and zoom in. The viewport changes to +120–600 s, but the
   resource lane remains labeled **cached window** after settling. The timeline
   query is rejected for the same retained pattern. Density can refresh
   independently, so the page contains a fresh density view beside cached
   resource history.
5. Add another rule, **Audit valid warnings**, with **`warning|error`** and
   Source **Syslog**. It is retained at **4 / 8**, but the original invalid rule
   still prevents the request from succeeding.
6. Remove **Audit grouped warnings**. The valid lane now loads with **249 records**
   in the current window, and the resource lane no longer has the cached-window
   warning. The two preset source lanes also refresh to their windowed counts.

Repeated with **`warning{2}`**: the frontend accepted and retained the rule,
then the server rejected it with **record lane patterns do not support counted
repetition**. Removing it restored normal operation. The audit-created valid
lane was removed afterward as well.

Cause:

- `frontend/assets/app.js:7824`, `validateRecordLanePattern()`, permits ordinary
  groups, counted repetition, and some patterns containing multiple quantified
  atoms that the backend disallows.
- `frontend/assets/app.js:7901`, `addRecordLane()`, appends the rule and resets
  the form before the asynchronous query. Failure does not roll back that rule.
- `src/router_dump_analyzer/source_record_core.py:524`,
  `compile_record_pattern()`, applies the stricter server policy.

Production-function probes independently confirm that `(warning|error)`,
`warning{2}`, and `warning.*error.*timeout` pass frontend validation but fail
backend validation. The valid control `warning|error` passes both. Only the
first two invalid patterns were exercised in the browser.

Evidence:

- `grouped-regex-rejected-but-retained.txt`
- `grouped-regex-zoom-stale.txt`
- `valid-lane-blocked-by-invalid.txt`
- `regex-remove-invalid-recovery.txt`
- `counted-regex-rejected-but-retained.txt`
- `source-lane-frontend-probe.json` and `source-lane-backend-probe.json`

## P2 — A direct reveal overwrites a newer manual time-cursor change

The recently added navigation guard covers explicit event/resource selections
and clear/reset, but ordinary **Selected time** input does not invalidate an
older reveal. This is distinct from the previous report's toolbar-resolution
race: the reproduction uses direct **Ctrl+Enter** on a log row.

Browser reproduction:

1. Apply and zoom to a selected period **+50–60 s**, so the +30 s event is outside
   the viewport. Keep the normalized log visible; the test also included Non-CTF
   records. The empty selected-period group precedes Other records.
2. Press Ctrl+Enter on the +30.000 s normalized route-create row
   (`node-a/scenario/node-a-route-create`). This requires a timeline refresh.
3. Immediately focus **Selected time** and press **End**.
4. The immediate snapshot confirms slider value **1,000,000** and selected
   moment **+720.000 s**.
5. When the older reveal completes, the slider changes to **41,667**, the
   selected moment becomes **+30.000 s**, and focus moves from the slider to the
   old event mark.

Repeated with a different event and opposite endpoint:

1. Ctrl+Enter the +120.000 s `etg:svc-000000` create row.
2. Immediately press **Home** on Selected time. The immediate value is **0**
   and selected time is **+0.000 s**.
3. The delayed reveal changes the value to **166,667** and time to
   **+120.000 s**. The later explicit cursor choice is again lost.

Cause: the input handler at `frontend/assets/app.js:12119` directly calls
`setCursor()` at line 4151. Neither advances navigation authority. The pending
`jumpToTimelineEvent()` at line 4460 therefore remains eligible and later calls
`selectEvent()` with its obsolete target. A composed probe using these actual
production functions reproduces the same 720-to-30 overwrite.

Evidence:

- `cursor-vs-reveal-immediate.txt` and `cursor-vs-reveal-settled.txt`
- `cursor-vs-reveal-repeat-immediate.txt` and `-settled.txt`
- `cursor-navigation-probe.mjs` and `cursor-navigation-probe.json`

## Stateful sequences that passed

- Applied and zoomed to +600–610 s. The log grouped **100,002 matching records**
  into the selected period while retaining the complete stream separately.
- Selected normalized events `node-a/scale-event-01000000` and
  `node-a/scale-event-01000001`, then added two browser-only review markers.
  Both the timeline and log showed the marks.
- Changed the log layer to Control plane, cleared the range, restored All
  layers and the range, reselected those same event identities, and removed
  their markers. Both markers were removed; no durable review session was used.
- Selected unloaded resource `etg-001874`, switched to Combined, and Reset.
  The selected root and its association lane survived the completed request.
  A source-only suspicion that Reset would drop the root was disproved: the
  backend includes selected relationship-history roots in the response.
- Applied an empty +50–60 s period. The log correctly showed zero selected-period
  matches and all records under Other records. Including Non-CTF records updated
  the total to 1,252,505 without changing the empty-period result.
- A later +120–121 s mixed-stream range correctly reported 10,021 records.

Key evidence: `range-600-610-settled.txt`, `marked-identities.json`,
`range-review-markers-created.txt`, `markers-after-filter-clear-range.txt`,
`markers-removed-after-range-cycle.txt`, `combined-unloaded-root-reset.txt`,
`empty-period-log.txt`, `empty-period-merged-log.txt`, and
`mixed-range-120-121.txt`.

## Validation and scope

A parallel reviewer used `router-plugin-validate` for source review and prepared
isolated production-function probes. The parent independently ran:

```text
node .runtime/cross-component-audit-2026-10-20/source-lane-validator-probe.mjs
python .runtime/cross-component-audit-2026-10-20/source-lane-validator-probe.py
node .runtime/cross-component-audit-2026-10-20/cursor-navigation-probe.mjs
```

All probe assertions passed, reproducing the reported defects. Python used the
configured `router-dump-analyzer-demo` environment. Controlled probe results are
separate from the two repeated browser reproductions for each finding.

The final console read contained no warnings/errors; query rejection was
surfaced by the application. Screenshot capture remained unavailable, so the
evidence consists of saved DOM snapshots, identity/focus observations and
probe outputs. No CPU/RSS benchmark or exhaustive browser matrix was run.
The previous 428-test result applies to the unchanged product revision; the full
frontend suite was not rerun for this report-only change.

Temporary browser-only markers and custom source lanes were removed. The browser
was restored to the loaded overview with 13 representative resource lanes, two
source lanes and the +0–720 s window (`restored-overview.txt`).

Documentation drift check completed: no public plug-in behavior, API or
author-facing command changed, so the maintained authoring documents, examples
and skills require no update. Both new findings remain open.
