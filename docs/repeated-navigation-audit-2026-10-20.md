# Repeated lane and log navigation audit — 2026-10-20

Resolution: all three findings below are fixed and validated in
[Nine audit repairs](nine-audit-fixes-2026-10-20.md). The original observations follow.

Three further bugs were reproduced in the browser on committed version
`1e9a2d75d396ae27f43700c879626d8d94c9439f`. This follows the
[previous audit repairs](outstanding-audit-fixes-2026-10-20.md). No product code,
tests or skills were changed during this exploration.

The parent used the existing in-app browser at
`http://127.0.0.1:8883/node`, PE-A, with **1,250,005 normalized events and 7,510
resources**. Actions included keyboard activation, Ctrl-click, repeated view
history traversal, source-preset toggles, hiding/showing marks, filtered-log
Home/End, clearing the resource lanes, and navigation in both directions.
All observations below include the settled asynchronous result.

Local evidence is in `.runtime/repeat-navigation-audit-2026-10-20/`.

## P2 — Toolbar reveal can override a newer resource selection

The navigation guard begins too late when the jump originates from the
event-log toolbar. The old selection-resolution response starts a new jump
after the user has already chosen a different resource.

Browser reproduction:

1. Keep the route `route:blue:198.51.100.0/30` loaded and selected. The captured
   reproduction followed **Lanes → None**, revealing its +30.000 s create
   event, then zooming/panning to a 480-second window.
2. Search the event log for `failure` and press End in a row. It settles at
   filtered index 24,924, event `node-a/scale-event-01249997`, DTE 247,
   +624.999 s.
3. Activate toolbar **Reveal in timeline** with Enter, then immediately activate
   the correlation-graph button **Selected Control plane / IP_ROUTE 30
   installed** with Enter.
4. The immediate snapshot still shows the newer route selection and the old
   +0–480 s window.
5. When the earlier reveal finishes, the selected resource changes to
   **DTE dte-000247**, another lane appears, and the window moves to
   **+240–720 s**. The newer resource choice is lost.

Repeated with a different target: press Home in the failure log to select
the first failure (+600.075 s, DTE 9); activate **Reveal in timeline**, then
reselect the loaded **DTE dte-000247** graph node. The immediate snapshot keeps
DTE 247, but the settled result changes it to **DTE dte-000009** and grows to
three resource lanes. Thus both attempts overrode the later user action.

Cause: `frontend/assets/app.js:10845`, `revealFocusedEventLogSelection()`, awaits
`resolveEventLogSelection()` before entering the guarded jump helper. The
resolver at line 10229 validates log-selection identity, but a newer resource
selection or timeline clear need not change that identity. The late helper call
creates a fresh navigation intent, incorrectly giving the old operation authority.

Evidence:

- `toolbar-reveal-competing-resource-immediate.txt`
- `toolbar-reveal-competing-resource-settled.txt`
- `toolbar-race-repeat-immediate.txt`
- `toolbar-race-repeat-settled.txt`

## P2 — A pending timeline-to-log lookup steals focus from a newer row

Browser reproduction:

1. Clear the event-log search and keep the first normalized page visible.
2. Ctrl-click the timeline mark **Scenario Resource Upsert at +270.0 s**
   (`node-a/scenario/node-a-route-recreate`).
3. Immediately focus the first +30.000 s create row and press Enter.
4. The immediate observation shows that row focused and selected at index 0.
5. After the pending locate completes, focus and scroll jump to the older
   +270.000 s destination at index **500,003**. That row is focused but not
   selected; the selected moment still reads **+30.000 s**.

Repeated after Home returned to index 0: Ctrl-click the DTE 9 failover mark
`node-a/scale-event-00500384`, then select the +30.000 s row again. The settled
focus moves to **+360.038 s**, index **500,388**, overriding the newer row focus.

Control case: Ctrl-click the +270 s mark and immediately change Search to
`audit-no-match-20261020`. The final result remains **0 matching records** with
focus in Search. Changed-query invalidation works; the uncovered case is a newer
selection within the same query.

Cause: `locateServerEventLogEntry()` at `frontend/assets/app.js:10946` checks
query and locate generations. `setEventLogSelectionRanges()` at line 9209
advances selection authority but not locate authority. The obsolete response
therefore reaches `focusServerEventLogTarget()` at line 10896, which scrolls
and schedules focus on its old destination.

Evidence:

- `log-locate-competing-selection-immediate.txt` and `-settled.txt`
- `log-locate-focus-immediate.json` and `-settled.json`
- `log-locate-repeat-immediate.txt`, `-settled.txt`, and `-focus.json`
- `changed-query-cancels-locate.txt` and `changed-query-focus.json`

## P2 — Source-lane preset toggles lose keyboard focus after refresh

Browser reproduction:

1. Open **Lanes** and focus the source-lane checkbox **Unmatched external
   records**.
2. Press Space to disable it. After refresh, the count changes from two source
   lanes to one, but `document.activeElement` is **BODY**.
3. Refocus the checkbox and press Space to enable it. The count returns to two;
   focus again becomes **BODY** after refresh.

The resource-checkbox repair does not cover the separate source-lane manager.
Repeated keyboard toggling requires finding the checkbox again after every
refresh, and subsequent keyboard navigation starts outside the intended control.

Cause: `setRecordLanePreset()` at `frontend/assets/app.js:7849` calls
`refreshRecordLanes()` at line 7844, which renders the timeline and picker.
`renderRecordLaneManager()` replaces `record-lane-list.innerHTML` at line 7886
and rebinds handlers without restoring the activated preset's identity.

Evidence: `source-preset-off.txt`, `source-preset-focus-off.json`, and
`source-preset-focus-on.json`.

## Other sequences and validation limits

- Three consecutive Back/Forward cycles consistently restored the expected
  +0–480 s and +47.9–527.9 s windows at zoom 1.5. Evidence:
  `view-history-cycles.json`.
- **None → reveal the +30 s normalized event** recovered from zero resource
  lanes to the intended single route lane and focused its event mark.
- Combined layout disabled resource selection presets; switching back to
  Separate enabled them. None then settled at zero resource lanes, preserving
  the two source lanes.
- The `failure` search returned 24,925 rows and kept input focus. End reached
  filtered index 24,924 and Home returned to the first failure. Evidence:
  `failure-search.txt` and `failure-end-focus.json`.
- Browser warning/error logs were empty during the reproduced navigation races.
  These are state/authority errors, not JavaScript exceptions.
- The browser was restored to the loaded overview: 13 representative resource
  lanes, two source lanes, no log search, and the +0–720 s window. Evidence:
  `restored-overview.txt` and `browser-console.json`.

One UX ambiguity was observed but is not counted as a fourth bug: **Hide marks
→ Reveal in timeline** moved the viewport to the target while leaving the mark
hidden and focus on the toolbar; **Show marks** restored visibility. Existing
documentation treats hide/show as independent presentation state and does not
promise that Reveal overrides it (`docs/api-contract.md:4309`,
`docs/architecture.md:2597`). Clear feedback or a deliberate visibility policy
would make this interaction easier to understand.

A parallel reviewer used `router-plugin-validate` and prepared composed probes
from the production resolver/reveal and locate/selection functions. The parent
independently ran
`node .runtime/repeat-navigation-audit-2026-10-20/agent-navigation-probes.mjs`;
both assertions reproduced the obsolete-action behavior. The probes' timeline
clear variant is controlled evidence, while the newer-resource variants above
were reproduced manually in the browser. The probe output is
`agent-navigation-probes.json`.

Screenshot capture was unavailable; DOM snapshots and active-element
observations are retained instead. This was an interaction audit, not an
exhaustive browser matrix or CPU/RSS benchmark. No new performance regression is
claimed from browser-tool elapsed times. The existing 428-test result applies to
this unchanged product revision; the full frontend suite was not repeated for
this report-only change.

Documentation drift check completed: this report changes no plug-in behavior,
public APIs or author-facing commands. No changes to the maintained authoring
documents, examples or skills are required. The three findings remain open.
