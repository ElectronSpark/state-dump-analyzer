# Extended resource-lane and navigation audit — 2026-10-20

Follow-up: findings were repaired and validated in
[Outstanding frontend audit fixes](outstanding-audit-fixes-2026-10-20.md).
The observations below describe the pre-fix audit.

This continuation adds three browser-confirmed issues to the earlier
[lane and jump audit](lane-jump-audit-2026-10-20.md). It also confirms an
asynchronous keyboard-navigation variant using an isolated production-function
probe. No product code or skills were changed.

The parent exercised the existing in-app browser at
`http://127.0.0.1:8883/node`, using PE-A with **1,250,005 events and 7,510
resources**. A parallel agent reviewed the related code and prepared focused
probes; the parent independently reran all three probes. Evidence is saved in
`.runtime/lane-sequences-2026-10-20/`. Source references describe the working
tree, including the previously pending fixes, at HEAD `f4076ce`.

## P2 — Retained-source lookup throws and prevents timeline jumps

Browser reproduction from a fresh load:

1. In the event log, turn off **Normalized events** and enable **Non-CTF
   records**. The log displays 2,500 records.
2. Rendering the first page raises `TypeError: Cannot read properties of
   undefined (reading 'some')` from `sourceRecordLaneFor()` through
   `eventLogHoverModel()` and `registerVisibleEventLogHoverModels()`.
3. Focus the unmatched +30.000 s Syslog row with `source_sequence=0`
   (`source-external-unmatched-000000`) and press Ctrl+Enter to reveal it.
4. The jump raises the same exception through `ensureSourceRecordLane()` and
   `jumpSourceRecordToTimeline()`, rather than completing the reveal.

Cause: `normalizeRecordLane()` at `frontend/assets/app.js:2481` creates a
`marks` array but no `clusters` field. At line 4339, `sourceRecordLaneFor()`
unconditionally evaluates `lane.clusters.some(...)` after a lane's marks do not
match. A record in a later lane, or absent from every current lane, therefore
throws. Display clusters are derived separately by `buildSourceGlyphs()`.

The production-function probe covers normalization followed by first-lane,
second-lane and absent-record lookups, hover-model creation, and jump-lane
creation. The first-lane case succeeds; the other relevant paths throw. The
absent-record jump fails before adding a rule or requesting a timeline.

Evidence: `source-log-clean-reload-errors.json`,
`source-record-reveal-errors.json`, and
`source-review/source-record-lane-lookup.mjs`. Fresh exceptions were captured
at 00:37:37 and 00:37:57 UTC on October 21 (October 20 local time).

Suggested regression coverage: use production lane normalization with two
source lanes and a missing UID. Existing untimed-source navigation coverage
returns before this lookup and does not exercise the failing path.

## P2 — Duplicate child events move focus and popups to another tree instance

Browser reproduction:

1. Reset the timeline to its 13 representative resource lanes in Separate mode.
2. Expand `etg-000000` by clicking its lane label. Its `primary` ETE now appears
   both as a standalone root and as correlated children.
3. In the child under the `owns` relationship, press Enter on **Evpn Single
   Home Service Create at +120.0 s**.
4. After the render settles, keyboard focus is on the standalone `primary`
   root's event, although the child instance still exists.
5. Repeat with a mouse click on the child's **Evpn Mass Service Failover at
   +360.0 s** mark. It produces the same wrong-instance focus and popup anchor.

The selected event UID and resource are correct; the containing tree instance
is wrong. In the keyboard case, the root mark was at viewport y=-84.7 while the
clicked child remained at y=340.9. The event popup was anchored at y=-81.5.
The mouse case likewise anchored the popup above the viewport (y=-32.7).

Cause: `timelineFocusDescriptor()` and `timelineElementForFocusDescriptor()`
at `frontend/assets/app.js:3353` and `:3376` retain event/resource identity but
omit the containing row's `data-tree-key`. The replacement-mark lookup at
`:3634` also picks the first event/resource match. Both paths need to retain
the original tree instance while it remains available.

Evidence: `duplicate-child-event-focus.json`,
`duplicate-child-event-focus-settled.json`,
`duplicate-child-pointer-settled.json`, and
`source-review/duplicate-instance-focus.mjs`.

## P2 — Virtual-log navigation loses keyboard continuity

Browser reproduction independent of the retained-source exception:

1. Reload with only **Normalized events** enabled.
2. Focus the first event row (`node-a/scenario/node-a-route-create`) and press
   End.
3. The virtual log reaches its final row at +624.999 s,
   `node-a/scale-event-01249999`, selection index 1,250,004.
4. After the page settles, the active element is BODY, so arrow keys no longer
   continue through event rows. No new source-lane exception was emitted by
   this normalized-only sequence.

Home/End currently use native scrolling; the log has no handlers for those
keys. `renderEventTableWindow()` at `frontend/assets/app.js:9963` only restores
the previously focused row if it remains in the rendered window. When native
scrolling removes that row, no focus target survives. The earlier source-only
Home/End observations are not independent evidence because the source-lane
exception also interrupts this render path.

A separate **probe-confirmed, not browser-timing-confirmed** variant affects
ArrowDown across an uncached page. `focusEventLogSelectionIndex()` at `:10804`
tries to focus the target on one animation frame. If the page arrives later,
selection advances to row 120 but focus stays on row 119, which is retained in
overscan. A later ArrowDown can therefore repeat the same step. Preserve the
latest navigation target across page arrival, while allowing an intentional
user focus move to win.

Evidence: `normalized-log-end-focus-settled.json`,
`source-log-end-focus-settled.json`, and
`source-review/uncached-log-keyboard-focus.mjs`.

## Longer sequences that passed

- **None → Combined**, repeated: the selected ETG root is hydrated and shown.
  A source-review suspicion of a blank Combined root was rejected by the
  browser result.
- **Combined → hide root → Selected → Separate**: hiding the root produces
  the empty state; Selected restores it; Separate returns to one resource lane.
- **Zoom in twice → pan later → Back twice → Forward twice**: view windows
  restore to 200–520 s, 120–600 s, 200–520 s and 232–552 s respectively.
- **Pan later → Center → Fit**: Center returns to 200–520 s around the selected
  event; Fit restores the full 0–720 s capture.
- **Apply range 600–625 s → Zoom range → Back → Forward → Clear range**:
  range zoom is 597.6–627.3 s, Back restores 0–720 s, Forward restores the range
  zoom, and clearing disables Zoom range.

These checks did not establish a new CPU or memory regression. Browser tool
round-trip durations were not treated as application latency. This was a
functional exploration, not another controlled 1M performance measurement.

## Validation and handoff

The parent reran these isolated probes successfully; success means the probes
reproduced the defects, not that the defects are fixed:

```powershell
node .runtime/lane-sequences-2026-10-20/source-review/duplicate-instance-focus.mjs
node .runtime/lane-sequences-2026-10-20/source-review/uncached-log-keyboard-focus.mjs
node .runtime/lane-sequences-2026-10-20/source-review/source-record-lane-lookup.mjs
```

The browser was reloaded and returned to Overview with the default 13 resource
lanes, all layers enabled, Separate mode, full 0–720 s window, and normalized
events enabled. The restored DOM is saved as `restored-default.txt`.
Screenshot capture was unavailable in this pass; DOM observations and console
traces are retained instead.

Plug-in documentation drift check completed: this change adds only the audit
report and local diagnostic probes, with no author-visible API or behavior
change. No maintained authoring documentation or skill update was required.
Existing product changes were preserved, and no commit or push was performed.
