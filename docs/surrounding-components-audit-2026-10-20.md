# Surrounding-component browser audit — 2026-10-20

Resolution: all four findings below and the preceding five findings are fixed
and validated in [Nine audit repairs](nine-audit-fixes-2026-10-20.md).
The original observations follow.

This continuation found **two new browser-confirmed bugs** and **two additional
race defects confirmed by controlled production-function probes** on commit
`1e9a2d75d396ae27f43700c879626d8d94c9439f`. They are additional to the five open
findings in the [repeated-navigation audit](repeated-navigation-audit-2026-10-20.md)
and [cross-component audit](cross-component-audit-2026-10-20.md). The evidence
levels below are intentional: the two races were not reproduced in the browser.

The parent used the existing in-app browser at `http://127.0.0.1:8883/node`,
PE-A, with **1,250,005 normalized events and 7,510 resources**. Exploration
covered range validation, keyboard range boundaries, timeline actions, repeated
source-record reveals, resource-table selection, correlation pagination and
panel collapse, and the surrounding review connection controls. A parallel
reviewer inspected the relevant code and constructed isolated probes; the
parent reviewed and reran them.

No product code, tests, or skills were changed. Local snapshots and probe
artifacts are in `.runtime/surrounding-components-audit-2026-10-20/`.

## P2 — Keyboard adjustment can push a short range outside the capture

**Browser confirmed at both boundaries.** A typed range may be shorter than one
timeline pixel. Keyboard adjustment enforces the minimum width without clamping
the resulting boundary back into the capture. The range handles and summary
then disagree with the text fields, which clamp only their displayed values.

Reproduction at the start:

1. Keep the full +0–720 s capture visible.
2. Enter Start **0**, End **0.01**, and activate **Apply range**.
3. Focus **Range start +0.000 s** and press **ArrowRight**.
4. The start becomes **−0.602 s**, outside the capture and opposite the requested
   movement. Its accessible value text also reports −0.602 s, while the Start
   offset field remains **0**.

Mirror reproduction at the end:

1. Enter Start **719.986**, End **719.996**, and apply.
2. Focus **Range end +719.996 s** and press **ArrowLeft**.
3. The summary becomes **+719.986 s to +720.598 s / 0.612 s**. The end exceeds
   the capture while the End offset field displays **720**.

The displacement depends on the viewport's pixel width. A probe with a
1,860-second capture and 900-pixel track independently reproduces both cases
and confirms that the out-of-bounds values enter the range-summary request.
The same probe verifies that the pointer-drag path does clamp correctly.

Cause: `frontend/assets/app.js:4086`, `timelineHandleKeyDown()`, applies the
minimum-width constraints at lines 4101 and 4108 without a final `clampNs()`.
`formatRangeInput()` at line 5065 clamps the display, masking the actual bounds.
Both boundary constraints and capture bounds must hold simultaneously; a
minimum visual width must not force an otherwise valid interval outside the
capture.

Recovery passed: applying an ordinary +50–60 s range restored consistent
handles, fields, and summary, with zero events and no endpoint difference.

Evidence:

- `tiny-range-before.txt`, `tiny-range-start-arrow.txt`
- `tiny-range-end-before.txt`, `tiny-range-end-arrow.txt`
- `tiny-range-end-state.json`, `range-normal-recovery.txt`
- `state-race-probes.json`, key `narrowRangeKeyboard`

## P3 — Correlation pagination resets disclosure state and keyboard focus

**Browser confirmed twice.** Loading more relationships replaces the entire
index instead of preserving the user's current inspection state.

Reproduction:

1. Move the selected time to capture end. In Resource tables choose **IP routing**,
   then select **blue / node-a/control-plane/IP_ROUTING/blue**.
2. Wait for the focused graph. Its response has **499 incoming relationships**;
   the index initially shows **30 of 499**, with a **Show 30 more** button.
3. Collapse **Declared source endpoints**. Expand the incoming relationship
   whose edge ID is `node-a/scale-rel-000000005`.
4. Activate **Show 30 more** with Enter.
5. The index correctly grows to 60 items, but the source group reopens, the
   expanded relationship closes, and `document.activeElement` becomes `BODY`.

Repeated after opening edge `node-a/scale-rel-000000009`, collapsing the source
group again, and activating pagination with Space: the index grows to 90 and
loses the same disclosure state and focus. Keyboard users must find the button
again before continuing pagination.

Cause in `frontend/assets/app.js`: the pagination handler at lines 7291–7295
calls `renderCorrelationList()`; line 7269 replaces the list with `innerHTML`;
line 7259 recreates both groups open; line 7242 recreates every relationship
detail closed. Focus is not restored.

Pagination within the same resource/time/query should preserve group state,
expanded edge identities, scroll position, and a usable focus target. When a
page exhausts the results, focus should move to a stable nearby control.

The separate panel **Collapse correlation → Expand correlation** control
retained the 90-item page correctly.

Evidence:

- `correlation-pagination-before.txt`, `correlation-pagination-after.txt`
- `correlation-pagination-state.json`
- `correlation-pagination-repeat.txt`, `correlation-pagination-repeat-state.json`
- `correlation-collapse-roundtrip.txt`

## P2 — Repeated pending source reveals can consume all source-lane slots

**Production-function probe confirmed; browser race not reproduced.** With no
source lane already containing a target record, repeated reveals made before
the timeline response arrives append a new transient rule each time for the
same source UID.

The probe composes the actual `jumpSourceRecordToTimeline()`,
`ensureSourceRecordLane()`, and `requestTimeline()` functions, including their
navigation-intent, ownership, and abort checks. Network completion is controlled
and DOM rendering is stubbed. Eight pending reveals produce **eight distinct
lane IDs with one identical pattern**, exhausting the eight-lane capacity.
A ninth reveal reports **Remove a source-record lane before adding a jump lane**
and supersedes the last useful request's navigation authority. After resolving
that response, there are still eight retained rules and no loaded source lanes.

Cause: `frontend/assets/app.js:4353`, `sourceRecordLaneFor()`, checks rendered
marks/clusters. `ensureSourceRecordLane()` at line 4386 does not check for an
existing pending rule for that UID before appending one; stale completion at
lines 4406–4407 does not roll the rule back. Each reveal at line 4413 advances
the navigation intent. Reset does not remove these rules.

Pending reveals of the same UID should reuse one lane allocation. Superseded
requests must not leave unnecessary allocations that consume capacity.

Browser control: with both default source presets disabled, three serial
Ctrl+Enter reveals of the +30 s unmatched `daemon_warning` settled to **one**
jump lane. Browser tool timing did not keep the request pending long enough to
reproduce the probe's overlap. That one test lane was removed afterward.

Evidence: `state-race-probes.{mjs,json}`, key `repeatedSourceJump`;
`source-repeat-immediate.txt`, `source-repeat-settled.txt` for the browser control.

## P2 — Pending correlation preparation can reopen a dialog after disconnect

**Production-function probe confirmed; not browser-confirmed.** The probe starts
correlation preparation under a writable scope with two selected normalized
events, then runs the actual `connectDurableReview()` branch used when a
required scope field is cleared. This disconnects the review and closes the
dialog. Resolving the earlier selection request then reopens the dialog in
browser-only mode, with both prepared subjects carrying an empty `revision_id`.

The probe composes actual selection resolution, subject projection, dialog
preparation/closing, and the disconnect branch; only network, DOM, and unrelated
rendering dependencies are stubbed.

Cause: `frontend/assets/app.js:10581`, `openManualCorrelationDialog()`, checks
writability only before awaiting `resolveEventLogSelection()`. It captures no
connection token and does not recheck the scope before projecting subjects or
opening the modal. `connectDurableReview()` at line 1787 closes an existing
dialog but does not cancel a preparation still pending.

Preparation must belong to the scope under which it started, and must be
discarded after disconnect/reconnect. The current save handler rejects a save
in local mode; this audit does **not** demonstrate an unauthorized durable
write. No correlation was saved, and the browser remained unconnected.

Evidence: `state-race-probes.{mjs,json}`, key `correlationAfterDisconnect`.

## Other controls, limits, and cleanup

- Reversed range 610–600 produced **End must be at or after start**. Correcting
  it to 600–610 and using **Apply and zoom** recovered: 100,002 events, 9,925
  failures, and the explicit bounded endpoint-comparison notice.
- **Actions → Select visible duration** selected the full +0–720 s capture.
  An earlier menu opening disappeared before activation once; reopening worked.
  There is insufficient evidence to classify that one observation as another bug.
- Browser warning/error logs were empty at the end of the audit. Screenshot
  capture again failed with **Unable to capture screenshot**; retained evidence
  consists of DOM snapshots, read-only DOM state, and probes, not screenshots.
- The parent reran `node .runtime/surrounding-components-audit-2026-10-20/state-race-probes.mjs`;
  all three defect assertions and the drag-clamping control passed.
- No new CPU/memory benchmark or full frontend suite was run for this report-only
  audit. Earlier same-code frontend results remain 428 passing tests; these
  newly observed behaviors are gaps in that coverage.
- The audit-created jump lane was removed. Reload restored Overview, default
  13 resource lanes and two source lanes, all layers, full capture, empty range,
  normal event-log filters, and browser-only review mode.

Plug-in documentation drift check completed: this change records audit evidence
only. It changes no plug-in API, author-visible behavior, or author-facing
command; no authoring-document or skill update is required.
