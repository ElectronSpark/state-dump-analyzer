# Repeated and cross-component frontend audit — 2026-10-21

Historical pre-repair observations follow. Repairs and validation are recorded
in [the consolidated repair report](audit-repairs-2026-10-21.md).

Seven new findings were open on commit
`112d346447316af6ae8f5503c252d5b66d317b07`: **four browser-confirmed findings**
and **three additional findings confirmed by controlled production-function
probes**. These extend the [previous nine repairs](nine-audit-fixes-2026-10-20.md)
with different operations and larger lane sets. No product code, tests, or
skills were changed in this audit.

The primary agent explored the in-app browser against the existing 1M demo:
`http://127.0.0.1:8883/node`, PE-A, **1,250,005 normalized events and 7,510
resources**. Operations included lane presets and combined/separate lane controls,
log-to-timeline reveals, view history, hiding lanes, resource tabs, 100 individual
ETG lane additions, repeated exact-event pagination, typed ranges, capacity
rejection, and failure-to-success recovery. Read-only reviewers investigated
related code; the primary agent inspected and reran their probes.

Browser evidence is in `.runtime/repeated-cross-audit-2026-10-21/`. The navigation
race tests used a temporary loopback proxy on port 8895 that delayed the real
`event-log/selection` response by eight seconds. This is controlled browser
timing, not a measured latency regression. The other browser findings below
were reproduced on the normal 8883 page without artificial delay.

## 1. P2 — Pending Reveal overrides newer viewport navigation and lane hiding

**Browser confirmed with controlled delay, in two different operations.** The
previous fix protects newer resource/cursor actions, but Back, pan, and lane
hiding do not invalidate the same navigation intent.

Reproduction for Back:

1. Apply and zoom a 500–600 s range, then a 50–60 s range, creating separated
   viewport-history entries. Select the log's +30 s route-create event.
2. Activate toolbar **Reveal in timeline** while selection resolution is delayed.
3. Immediately activate **Back view**. The visible window becomes
   **+490.4–+609.5 s**.
4. Let the older Reveal finish. It replaces the newer view with **+0.0–+119.0 s**
   and discards the forward-history entry.

Reproduction for hiding:

1. Select the +120 s `etg:svc-000000` create event and activate toolbar Reveal.
2. Before selection resolution finishes, activate **Hide etg-000000 from
   Resource timeline**. Its hide control disappears and the lane count is 13.
3. The older response adds that lane back, restoring 14 lanes and moving the
   viewport to **+60.4–+179.5 s**.

`revealFocusedEventLogSelection()` captures intent at `frontend/assets/app.js:10924`,
but `restoreTimelineView()` (11418), `panTimelineViewportByPixels()` (11643), and
`setExplicitLaneVisibility()` (7827) do not advance it. A production-function
probe also confirms the pan variant. These newer actions must supersede the
pending reveal before it creates another navigation intent.

Evidence: `delayed-reveal-back-{immediate,settled}.txt`,
`delayed-reveal-hide-{immediate,settled}.txt`, `navigation-audit.png`; additional
probe: `.runtime/postfix-navigation-audit-2026-10-21/viewport-intent-probe.{mjs,json}`.
An initial attempt without delay completed Reveal before Back and did not
reproduce the race; it is not counted as a failure.

## 2. P3 — Exact-event pagination loses keyboard focus

**Browser confirmed twice, including an intermediate page.** The default small
lane set does not expose this pagination; the 100-lane case does.

1. Use **Lanes → None**, then select ETGs `etg-000000` through `etg-000099`.
   Keep the full capture visible in Separate layout.
2. Open a server-backed cluster on `etg-000000`. The first tested cluster
   covers approximately +120.187–+144 s and loads **100 of 128 exact events**.
3. Focus **Load more events** and press Enter. Focus immediately becomes
   `BODY` while loading, and remains there after **128 of 128** load.
4. Repeat on the approximately +240.075–+258.675 s cluster with **249 events**.
   Press Space on Load more. After **200 of 249** load, the replacement
   **Load more events** button exists, but focus is still `BODY`.

`refreshOpenClusterHover()` at `frontend/assets/app.js:4773` replaces the popup
contents both when loading begins and when it ends. It preserves scroll but
does not preserve or recover focus. Pagination needs a stable keyboard
destination both when more pages remain and when the final button disappears.

Evidence: `cluster-pagination-{immediate,settled}.json`,
`cluster-pagination-repeat-{immediate,settled}.json`, corresponding settled
snapshots, and `lanes100-cluster.txt`.

## 3. P2 — Cluster accessibility and range facts treat preview counts as exact

**Browser confirmed.** In the same 100-lane view, an event marker visibly displays
**249** while its accessible name says **50 collapsed events**. Another visibly
displays 128 with the same accessible count of 50.

For the 249-event cluster:

1. Load its first two exact pages, totaling 200 events.
2. Apply a **240–245 s** range without zooming, then reopen that cluster.
3. The marker's accessible name says **“50 collapsed events; 49 of 50 events
   are in the selected range.”**
4. The popup already contains **66 exact events marked in-range**, among
   **200 of 249** loaded events. The asserted 49/50 facts are therefore false.

The server and visible marker totals are correct. `applyRangeHighlight()` at
`frontend/assets/app.js:4020–4040` derives membership from `cluster.items`, a
bounded preview, and then overwrites the accurate accessible label with that
preview's length. It does this even with no selected range. It also overwrites
the stale-window explanation. Preserve the authoritative total and qualify
preview-based membership instead of presenting it as an exact count.

Evidence: `cluster-count-and-range.{json,txt}`, `lanes100-settled.txt`.
The decisive values in the JSON are visibleMarker=249, loaded=200,
exactInRange=66, and the incorrect accessible 49/50 label.

## 4. P3 — Rejected resource-lane additions remain checked

**Browser confirmed repeatedly.** At the 100-lane limit, the picker shows
successful-looking choices that were never retained.

1. With ETGs 000000–000099 selected, toggle `etg-000100`, then `etg-000101`.
2. Each operation correctly announces the 100-lane limit, but both checkboxes
   remain checked. The picker has **102 checked ETGs** while the timeline
   reports **100 lanes**.
3. Closing and reopening the picker leaves the mismatch unchanged.
4. Searching for `etg-00010` rerenders the controls and shows both rejected
   choices unchecked. Clearing the search now shows exactly 100 checked ETGs.

Recovery control passed: after deselecting `etg-000000`, adding `etg-000100`
succeeds, with exactly 100 checked choices and the old target unchecked.

`setExplicitLaneVisibility()` at `frontend/assets/app.js:7827` returns false on
capacity rejection, but the lane-picker change listener at 8070 ignores that
return value. The browser's already-toggled checkbox is never restored. Update
the initiating control to the retained state when the mutation is refused.

Evidence: `lane-cap-check.txt`, `lane-cap-mismatch.{json,txt}`,
`lane-cap-reopened.json`, `lane-cap-after-search.txt`, `lane-cap-recovery.txt`.

## 5. P2 — Old timeline and detail records accumulate across navigation

**Performance/memory defect confirmed by a production-function probe; browser
RSS and CPU were not measured.** Windowing limits rendered rows but does not
bound these retained client-side maps.

The probe runs actual timeline/mark/source normalization, detail hydration, and
log-owned-cache pruning. Each of 100 successive windows contains only 20 new
events and 20 new sources:

| Visited windows | Current visible events / sources | Retained event / source maps |
| --- | --- | --- |
| 1 | 20 / 20 | 20 / 20 |
| 50 | 20 / 20 | 1,000 / 1,000 |
| 100 | 20 / 20 | 2,000 / 2,000 |

After hydrating 200 other event details and clearing every lane, the maps still
retain **2,200 events, 2,000 sources, and 200 details**. The detail map may share
objects with the event map; these are entry counts, not additive object/byte
measurements. The probe verifies that log-owned entries are actually removed
by the pruning routine, while old timeline/detail entries survive.

Relevant code: `normalizeMark()` (2290), `normalizeSourceMark()` (2457),
`normalizeTimeline()` (2500), `hydrateEventDetail()` (4220), and
`pruneServerEventLogOwnedCaches()` (9647), all in `frontend/assets/app.js`.
Repeated exploration therefore grows retention with distinct records visited
instead of the current window. A bounded cache must protect current lanes,
selection, open details, and pending requests while evicting old entries.

Evidence: `.runtime/source-log-audit-2026-10-21/source-log-probes.{mjs,json}`.
This establishes retention behavior, not a measured browser heap increase or
a specific CPU slowdown.

## 6. P2 — Canceling a brush can restore a permanently loading range summary

**Controlled production-function probe confirmed; not reproduced in the browser.**

1. Apply range A, 600–610 s, and leave its summary request pending.
2. Begin a Shift/range-brush gesture at 50 s before that request completes.
3. Let A's response finish while the new gesture remains active.
4. Cancel the gesture, for example with Escape.

The probe restores A's bounds, but its summary is the saved
`{source: "loading"}` placeholder, with `rangeAbortController=null` and no
replacement request. While brushing, A's completed count also briefly renders
against the new 50–50 s bounds.

`timelinePointerDown()` captures `priorSummary` at `frontend/assets/app.js:3750`;
`finishTimelinePointer()` restores it at 3964/3981. `requestRangeSummary()` at
5194 can complete in between without invalidation by the brush. Restore a
result belonging to the restored bounds, or request it again; do not revive a
loading placeholder whose request has already finished.

Evidence: `.runtime/postfix-navigation-audit-2026-10-21/cancelled-brush-summary-probe.{mjs,json}`.
The probe uses the real request, pointer-down, and cancellation functions, with
network, pointer/DOM services, and unrelated rendering stubbed.

## 7. P2 — A source jump's UID regex can omit the actual target

**Real core query confirmed with synthetic records; not demonstrated in the
current demo/browser.** A transient jump rule matches text, not exact identity.

The probe supplies a target with a valid 64-hex UID and 5,000 earlier records
of the same source type whose messages mention that UID. The actual
`record_lanes_for_window()` query reports 5,001 matches, returns its allowed
5,000 marks, and omits the real target. Thus a generated jump lane can fill with
references to the target while failing to expose the target itself.

`ensureSourceRecordLane()` at `frontend/assets/app.js:4386` creates an escaped
UID regex. `_record_matches()` searches the complete `source_record_haystack`,
including messages (`src/router_dump_analyzer/source_record_core.py:371,602,708`).
Navigation needs exact source identity selection rather than a whole-record
text search. The synthetic setup establishes the edge case; it does not imply
that this particular dump contains those references.

Evidence: `.runtime/source-log-audit-2026-10-21/exact-source-probe.{py,json}`.

## Checks, limits, and recovery

The primary agent reran:

```powershell
node .runtime/source-log-audit-2026-10-21/source-log-probes.mjs
node .runtime/postfix-navigation-audit-2026-10-21/viewport-intent-probe.mjs
node .runtime/postfix-navigation-audit-2026-10-21/cancelled-brush-summary-probe.mjs
python -X utf8 .runtime/source-log-audit-2026-10-21/exact-source-probe.py
```

All reproduced the recorded defects. These are diagnostic probes asserting
current faulty behavior, not new passing product regression tests.

Empty-lane reveal, combined-to-separate switching, settled resource-tab
selection, accepted lane additions below the limit, and capacity recovery were
also exercised. A separate probe found that canceled reveals of different
source targets retain pending lane allocations, but that behavior depends on
whether cancellation should undo the requested lane addition; it is not counted
as an additional bug here.

The unchanged commit already has 451 passing frontend tests and a completed
conformance inventory check. They were not rerun for this documentation-only
audit. No CPU/RSS benchmark or natural-latency regression is claimed. Browser
automation time includes tool overhead and was not treated as application CPU.
The original tab's screenshot operation was unavailable; the temporary tab
provided `navigation-audit.png`, while DOM snapshots and focus/checkbox records
capture the other browser results.

Neither browser tab recorded console warnings or errors during these checks
(`browser-console.json`); the defects do not require a thrown exception. The
temporary proxy was stopped and its tab closed. The original 8883 page was
restored to the full capture with 13 resource lanes, two default source lanes,
normalized events enabled, and browser-only review (`restored-demo.txt`).

The required plug-in documentation drift check found no public behavior,
contract, example, or author-command change: only this audit report is added,
so no authoring-material update is required.
