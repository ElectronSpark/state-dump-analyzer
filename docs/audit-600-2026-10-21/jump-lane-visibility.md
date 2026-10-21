# SN012 — P2: resource jumps leave the focused lane behind sticky controls

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed with two targets in SX011, expanding S173.

The Correlations **Ctrl-click to timeline** action selects the intended resource
and focuses its canonical lane, but the lane remains covered by the global
header or sticky timeline controls after the jump settles. The user cannot see
the promised destination without additional page navigation. Resource identity,
graph root, cursor and visible time window remain correct.

## Browser reproduction

1. In the synthetic 1M single-node demo, use Separate lanes at capture End,
   with the full +0–+720-second window. Select
   `node-a/control-plane/IP_ROUTING/blue` and open Correlations.
2. Expand the incoming `next_hop` relationship from
   `node-a/data-bridge-layer/ETE/etg-000001/primary` to blue. Ctrl-click its
   explicit endpoint button to jump to the timeline, then wait for graph
   refresh and scrolling to settle.
3. The exact root lane label owns focus, but its saved rectangle is
   approximately **11–71 px** vertically. The global header occupies
   **0–84 px**. Hit-testing the label area at `(120, 40)` returns the
   **Router State Lab** header, not the lane.
4. Return to Correlations for the now-selected primary ETE. Expand its incoming
   `owns` relationship, `node-a/scale-rel-000000004`, and Ctrl-click the
   `node-a/data-bridge-layer/ETG/blue/etg-000001` endpoint.
5. After the graph reports no pending query, the exact ETG root lane label owns
   focus at approximately **55–115 px**. The recorded hit-test returns
   `#timeline-pan-controls`. A later read retains the same target and rectangle;
   this is not merely an intermediate smooth-scroll sample.

The first jump was originally S173, whose identity, focus and time assertions
passed. SX011 adds the visibility assertion and a second target; it does not
reinterpret those passing assertions as identity failures.

S179 provides a passing control. Starting from ETG1874, the auditor expanded
its incoming `next_hop` relationship, `node-a/scale-rel-000240074`, and
Ctrl-clicked the source `node-a/data-bridge-layer/DTE/blue/dte-001874`. This
newly added lane became the exact graph root and focused canonical root lane
at approximately **345–405 px**, remaining visible on the later settled read.
Cursor and full time window were preserved. The failing S173/SX011 targets
were already loaded; this contrast is useful diagnostic evidence, not proof
that every new-lane jump succeeds or every loaded-lane jump fails.

## Recovery and evidence

Selecting the **Timeline** section link, then scrolling the page slightly,
exposes ETG1 at approximately **498–558 px** in the 720 px viewport. The saved
`recovered` state has `hitIsTarget: true` and the same graph root. This is a
visibility failure with a manual recovery, not a missing lane or keyboard trap.

- [S173.json](../../.runtime/audit-600-2026-10-21/single-node/S173.json)
  records the initial endpoint jump and its passing identity/time assertions.
- [SX011.json](../../.runtime/audit-600-2026-10-21/single-node/SX011.json)
  records both covered targets, settled/later observations, hit-tests and
  recovery. `before`/`geometry` describe the ETE; `secondAfter`, `secondTree`,
  `secondGeometry` and `secondLate` describe the ETG.
- [S179.json](../../.runtime/audit-600-2026-10-21/single-node/S179.json)
  records the passing newly added DTE1874 control, including matching `tree`
  and `lateTree` focus geometry after graph refresh.
- [First jump screenshot](../../.runtime/audit-600-2026-10-21/single-node/SX011-jump-target-hidden.png)
  shows the sticky controls and a lower `ae-00000` lane, without the focused ETE.
- [Second jump screenshot](../../.runtime/audit-600-2026-10-21/single-node/SX011-second-jump-covered.png)
  shows the sticky controls over the lane region. The matching DOM evidence,
  rather than the screenshot alone, establishes the hidden target's identity
  and focus.

The primary auditor performed the browser actions. This report's author
reviewed the saved records, both screenshots and source. No CPU, memory or
request-duration measurement is claimed.

## Source mechanism and remaining uncertainty

`jumpToTimelineResource()` selects the resource at
[app.js:4570](../../frontend/assets/app.js), then schedules one animation frame.
Lines 4574–4579 find its lane, call
`row.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" })`,
focus the label with `preventScroll: true`, and pulse the row. There is no
subsequent check that the target is visible outside sticky overlays.

The timeline has nested scrolling and sticky geometry. Its vertical scroller is
bounded to `min(68vh, 720px)` with `overflow: auto` at
[styles.css:3140–3143](../../frontend/assets/styles.css). The floating controls
are a sibling preceding that scroller in
[node.html:199–215](../../frontend/pages/node.html), and stick below the global
header at styles lines 703–709. The global header itself is sticky at the top
with z-index 50, lines 77–89. The topbar ResizeObserver in app.js lines
12146–12165 updates the floating header's offset; it does not reconcile a
jump destination with the visible portion of the nested scroller.

Selection also starts a graph request at app.js line 7776. Its completion can
refresh or rerender the timeline at lines 6939–6943;
`rerenderTimelinePreservingScroll()` at lines 6885–6894 restores the scroller's
numeric offsets rather than ensuring the jump target remains visible. The
saved observations do not distinguish an initially unsuitable nested-scroll
landing from subsequent refresh/reflow. Both remain possible contributors;
the confirmed gap is that the settled destination is covered and no later
visibility correction occurs.

A repair should keep the passing canonical identity and time behavior while
ensuring the target is visible within both the timeline scrollport and the page
area below sticky controls after relevant layout settles. Validate that result
with both already-loaded and newly loaded lanes, and with graph refresh active.

This is separate from [SN011](correlation-pagination-focus.md), where pagination
moves a replacement focus control outside the viewport, and from the older
[duplicate-child event finding](../lane-sequences-audit-2026-10-20.md), where
focus moved to the wrong tree instance. Here both tested canonical root
instances are correct. No preceding report reviewed for this audit records
this exact covered-resource-jump failure.

No product code, skills, ledgers, aggregate counts or checkpoint were changed
by this report. Documentation drift check found no public plug-in boundary,
example or author-command change; no maintained authoring update or test-suite
run was required.
