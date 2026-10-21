# SN008 — P2: Full-capture range summary repeatedly stays loading for tens of seconds

On the existing local 1M demo, selecting the full **0–720-second** capture
repeatedly leaves **Loading range summary…** visible for more than 30 seconds,
including after that same full-range result has already been computed. The
normalized log can already report its complete matching-record count while
the summary remains pending. This delays inspecting aggregate failures,
affected resources, relationship changes and endpoint differences. Pressing
End on the range-end handle already at 720 seconds also discards the completed
facts and repeats the delay without changing either range boundary.

The primary auditor performed the browser operations on revision
`112d346447316af6ae8f5503c252d5b66d317b07`. This note reviews the saved browser
records and source investigation; its author did not run an additional UI
sequence, API timing or server profiler. The saved loading and completed
screenshots were also visually reviewed while preparing this note.

## Reproduction and observed result

Use the existing node-a demo at `http://127.0.0.1:8883/node#timeline`, with all
layers enabled, Normalized events only and search cleared. The actual capture
runs from `1759679999996000000` to `1759680719996000000` ns, a duration of
720 seconds, with 1,250,005 normalized events.

1. At Fit, apply a narrow range near either capture boundary. S093 uses
   **0–0.01 s**; S098 uses **719.986–719.996 s**.
2. Focus the start range handle and press Home, then focus the end handle and
   press End, waiting for each current range result. The final selected range
   is **0–720 s**. Handle ordering/focus, capture bounds and cursor behavior
   remain correct.
3. Observe **Loading range summary…**. In the measured S098 final End operation,
   the panel is still loading at **36.207 s** and displays completed facts by
   **36.639 s** after the recorded action start.
4. After completion, explicitly reapply the identical **0–720 s** selection.
   SX005 again observes loading at **23.344 s** and **33.501 s**. Its next saved
   completed observation is at **62.874 s**; the exact completion time between
   those observations is unknown.
5. During SX005's pending summary, Back moves the viewport to
   **+599.0–610.9 s**, and Forward restores **+0.0–720.0 s**. The selected range
   stays **0–720 s**. Both pending states already show **1,250,005 matching
   records** in the normalized log. The eventual summary does not overwrite
   the final viewport.
6. With completed **0–720 s** facts visible, focus the range-end handle already
   at 720 and deliver native End. SX006 immediately replaces the facts with
   loading while both boundaries, viewport and cursor remain unchanged. It is
   still loading at **30.487 s** and first observed complete at **43.935 s**.
   End-handle focus is preserved throughout. The earlier failed locator attempt
   did not deliver input and is excluded; the recorded native interaction is
   the evidence for this redundant operation.

This is a slow summary operation, not a demonstrated global UI freeze. The
log observation establishes that its selected-period result/count is available;
it does not mean 1.25 million log rows were rendered in the DOM.

## Timing evidence and limits

| Sequence | Action start, UTC on 2026-10-21 | Last observed loading | First observed complete | Supported conclusion |
| --- | --- | --- | --- | --- |
| S098 final End to 0–720 | 08:39:07.414 | 08:39:43.621 / 36.207 s | 08:39:44.053 / 36.639 s | The observed UI transition lies between these two samples. |
| SX005 identical reapply | 08:41:57.278 | 08:42:30.779 / 33.501 s | 08:43:00.152 / 62.874 s | Loading persists past 33.5 s; completion is only known by the later check. |
| SX006 unchanged End | 08:45:13.725 | 08:45:44.212 / 30.487 s | 08:45:57.660 / 43.935 s | A no-op boundary key replaces completed facts with another prolonged loading state. |

These are **browser action-to-observation wall times**, including automation
and observation overhead. They are not server request-duration, CPU, RSS or
heap measurements. In particular, **62.874 seconds is not a measured service
latency**, and SX006's 43.935-second check likewise gives only an upper observation
bound. There is no paired HTTP start/finish instrumentation or phase profile
in this evidence. Reapplying an already computed range demonstrates recurrence;
it does not prove which internal caches were populated or attribute a cold/warm
speed difference.

[S093.json](../../.runtime/audit-600-2026-10-21/single-node/S093.json) is the
initial discovery: functional handle/count assertions pass, but its prolonged
loading observation was later classified with this repeated issue. Its long
tool call also performed accessibility work and is not used as an exact timing.
[S098.json](../../.runtime/audit-600-2026-10-21/single-node/S098.json) contains
the tighter measured interval, also saved separately in
[full-range-timing-02.json](../../.runtime/audit-600-2026-10-21/single-node/full-range-timing-02.json).
[SX005.json](../../.runtime/audit-600-2026-10-21/single-node/SX005.json) records
the identical-query repetition and responsive Back/Forward control.
[SX006.json](../../.runtime/audit-600-2026-10-21/single-node/SX006.json) adds
the no-op End repetition with exact unchanged bounds and verified handle focus.

The [visible loading screenshot](../../.runtime/audit-600-2026-10-21/single-node/SN008-full-range-loading-visible.png)
shows **0–720 s** and the loading label during SX005's approximately 33.5-second
pending observation. The
[completed screenshot](../../.runtime/audit-600-2026-10-21/single-node/SN008-full-range-complete.png)
shows populated aggregate facts and endpoint-scope disclosure. Images establish
the visible states, not exact durations. The earlier image named
`SN008-full-range-loading.png` did not show the summary and is excluded as
loading evidence.

Completed facts agree across the saved runs: **1,250,005 events**, **24,925
failures**, **7,502 affected resources**, **459,898 relationship changes**, and
**500 of 7,502 endpoint states evaluated**, with five truncated detail sets.
The bounded endpoint comparison is disclosed correctly; no incorrect aggregate
count or missing full-result completion is claimed by this finding.

## Likely cause from source, not measured attribution

The separate
[source investigation](../../.runtime/audit-600-2026-10-21/single-node/full-range-latency-source.md)
identifies the strongest candidate in
[normalized_data.py](../../src/router_dump_analyzer/normalized_data.py):
`range_summary()` at lines 4095–4110 redacts/projects every selected event into
`projected_selected`. The event-detail response limit of 500 is applied only at
line 4176, after the full list and additional aggregate passes have been built.
For this selected stream, that means work proportional to all 1,250,005 events
despite bounded returned details. The compiled projection policy is cached;
this is not a claim that it is rebuilt for every event.

The timestamp index narrows range lookup, but a full-capture range still selects
the entire event stream. Endpoint evaluation has its own 500-resource cap; the
source does **not** evaluate every one of the 7,502 endpoints. Relationship and
status processing add work, and first-touch resource intervals may need building.
The evidence does not assign percentages of elapsed time or memory to any of
these stages. The frontend renders bounded summary details rather than 1.25
million event DOM nodes.

[app.js](../../frontend/assets/app.js), `requestRangeSummary()` at
lines 5194–5229, has stale-request/abort guards but no result cache,
unchanged-range check or debounce. Range-handle handling at lines 4087–4120
requests the summary and refreshes the log independently, consistent with their
different completion times. SX006 establishes the redundant no-op refresh
through the actual UI; attribution of its elapsed cost remains unprofiled.
The synchronous range endpoint at
[runtime_api.py](../../src/router_dump_analyzer/web/runtime_api.py),
lines 2053–2072, supplies no cooperative disconnect probe to this computation.
Redundant or cancelled work could amplify cost, but overlap is **not established**
for the timed repetition and is not required to demonstrate the visible delay.

A focused repair direction is to collect exact safe aggregate facts while
projecting only the bounded event-detail prefix, preserving redaction, ordering,
counts and independent truncation semantics. Truncating the selected stream
before counting would be incorrect. Add visit/projection-count checks and
repeat the actual full-range browser measurement before claiming improvement;
unchanged-range reuse and cooperative cancellation are separate follow-ups.
No repair or new index was implemented for this audit note.

This differs from the prior cancelled-brush/orphaned-loading correctness issue:
these selections eventually complete successfully without that cancellation
sequence. S093, S098, SX005 and SX006 are related observations of this one SN008
finding; case counts and overall audit totals remain owned by the ledgers and
main report.

## Further handle-key repetition

S103 starts with the settled 50–60-second range, moves the start inward with
Right and the end inward with Left, reapplies the original range, and expands
with Home/End. Exact boundaries, focus, viewport, cursor and final log counts
all pass. The full-capture summary is still loading at **37.829 seconds** and
is complete at the next recorded check, **89.393 seconds**. The latter is only
an upper observation bound: unrelated packet checks occurred between samples.
This reproduces SN008 without establishing an 89-second service duration.
See [S103 evidence](../../.runtime/audit-600-2026-10-21/single-node/S103.json).

S108, S113 and S118 also complete their functional handle sequences correctly.
Their first timed full-result checks are already complete at 55.423, 42.108
and 45.454 seconds, respectively; those values are not latency measurements.
S108's summary and an unrelated route retrace were concurrently pending and
both eventually completed. No request-level timing or causal attribution was
established, so that overlap is not a second confirmed performance defect.

## Documentation drift check

Completed. This report changes no product, plug-in API, fixture, skill, example
or author-facing command. No maintained plug-in authoring update or test rerun
was required for this evidence-only change.
