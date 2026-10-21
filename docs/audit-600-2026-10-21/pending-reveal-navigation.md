# Pending Reveal supersedes newer navigation — known finding reproduced

S067, S069 and S070 reproduce the existing P2 issue in
[finding 1 of the repeated cross-component audit](../repeated-cross-component-audit-2026-10-21.md):
an older toolbar Reveal can override a newer viewport command after log
selection resolution finishes. Back, pan and explicit lane hiding each fail
in two controlled route-event attempts. S077, S079 and S080 add the same
failures with an exact ETG event, including two more lane-hide attempts.
S087, S089 and S090 repeat them with the final single-effect DTE event.
S068, S078 and S088's unchanged-End interactions are passing controls. These are
renewed observations of the known issue, not new unique cross-audit findings.

The primary auditor performed the UI operations. This note's author reviewed
the saved observations, proxy lifecycle log and source at `112d346`; no
additional browser execution or source-function probe is claimed here.

## S067: two confirmed Back reproductions

Evidence is in [S067.json](../../.runtime/audit-600-2026-10-21/single-node/S067.json),
with the first attempt also retained in
[S067-controlled-first.json](../../.runtime/audit-600-2026-10-21/single-node/S067-controlled-first.json).
The [natural attempt](../../.runtime/audit-600-2026-10-21/single-node/S067-natural-attempt.json)
did not establish pending overlap and is excluded from the race conclusion.

The isolated browser origin was `http://127.0.0.1:8896/node`, forwarding real
requests to the existing `http://127.0.0.1:8883` demo. The temporary
[proxy](../../.runtime/audit-600-2026-10-21/delay-proxy.mjs) delayed only
`POST .../event-log/selection` by `15000` ms **before forwarding**. It did not
fabricate the response or change application state. Its
[lifecycle log](../../.runtime/audit-600-2026-10-21/delays.log) records request
arrival, configured delay, forwarding, response finish and close. Response
finish identifies the proxy handing off the completed response, not the time
the browser finished rendering; the final DOM observations supply that part.

Reproduction:

1. Establish the browser-only baseline against the same demo and pre-reveal
   `node-a/scenario/node-a-route-create`, the event at approximately +30 s on
   `node-a/control-plane/IP_ROUTE/route:blue:198.51.100.0/30`.
2. Apply and zoom +500–600 s, then +50–60 s. Record the actual viewport bounds:
   +490.4–609.5 s and +49.0–60.9 s respectively.
3. Clear and reselect the exact normalized-log row to require a fresh selection
   request. Activate toolbar **Reveal in timeline**.
4. While that real request is held by the proxy, activate **Back view**. The
   viewport returns to +490.4–609.5 s and **Forward view** becomes enabled.
5. Let the delayed request finish and the UI settle. The old Reveal moves the
   viewport to +0.0–119.0 s, focuses the old event mark and disables Forward.
6. Recreate the two windows and fresh selection, then repeat the overlap.

Both attempts have request-lifecycle evidence that Back completed before the
selection request was even forwarded:

| Attempt / request ID | Request arrived (UTC) | Back action interval (UTC) | Forwarded (UTC) | Finished, HTTP 200 (UTC) |
| --- | --- | --- | --- | --- |
| First / 99 | 06:15:39.029 | 06:15:39.046–06:15:40.099 | 06:15:54.035 | 06:15:54.049 |
| Repeat / 175 | 06:16:43.132 | 06:16:43.149–06:16:44.105 | 06:16:58.136 | 06:16:58.149 |

All timestamps are on 2026-10-21 in proxy session
`2026-10-21T06:13:55.925Z-19160`. In the combined evidence, state 3 is the first
successful Back and state 4 is its stale overwrite; states 8 and 9 are the
corresponding repeat. The `history.back` and `history.forward` booleans record
the controls' **disabled** properties: `forward: false` immediately after Back
becomes `forward: true` after the overwrite. These are not booleans indicating
history availability.

This demonstrates incorrect ordering under controlled latency. The artificial
15-second delay is not a natural-latency, CPU or memory regression measurement.

## Cause: newer actions do not invalidate navigation ownership

The toolbar already establishes ownership **before** awaiting selection:
`revealFocusedEventLogSelection()` increments and captures
`timelineNavigationIntent`, awaits `resolveEventLogSelection()`, then compares
the captured value with the current one
([app.js:10924–10928](../../frontend/assets/app.js)). The problem is not a guard
introduced too late after the await.

`restoreTimelineView()` updates the history index and viewport, invalidates an
old timeline request, rerenders and schedules current-window refinement, but
does not advance `timelineNavigationIntent`
([app.js:11418–11437](../../frontend/assets/app.js)).
`invalidatePendingTimelineWindowRequest()` only increments `timelineRequestId`
and aborts the timeline controller
([app.js:5421–5427](../../frontend/assets/app.js)). That protects timeline data
from an obsolete window; it does not invalidate the separately pending
selection continuation.

Consequently, the old toolbar continuation still passes its navigation check.
It invokes `jumpToTimelineEvent()`, which creates another navigation intent,
reveals the event and later focuses its mark
([app.js:4463–4514](../../frontend/assets/app.js)). The reveal moves the viewport
through `moveTimelineWindowToReveal()` and `applyTimelineZoom()`
([app.js:4365–4374](../../frontend/assets/app.js),
[app.js:11511–11526](../../frontend/assets/app.js)).
`rememberTimelineView()` removes history entries after the restored index when
recording that new viewport
([app.js:11312–11319](../../frontend/assets/app.js)). This explains both the
overwritten Back result and the lost Forward entry.

## S069: pan variant confirmed twice in the browser

[S069.json](../../.runtime/audit-600-2026-10-21/single-node/S069.json) adds two
controlled browser reproductions of the same ownership defect. The earlier
audit had source-function probe evidence for pan; these actual UI sequences
expand the browser coverage without introducing a separate underlying bug.

Starting at +49.0–60.9 s, the auditor initiated the delayed toolbar Reveal and
activated **Pan timeline later**. Both attempts immediately moved to
+50.2–62.1 s, but the older selection response subsequently moved the viewport
to +24.0–35.9 s and focused the old event. One subsequent **Back view** returned
to +50.2–62.1 s, rather than reaching the original +49.0–60.9 s window: the
obsolete Reveal had inserted an unwanted extra history entry. Back was
following that modified history, not independently choosing the wrong index.

| Attempt / request ID | Request arrived (UTC) | Pan action interval (UTC) | Forwarded (UTC) | Finished, HTTP 200 (UTC) |
| --- | --- | --- | --- | --- |
| First / 322 | 06:18:42.364 | 06:18:42.397–06:18:43.496 | 06:18:57.371 | 06:18:57.383 |
| Repeat / 400 | 06:19:36.863 | 06:19:36.864–06:19:37.853 | 06:19:51.875 | 06:19:51.887 |

These timestamps use the same date, proxy session and 15-second transport
delay as S067. States 2–4 show the first pan, overwrite and subsequent Back;
states 6–8 show the repeat.

## S070: later lane hiding is undone twice; settled hide recovers

[S070.json](../../.runtime/audit-600-2026-10-21/single-node/S070.json) records
two repeats using the exact canonical route resource named in S067. After
starting the delayed toolbar Reveal, the auditor opened **Lanes** and unchecked
that resource while selection resolution remained pending. Both immediate
states show an unchecked target, no actual target resource row and **Lanes
13 / 7,510**. After the older response completed, the target was checked again,
its row returned, the count was **14 / 7,510**, the viewport moved to
+24.0–35.9 s and focus returned to the old event mark.

| Attempt / request ID | Request arrived (UTC) | Hide action interval (UTC) | Forwarded (UTC) | Finished, HTTP 200 (UTC) |
| --- | --- | --- | --- | --- |
| First / 474 | 06:20:43.759 | 06:20:44.711–06:20:46.022 | 06:20:58.770 | 06:20:58.784 |
| Repeat / 546 | 06:21:40.803 | 06:21:41.682–06:21:43.015 | 06:21:55.812 | 06:21:55.823 |

The same date, proxy session and 15-second delay apply. States 2 and 5 prove
the successful hides before forwarding; states 3 and 6 show their later undo.
After the second response, the auditor unchecked the target again. Settled
state 7 shows unchecked, no row and count 13, establishing a successful next
action once obsolete work is no longer pending. The failure is ordering of
user intent, not an inability to hide this resource or a permanent mismatch
between the checkbox and rendered rows.

The [post-response screenshot](../../.runtime/audit-600-2026-10-21/single-node/S070-readded-after-response.png)
shows the checked target and returned resource row. The separate image named
[S070-hidden-while-pending.png](../../.runtime/audit-600-2026-10-21/single-node/S070-hidden-while-pending.png)
also depicts the checked, returned row at +24.0–35.9 s; despite its filename it
is **not** before-response evidence. The before-response claim rests on the
timestamped request/action records and DOM states 2/5, not that image.

The same source omission exists in the accepted pan operation
`panTimelineViewportByPixels()`
([app.js:11643–11667](../../frontend/assets/app.js)) and explicit lane visibility
`setExplicitLaneVisibility()`
([app.js:7827–7846](../../frontend/assets/app.js)). The latter is called directly
by the Lanes checkbox change handler
([app.js:8070](../../frontend/assets/app.js)). When the obsolete toolbar
continuation survives, `jumpToTimelineEvent()` explicitly removes the hidden
resource ID and makes its lane available
([app.js:4472–4489](../../frontend/assets/app.js)). That is legitimate for a new
explicit Reveal, but incorrect when a later hide should have superseded it.

## S068: unchanged End protects the newer cursor intent

S068 is a browser-confirmed protected control, recorded in
[S068.json](../../.runtime/audit-600-2026-10-21/single-node/S068.json).
Request 255 arrived at `06:17:38.224Z`; the unchanged-End interaction occurred
at `06:17:38.255–06:17:40.646Z`, before forwarding at `06:17:53.234Z` and HTTP
200 completion at `06:17:53.247Z`. The slider was already at `1000000` before
the second End. After completion it remained at the actual capture endpoint,
with focus on `time-cursor`, the prior inspector preserved and the viewport
still +49.0–60.9 s. ArrowLeft sent to the current focus, without retargeting the
slider, then changed its value to `999999`. Retaining the event inspector is
expected: cursor interaction does not itself clear the selected event UID.

The source explains this contrasting result. `timelineCursorInteraction()`
advances the same navigation intent on an End key or pointer interaction even
when the slider value does not change
([app.js:4158–4161](../../frontend/assets/app.js)); input, keydown and pointerdown
are bound at [app.js:12204](../../frontend/assets/app.js). This allows the
existing post-selection guard to discard the older toolbar continuation.

## S077–S080: exact ETG event repeats and unchanged-End control

The primary auditor repeated the sequences using
`node-a/scale-event-00000000`, the `evpn_single_home_service_create` event at
+120.000 s on `node-a/data-bridge-layer/ETG/blue/etg-000000`. These browser
operations used the same isolated origin and real backend described above,
with the 15-second selection-request delay in proxy session
`2026-10-21T07:30:48.034Z-22356`. All times below are UTC on 2026-10-21.

| Case / request ID | Request arrived | Newer action interval | Forwarded | Finished, HTTP 200 |
| --- | --- | --- | --- | --- |
| S077 Back / 169 | 07:33:56.350 | 07:33:56.352–07:33:57.479 | 07:34:11.355 | 07:34:11.380 |
| S078 unchanged End / 245 | 07:34:58.530 | 07:34:58.565–07:35:00.810 | 07:35:13.541 | 07:35:13.565 |
| S079 pan / 379 | 07:37:05.397 | 07:37:05.398–07:37:06.501 | 07:37:20.400 | 07:37:20.411 |
| S080 first hide / 435 | 07:38:14.787 | 07:38:16.051–07:38:17.938 | 07:38:29.792 | 07:38:29.803 |
| S080 repeat hide / 506 | 07:39:52.445 | 07:39:53.823–07:39:55.831 | 07:40:07.461 | 07:40:07.473 |

Each newer action completed before the corresponding selection request was
forwarded. Final observations were recorded after response completion; this
separates demonstrated pending overlap from merely issuing actions quickly.

[S077.json](../../.runtime/audit-600-2026-10-21/single-node/S077.json) records
the Back repetition. Its `immediate` state at 07:33:57.544 shows the restored
+490.4–609.5 s window and enabled Forward control. After the older response,
`final` at 07:34:38.197 shows +60.4–179.5 s, disabled Forward and focus on the
selected ETG cluster. The exact log UID remains selected. This repeats the
viewport and history overwrite with a different event and canonical resource.

[S078.json](../../.runtime/audit-600-2026-10-21/single-node/S078.json) is the
passing control: `endpoint` already has cursor `1000000` before Reveal, and
the newer End key leaves that value unchanged. After the response, `final`
still has cursor `1000000`, focus on `time-cursor` and viewport +49.0–60.9 s.
ArrowLeft delivered to the current focus then produces `999999` in `arrow`.
The selected ETG event is retained, as expected for cursor interaction. This
supports the existing cancellation mechanism for an unchanged cursor value;
it does not repair the other handlers' missing invalidation.

[S079.json](../../.runtime/audit-600-2026-10-21/single-node/S079.json) records
a complete pan sequence. `immediate` at 07:37:06.552 shows +50.2–62.1 s after
**Pan timeline later**. The post-response `final` at 07:37:46.539 instead shows
+114.0–125.9 s and focus on the exact ETG event mark. The next Back returns to
+50.2–62.1 s, showing the unwanted Reveal history entry rather than a separate
Back-index defect. The
[preliminary S079 record](../../.runtime/audit-600-2026-10-21/single-node/S079-preliminary.json)
read the UI too early and attempted Back before a settled conclusion. It is
explicitly superseded by this complete sequence and is not counted as an
additional reproduction or a passing result.

[S080.json](../../.runtime/audit-600-2026-10-21/single-node/S080.json) contains
two ETG hide repetitions. The first `immediate` and `repeat.immediate` states
show the exact target unchecked, no target row and **Lanes 12 / 7,510**.
Their respective `final` states show it checked again, the row restored and
**Lanes 13 / 7,510**, with +114.0–125.9 s in view and the exact ETG mark focused.
Both `rehide` states successfully remove the row again after the response.
The before/hide/overwrite count is **13 → 12 → 13** here; the earlier route
case's **14 → 13 → 14** must not be substituted for these observations.

These repetitions broaden resource and event coverage of the same ownership
defect. They do not establish a second cause or a natural 15-second latency,
CPU or memory regression.

## S087–S090: final DTE event repeats and protected cursor control

The final normalized scale event, `node-a/scale-event-01249999`, is a
`dte_next_hop_dependency_change` at +624.999 s with one affected resource,
`node-a/data-bridge-layer/DTE/blue/dte-000249`. The preceding S081–S086 settled
controls passed double-click, Ctrl+Enter/Escape, three toolbar reveals,
restoration of only the required disabled layer, a reverse-log round trip and
three Back/Forward cycles. This distinguishes the pending-selection failure
from ordinary navigation or the separate multi-effect target-layer finding.

The same primary auditor then ran these controlled overlaps in proxy session
`2026-10-21T07:30:48.034Z-22356`. Each new action again finished before the real
request was forwarded, and final DOM observations followed HTTP completion.
All times are UTC on 2026-10-21.

| Case / request ID | Request arrived | Newer action interval | Forwarded | Finished, HTTP 200 |
| --- | --- | --- | --- | --- |
| S087 Back / 1594 | 07:53:48.473 | 07:53:48.473–07:53:52.384 | 07:54:03.482 | 07:54:03.746 |
| S088 unchanged End / 1684 | 07:54:46.517 | 07:54:46.541–07:54:50.997 | 07:55:01.530 | 07:55:01.542 |
| S089 pan / 1741 | 07:55:41.857 | 07:55:41.859–07:55:45.911 | 07:55:56.859 | 07:55:57.063 |
| S090 first hide / 1864 | 07:56:59.088 | 07:57:03.219–07:57:03.714 | 07:57:14.098 | 07:57:14.108 |
| S090 repeat hide / 1995 | 07:58:19.016 | 07:58:22.916–07:58:23.231 | 07:58:34.029 | 07:58:34.042 |

[S087.json](../../.runtime/audit-600-2026-10-21/single-node/S087.json) shows
Back restoring +490.4–609.5 s with Forward enabled in `immediate`. After the
response, `final` instead shows +565.4–684.5 s, disabled Forward and focus on
the canonical DTE cluster whose `data-last-event-uid` is the exact target.

[S088.json](../../.runtime/audit-600-2026-10-21/single-node/S088.json) passes:
the second End leaves cursor `1000000` unchanged while selection resolution
is pending. `final` preserves that value, `time-cursor` focus and the
+49.0–60.9 s window. ArrowLeft on the current focus then changes the value to
`999999`. This is the same protected unchanged-value control as S068/S078.

[S089.json](../../.runtime/audit-600-2026-10-21/single-node/S089.json) shows
pan moving +49.0–60.9 s to +50.2–62.1 s before forwarding. The old response
then moves to +619.0–630.9 s and focuses the target DTE cluster. Back returns
to +50.2–62.1 s, again exposing the inserted stale Reveal history entry.

[S090.json](../../.runtime/audit-600-2026-10-21/single-node/S090.json) adds two
hide repetitions. `immediate` and `repeat.immediate` have the canonical DTE
checkbox unchecked, no target row and **Lanes 12 / 7,510**. Both corresponding
`final` states have it checked again, the row restored and **Lanes 13 / 7,510**,
with +619.0–630.9 s in view and the exact containing cluster focused. Each
settled `rehide` removes the lane successfully. These repeat the
**13 → 12 → 13** overwrite, without adding a unique bug.

The [immediate screenshot](../../.runtime/audit-600-2026-10-21/single-node/S090-immediate-hidden.png)
shows the exact DTE checkbox off and the count at 12. The
[post-response screenshot](../../.runtime/audit-600-2026-10-21/single-node/S090-stale-reveal-restores-lane.png)
shows the restored DTE249 row at +619.0–630.9 s, but an event popup overlaps
the picker. The checked-after claim therefore rests on the saved exact
checkbox DOM observations, not visibility of that checkbox in the latter
image. Neither screenshot is used to infer response timing; the lifecycle
records and timestamped states provide that evidence.

## Repair and regression scope

For a minimal repair, accepted user history, pan and lane-visibility actions
should invalidate the old navigation intent. Avoid unconditionally doing so in
every generic viewport helper: event navigation itself calls
`applyTimelineZoom()` and timeline-request invalidation after capturing its own
intent. Changing those helpers indiscriminately can cancel the jump's own
selection/focus continuation or interfere with ordinary window refinement.

The current [cross-component recovery tests](../../frontend/tests/cross_component_recovery.test.mjs)
cover toolbar selection superseded by cursor/resource selection (lines 29–52)
and direct-event navigation superseded by unchanged cursor interactions (lines
54–71). The [pan harness](../../frontend/tests/timeline_navigation.test.mjs)
checks viewport arithmetic and refresh behavior without a pending toolbar
selection continuation. A regression should compose the actual originating
Back/pan/hide handlers with that pending selection request and assert the
final window, history, visibility and focus. No tests were rerun for this
report-only work.

## Documentation drift check

Completed for this audit note. No product, plug-in API, fixture, skill, example
or author-facing command changed; maintained plug-in authoring documents need
no update. Case execution and counts remain owned by the main audit ledger.
