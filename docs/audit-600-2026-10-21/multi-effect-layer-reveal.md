# SN007 — P2: a multi-effect reveal enables a different resource's layer

Revealing the ETG0 create event from outside the viewport leaves its Data
bridge layer disabled when the same event also appears on a loaded Control
plane neighbor lane. The viewport moves to the event and the inspector stays
on ETG0, but no ETG0 mark is rendered and keyboard focus stays on **Reveal in
timeline**. The browser reproduced this twice. Manually enabling Data bridge
restored the ETG0 mark and focus, while the unrelated Hardware driver layer
remained disabled.

This is one target/layer consistency finding. It does not establish that a
generic event reveal must always choose the primary affected resource.

## Browser evidence and reproduction

The primary auditor executed the browser interactions on the existing PE-A
demo with 1,250,005 normalized events and 7,510 resources. This note's author
reviewed the saved DOM states, screenshot and source at `112d346`, and ran the
synthetic production-function probe described below. No additional browser
execution is claimed here.

Evidence:

- [S074: two failed reveals and manual recovery](../../.runtime/audit-600-2026-10-21/single-node/S074.json),
  recorded at `2026-10-21T06:52:16.999Z`.
- [Execution ledger](single-node-results.jsonl), S074, records the failed
  target-layer/focus assertion and the successful unrelated-layer and manual
  recovery controls.
- [Screenshot: target layer still disabled](../../.runtime/audit-600-2026-10-21/single-node/S074-target-layer-stays-disabled.png)
  shows Control plane enabled, Data bridge and Hardware driver disabled, and
  the event-containing +114.0–125.9-second viewport. It was captured after
  Back/Forward returned to that failed window. It is supporting layer/window
  evidence, not direct evidence of the post-reveal focus; use the DOM states
  below for focus.

Exact identities:

- Event: `node-a/scale-event-00000000`,
  `evpn_single_home_service_create`, +120.000 seconds.
- Chosen target: `node-a/data-bridge-layer/ETG/blue/etg-000000`.
- Other affected resource: `node-a/control-plane/NEIGHBOR/blue/peer-00000`.

Reproduction:

1. Pre-reveal the event, retain its affected neighbor lane, and apply/zoom the
   selected +50–60-second range. The padded viewport is +49.0–60.9 seconds,
   outside the event time.
2. Hide ETG0 using its exact Lanes checkbox, disable **Data bridge** and
   **Hardware driver**, and keep **Control plane** enabled.
3. Select the exact normalized-log row with Enter. Its inspector identifies
   `Data bridge / etg-000000`. Activate the visible **Reveal in timeline**
   button and wait for the settled result.
4. Reapply the outside viewport and repeat using native Enter on the Reveal
   button. Inspect the settled layers, target marks, inspector and active
   element again.
5. Enable Data bridge manually and repeat from outside the viewport as a
   recovery control.

An earlier selector click did not establish action delivery and is excluded
from the reproduction count. The two counted actions both produced a settled
viewport change; the second used native keyboard activation.

| Observation | S074 states | Viewport | Data bridge | Event target and focus |
| --- | --- | --- | --- | --- |
| Before the first counted reveal | 0–1 | +49.0–60.9 s | Off | Log TR focused; inspector identifies ETG0; no target marks in the window |
| First settled failure | 2–3 | +114.0–125.9 s | Off | Inspector still ETG0; only the neighbor's mark for this UID is rendered; Reveal button focused |
| Outside-window reset | 4 | +49.0–60.9 s | Still off before repeat | No target marks in the window; inspector still ETG0 |
| Second settled failure | 5–6 | +114.0–125.9 s | Off | Same ETG0 inspector, neighbor-only mark and Reveal-button focus |
| Manual layer recovery and another reveal | 7–8 | +114.0–125.9 s | On | Exact ETG0 mark is rendered and focused; Hardware driver remains off |

State indexes are zero-based. The event and selected range are independent:
the +120-second mark is correctly tagged `out-of-range` while the selected
range remains +50–60 seconds. That class is not an additional failure. No
CPU, memory or latency finding is asserted here.

## Source cause

The event genuinely affects several resources. The create branch in
[the scale generator](../../demo/rsl_demo_generator/_scale.py), starting at
line 728, emits ETG, primary ETE, DTE, VIF and neighbor effects for this first
service. [The compact event builder](../../demo/rsl_demo_plugin/scale_data.py),
lines 624–638, puts the primary resource first in `affected_resources`.

In [app.js](../../frontend/assets/app.js):

1. Log-row Enter calls `focusEventLogEntry` and then `selectEvent` without a
   resource argument (lines 9922 and 10125). `selectEvent` chooses the first
   event resource and records it as `selectedEventResourceId` (lines
   4255–4265), explaining the ETG0 inspector before the reveal.
2. `jumpToTimelineEvent` captures a `resourceId` from an already loaded event
   lane or the first event resource (lines 4472–4473). With the event outside
   the queried window, the fallback can select ETG0. The jump clears that
   resource's explicit hidden state and moves the viewport.
3. After the awaited timeline refresh, it replaces `lane` using
   `eventLaneFor(eventUid) || state.laneByResource.get(resourceId)` (line 4502).
   This lookup is not restricted to the captured resource. `eventLaneFor`
   returns the first lane containing the UID (line 4456), and
   `normalizeTimeline` sorts lanes by layer/kind/label (line 2571). A loaded
   `control-plane/NEIGHBOR` therefore precedes `data-bridge-layer/ETG`.
4. The jump enables `lane.layer`, now potentially Control plane, but calls
   `selectEvent` and searches the rendered focus target using the original
   ETG0 `resourceId` (lines 4505–4534). Data bridge remains disabled, so the
   selected ETG0 mark cannot be found and focused.

The same action therefore uses one canonical resource for selection/focus
and another for layer visibility. This is a post-refresh target mismatch,
separate from the previously recorded pending-reveal navigation race.

## Controlled probe and scope limits

A read-only Node probe extracted the production `eventLaneFor` and
`jumpToTimelineEvent` functions. It started with ETG and neighbor lanes without
the target UID, Data bridge disabled, and Control plane enabled. Its simulated
awaited refresh populated both lanes with the same UID. The resulting selected
resource remained ETG0, but `activeLayers` contained only Control plane.
A second same-UID call then chose the neighbor.

The probe used stubbed rendering, refresh and selection dependencies. It
confirms the target/layer decision mismatch, not live DOM behavior or a new
browser case. The actual missing mark and retained toolbar focus are established
by S074.

Choosing another affected lane during a generic reveal remains an uncounted
policy ambiguity. An earlier [lane/jump audit](../lane-jump-audit-2026-10-20.md)
accepted an ETG-create event reveal on an affected DTE lane. Neither that
precedent nor the current tests establishes that all reveals must target ETG.
SN007 instead concerns preserving one action's already chosen resource through
visibility, selection and focus.

## Repair boundary and validation target

Keep the chosen canonical resource consistent across the awaited refresh and
resolve its own lane before enabling its layer. The existing captured
`resourceId` and `laneByResource` provide the required identity; this finding
does not require a new navigation API or a global multi-effect targeting policy.

Validate an outside-window multi-effect event with two affected resources in
different layers, one target hidden and its layer disabled. The settled reveal
must make the chosen target visible and focusable, preserve unrelated disabled
layers, and retain the same inspector identity. Repeat from outside the window
and include the manual-layer recovery control. Existing
[selection-recovery tests](../../frontend/tests/timeline_selection_recovery.test.mjs)
stub `eventLaneFor` with a single target and do not cover this two-resource
post-refresh substitution.

Documentation drift check: this report adds audit evidence only. It changes no
plug-in behavior, public APIs, examples or author commands; no maintained
authoring-document update or conformance rerun was required.
