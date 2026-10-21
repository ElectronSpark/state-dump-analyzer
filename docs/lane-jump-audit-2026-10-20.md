# Resource lanes and jump exploration — 2026-10-20

Follow-up: findings were repaired and validated in
[Outstanding frontend audit fixes](outstanding-audit-fixes-2026-10-20.md).
The observations below describe the pre-fix audit.

This follow-up found three browser-confirmed frontend bugs and one navigation
race confirmed by an isolated production-function probe. No production code or
skills were changed. The earlier [four fixes](frontend-fixes-2026-10-20.md)
remain in the working tree, together with the pending backend optimizations.

The parent used the actual in-app browser on `http://127.0.0.1:8883/node`, PE-A,
with 1,250,005 events and 7,510 resources. A parallel agent used the validation
skill for source review and focused tests. Browser observations are distinguished
from source-only results below. Local evidence is under
`.runtime/lane-jump-audit-2026-10-20/`.

## P2 — Selecting another resource restores lanes excluded by Selected mode

Browser reproduction:

1. Open Lanes and choose **Selected** with `etg-000000` selected. Wait for
   `Lanes 1 / 7,510 · 2 logs`.
2. In Resource tables, search the ETG path bundles for `etg-001874`.
3. Click that resource's name and wait for its timeline request to settle.

The new resource becomes the selected focus, but the timeline grows to
**14 resource lanes**, restoring the previous representative resources such as
`etg-000000`, `etg-000001`, Ethernet Segments, routing and ETE lanes. Selecting a
new resource should preserve the Selected-only intent; a deliberate switch to a
custom set must at least begin from the currently displayed mode's selection,
rather than restoring an obsolete set.

Cause: `frontend/assets/app.js:7656` in `selectResource()` changes `laneMode` to
`custom` when a resource has no loaded lane, then appends to the old
`explicitLaneIds`. It does not first capture the current mode's lane set.
Equivalent patterns exist in event/resource jump helpers.

Evidence: `selected-before-resource-jump.txt`,
`selected-after-resource-jump.txt`, `selected-after-resource-jump.png`.
The isolated source probe independently produces `[a,b,c,d]` after selecting
missing resource `d` when Selected mode had only `a` loaded.

## P2 — Lane-checkbox updates discard keyboard focus

Browser reproduction:

1. Open Lanes, search for `etg-00187`, and keyboard-toggle the
   `etg-001870` checkbox with Space.
2. The checkbox becomes checked, but `document.activeElement` becomes BODY.
3. Press Tab. Focus moves to the **Router State Lab overview** link at the top
   of the page instead of continuing through the lane choices.

Repeating Space on `etg-001871` also lost focus to BODY. This interrupts ordinary
keyboard selection of multiple lanes and can send the next key to an unrelated
page control.

Cause: `renderLanePicker()` at `frontend/assets/app.js:7850` replaces the
checkbox subtree during the render triggered by `setExplicitLaneVisibility()`.
Existing focus restoration covers timeline content, not the picker controls.

Evidence: `lane-keyboard-body-focus.json` records BODY immediately after the
second toggle; `lane-keyboard-focus.json` records the header link after Tab;
`lane-keyboard-focus.txt` and `.png` retain the surrounding UI.

## P3 — Combined resource lanes ignore layer visibility

Browser reproduction:

1. Select a Data bridge resource, switch to **Combined**, and turn off the
   **Data bridge** layer chip.
2. The chip becomes unpressed, but the Data bridge root row and its correlation
   lane remain visible, with `Lanes 2 combined · 2 logs`.
3. Switch to **Separate** with the same layer disabled: the Data bridge resource
   rows disappear as expected.

The parent reproduced this with `etg-001874`, then again with `dte-000009`.
Combined mode disables canonical lane-selection presets, but leaves the layer
controls enabled without explaining that they do not hide the selected root.

Cause: `renderTimeline()` at `frontend/assets/app.js:3404` checks explicit hidden
resource IDs for the combined root but does not apply `activeLayers`. The
Separate path uses the filtered visible lanes. Either Combined must honor the
layer choice or the control must clearly convey a narrower scope.

Evidence: `combined-hidden-layer.txt`, `separate-hidden-layer.txt`,
`combined-hidden-layer-repeat.txt`, and their combined-view screenshots. The
repeat screenshot shows the off Data bridge chip and the remaining root without
the picker obscuring the view.

## P2 — Obsolete asynchronous jumps can override newer selections (source probe)

An isolated probe executing the production `jumpToTimelineResource()` function
reproduces this order:

1. Jump to missing resource `a` and leave its refresh pending.
2. Jump to already-loaded resource `b`; the current selection becomes `b`.
3. Complete the old refresh with `false`, indicating it was superseded.
4. The old jump nevertheless selects `a`: observed selection order `[b,a]`.

`frontend/assets/app.js:4499` unconditionally continues after the awaited
refresh. `jumpToTimelineEvent()` at line 4436 has the same lack of a navigation
intent check after awaiting. Lower-level latest-response protection prevents
obsolete query data from being accepted, but does not stop these later selection
and scroll side effects.

This is confirmed by the controlled production-function probe, **not by a
reliable browser reproduction in this pass**. Attempts to rapidly switch between
log rows encountered virtualization and a hover card obstructing the row center.
Selecting the unobstructed timestamp cell worked. Those automation delivery
issues are not counted as additional product bugs.

Evidence: `source-review/navigation-probes.mjs` and
`source-review/navigation-probes.log`. The fix should guard the navigation intent
through each await and scheduled focus/scroll callback, including replacement
and clear actions; checking query response freshness alone is insufficient.

## Performance observation

The first normalized-event search for `svc-000009` remained at **loading visible
page** at 37.359 seconds and displayed **1,195 matching records** by the next
completion observation at 82.250 seconds. Other UI work occurred between these
reads; this establishes observation bounds, not an exact search duration.

A repeat of the same search returned the visible result status in **388 ms**
measured around fill plus status wait, including browser automation overhead.
The source path builds the complete safe search corpus on first use, consistent
with the earlier controlled [projection measurements](validation-projection-2026-10-20.md).
No stuck-request defect or new performance regression is established here. The
global load banner has an index-building stage, although the local event-log
status only says it is loading a page.

Source review also found that obsolete search responses are discarded without
cancelling the outstanding request (`requestServerEventLogPage()` at line 9554,
`prepareServerEventLogQuery()` at line 9598). Abandoned terms may still perform
exact scans. This is an optimization candidate, not a measured regression from
the single-query browser check. No per-action CPU/RSS benchmark was run.

Evidence: `search-loading.txt`, `resource-event-search-ready.txt`,
`search-observations.json`, and `warm-search.json`.

## Passing paths and validation limits

| Path | Observation |
| --- | --- |
| None and Selected presets | None eventually showed zero resource lanes with an explicit empty state; Selected restored one. Source-record lanes remained independently visible. |
| Catalog search | The lane picker found the tail resource `etg-001874` beyond its first 300 displayed catalog entries. |
| Selected + correlated | At the final time, selected DTE9 loaded itself and its relevant ETG10 dependency. |
| Tree expansion | Expanding ETG10 added DTE9 as an inverse `next_hop` child: three actual rows representing two unique resources. This is expected, not an empty-expander bug. |
| Explicit lane hiding | The resource-table checkbox hid its lane. Merely selecting the corresponding graph node kept that explicit hide intact. |
| Event reveal | Selecting event `node-a/scale-event-00000009` and using Reveal in timeline enabled its hidden layer and focused its exact mark on an affected DTE9 resource lane. Its multi-resource effects remained listed. |
| Reveal outside viewport | After panning to about 127.9–447.9 s, revealing the event around 120 s moved the view to 0–320 s. |
| Reverse jump | The timeline mark's context-menu action Reveal in normalized log returned focus to TR `data-event-uid=node-a/scale-event-00000009`. |
| Lane focus | Control-click on the DTE9 lane label selected DTE9. A plain label click controls tree expansion and is not a resource-selection action. |

The focused existing tests passed: **44 passed, 0 failed**.

```text
node --test frontend/tests/timeline_navigation.test.mjs frontend/tests/timeline_layers.test.mjs frontend/tests/event_log_time.test.mjs frontend/tests/resource_table_rendering.test.mjs
```

The complete 404-test frontend run and conformance declaration inventory from
the immediately preceding fix validation remain applicable to the unchanged
production code; they were not rerun in this exploratory pass. The passing
existing tests do not cover the defects above. Browser warning/error logs were
empty.

The user's tab was reloaded and returned to Overview with the default selection,
Separate layout, all layers enabled, no filters/range, and the full capture
window. No durable management data or policy changed. This is targeted lane and
navigation exploration, not an exhaustive viewport, accessibility, pointer,
concurrency or scale matrix. Documentation drift check completed: this report
only records findings; maintained plug-in authoring materials need no update.
