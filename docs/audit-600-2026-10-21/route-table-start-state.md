# MN010 — P2: route-table seeding leaves the start control in the previous direction's state

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed in M188, repeated in M191, and confirmed in the
inverse direction in MX012.

**Use in trace** changes the form's trace direction but does not update the
enabled state or help text of **Start trace at**. A Return seed leaves the
Forward-only observation field enabled and marked used. A Forward seed after
Return mode leaves that required field disabled and marked unused, preventing
the user from editing it. Both mismatches persist after a successful trace.
The observed trace direction and endpoint identities themselves remain correct.

## Return seed from Both directions — M188

1. Load `single-active-primary` with Both directions, strict policy, observed
   steering and default limits, then execute the baseline trace.
2. In Route tables, inspect the node-b main row
   `node-b/route/single-active-primary`. Its visible plug-in details identify
   the Return direction. Use the protocol and exact displayed-prefix filters
   to retain that row, then click **Use in trace**.
3. The form changes to **Return only**, preserving source `node-a` and
   destination `node-b`. Start trace at is populated with **PE-B / Beta NOS**,
   but remains enabled. Its field has `data-route-start-usage="used"` and
   displays **Forward observation/lookup node; it may be a transit node**.
4. Explicitly trace. The successful Return result correctly runs from PE-B
   toward PE-A, and the exact source row is marked as used by the focused trace.
   The start field still has the stale enabled/used state and Forward help.
   **Show source row** also returns to the correct node-b row.

This is not a claim that the Return query uses the displayed Forward start.
The failing assertion concerns the misleading editable control; the seeded
trace and source-row navigation pass.

M191 repeats the Return seed on `all-active-ecmp`, using the exact node-b main
row `node-b/route/all-active-ecmp`. The Return trace succeeds with two active
paths and correctly focuses that row; Show source row also selects the correct
node. Start trace at nevertheless remains enabled and marked used with Forward
help after completion. This extends MN010 across another scenario without
adding a distinct defect or a failed route execution.

## Inverse seed and manual recovery — MX012

Starting from M188, manually change Directions to **Both**, then **Return only**.
This real change correctly disables Start trace at, marks it unused, and shows
**Not used for return-only tracing; return starts at the destination side**.

Then click **Use in trace** on the same scenario's node-a Forward candidate,
`node-a/route/candidate/single-active-primary/1`. The form changes to
**Forward only**, and the start value changes to **PE-A / Alpha NOS**. It remains
disabled and marked unused with Return-only help. An explicit Forward trace
succeeds with the selected candidate and no error, but the start field remains
disabled afterward.

Manually changing **Both → Forward only** restores an enabled, used start field
and Forward help. That recovery also clears the seeded-row association as the
normal direction-change handler specifies; it is not evidence that the seeded
row reference survives the manual workaround. The candidate control avoids
MN009's separate main-row endpoint-identity failure.

## Evidence and scope

- [M188.json](../../.runtime/audit-600-2026-10-21/multi-node/M188.json):
  `seededForm` records Return controls; `seededTable.start` and
  `resultTable.start` record the stale enabled/used state before and after the
  successful Return result. `sourceReturn` records source-row navigation.
- [M191.json](../../.runtime/audit-600-2026-10-21/multi-node/M191.json):
  `result` records two active Return paths; `resultTable` records the exact
  focused ECMP row and its stale enabled/used start control.
- [MX012.json](../../.runtime/audit-600-2026-10-21/multi-node/MX012.json):
  `manualReverse` establishes the correct disabled baseline; `forwardSeed`
  and `forwardAfter` preserve the incorrect state; `recovered` records the
  manual direction-toggle control.
- [Return seed screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN010-return-seed-start-enabled.png)
  shows Return only beside the enabled start field and Forward help.
- [Forward seed screenshot](../../.runtime/audit-600-2026-10-21/multi-node/MN010-forward-seed-start-disabled.png)
  shows Forward only beside the disabled field and Return-only help.

The primary auditor performed the browser actions; this report's author
reviewed the records, both screenshots and source. Hidden prior-result text
in an invalidated form is not treated as a new trace result. No request-body
capture, wrong backend path, CPU, memory or latency claim is made. These are
two directions of one control-state defect.

## Source cause and repair invariant

`useRouteTableEntry()` writes the direction select's `.value` at
[topology.js:9593–9595](../../frontend/assets/topology.js), then invalidates the
old result and updates the URL without synchronizing dependent start controls.
Programmatically setting `.value` does not invoke the select's change handler.

The existing `syncRouteStartControlState()` at lines 2982–2994 derives the
enabled state, `is-unused` class, usage attribute and help text from the current
direction. Its only call sites are initial control rendering at line 4471 and
the real direction-change handler at lines 9997–10001. Neither route-table
seeding nor trace completion calls it.

Trace construction separately reads the actual direction at lines 3025–3027
and includes the Forward start only when appropriate at lines 3083–3087.
This explains why the tested Return and Forward requests can succeed despite
the incorrect field presentation. The busy-state helper at lines 245–257
remembers and restores the field's pre-request disabled state; completion at
lines 9786–9795 therefore preserves the stale state instead of repairing it.

Synchronize the existing start-control presentation after applying a row's
direction and retiring any previous request, while preserving the exact
seeded-row reference. Dispatching the normal direction-change event is not
equivalent: that handler also calls `clearFocusedRouteEntry()`. Validate both
direction replacements, the state before and after submission, and any pending
trace replacement so busy-state restoration cannot reintroduce stale controls.

The existing [route-table entry regression](../../frontend/tests/topology_entry_regressions.test.mjs)
checks scenario guidance after seeding, not direction-dependent input state.
The [route control harness](../../frontend/tests/route_controls.test.mjs) stubs
`syncRouteStartControlState()`. These tests were inspected, not rerun.
This finding is distinct from [MN009](route-table-seed-identity.md): the traces
here succeed, while the field's editable state and explanatory text are wrong.

Only this report was changed for the reporting task. No product code, skills,
ledgers, aggregate counts or checkpoint were edited. Documentation drift check
found no public plug-in boundary, example or author-command change; no
maintained authoring update was required.
