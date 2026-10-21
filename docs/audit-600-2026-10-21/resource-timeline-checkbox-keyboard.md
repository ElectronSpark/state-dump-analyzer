# SN015 — P2: Space selects a resource row instead of toggling its Timeline checkbox

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed in S213 and repeated from checked and unchecked ETG
states and a checked ETE state in SX014.

Pressing native Space while a flat resource table's **Timeline** checkbox has
verified input focus does not change its checked state or lane membership.
Instead, the containing resource row is selected and focus falls to BODY.
Pointer activation of the same ETG checkbox correctly hides and restores its
lane. The failed checkbox activation is distinct from the previously recorded
[SN005 row-selection focus loss](findings.md); the focus-loss consequence overlaps
that finding and is not counted again here.

## Browser reproduction

1. In the synthetic 1M PE-A node demo, use capture End, Separate layout and all
   layers. In Resources choose the flat ETG tab and search `etg-000000`.
2. Identify the checked Timeline input for
   `node-a/data-bridge-layer/ETG/blue/etg-000000`. Focus it without toggling it.
   S213's `focused` observation verifies active element `INPUT` with that exact
   `data-lane-toggle` identity.
3. Send native Space to current focus. The settled `spaceOff` observation shows
   the checkbox still checked, the ETG lane still present and the count still
   `13 / 7,510 · 2 logs`. Active element is now BODY.
4. Open Lanes and find the same canonical resource. Its picker checkbox remains
   checked and its actual timeline row remains present, agreeing with the table.

S213 sends a second Space without refocusing. That key lands on BODY after the
first action; it is not another delivered checkbox activation and is not evidence
of a successful off/on round trip.

SX014 expands and repeats the failure with input focus verified before each
native Space:

| Control and initial state | Settled result after Space |
| --- | --- |
| ETG0 checked | Still checked; 13 resource lanes; focus BODY |
| ETG0 unchecked after a pointer click | Still unchecked; 12 resource lanes; focus BODY |
| `node-a/data-bridge-layer/ETE/etg-000000/primary` checked | Still checked; 12 resource lanes; its row becomes selected; focus BODY |

The pointer control in SX014 turns ETG0 off, removes that exact canonical lane
and changes the resource count from 13 to 12. After the unchecked and ETE keyboard
repetitions, a pointer click turns ETG0 on and restores the original canonical
13-resource set. The displayed log count remains 2. These controls show that the
checkbox's visibility action works through pointer input and that this failure
does not arise from a rejected lane-limit addition or stale checked presentation.

The later [SX015 bundle control](resource-bundle-focus.md) narrows the activation
failure to the tested flat-table path. Native Space on the backup ETE Timeline
checkbox inside ETG path bundles correctly toggles off and on and changes the
resource count 13 → 12 → 13. It still loses focus after each render and requires
explicit refocusing before the second key. Thus successful checkbox activation
and retained keyboard focus are separate assertions; the bundle focus loss extends
SN005 rather than adding another activation failure to SN015.

## Evidence and limits

- [S213.json](../../.runtime/audit-600-2026-10-21/single-node/S213.json), finalized
  at `2026-10-21T12:47:01.387Z`, contains verified input focus, the failed first
  Space, the intentionally unrefocused second key and picker/table agreement.
- [SX014.json](../../.runtime/audit-600-2026-10-21/single-node/SX014.json), finalized
  at `2026-10-21T12:49:10.248Z`, contains the checked/unchecked ETG and checked ETE
  repetitions plus pointer hiding and restoration.
- [SX015.json](../../.runtime/audit-600-2026-10-21/single-node/SX015.json), finalized
  at `2026-10-21T12:56:38.447Z`, records the passing bundle activation control and
  its separate focus-retention failure.
- [Before Space](../../.runtime/audit-600-2026-10-21/single-node/SN015-checkbox-before-space.png)
  shows the checked ETG Timeline input with its focus outline.
- [After Space](../../.runtime/audit-600-2026-10-21/single-node/SN015-checkbox-after-space.png)
  shows that checkbox still checked and its focus outline absent. BODY focus and
  exact canonical membership are established by the DOM observations, not by the
  screenshot alone.

The primary auditor performed the native keyboard and pointer operations. This
report's author reviewed the final records, both images and source. Failed
locator calls are excluded from the reproductions. The current baseline metadata
identifies PE-A 1M, capture End, Separate layout and all layers; the named states
record the target inputs, checked values, focus and lane membership used here.
The saved observations do not independently inventory all log stream controls;
this finding does not rely on an assumed stream selection.
No other-browser, request-race or performance result is claimed.

## Source cause and repair invariant

The flat rows in [app.js:6094–6107](../../frontend/assets/app.js) contain native
checkbox inputs but attach an Enter/Space `keydown` handler to the entire row.
That handler does not check `event.target`: a Space originating on the nested
input bubbles to it, calls `preventDefault()` and invokes `selectResource()`.
This suppresses the checkbox's native activation and performs row selection.

`bindLaneVisibilityCheckboxes()` at lines 5899–5907 stops propagation for
**click** only and calls `setExplicitLaneVisibility()`. The prevented keyboard
activation never reaches that normal checkbox-click path. Pointer clicks do,
which explains the working control. `selectResource()` then rebuilds the table
at lines 7772–7773 without restoring the replaced input, explaining BODY focus.
The explicit visibility setter also rebuilds the table at lines 7843–7845, so
preserving activation alone does not establish correct focus after a real toggle.

Keep row Enter/Space selection for events originating on the row, while allowing
nested controls to perform their native actions. The bundle-row handler already
uses an `event.target !== row` guard at lines 6016–6021; it is a relevant existing
mechanism consistent with SX015's passing activation control. After a successful
toggle and refresh, retain focus on the same canonical checkbox without stealing
it from a newer user action. Validate checked-to-unchecked and unchecked-to-checked
transitions, exact table/picker/timeline agreement, and pointer recovery.

Only this report and its linked SN005 bundle scope note were changed. No product
code, skill, execution ledger, aggregate
count or checkpoint was changed. Documentation drift check found no public
plug-in boundary or author-visible behavior change from documenting this defect;
maintained authoring materials required no update. No tests were run for this
reporting task.
