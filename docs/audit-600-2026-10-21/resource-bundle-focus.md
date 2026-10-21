# SN005 scope extension — P3: resource-bundle controls lose focus after activation

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed in S216, S222, S228 and SX015; extends the existing
[SN005 resource-table focus-loss finding](findings.md), not a new unique defect.

Resource-bundle disclosure, inline Details and Timeline checkbox actions apply
their requested change, but rebuilding the table drops keyboard focus to BODY.
The next key cannot operate the same control without explicit refocusing.
Expansion state, resource identity and lane visibility changes remain correct.

## S216: disclosure and Details

At capture End in the synthetic 1M PE-A demo, choose **ETG path bundles**, search
`etg-000000` and wait for the five displayed bundle rows. The tested root path is
`etg-path-bundles:root:node-a/data-bridge-layer/ETG/blue/etg-000000`.

1. Activate the root disclosure with native Enter. The root collapses to one
   visible bundle row, with `aria-expanded="false"`, but focus becomes BODY.
2. Send Enter to current focus without reacquiring the button. The root stays
   collapsed. Explicitly refocus its replacement disclosure and activate it:
   expansion succeeds and the five rows return.
3. Activate **Details** for the backup child at the root path plus
   `>node-a/scale-rel-000006375:0`. Its inline details open correctly, but focus
   again becomes BODY. An unrefocused Enter leaves Details open.
4. Refocus the same path's **Hide details** button and activate it. Details
   close. Explicitly targeted root collapse/re-expand succeeds again, and
   returning to the flat ETG view restores its coherent schema and search.

The detail panel identifies
`node-a/data-bridge-layer/ETE/etg-000000/backup`, with **standby** status,
**ETE path** view role, **backup** path role and displayed relationship active
interval **+240.000 s → open**. That interval is not a claim about the resource's
entire lifetime.
Its **owns** relationship points from canonical ETG0 to that backup ETE with
**exact** quality. The saved `details` and `detailsRepeat` panel text agrees;
the unrefocused key does not substitute another child or lose its facts.
The 13-resource lane set and displayed 2-log count stay unchanged in S216.

## S222 and S228: primary child and duplicate next-hop instance

S222 repeats Details activation on the primary ETE child at the same root path
plus `>node-a/scale-rel-000000000:1`. Its panel correctly names
`node-a/data-bridge-layer/ETE/etg-000000/primary`, the **owns** relationship from
ETG0, **exact** quality and displayed relationship interval **+120.000 s → open**.
Opening it drops focus to BODY; unrefocused Enter leaves the panel open.
Explicitly refocused closure and root collapse/re-expand recover, and the flat
ETE view returns both canonical primary/backup rows with primary still selected.

S228 targets the primary branch's next-hop instance, whose path appends
`>node-a/scale-rel-000000001:0` to that primary ETE path. Canonical ETG1 also
appears under the backup branch, making the relationship path necessary to
distinguish these two Details controls. The saved `focused` state verifies
BUTTON focus on the primary-branch **Details** path before native Return.
Its resulting panel correctly identifies
`node-a/data-bridge-layer/ETG/blue/etg-000001`, the **next_hop** relationship from
the primary ETE, **exact** quality and displayed relationship interval
**+120.000 s → open**. Only that instance's Details are open, but focus becomes
BODY. A subsequent unrefocused Return leaves the panel open.

Explicitly refocusing **Hide details** closes that instance. Root collapse and
re-expand restore the five-row structure. Returning to DTE and replacing the
retained ETG search with `dte-000009` restores the correct flat schema and selected
canonical DTE9 row. The intermediate empty DTE result still has the old
`etg-000000` search; it is not evidence of a mixed-schema response. Both cases
preserve the 13-resource lane set and displayed 2-log count. These are additional
SN005 control/instance coverage, not new unique defects or resource-lifetime
claims.

## SX015: checkbox activation works, focus retention fails

With that same bundle expanded, focus the Timeline checkbox for the canonical
backup ETE. The saved `focused` state verifies INPUT focus on its exact
`data-lane-toggle` identity. Native Space correctly unchecks it, removes only
that resource's timeline lane and changes the resource count from 13 to 12.
Focus nevertheless becomes BODY.

The auditor explicitly refocuses the replacement input before the next Space.
That key correctly checks it, restores the original canonical 13-resource set
and again leaves BODY focused. The displayed log count stays 2. This is a passing
activation control for [SN015's flat-table Space interception](resource-timeline-checkbox-keyboard.md),
and a failing focus-retention control for SN005. It does not demonstrate an
uninterrupted keyboard off/on sequence: the refocus between keys is required.

## Evidence and limits

- [S216.json](../../.runtime/audit-600-2026-10-21/single-node/S216.json), finalized
  at `2026-10-21T12:55:12.067Z`, contains the root and child instance paths,
  collapse/open states, BODY focus, unrefocused-key observations and recovery.
- [SX015.json](../../.runtime/audit-600-2026-10-21/single-node/SX015.json), finalized
  at `2026-10-21T12:56:38.447Z`, contains both verified input-focus states,
  successful checkbox transitions and exact lane removal/restoration. Its
  `pendingBundle` observation precedes the settled `bundle` state by timestamp;
  keyboard testing begins only after the bundle rows are present.
- [S222.json](../../.runtime/audit-600-2026-10-21/single-node/S222.json), finalized
  at `2026-10-21T13:20:26.424Z`, records primary-child Details facts, BODY focus,
  unrefocused activation, explicit recovery and return to the flat ETE view.
- [S228.json](../../.runtime/audit-600-2026-10-21/single-node/S228.json), finalized
  at `2026-10-21T13:32:30.074Z`, records the focused primary-branch next-hop
  Details button, exact instance expansion, full relationship facts, BODY focus,
  unrefocused-key observation and recovery through the DTE return.
- [Bundle Details screenshot](../../.runtime/audit-600-2026-10-21/single-node/SN005-bundle-details-focus-loss.png)
  shows the open backup detail panel in the bundle. A root hover card obscures
  part of that panel, so the full detail facts and BODY focus are established
  by the saved DOM records, not the image alone.
- [Duplicate next-hop Details screenshot](../../.runtime/audit-600-2026-10-21/single-node/S228-next-hop-instance-details-focus-loss.png)
  shows both ETG1 instances and **Hide details** on the primary branch. The full
  detail facts are clipped below the inner table viewport. The image verifies
  the instance with open Details; its full facts and focus are established by
  the saved DOM records.

The primary auditor performed the browser actions. This report's author reviewed
the final artifacts, images and source. S216 and S222's recorded steps identify
the native button actions; separate before-action focused-button snapshots were
not saved for those cases. Their resulting BODY focus, unrefocused-key states
and recovery are directly recorded; S228 additionally saves the focused Details
button before activation. These results establish the tested root disclosure,
backup/primary-child and primary-branch next-hop Details, and checkbox
interactions; no universal result for every
bundle view or browser is claimed. Tool delays are not CPU, memory or application
latency measurements. This scope extension adds no unique finding.

## Source cause and repair invariant

[renderResourceBundleTable](../../frontend/assets/app.js) replaces the table's
`innerHTML` at lines 5978–5981. Disclosure and Details click handlers update their
path-keyed expansion maps, then call `renderResourceTables()` at lines 5982–6003.
They do not preserve and restore the activated button's focus. This is the same
table-replacement mechanism behind SN005's flat-row selection focus loss, reached
through different controls. Here the expansion maps remain correct; this is not
[SN010's correlation disclosure-state reset](correlation-disclosure-reset.md).

The bundle row's key handler at lines 6016–6021 rejects events originating on
nested controls. Consequently Space can reach the checkbox's native activation
and `bindLaneVisibilityCheckboxes()` at lines 5899–5907. That calls
`setExplicitLaneVisibility()`, whose immediate table render at lines 7843–7845
again replaces the focused input. This explains why activation passes in the
bundle while focus still fails, unlike the additional flat-row interception
identified in SN015.

After rendering, restore the same control type and bundle path, not just a
resource ID that can occur in several relationship branches. Preserve native
checkbox activation, exact lane membership and existing expansion maps, and do
not steal focus from a newer user action. Consecutive native keys should work
without explicitly refocusing between activations.

This update changes only this scope report. No product
code, skill, ledger, aggregate count or checkpoint was edited. Documentation drift
check found no public plug-in boundary or author-visible behavior change from
recording this existing defect; maintained authoring materials required no update.
No tests were run for this reporting task.
