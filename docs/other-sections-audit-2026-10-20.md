# Topology, Fabric, route and dashboard audit — 2026-10-20

Follow-up: findings were repaired and validated in
[Outstanding frontend audit fixes](outstanding-audit-fixes-2026-10-20.md).
The observations below describe the pre-fix audit.

Five additional browser-confirmed issues were found outside the resource-lane
and event-log workflows. No product code or skills were changed. This follows
the [lane-sequence audit](lane-sequences-audit-2026-10-20.md).

The parent exercised the existing in-app browser on loopback port 8883, using
the same working tree at HEAD `f4076ce` with previous changes still pending.
The node fixture has 1,250,005 events and 7,510 resources; the Fabric workspace
advertises 10 devices and 693 route rows. A parallel agent reviewed source and
prepared isolated probes. The parent independently reproduced the UI findings
and reran all three probes. Evidence is under
`.runtime/other-sections-2026-10-20/`.

## P2 — Old topology responses erase newer validation errors

Browser reproduction:

1. Open node **Topology** with Absolute timestamp and Strict clock policy.
2. Enter `1759680400000000000` and click **Reconstruct topology**.
3. While **Reconstructing...** is disabled, replace the timestamp with
   `invalid` and change Clock policy to **Best effort**.
4. The page displays **Absolute time must be an integer nanosecond timestamp.**
   The previous valid request is still pending.
5. When that request finishes, the error disappears. The timestamp input still
   contains `invalid`, but results now show the old request's
   `2025-10-05T16:06:40.000Z` time.

This is not just delayed rendering: the newer invalid intent has been
acknowledged and then overwritten. The disabled submit button does not prevent
the sequence because the enabled clock-policy change handler submits directly.

Cause: `requestTopology()` at `frontend/assets/app.js:8706` validates before
aborting the old request or advancing its generation. The validation catch
returns without invalidating the earlier request; its completion clears the
error at line 8740. Preserve current validation feedback and distinguish the
last applied result from the latest invalid query.

Evidence: `topology-invalid-during-request.txt`,
`topology-invalid-after-old-response.txt`, and
`source-review/topology-invalid-query-race.mjs`. The probe reproduces the same
error-to-empty transition with query generation unchanged at 1.

## P2 — Directed inferred topology edges lose their arrows and labels

Browser reproduction:

1. In node Topology, choose **Underlay connectivity**. Its default status
   perspective becomes **Hardware observed forwarding**.
2. Inspect **Relationships and inferred connectivity** after reconstruction.
3. Edges such as ETE `etg-000000/primary` to `ae-00000` are shown with an
   undirected dash and **Unknown relationship (relationship:egresses_via)**.

The server's inferred-edge shape explicitly carries `directed: true` and
`inference.rule_id: "relationship:egresses_via"`. That inference rule ID is
not a relationship descriptor ID. The raw `egresses_via` descriptor exists.
`renderTopologyConnectivity()` at `frontend/assets/app.js:8653` treats the
rule ID as a descriptor lookup key and uses only the descriptor's direction
when drawing the separator, discarding the edge's explicit direction.

Preserve the server-declared direction and render inference-rule identity
separately from relationship type. Do not infer arbitrary device semantics by
parsing rule IDs in the core.

Evidence: `underlay-direction-rows.json` and
`source-review/inferred-connectivity-direction.mjs`. The parent reran the
production renderer probe with the server-shaped edge: it produces a dash and
the unknown label despite `directed: true`.

A smaller related presentation issue exists in node Route: active next-hop
branches show **Unknown relationship (candidate_next_hop)**. The backend emits
that relation type in `runtime_api.py`, but the demo vocabulary has no matching
descriptor. This was observed on All-active ECMP and Cross-layer forwarding
inconsistency. It does not by itself establish an incorrect route decision.

## P2 — Dashboard actions discard keyboard focus

Browser reproduction:

1. Open **Dashboards**, focus the scale-overview module's **Collapse** button,
   and press Enter.
2. The module collapses, but the active element becomes BODY.
3. Focus **Expand** and press Enter: the module expands and focus again becomes
   BODY.
4. Focus its **Move down** button and press Enter: it moves from index 01 to
   index 02, but focus is again lost.

`renderPluginDashboards()` at `frontend/assets/app.js:6504` replaces both
dashboard subtrees without preserving the activated control. Retain focus on
the equivalent control after expand/reorder, or a meaningful surviving control
when closing a module.

Evidence: `dashboard-collapse-focus.json` and
`dashboard-expand-move-focus.json`. Reset layout restored the original order
and open/closed module state after testing.

## P2 — Fabric device selection discards keyboard focus

Browser reproduction:

1. Open **Fabric** and focus the checked **PE-C / Epsilon edge NOS** checkbox.
2. Press Space. Selection becomes **9 of 10 available included**, but the
   active element becomes BODY.
3. Focus and toggle it again to restore all 10 devices; the same rerender path
   is used.

The page correctly warns that controls are pending and still displays the last
applied reconstruction. The defect is keyboard continuity while selecting
multiple devices. `renderCapabilityNodeIndex()` at
`frontend/assets/topology.js:5394` replaces the checkbox list inside its change
handler at line 5414, without restoring focus.

Evidence: `fabric-device-focus.json`. All devices were reselected and the
fabric reconstructed before subsequent tests.

## P3 — Using a route-table row retains the previous scenario description

Browser reproduction:

1. Run **Packet evolution · MTU drop after encapsulation** in Fabric Route
   trace. Both directions correctly report a drop.
2. In Route tables, choose **PE-C / Epsilon edge NOS**, search `192.0.2.2`,
   and click **Use in trace** for the management route `192.0.2.2/32`.
3. The scenario selector changes to **Any router to any router**, and the
   seeded badge correctly identifies PE-C / management / `192.0.2.2/32`.
4. The explanatory paragraph still says the node plug-in declares a DF packet
   drop after tunnel overhead exceeds an egress constraint.

The subsequent trace is reachable in both directions. This is stale guidance,
not observed leakage of the previous MTU fault into the request.
`useRouteTableEntry()` at `frontend/assets/topology.js:9546` changes the select
value and refreshes steering options, but does not call
`renderRouteScenarioGuide()`. Programmatic value changes do not invoke the
normal scenario change listener.

Evidence: `route-table-after-mtu-seed.txt` and
`source-review/route-seed-description.mjs`.

## Other exercised workflows

- Node topology: association → underlay projection, hardware status, relative
  watermark values -5 s, -600 s and 0, invalid relative input and correction.
  Completed results reflected the requested basis, and missing node status
  remained explicitly reported.
- Node Route: All-active ECMP, Recursive next-hop cycle and Cross-layer
  forwarding inconsistency projections. Node Route is explicitly a local
  observed projection, so lack of a recursive warning there was not counted
  as a tracing bug.
- Cross-node tracer: recursive cycle detected in both directions; MTU
  encapsulation drop reported with 1,490 B → 1,510 B packet evolution;
  Return and All paths views switched correctly; the table-seeded management
  route was reachable in both directions.
- Route tables: node filtering, no-match destination filter, Clear filters,
  text search and Use in trace. One Clear filters input call timed out in the
  automation transport, but the next DOM observation showed all 693 rows
  restored. This was not treated as proof of a product performance defect.
- Consistency: four pass results remained distinct from zero fail/unknown,
  with explanatory counts and resource references.
- Dashboards: opening the closed mass-operation module displayed its phase
  counts; Reset layout restored the defaults.
- Private analysis: discovered the existing authorized synthetic workspace
  `manual-audit/manual-audit/workflow` as `local-reviewer`, confirmed execution
  was disabled, loaded the prior completed offline run
  `c35379dc10cf4ca78401760b08765310`, then requested a missing run ID. The old
  report cleared and `resource not found` appeared. Clear from memory removed
  the scope and lookup state. No run, review decision or policy change was
  created.

## Validation and handoff

The parent reran all three production-function probes successfully. Probe
success means the defects were reproduced, not fixed:

```powershell
node .runtime/other-sections-2026-10-20/source-review/inferred-connectivity-direction.mjs
node .runtime/other-sections-2026-10-20/source-review/topology-invalid-query-race.mjs
node .runtime/other-sections-2026-10-20/source-review/route-seed-description.mjs
```

No full test-suite rerun or controlled 1M memory/CPU measurement was needed for
this audit-only change. No new performance regression was established. The
final node-page warning/error log was empty.

The user tab was returned to `/node#overview`, with 13 default resource lanes,
all layers, Separate mode, normalized events, and the 0–720 s window. Topology
was restored to a valid absolute timestamp, Strict policy and the original
association/data-bridge defaults. Evidence: `restored-overview.txt`.
Screenshot capture was unavailable; DOM and console evidence were retained.

Plug-in documentation drift check completed. Only this report and isolated
local probes were added, with no author-visible behavior or API change; no
maintained authoring documentation or skill update was required. Existing
working-tree changes were preserved. No commit or push was performed.
