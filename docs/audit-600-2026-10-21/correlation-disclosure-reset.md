# SN010 — P3: reopening Correlations resets relationship disclosures

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed twice in SX009 by the primary auditor.

Collapsing and reopening the Correlations panel loses the relationship index's
open/closed choices even when the resource, time and graph scope are unchanged.
Previously collapsed direction groups reopen, and the inspected relationship
closes. Users must reconstruct their inspection after briefly hiding the panel.
The graph data, selected resource and panel-toggle focus remain correct.

## Browser reproduction

Use the existing 1M demo at capture End, with focused resource
`node-a/data-bridge-layer/ETG/blue/etg-000000`. The settled graph shows four
resources and four outgoing relationships at +720.000 seconds; the scope
button reads **Show all correlations**.

1. Expand the `owns` relationship `node-a/scale-rel-000000000` under
   **Declared source endpoints**, then collapse that direction group. Its
   nested relationship retains `open=true` while the group has `open=false`.
2. Activate **Collapse correlation**, then press native Enter on the same
   button to **Expand correlation**. Do not change time, resource or scope.
3. The outgoing group has reopened and the `owns` detail is now closed.
4. Repeat with `selected_egress`, edge `node-a/scale-rel-000000003`, expanded
   under outgoing; collapse **Declared target endpoints** instead. After the
   panel collapse/expand round trip, the incoming group reopens and the
   selected-egress detail closes.

Both runs preserve the exact root, the slider's endpoint value `1000000`, the
full +0–720-second viewport, four graph nodes, the same four edge IDs and focused
scope. The settled stage is not busy, and focus remains on
`#correlation-panel-toggle` after expansion. The second run's incoming group
contains zero relationships: its collapse preference is still lost independently
of the expanded outgoing relationship.

The expected behavior is to retain group and relationship disclosure state
when reopening an unchanged query. These observations establish a disclosure
reset, not missing graph data, lost keyboard focus or a response race.

## Evidence

- [SX009.json](../../.runtime/audit-600-2026-10-21/single-node/SX009.json):
  `states.disclosed` / `states.expanded` record the first round trip;
  `states.repeat.disclosed` / `states.repeat.expanded` record the second.
- [Before collapse](../../.runtime/audit-600-2026-10-21/single-node/SN010-before-collapse.png)
  shows the second run's selected-egress detail open and incoming group closed.
- [After reopening](../../.runtime/audit-600-2026-10-21/single-node/SN010-after-collapse.png)
  shows that detail closed and the incoming group's empty-state text visible.

This report's author reviewed the saved observations, both screenshots and
source; the primary auditor performed the browser interactions. Hidden
`#correlation-hover` text retained from an earlier resource is excluded from
visible-state claims. No CPU, memory or request-duration measurement is claimed.

## Source cause and repair invariant

The panel toggle calls `syncCorrelationPanel()` to hide/show existing content,
then schedules `renderGraph()` whenever it expands
([app.js:7359–7365](../../frontend/assets/app.js)). That render unconditionally
calls `renderCorrelationList(scoped)` at line 7692. The list replaces
`container.innerHTML` at lines 7280–7285, generating every direction group
with `open` at line 7270 and every relationship detail without it at line 7253.
The existing DOM disclosure state is discarded although the query did not change.

Pagination already captures disclosure states by direction and edge identity
and restores them after its own render at lines 7306–7317. That protection is
local to the Show-more handler; panel expansion does not use it. This is a
different trigger from the earlier
[pagination disclosure finding](../surrounding-components-audit-2026-10-20.md),
whose repair is present in this revision.

Preserve the same-query index DOM when only revealing the panel, or preserve
its disclosure choices through the existing identity-based mechanism when a
repaint is needed. Continue permitting query changes to rebuild applicable
content, and retain the passing panel-toggle focus behavior. Validate both
direction groups and distinct edges, including two relationship types sharing
the same endpoint.

No product code, skills, ledgers or aggregate counts were changed by this report.
Documentation drift check: this audit records existing frontend behavior and
changes no public plug-in boundary, example or author command. No maintained
authoring update or test-suite run was required.
