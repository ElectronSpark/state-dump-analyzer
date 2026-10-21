# SN014 — P3: resource search hides the selected flat-kind tab when it has no matches

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed in S211 and repeated across ETG and NEIGHBOR in SX013.

A resource search with no matches removes every flat-kind tab, including the
selected one. If the search matches only another kind, the selected tab still
disappears while that other kind appears unselected. The table remains scoped to
the original kind: its summary names that kind, and clearing the search restores
its selected tab and correct rows. This is loss of the visible active filter and
its navigation control, not an actual kind reset or mixed-kind query result.

## Browser reproduction and controls

1. In the synthetic 1M PE-A node demo, use capture End, Separate layout and all
   layers. Open Resources and choose the flat **Encapsulation Tunnel Group** tab.
   S211's settled baseline shows `1–500 of 1,875`, with ETG selected.
2. Search `etg-000000`. The settled table contains the exact resource
   `node-a/data-bridge-layer/ETG/blue/etg-000000`, and ETG remains selected.
3. Replace the search with `AUDIT600_NO_SUCH_RESOURCE_9c74` and wait for
   `#resource-table-wrap[aria-busy="false"]`. The table correctly says
   **No resources match this view.** and the summary still names Encapsulation
   Tunnel Group, but no `[data-kind]` tab remains. Only the two unselected bundle
   views, **ETG path bundles** and **Interface neighbors**, remain visible.
4. Clear the search and wait. ETG is selected again and its first 500 of 1,875
   rows return. Selecting the exact first restored ETG resource succeeds and
   highlights that canonical row.

SX013 repeats the ETG no-match state, then changes the query to `peer-00000`
without choosing another kind. The table is still empty and its summary still
names ETG. The only flat tab is now **Neighbors**, with `aria-selected="false"`;
ETG has no visible tab. Selecting Neighbors works and displays the exact resource
`node-a/control-plane/NEIGHBOR/blue/peer-00000`.

Applying the no-match sentinel with NEIGHBOR selected removes all flat tabs
again. Clearing then restores NEIGHBOR selected and all 375 neighbor rows on a
complete single page. The recorded canonical set of 13 resource lanes and the
`13 / 7,510 · 2 logs` count remain unchanged throughout both cases. Search focus
remains in the search input in the empty-state observations. These passing
controls bound the defect to tab presentation and access to the active filter.

## Evidence and limits

- [S211.json](../../.runtime/audit-600-2026-10-21/single-node/S211.json), finalized
  at `2026-10-21T12:42:58.335Z`, records the baseline, matching search, settled
  empty state, same-kind restoration and successful exact resource selection.
- [SX013.json](../../.runtime/audit-600-2026-10-21/single-node/SX013.json), finalized
  at `2026-10-21T12:43:45.817Z`, records the repetition, other-kind-only search,
  working explicit kind switch, NEIGHBOR repetition and recovery.
- [Empty-search screenshot](../../.runtime/audit-600-2026-10-21/single-node/SN014-empty-search-hides-kind-tabs.png)
  shows the sentinel query, the two remaining bundle tabs, the ETG empty summary
  and empty table together. It does not show the prior selected tab; that
  before/after comparison comes from the saved DOM states.

The primary auditor performed the browser operations. This report's author
reviewed the final saved observations, screenshot and source. No internal state
was read through browser code: retention of the kind is supported by the named
empty summary and same-kind recovery, and explained by the source below. The
recorded control-tool timeout while locating the restored row is not treated as
a product failure or performance measurement. No request race, CPU, memory or
data-loss claim is made. These repetitions constitute one finding.

## Source cause and repair invariant

The resource query computes search-filtered `counts_by_kind` in
[normalized_data.py:3897–3917](../../src/router_dump_analyzer/normalized_data.py).
Search rejection occurs before incrementing a kind's count; the explicit kind
filter is applied afterward. Therefore a global no-match returns empty counts
and rows, while `peer-00000` can return a NEIGHBOR count with no ETG rows.

[renderResourceTables](../../frontend/assets/app.js), lines 6033–6042, derives
the complete flat-tab list from those counts, falling back to the returned item
groups. Its selection logic at lines 6043–6053 correctly avoids replacing an
existing selected kind while search is active. However, lines 6061–6062 render
tabs only for the newly derived kind list. The preserved selected kind is absent
from that list when its search count is zero, so its active tab disappears.
The summary at lines 6082–6090 still uses the preserved selected kind, explaining
the observed empty ETG/NEIGHBOR summaries and correct recovery.

Keep an explicit selected kind represented in the tab controls when its search
count is zero, without replacing it with another matching kind or mixing their
rows. Preserve the working search counts, explicit kind switching, clear-search
recovery, temporal attribution and lane membership. The confirmed evidence does
not require changing the resource-query API or claiming that every unmatched
kind must remain visible; retaining the active filter addresses the demonstrated
loss.

Only this report was added. No product code, skill, execution ledger, aggregate
count or checkpoint was changed. Documentation drift check found no
author-visible behavior or public plug-in boundary change from documenting the
existing defect; maintained authoring materials required no update. No tests
were run for this reporting task.
