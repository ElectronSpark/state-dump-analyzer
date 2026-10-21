# SN009 — P2: a second selection action cancels the first without a selection change

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed by the primary auditor; source diagnosis independently
verified with an isolated production-function probe.

After a fresh selection, clicking **Show marks** and then **Remove
marker** before selection resolution finishes removes the review markers but
leaves the underlying event glyphs hidden. Both commands concern the same two
unchanged selected rows and should complete. The first command is incorrectly
rejected as though the selection had changed. A warmed selection can make the
same interaction pass, which obscures the race during repetition.

## Browser evidence

The primary auditor performed these UI operations on the existing 1M demo in
browser-only marker mode. This report's author inspected the saved snapshots
and source, and did not independently operate the browser.

1. Enable the normalized stream, select the +30 s cursor, set zoom 2 and click
   **Center**. Verify that the exact scenario events
   `node-a/scenario/node-a-route-create` and
   `node-a/scenario/node-a-route-reroute` have visible glyphs.
2. Select normalized-log indices 0 and 2, mark both, then hide them. The rows
   gain `timeline-hidden timeline-marked`; review markers remain visible with
   `underlying-hidden` while the actual event glyphs disappear.
3. Enter a query with no matches, clear it, and reselect the same two rows.
   This creates a fresh selection whose action payload is not cached.
4. Click **Show marks**, then quickly **Remove marker**, without changing
   the selected rows between commands. Wait for the resulting state to settle.
5. The review markers disappear, but both selected rows retain
   `timeline-hidden` and both actual event glyphs remain absent.
6. Click Show alone afterward. Both hidden flags clear and both glyphs return.

[S125.json](../../.runtime/audit-600-2026-10-21/single-node/S125.json)
records the initial sequence. Its `shown` and `cleaned` observations were taken
before the asynchronous action finished. They do **not** establish that Remove
marker failed: `later` records its successful completion, with both rows still
hidden and the review-marker array empty. `showAloneImmediate` records recovery.

The primary auditor repeated the sequence in
[SX007.json](../../.runtime/audit-600-2026-10-21/single-node/SX007.json).
The warmed Show/Remove-marker sequence passed. After another mark/hide,
no-match query, clear and reselection cycle, `repeatQuick` reproduced hidden
rows with no review markers; `repeatSettled` confirms that outcome and
`recovery` records Show alone restoring both glyphs. The
[browser screenshot](../../.runtime/audit-600-2026-10-21/single-node/SN009-show-remove-hidden-rows.png)
preserves the affected selected rows. The repeated cold-selection failure and warmed
control distinguish cancellation from a persistent rendering or marker-removal
failure. These observations do not measure CPU, memory or request duration.

### Retained-source identity expansion

[S131.json](../../.runtime/audit-600-2026-10-21/single-node/S131.json) confirms the
same failure for Non-CTF source records in the browser. After zooming to
+120–121 s and clearing the selected range, the auditor verified separate
exact glyphs at +120.100 s and +120.200 s for
`source:source-external-unmatched-000001` and
`source:source-external-unmatched-000002`. The corresponding full-stream rows
were indices 3 and 5.

Mark, Hide, a no-match query, clear, reselection and rapid Show/Remove-marker
again left both selected source rows `timeline-hidden`, both exact glyphs
absent and zero review markers after settlement. Show alone cleared the hidden
flags and restored the glyphs. The final file's `settled` and `recovered`
snapshots establish those outcomes. These are unmatched retained-source
identities; they are not matched-source aliases of normalized events. S131
extends SN009's confirmed scope without adding another unique defect.

### Inverse command order on CTF source records

[SX008.json](../../.runtime/audit-600-2026-10-21/single-node/SX008.json) confirms
the inverse command order in the browser using the exact CTF source identities
`source:source-ctf-unmatched-000001` and
`source:source-ctf-unmatched-000002` at rows 3 and 5. After marking and hiding
their separate glyphs, the auditor entered a no-match query, cleared it,
reselected those IDs and rapidly clicked **Remove marker**, then **Show marks**.
The settled state showed both actual glyphs but retained both review markers:
the second action succeeded while the first was lost. Retrying Remove marker
alone removed both reviews without hiding the glyphs.

This is one observed inverse-order browser interaction, with settled and
recovery snapshots. The initial Hide tool timeout occurred after delivery;
the auditor verified the hidden glyphs and flags before continuing. Network
response order was not established by this UI sequence. It expands the
confirmed behavior of SN009 without adding a unique defect.

### Pending Add followed by Hide in a mixed-stream selection

[S149.json](../../.runtime/audit-600-2026-10-21/single-node/S149.json) extends the
browser reproduction to **Add review marker**, then **Hide marks**, with all
three streams enabled. The selected identities were normalized-log index 1,
`event:node-a/scenario/node-a-route-create`, and CTF source index 3,
`source:source-ctf-unmatched-000000`. Their separate exact glyphs were visible
before the actions.

The normalized event had already been marked during setup, before the second
selection became visible. With both rows selected, another Add was started,
then Hide was activated while Add was still pending. The saved `marked` and
`hidden` snapshots have the marker buttons disabled while Hide remains
enabled; the initial accessibility-tree wait did not establish that Add had
finished. In `settledConcurrent`, both selected glyphs are hidden, but only
the previously existing normalized-event review marker remains. The pending
Add was canceled, so the CTF marker was never added; this is not evidence that
one combined Add partially committed.

The serial controls pass: retrying Add alone marks both exact identities; a
no-match query and clear preserve both hidden/marked flags; after reselection,
Show is allowed to finish before Remove is started. `shown` restores both
glyphs while retaining both reviews, and `removed` removes the created reviews
while keeping the glyphs visible. The unrelated Non-CTF glyph remains visible.
This case demonstrates pending-action cancellation alongside successful
serial operations, filter reconstruction and cleanup, without another unique
finding.

## Source diagnosis

`resolveEventLogSelection()` checks the cache against a signature consisting of
the query and selected ranges. On a cache miss, however, it increments the
shared `eventLogSelectionRequestId` for **each caller** before sending its own
request. On return it rejects any response whose request ID is no longer the
latest, even when its selection signature is unchanged
([app.js:10305–10336](../../frontend/assets/app.js)).

Show enters `applyEventLogTimelineAction("show")`, starts request N and awaits
the selection payload. Remove marker enters the same handler with `"unmark"`,
starts request N+1 for the identical selection, and invalidates Show. Show's
continuation never reaches `hiddenTimelineEntryIds.delete(entryId)` at line
10886. Unmark does complete: it removes the local marker IDs, while correctly
leaving visibility state independent of marker state
([app.js:10818–10923](../../frontend/assets/app.js)). This is premature action
cancellation, rather than a stale snapshot overwriting the hidden-ID set.

The marker-operation lock covers mark/unmark and durable review operations;
Show has no owner in that lock. Its button is not disabled while a marker
operation is pending. Thus the two UI commands can overlap. The controls are
wired directly to these handlers at lines 12376–12379. When the selection cache
is populated, both handlers receive the same cached payload without advancing
the shared request ID, and both commands complete.

Actual selection mutations also advance the same counter and invalidate the
cache, at lines 9267–9293 and 9486–9487. That protection is necessary; starting
another consumer of an unchanged selection should not be treated as another
selection mutation.

## Isolated source reproduction

Run from the repository root:

```text
node .runtime/audit-600-2026-10-21/single-node/S125-source-race.mjs
```

The [probe](../../.runtime/audit-600-2026-10-21/single-node/S125-source-race.mjs)
extracts and composes the actual selection resolver, action handler, marker
projection functions and operation wrappers. It imports the production review
operation-lock implementation. Network responses, DOM rendering, cache
pruning and unrelated controls are isolated substitutes; it is not an API or
browser integration test. It preserves the exact two scenario UIDs and keeps
the query/ranges unchanged throughout each overlap.

All six probe cases passed their assertions of the current behavior:

| Selection payload | Commands | Response order | Result |
| --- | --- | --- | --- |
| Uncached | Show, then Unmark | First response first | Show canceled; both rows hidden; no markers |
| Uncached | Show, then Unmark | Second response first | Same failure |
| Cached | Show, then Unmark | No request | Both complete |
| Uncached | Unmark, then Show | First response first | Unmark canceled; glyphs shown; markers retained |
| Uncached | Unmark, then Show | Second response first | Same inverse failure |
| Cached | Unmark, then Show | No request | Both complete |

Retrying the canceled action alone recovered in every uncached case. Both
request bodies were identical in every overlap. The probe records the
misleading "selection changed" error as well as the successful second action.
The inverse command order is also browser-confirmed by SX008 above. Explicit
control of both network response orders remains **source-probe evidence**;
the browser interaction does not establish which response arrived first.

Results and the source SHA-256 are retained in
[S125-source-race.json](../../.runtime/audit-600-2026-10-21/single-node/S125-source-race.json).
No frontend test suite was executed for this diagnosis.

## Related exposure and repair invariant

Copy plug-in text, manual-correlation preparation and toolbar Reveal also call
the same resolver (lines 10356, 10671 and 10927). They can therefore invalidate
another uncached selection consumer without changing the selected rows. Those
additional action combinations are source-identified exposure, not separately
browser-confirmed defects. Mark followed by Unmark has its own operation lock
and should not be assumed equivalent to Show followed by Unmark.

Keep a generation for the actual selection/query, and share an in-flight
payload resolution for that generation, or otherwise let independent actions
consume an unchanged selection without canceling one another. Preserve
invalidation when the user genuinely changes the selection, query or revision.
Actions that modify the same property should still have explicit ordering;
visibility and marker changes should both survive this tested combination.

No product code, skills or maintained plug-in authoring materials were changed.
Documentation drift check: the report records existing frontend behavior and
does not change the public plug-in boundary, so no authoring update or
conformance-command run was required.
