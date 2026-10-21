# SN011 — P3: relationship pagination leaves keyboard focus outside the viewport

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Status: browser-confirmed in S171 and repeated through the final page in SX010.

Activating **Show more** preserves keyboard focus on the replacement control,
but the growing relationship list moves that control far below the viewport.
On the last page, focus moves to a direction summary above the viewport.
Keyboard input still works, but users lose sight of the active control and
must navigate again to bring it into view. Relationship contents and disclosure
choices remain correct.

## Browser reproduction

1. At capture End, select `node-a/control-plane/IP_ROUTING/blue` and use the
   focused Correlations graph. Its capped response contains 499 incoming
   relationships; the index initially displays 30.
2. Collapse **Declared source endpoints**, keep **Declared target endpoints**
   open, and expand incoming edge `node-a/scale-rel-000000005`.
3. Scroll the incoming **Show 30 more** button into view and activate it with
   native Enter. The list grows to 60 and the replacement button owns focus,
   but its top is approximately 2,051 px in a 720 px viewport.
4. Send native Space to the retained focus. The list grows to 90 and focus
   follows the replacement button to approximately 3,755 px below the top.
5. Continue with native Enter on the current focus through the remaining
   pages. At 480 items the control reads **Show 19 more**. At 499 it disappears
   and focus falls back to the incoming direction summary, now above the
   viewport at approximately −1,529 px.

S171 saves the first two pagination actions. SX010 continues through fourteen
more actions, reaching all 499 unique edges in the returned response. Every
saved page preserves the open first relationship, collapsed outgoing group,
expanded incoming group, selected root and +720.000-second graph time.
During SX010's pagination sequence, document scroll remains about 8,895 px
while the active control moves outside the visible region. This does not claim
the capped response contains every relationship in the complete dataset.

## Recovery and evidence limits

Native Tab followed by Shift+Tab eventually scrolls the incoming summary into
view. SX010's final `settledRecovery` records it at approximately 326–394 px
within the 720 px viewport. The immediate `tabRecovery` and `shiftTabRecovery`
samples caught smooth scrolling in progress; they do not establish a failed
recovery or keyboard trap.

- [S171.json](../../.runtime/audit-600-2026-10-21/single-node/S171.json):
  `states.page1` and `states.page2` contain focus geometry and preserved list state.
- [SX010.json](../../.runtime/audit-600-2026-10-21/single-node/SX010.json):
  `states.pages` records each later page, including the final summary fallback;
  `states.settledRecovery` establishes recovery.
- [Pagination viewport](../../.runtime/audit-600-2026-10-21/single-node/SN011-pagination-focus-offscreen.png)
  and [final-page viewport](../../.runtime/audit-600-2026-10-21/single-node/SN011-final-page-focus-offscreen.png)
  show the visible list while the focused destination is outside it. The
  matching DOM records establish which element owns focus and its coordinates;
  the screenshots alone cannot establish the offscreen element's identity.

The primary auditor performed the browser actions. This report's author
reviewed the saved records, screenshots and source. No CPU, memory or request-
duration measurement is claimed, and successful repeated Enter/Space activation
is distinguished from visible focus.

## Source cause and repair invariant

The list places its Show-more control after the rendered items at
[app.js:7267–7272](../../frontend/assets/app.js). The pagination handler saves
disclosures and `container.scrollTop`, increases the item limit, rerenders,
and restores disclosures at lines 7306–7317. It then selects the replacement
Show-more button, or the group's summary when no button remains, and calls
`focus({ preventScroll: true })` at line 7319. Line 7320 restores the saved
container scroll value. No step brings that focus destination into view.

The correlation list grows with the document rather than providing a bounded
scroll area; its styling at [styles.css:4328–4333](../../frontend/assets/styles.css)
adds no height or overflow constraint. Restoring its own `scrollTop` therefore
does not compensate for the replacement button moving down the page, or the
final fallback moving to the top of the group.

Retain the passing identity, disclosure and focus restoration, and ensure the
resulting focus target is visible after layout. Check both intermediate pages
and the final-page fallback with real Enter/Space input and settled geometry.
This differs from the older
[pagination disclosure/focus-loss finding](../surrounding-components-audit-2026-10-20.md):
focus now remains on a connected element and disclosures survive, but visibility
does not. It is also separate from SN010's panel collapse/expand reset.

No product code, skills, ledgers, aggregate counts or checkpoint were changed
by this report. Documentation drift check found no public plug-in boundary,
example or author-command change; no maintained authoring update or test-suite
run was required.
