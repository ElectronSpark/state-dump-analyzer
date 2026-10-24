# VPN service activation lost during native focus scrolling

Source review: `d29f981`. Browser confirmation supplied by the parent audit, move 100. This is the third new functional finding in that audit. No product code was changed.

## Confirmed natural reproduction

Use the same unchanged, settled VPN route throughout; no pending trace replacement is needed.

1. Press Escape to close service details.
2. Click **Focused path**.
3. Scroll the document upward about 0.6 pages at the right margin, preserving keyboard focus.
4. Press native Tab to move into the offscreen VPN service strip, then immediately press Return.
5. At activation, the trigger's top is approximately **837 px**, below the **720 px** viewport. The service popup is hidden.
6. Once native focus scrolling finishes, the trigger's top is approximately **341 px**, but the popup remains **hidden and empty**.
7. Press Return again. The same service popup opens.

Expected: explicit keyboard activation of the newly focused strip should open its service details once its anchor has been revealed. It should not silently discard the activation because the browser is still bringing the focused target into view.

## Source chain

- `frontend/assets/styles.css:32` enables smooth document scrolling.
- `frontend/assets/topology.js:8469`, `bindRoutePresentationElements`, calls `showRoutePresentationPreview` immediately on focus. Its Enter/Space handler likewise calls the same helper immediately with `pinned=true`. Neither path finishes or accounts for the focus-triggered reveal.
- `showRoutePresentationPreview` (`:8425`) sets the preview ID, pin state, and trigger, populates the card, and calls `positionRoutePathPreview` synchronously (`:8459`).
- `positionRoutePathPreview` (`:8547`) checks the trigger's current rectangle. The offscreen test `rect.top >= window.innerHeight` (`:8555`) is true for the observed 837/720 geometry, so it calls `clearRoutePresentationPreview` (`:8556`). This is appropriate for an existing popup whose anchor has actually left view, but it also discards an explicit activation while focus scrolling is still in progress.
- `clearRoutePresentationPreview` (`:8404`) resets the ID and pin, sets `routePresentationTrigger=null` (`:8409`), and hides/empties the card. The original activation is no longer represented.
- The captured document scroll handler (`:10310`) only repositions service details when `state.routePresentationTrigger` exists (`:10315`). Once the focus-scroll completes, there is no anchor left to reposition and no popup to recover. The second Return succeeds because the trigger is then visible.

The unchanged-route reproduction rules out semantic trace replacement as the necessary cause. This is also different from the earlier ResizeObserver issue: a delayed graph redraw is not needed to lose the activation.

## Prior repairs and coverage gap

`docs/vpn-popup-repairs-2026-10-23/README.md` records LV01's clipped-anchor dismissal and LV03's protection against layout-only redraws replacing the strip. Existing tests in `frontend/tests/route_audit_regressions.test.mjs` activate an already visible trigger, then move it offscreen (`:130`, `:163`), or activate during a graph resize while its anchor remains visible (`:290`). They do not model an initially offscreen focused trigger whose native reveal finishes after activation.

The earlier timeline-popup repair already encountered the analogous distinction: `frontend/assets/app.js:4820` explicitly completes the nearest reveal with `behavior: "instant"` before applying visibility rules, with additional sticky-header handling. The VPN service-strip activation path currently lacks equivalent ordering. This is root-cause context, not a product patch or a request to remove clipped-anchor dismissal.

Documentation drift check: only an ignored runtime audit record was added. No product/API/authoring behavior changed; maintained authoring documents require no update.
