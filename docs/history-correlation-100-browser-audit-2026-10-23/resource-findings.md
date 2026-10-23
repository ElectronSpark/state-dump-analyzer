# Resource-correlation findings — 2026-10-23

## P2 — Pinned correlation popup blocks surrounding controls after scrolling

**Confirmed by the parent browser audit.** Pin the DTE resource-state popup in the single-node correlation graph, then scroll to Timeline. The popup remains fixed after its graph anchor leaves view and covers **Actions**. Hit-testing the button center returns the popup's `<dd>+720.000s</dd>`; clicks do not open Actions. Escape dismisses the card and the same button works.

Evidence: `correlation-pin-over-actions.png`, `correlation-pin-over-actions.txt`, and the source diagnosis in `resource-oracle.md`.

Root cause: `#correlation-hover` is body-mounted, fixed, interactive and positioned only on opening (`frontend/assets/app.js:7320–7377`; `frontend/assets/styles.css:3487`). Pinning suppresses pointer-leave closure. Document scrolling updates only `#timeline-hover` (`app.js:12502`), and no correlation anchor is retained for clipping or repositioning. Actions' existing popup close runs only once its click handler is reached, which the overlay prevents. Escape reaches `clearPinnedGraphInspection`, explaining recovery.

This card is separate from the previously fixed Fabric, VPN-service and timeline-marker popup implementations. Repair the existing correlation show/close/scroll lifecycle rather than adding per-button dismissal workarounds. No fix was made during this audit.

## Performance observation — slow cursor workflows with retained resource search

Complete scripted UI workflows recorded **14,538 ms** (move 069) and **9,581 ms** (072) with resource search `dte-000000`. Another retained-search observation took **11,641 ms** (076). A fresh cursor control with empty resource search took **3,420 ms** at +600.800 s (`cursor-performance-control.json`). These include actions, dependent reads and observation; they are not isolated request or CPU timings. Move 077's 1,935 ms snapshot still had a pending graph and is not complete all-component settlement.

Source-backed lead: `resources_at()` builds safe search documents for all resources at each uncached timestamp before kind filtering (`src/router_dump_analyzer/normalized_data.py:3898–3916`). The cache holds two exact timestamp snapshots (`demo/rsl_demo_plugin/scale_data.py:331`), so tiny cursor changes can rebuild the projection even when only one DTE matches. State lookup scans interval candidates (`normalized_data.py:537`).

The empty-search control supports investigating that path but is not a controlled paired benchmark. Different timestamps, cache state, graph/dashboard/topology work and tool observation may contribute. No CPU spike attribution, memory regression or exact backend bottleneck is established. A request trace/profile and paired search-on/search-off sequence remain needed.

## Correctness checks and limits

Settled graph/table checks matched the source oracle: absent → created at +120 s; failover at +360.0375 s; restoration at +480.0375 s; successful churn at +600 s and +600.075 s; unchanged next hop at failed +600.75 s. Range changes preserved the selected instant, reverse-time creation checks returned to absence, and post-reload failover reconstruction matched IP_ROUTING (`100-settled-graph.txt`).

The Ctrl-click timeline-to-log test (087) initially reached the correct row, but persistent focus/visibility after later virtualization was not established. It is **inconclusive, not a confirmed defect**. Source-only candidates listed in `resource-oracle.md` are also not counted as browser findings.

Detailed review: `resource-review.md`. This supporting agent reviewed saved evidence and source; the parent agent performed the browser operations. No product changes or public plug-in behavior changes were made.
